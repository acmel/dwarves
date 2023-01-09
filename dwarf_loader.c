/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>
*/

#include <assert.h>
#include <dirent.h>
#include <dwarf.h>
#include <elfutils/libdwfl.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libelf.h>
#include <limits.h>
#include <pthread.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "list.h"
#include "dwarves.h"
#include "dutil.h"
#include "hash.h"

#ifndef DW_AT_alignment
#define DW_AT_alignment 0x88
#endif

#ifndef DW_AT_GNU_vector
#define DW_AT_GNU_vector 0x2107
#endif

#ifndef DW_TAG_GNU_call_site
#define DW_TAG_GNU_call_site 0x4109
#define DW_TAG_GNU_call_site_parameter 0x410a
#endif

#ifndef DW_TAG_call_site
#define DW_TAG_call_site 0x48
#define DW_TAG_call_site_parameter 0x49
#endif

#ifndef DW_FORM_implicit_const
#define DW_FORM_implicit_const 0x21
#endif

#ifndef DW_OP_addrx
#define DW_OP_addrx 0xa1
#endif

static pthread_mutex_t libdw__lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t hashtags__bits = 12;
static uint32_t max_hashtags__bits = 21;

static uint32_t hashtags__fn(Dwarf_Off key)
{
	return hash_64(key, hashtags__bits);
}

bool no_bitfield_type_recode = true;

static void __tag__print_not_supported(uint32_t tag, const char *func)
{
	static bool dwarf_tags_warned[DW_TAG_GNU_call_site_parameter + 64];

	if (tag < sizeof(dwarf_tags_warned)) {
		if (dwarf_tags_warned[tag])
			return;
		dwarf_tags_warned[tag] = true;
	}

	fprintf(stderr, "%s: tag not supported %#x (%s)!\n", func,
		tag, dwarf_tag_name(tag));
}

#define tag__print_not_supported(tag) \
	__tag__print_not_supported(tag, __func__)

struct dwarf_off_ref {
	unsigned int	from_types : 1;
	Dwarf_Off	off;
};

typedef struct dwarf_off_ref dwarf_off_ref;

struct dwarf_tag {
	struct hlist_node hash_node;
	dwarf_off_ref	 type;
	Dwarf_Off	 id;
	union {
		dwarf_off_ref abstract_origin;
		dwarf_off_ref containing_type;
	};
	struct tag	 *tag;
	uint32_t         small_id;
	uint16_t         decl_line;
	const char	 *decl_file;
};

static dwarf_off_ref dwarf_tag__spec(struct dwarf_tag *dtag)
{
	return *(dwarf_off_ref *)(dtag + 1);
}

static void dwarf_tag__set_spec(struct dwarf_tag *dtag, dwarf_off_ref spec)
{
	*(dwarf_off_ref *)(dtag + 1) = spec;
}

struct dwarf_cu {
	struct hlist_head *hash_tags;
	struct hlist_head *hash_types;
	struct dwarf_tag *last_type_lookup;
	struct cu *cu;
	struct dwarf_cu *type_unit;
};

static int dwarf_cu__init(struct dwarf_cu *dcu, struct cu *cu)
{
	static struct dwarf_tag sentinel_dtag = { .id = ULLONG_MAX, };
	uint64_t hashtags_size = 1UL << hashtags__bits;

	dcu->cu = cu;

	dcu->hash_tags = cu__malloc(cu, sizeof(struct hlist_head) * hashtags_size);
	if (!dcu->hash_tags)
		return -ENOMEM;

	dcu->hash_types = cu__malloc(cu, sizeof(struct hlist_head) * hashtags_size);
	if (!dcu->hash_types) {
		cu__free(cu, dcu->hash_tags);
		return -ENOMEM;
	}

	unsigned int i;
	for (i = 0; i < hashtags_size; ++i) {
		INIT_HLIST_HEAD(&dcu->hash_tags[i]);
		INIT_HLIST_HEAD(&dcu->hash_types[i]);
	}
	dcu->type_unit = NULL;
	// To avoid a per-lookup check against NULL in dwarf_cu__find_type_by_ref()
	dcu->last_type_lookup = &sentinel_dtag;
	return 0;
}

static struct dwarf_cu *dwarf_cu__new(struct cu *cu)
{
	struct dwarf_cu *dwarf_cu = cu__zalloc(cu, sizeof(*dwarf_cu));

	if (dwarf_cu != NULL && dwarf_cu__init(dwarf_cu, cu) != 0) {
		cu__free(cu, dwarf_cu);
		dwarf_cu = NULL;
	}

	return dwarf_cu;
}

static void dwarf_cu__delete(struct cu *cu)
{
	if (cu == NULL || cu->priv == NULL)
		return;

	struct dwarf_cu *dcu = cu->priv;

	// dcu->hash_tags & dcu->hash_types are on cu->obstack
	cu__free(cu, dcu);
	cu->priv = NULL;
}

static void __tag__print_type_not_found(struct tag *tag, const char *func)
{
	struct dwarf_tag *dtag = tag->priv;
	fprintf(stderr, "%s: couldn't find %#llx type for %#llx (%s)!\n", func,
		(unsigned long long)dtag->type.off, (unsigned long long)dtag->id,
		dwarf_tag_name(tag->tag));
}

#define tag__print_type_not_found(tag) \
	__tag__print_type_not_found(tag, __func__)

static void hashtags__hash(struct hlist_head *hashtable,
			   struct dwarf_tag *dtag)
{
	struct hlist_head *head = hashtable + hashtags__fn(dtag->id);
	hlist_add_head(&dtag->hash_node, head);
}

static struct dwarf_tag *hashtags__find(const struct hlist_head *hashtable,
					const Dwarf_Off id)
{
	if (id == 0)
		return NULL;

	struct dwarf_tag *tpos;
	struct hlist_node *pos;
	uint32_t bucket = hashtags__fn(id);
	const struct hlist_head *head = hashtable + bucket;

	hlist_for_each_entry(tpos, pos, head, hash_node) {
		if (tpos->id == id)
			return tpos;
	}

	return NULL;
}

static void cu__hash(struct cu *cu, struct tag *tag)
{
	struct dwarf_cu *dcu = cu->priv;
	struct hlist_head *hashtable = tag__is_tag_type(tag) ?
							dcu->hash_types :
							dcu->hash_tags;
	hashtags__hash(hashtable, tag->priv);
}

static struct dwarf_tag *dwarf_cu__find_tag_by_ref(const struct dwarf_cu *cu,
						   const struct dwarf_off_ref *ref)
{
	if (cu == NULL)
		return NULL;
	if (ref->from_types) {
		return NULL;
	}
	return hashtags__find(cu->hash_tags, ref->off);
}

static struct dwarf_tag *dwarf_cu__find_type_by_ref(struct dwarf_cu *dcu,
						    const struct dwarf_off_ref *ref)
{
	if (dcu == NULL)
		return NULL;
	if (ref->from_types) {
		dcu = dcu->type_unit;
		if (dcu == NULL) {
			return NULL;
		}
	}

	if (dcu->last_type_lookup->id == ref->off)
		return dcu->last_type_lookup;

	struct dwarf_tag *dtag = hashtags__find(dcu->hash_types, ref->off);

	if (dtag)
		dcu->last_type_lookup = dtag;

	return dtag;
}

static void *memdup(const void *src, size_t len, struct cu *cu)
{
	void *s = cu__malloc(cu, len);
	if (s != NULL)
		memcpy(s, src, len);
	return s;
}

/* Number decoding macros.  See 7.6 Variable Length Data.  */

#define get_uleb128_step(var, addr, nth, break)			\
	__b = *(addr)++;					\
	var |= (uintmax_t) (__b & 0x7f) << (nth * 7);		\
	if ((__b & 0x80) == 0)					\
		break

#define get_uleb128_rest_return(var, i, addrp)			\
	do {							\
		for (; i < 10; ++i) {				\
			get_uleb128_step(var, *addrp, i,	\
					  return var);		\
	}							\
	/* Other implementations set VALUE to UINT_MAX in this	\
	  case. So we better do this as well.  */		\
	return UINT64_MAX;					\
  } while (0)

static uint64_t __libdw_get_uleb128(uint64_t acc, uint32_t i,
				    const uint8_t **addrp)
{
	uint8_t __b;
	get_uleb128_rest_return (acc, i, addrp);
}

#define get_uleb128(var, addr)					\
	do {							\
		uint8_t __b;				\
		var = 0;					\
		get_uleb128_step(var, addr, 0, break);		\
		var = __libdw_get_uleb128 (var, 1, &(addr));	\
	} while (0)

static uint64_t attr_numeric(Dwarf_Die *die, uint32_t name)
{
	Dwarf_Attribute attr;
	uint32_t form;

	if (dwarf_attr(die, name, &attr) == NULL)
		return 0;

	form = dwarf_whatform(&attr);

	switch (form) {
	case DW_FORM_addr: {
		Dwarf_Addr addr;
		if (dwarf_formaddr(&attr, &addr) == 0)
			return addr;
	}
		break;
	case DW_FORM_implicit_const:
	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
	case DW_FORM_sdata:
	case DW_FORM_udata: {
		Dwarf_Word value;
		if (dwarf_formudata(&attr, &value) == 0)
			return value;
	}
		break;
	case DW_FORM_flag:
	case DW_FORM_flag_present: {
		bool value;
		if (dwarf_formflag(&attr, &value) == 0)
			return value;
	}
		break;
	default:
		fprintf(stderr, "DW_AT_<0x%x>=0x%x\n", name, form);
		break;
	}

	return 0;
}

static uint64_t attr_alignment(Dwarf_Die *die, struct conf_load *conf)
{
	return conf->ignore_alignment_attr ? 0 : attr_numeric(die, DW_AT_alignment);
}

static uint64_t dwarf_expr(const uint8_t *expr, uint32_t len __maybe_unused)
{
	/* Common case: offset from start of the class */
	if (expr[0] == DW_OP_plus_uconst ||
	    expr[0] == DW_OP_constu) {
		uint64_t result;
		++expr;
		get_uleb128(result, expr);
		return result;
	}

	fprintf(stderr, "%s: unhandled %#x DW_OP_ operation\n",
		__func__, *expr);
	return UINT64_MAX;
}

static Dwarf_Off __attr_offset(Dwarf_Attribute *attr)
{
	Dwarf_Block block;

	switch (dwarf_whatform(attr)) {
	case DW_FORM_implicit_const:
	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
	case DW_FORM_sdata:
	case DW_FORM_udata: {
		Dwarf_Word value;
		if (dwarf_formudata(attr, &value) == 0)
			return value;
		break;
	}
	default:
		if (dwarf_formblock(attr, &block) == 0)
			return dwarf_expr(block.data, block.length);
	}

	return 0;
}

static Dwarf_Off attr_offset(Dwarf_Die *die, const uint32_t name)
{
	Dwarf_Attribute attr;

	if (dwarf_attr(die, name, &attr) == NULL)
		return 0;

	return __attr_offset(&attr);
}

static const char *attr_string(Dwarf_Die *die, uint32_t name, struct conf_load *conf __maybe_unused)
{
	const char *str = NULL;
	Dwarf_Attribute attr;

	if (dwarf_attr(die, name, &attr) != NULL) {
		str = dwarf_formstring(&attr);

		if (conf && conf->kabi_prefix && str && strncmp(str, conf->kabi_prefix, conf->kabi_prefix_len) == 0)
			return conf->kabi_prefix;
	}

	return str;
}

static struct dwarf_off_ref attr_type(Dwarf_Die *die, uint32_t attr_name)
{
	Dwarf_Attribute attr;
	struct dwarf_off_ref ref;
	if (dwarf_attr(die, attr_name, &attr) != NULL) {
		Dwarf_Die type_die;
		if (dwarf_formref_die(&attr, &type_die) != NULL) {
			ref.from_types = attr.form == DW_FORM_ref_sig8;
			ref.off = dwarf_dieoffset(&type_die);
			return ref;
		}
	}
	memset(&ref, 0, sizeof(ref));
	return ref;
}

static int attr_location(Dwarf_Die *die, Dwarf_Op **expr, size_t *exprlen)
{
	Dwarf_Attribute attr;
	if (dwarf_attr(die, DW_AT_location, &attr) != NULL) {
		if (dwarf_getlocation(&attr, expr, exprlen) == 0) {
			/* DW_OP_addrx needs additional lookup for real addr. */
			if (*exprlen != 0 && expr[0]->atom == DW_OP_addrx) {
				Dwarf_Attribute addr_attr;
				dwarf_getlocation_attr(&attr, expr[0], &addr_attr);

				Dwarf_Addr address;
				dwarf_formaddr (&addr_attr, &address);

				expr[0]->number = address;
			}
			return 0;
		}
	}

	return 1;
}

static void *__tag__alloc(struct dwarf_cu *dcu, size_t size, bool spec)
{
	struct dwarf_tag *dtag = cu__zalloc(dcu->cu, (sizeof(*dtag) + (spec ? sizeof(dwarf_off_ref) : 0)));

	if (dtag == NULL)
		return NULL;

	struct tag *tag = cu__zalloc(dcu->cu, size);

	if (tag == NULL)
		return NULL;

	dtag->tag = tag;
	tag->priv = dtag;
	tag->type = 0;
	tag->top_level = 0;

	return tag;
}

static void *tag__alloc(struct cu *cu, size_t size)
{
	return __tag__alloc(cu->priv, size, false);
}

static void *tag__alloc_with_spec(struct cu *cu, size_t size)
{
	return __tag__alloc(cu->priv, size, true);
}

static void tag__init(struct tag *tag, struct cu *cu, Dwarf_Die *die)
{
	struct dwarf_tag *dtag = tag->priv;

	tag->tag = dwarf_tag(die);

	dtag->id  = dwarf_dieoffset(die);

	if (tag->tag == DW_TAG_imported_module ||
	    tag->tag == DW_TAG_imported_declaration)
		dtag->type = attr_type(die, DW_AT_import);
	else
		dtag->type = attr_type(die, DW_AT_type);

	dtag->abstract_origin = attr_type(die, DW_AT_abstract_origin);
	tag->recursivity_level = 0;

	if (cu->extra_dbg_info) {
		pthread_mutex_lock(&libdw__lock);

		int32_t decl_line;
		const char *decl_file = dwarf_decl_file(die);
		static const char *last_decl_file, *last_decl_file_ptr;

		if (decl_file != last_decl_file_ptr) {
			last_decl_file = decl_file ? strdup(decl_file) : NULL;
			last_decl_file_ptr = decl_file;
		}

		dtag->decl_file = last_decl_file;
		dwarf_decl_line(die, &decl_line);
		dtag->decl_line = decl_line;

		pthread_mutex_unlock(&libdw__lock);
	}

	INIT_LIST_HEAD(&tag->node);
}

static struct tag *tag__new(Dwarf_Die *die, struct cu *cu)
{
	struct tag *tag = tag__alloc(cu, sizeof(*tag));

	if (tag != NULL)
		tag__init(tag, cu, die);

	return tag;
}

static struct ptr_to_member_type *ptr_to_member_type__new(Dwarf_Die *die,
							  struct cu *cu)
{
	struct ptr_to_member_type *ptr = tag__alloc(cu, sizeof(*ptr));

	if (ptr != NULL) {
		tag__init(&ptr->tag, cu, die);
		struct dwarf_tag *dtag = ptr->tag.priv;
		dtag->containing_type = attr_type(die, DW_AT_containing_type);
	}

	return ptr;
}

static uint8_t encoding_to_float_type(uint64_t encoding)
{
	switch (encoding) {
	case DW_ATE_complex_float:	return BT_FP_CMPLX;
	case DW_ATE_float:		return BT_FP_SINGLE;
	case DW_ATE_imaginary_float:	return BT_FP_IMGRY;
	default:			return 0;
	}
}

static struct base_type *base_type__new(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct base_type *bt = tag__alloc(cu, sizeof(*bt));

	if (bt != NULL) {
		tag__init(&bt->tag, cu, die);
		bt->name = attr_string(die, DW_AT_name, conf);
		bt->bit_size = attr_numeric(die, DW_AT_byte_size) * 8;
		uint64_t encoding = attr_numeric(die, DW_AT_encoding);
		bt->is_bool = encoding == DW_ATE_boolean;
		bt->is_signed = (encoding == DW_ATE_signed) || (encoding == DW_ATE_signed_char);
		bt->is_varargs = false;
		bt->name_has_encoding = true;
		bt->float_type = encoding_to_float_type(encoding);
		INIT_LIST_HEAD(&bt->node);
	}

	return bt;
}

static struct array_type *array_type__new(Dwarf_Die *die, struct cu *cu)
{
	struct array_type *at = tag__alloc(cu, sizeof(*at));

	if (at != NULL) {
		tag__init(&at->tag, cu, die);
		at->dimensions = 0;
		at->nr_entries = NULL;
		at->is_vector	 = dwarf_hasattr(die, DW_AT_GNU_vector);
	}

	return at;
}

static struct string_type *string_type__new(Dwarf_Die *die, struct cu *cu)
{
	struct string_type *st = tag__alloc(cu, sizeof(*st));

	if (st != NULL) {
		tag__init(&st->tag, cu, die);
		st->nr_entries = attr_numeric(die, DW_AT_byte_size);
		if (st->nr_entries == 0)
			st->nr_entries = 1;
	}

	return st;
}

static void namespace__init(struct namespace *namespace, Dwarf_Die *die,
			    struct cu *cu, struct conf_load *conf)
{
	tag__init(&namespace->tag, cu, die);
	INIT_LIST_HEAD(&namespace->tags);
	INIT_LIST_HEAD(&namespace->annots);
	namespace->name  = attr_string(die, DW_AT_name, conf);
	namespace->nr_tags = 0;
	namespace->shared_tags = 0;
}

static struct namespace *namespace__new(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct namespace *namespace = tag__alloc(cu, sizeof(*namespace));

	if (namespace != NULL)
		namespace__init(namespace, die, cu, conf);

	return namespace;
}

static void type__init(struct type *type, Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	namespace__init(&type->namespace, die, cu, conf);
	__type__init(type);
	type->size		 = attr_numeric(die, DW_AT_byte_size);
	type->alignment		 = attr_alignment(die, conf);
	type->declaration	 = attr_numeric(die, DW_AT_declaration);
	dwarf_tag__set_spec(type->namespace.tag.priv,
			    attr_type(die, DW_AT_specification));
	type->definition_emitted = 0;
	type->fwd_decl_emitted	 = 0;
	type->resized		 = 0;
	type->nr_members	 = 0;
	type->nr_static_members	 = 0;
	type->is_signed_enum	 = 0;

	Dwarf_Attribute attr;
	if (dwarf_attr(die, DW_AT_type, &attr) != NULL) {
		Dwarf_Die type_die;
		if (dwarf_formref_die(&attr, &type_die) != NULL) {
			uint64_t encoding = attr_numeric(&type_die, DW_AT_encoding);

			if (encoding == DW_ATE_signed || encoding == DW_ATE_signed_char)
				type->is_signed_enum = 1;
		}
	}
}

static struct type *type__new(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct type *type = tag__alloc_with_spec(cu, sizeof(*type));

	if (type != NULL)
		type__init(type, die, cu, conf);

	return type;
}

static struct enumerator *enumerator__new(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct enumerator *enumerator = tag__alloc(cu, sizeof(*enumerator));

	if (enumerator != NULL) {
		tag__init(&enumerator->tag, cu, die);
		enumerator->name = attr_string(die, DW_AT_name, conf);
		enumerator->value = attr_numeric(die, DW_AT_const_value);
	}

	return enumerator;
}

static enum vscope dwarf__location(Dwarf_Die *die, uint64_t *addr, struct location *location)
{
	enum vscope scope = VSCOPE_UNKNOWN;

	if (attr_location(die, &location->expr, &location->exprlen) != 0)
		scope = VSCOPE_OPTIMIZED;
	else if (location->exprlen != 0) {
		Dwarf_Op *expr = location->expr;
		switch (expr->atom) {
		case DW_OP_addr:
		case DW_OP_addrx:
			scope = VSCOPE_GLOBAL;
			*addr = expr[0].number;
			break;
		case DW_OP_reg1 ... DW_OP_reg31:
		case DW_OP_breg0 ... DW_OP_breg31:
			scope = VSCOPE_REGISTER;	break;
		case DW_OP_fbreg:
			scope = VSCOPE_LOCAL;	break;
		}
	}

	return scope;
}

enum vscope variable__scope(const struct variable *var)
{
	return var->scope;
}

const char *variable__scope_str(const struct variable *var)
{
	switch (var->scope) {
	case VSCOPE_LOCAL:	return "local";
	case VSCOPE_GLOBAL:	return "global";
	case VSCOPE_REGISTER:	return "register";
	case VSCOPE_OPTIMIZED:	return "optimized";
	default: break;
	};

	return "unknown";
}

static struct variable *variable__new(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct variable *var;
	bool has_specification;

	has_specification = dwarf_hasattr(die, DW_AT_specification);
	if (has_specification) {
		var = tag__alloc_with_spec(cu, sizeof(*var));
	} else {
		var = tag__alloc(cu, sizeof(*var));
	}

	if (var != NULL) {
		tag__init(&var->ip.tag, cu, die);
		var->name = attr_string(die, DW_AT_name, conf);
		/* variable is visible outside of its enclosing cu */
		var->external = dwarf_hasattr(die, DW_AT_external);
		/* non-defining declaration of an object */
		var->declaration = dwarf_hasattr(die, DW_AT_declaration);
		var->has_specification = has_specification;
		var->scope = VSCOPE_UNKNOWN;
		INIT_LIST_HEAD(&var->annots);
		var->ip.addr = 0;
		if (!var->declaration && cu->has_addr_info)
			var->scope = dwarf__location(die, &var->ip.addr, &var->location);
		if (has_specification) {
			dwarf_tag__set_spec(var->ip.tag.priv,
					    attr_type(die, DW_AT_specification));
		}
	}

	return var;
}

static int tag__recode_dwarf_bitfield(struct tag *tag, struct cu *cu, uint16_t bit_size)
{
	int id;
	type_id_t short_id;
	struct tag *recoded;
	/* in all the cases the name is at the same offset */
	const char *name = namespace__name(tag__namespace(tag));

	switch (tag->tag) {
	case DW_TAG_typedef: {
		const struct dwarf_tag *dtag = tag->priv;
		struct dwarf_tag *dtype = dwarf_cu__find_type_by_ref(cu->priv, &dtag->type);

		if (dtype == NULL) {
			tag__print_type_not_found(tag);
			return -ENOENT;
		}

		struct tag *type = dtype->tag;

		id = tag__recode_dwarf_bitfield(type, cu, bit_size);
		if (id < 0)
			return id;

		struct type *new_typedef = cu__zalloc(cu, sizeof(*new_typedef));
		if (new_typedef == NULL)
			return -ENOMEM;

		recoded = (struct tag *)new_typedef;
		recoded->tag = DW_TAG_typedef;
		recoded->type = id;
		new_typedef->namespace.name = tag__namespace(tag)->name;
	}
		break;

	case DW_TAG_const_type:
	case DW_TAG_volatile_type:
	case DW_TAG_atomic_type: {
		const struct dwarf_tag *dtag = tag->priv;
		struct dwarf_tag *dtype = dwarf_cu__find_type_by_ref(cu->priv, &dtag->type);

		if (dtype == NULL) {
			tag__print_type_not_found(tag);
			return -ENOENT;
		}

		struct tag *type = dtype->tag;

		id = tag__recode_dwarf_bitfield(type, cu, bit_size);
		if (id >= 0 && (uint32_t)id == tag->type)
			return id;

		recoded = cu__zalloc(cu, sizeof(*recoded));
		if (recoded == NULL)
			return -ENOMEM;

		recoded->tag = DW_TAG_volatile_type;
		recoded->type = id;
	}
		break;

	case DW_TAG_base_type:
		/*
		 * Here we must search on the final, core cu, not on
		 * the dwarf_cu as in dwarf there are no such things
		 * as base_types of less than 8 bits, etc.
		 */
		recoded = cu__find_base_type_by_name_and_size(cu, name, bit_size, &short_id);
		if (recoded != NULL)
			return short_id;

		struct base_type *new_bt = cu__zalloc(cu, sizeof(*new_bt));
		if (new_bt == NULL)
			return -ENOMEM;

		recoded = (struct tag *)new_bt;
		recoded->tag = DW_TAG_base_type;
		recoded->top_level = 1;
		new_bt->name = strdup(name);
		new_bt->bit_size = bit_size;
		break;

	case DW_TAG_enumeration_type:
		/*
		 * Here we must search on the final, core cu, not on
		 * the dwarf_cu as in dwarf there are no such things
		 * as enumeration_types of less than 8 bits, etc.
		 */
		recoded = cu__find_enumeration_by_name_and_size(cu, name, bit_size, &short_id);
		if (recoded != NULL)
			return short_id;

		struct type *alias = tag__type(tag);
		struct type *new_enum = cu__zalloc(cu, sizeof(*new_enum));
		if (new_enum == NULL)
			return -ENOMEM;

		recoded = (struct tag *)new_enum;
		recoded->tag = DW_TAG_enumeration_type;
		recoded->top_level = 1;
		new_enum->nr_members = alias->nr_members;
		/*
		 * Share the tags
		 */
		new_enum->namespace.tags.next = &alias->namespace.tags;
		new_enum->namespace.shared_tags = 1;
		new_enum->namespace.name = strdup(name);
		new_enum->size = bit_size;
		break;
	default:
		fprintf(stderr, "%s: tag=%s, name=%s, bit_size=%d\n",
			__func__, dwarf_tag_name(tag->tag),
			name, bit_size);
		return -EINVAL;
	}

	uint32_t new_id;
	if (cu__add_tag(cu, recoded, &new_id) == 0)
		return new_id;

	free(recoded);
	return -ENOMEM;
}

static int add_llvm_annotation(Dwarf_Die *die, int component_idx, struct conf_load *conf,
			       struct list_head *head)
{
	struct llvm_annotation *annot;
	const char *name;

	if (conf->skip_encoding_btf_decl_tag)
		return 0;

	/* Only handle btf_decl_tag annotation for now. */
	name = attr_string(die, DW_AT_name, conf);
	if (strcmp(name, "btf_decl_tag") != 0)
		return 0;

	annot = zalloc(sizeof(*annot));
	if (!annot)
		return -ENOMEM;

	annot->value = attr_string(die, DW_AT_const_value, conf);
	annot->component_idx = component_idx;
	list_add_tail(&annot->node, head);
	return 0;
}

static int add_child_llvm_annotations(Dwarf_Die *die, int component_idx,
				      struct conf_load *conf, struct list_head *head)
{
	Dwarf_Die child;
	int ret;

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0)
		return 0;

	die = &child;
	do {
		if (dwarf_tag(die) == DW_TAG_LLVM_annotation) {
			ret = add_llvm_annotation(die, component_idx, conf, head);
			if (ret)
				return ret;
		}
	} while (dwarf_siblingof(die, die) == 0);

	return 0;
}

int class_member__dwarf_recode_bitfield(struct class_member *member,
					struct cu *cu)
{
	struct dwarf_tag *dtag = member->tag.priv;
	struct dwarf_tag *type = dwarf_cu__find_type_by_ref(cu->priv, &dtag->type);
	int recoded_type_id;

	if (type == NULL)
		return -ENOENT;

	recoded_type_id = tag__recode_dwarf_bitfield(type->tag, cu, member->bitfield_size);
	if (recoded_type_id < 0)
		return recoded_type_id;

	member->tag.type = recoded_type_id;
	return 0;
}

static struct class_member *class_member__new(Dwarf_Die *die, struct cu *cu,
					      bool in_union, struct conf_load *conf)
{
	struct class_member *member = tag__alloc(cu, sizeof(*member));

	if (member != NULL) {
		tag__init(&member->tag, cu, die);
		member->name = attr_string(die, DW_AT_name, conf);
		member->alignment = attr_alignment(die, conf);

		Dwarf_Attribute attr;

		member->has_bit_offset = dwarf_attr(die, DW_AT_data_bit_offset, &attr) != NULL;

		if (member->has_bit_offset) {
			member->bit_offset = __attr_offset(&attr);
			// byte_offset and bitfield_offset will be recalculated later, when
			// we discover the size of this bitfield base type.
		} else {
			if (dwarf_attr(die, DW_AT_data_member_location, &attr) != NULL) {
				member->byte_offset = __attr_offset(&attr);
			} else {
				member->is_static = !in_union;
			}

			/*
			 * Bit offset calculated here is valid only for byte-aligned
			 * fields. For bitfields on little-endian archs we need to
			 * adjust them taking into account byte size of the field,
			 * which might not be yet known. So we'll re-calculate bit
			 * offset later, in class_member__cache_byte_size.
			 */
			member->bit_offset = member->byte_offset * 8;
			member->bitfield_offset = attr_numeric(die, DW_AT_bit_offset);
		}

		/*
		 * If DW_AT_byte_size is not present, byte size will be
		 * determined later in class_member__cache_byte_size using
		 * base integer/enum type
		 */
		member->byte_size = attr_numeric(die, DW_AT_byte_size);
		member->bitfield_size = attr_numeric(die, DW_AT_bit_size);
		member->bit_hole = 0;
		member->bitfield_end = 0;
		member->visited = 0;

		if (!cu__is_c(cu)) {
			member->accessibility = attr_numeric(die, DW_AT_accessibility);
			member->const_value   = attr_numeric(die, DW_AT_const_value);
			member->virtuality    = attr_numeric(die, DW_AT_virtuality);
		}
		member->hole = 0;
	}

	return member;
}

static struct parameter *parameter__new(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct parameter *parm = tag__alloc(cu, sizeof(*parm));

	if (parm != NULL) {
		tag__init(&parm->tag, cu, die);
		parm->name = attr_string(die, DW_AT_name, conf);
	}

	return parm;
}

static struct inline_expansion *inline_expansion__new(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct inline_expansion *exp = tag__alloc(cu, sizeof(*exp));

	if (exp != NULL) {
		struct dwarf_tag *dtag = exp->ip.tag.priv;

		tag__init(&exp->ip.tag, cu, die);
		dtag->decl_file = attr_string(die, DW_AT_call_file, conf);
		dtag->decl_line = attr_numeric(die, DW_AT_call_line);
		dtag->type = attr_type(die, DW_AT_abstract_origin);
		exp->ip.addr = 0;
		exp->high_pc = 0;

		if (!cu->has_addr_info)
			goto out;

		if (dwarf_lowpc(die, &exp->ip.addr))
			exp->ip.addr = 0;
		if (dwarf_lowpc(die, &exp->high_pc))
			exp->high_pc = 0;

		exp->size = exp->high_pc - exp->ip.addr;
		if (exp->size == 0) {
			Dwarf_Addr base, start;
			ptrdiff_t offset = 0;

			while (1) {
				offset = dwarf_ranges(die, offset, &base, &start,
						      &exp->high_pc);
				start = (unsigned long)start;
				exp->high_pc = (unsigned long)exp->high_pc;
				if (offset <= 0)
					break;
				exp->size += exp->high_pc - start;
				if (exp->ip.addr == 0)
					exp->ip.addr = start;
			}
		}
	}
out:
	return exp;
}

static struct label *label__new(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct label *label = tag__alloc(cu, sizeof(*label));

	if (label != NULL) {
		tag__init(&label->ip.tag, cu, die);
		label->name = attr_string(die, DW_AT_name, conf);
		if (!cu->has_addr_info || dwarf_lowpc(die, &label->ip.addr))
			label->ip.addr = 0;
	}

	return label;
}

static struct class *class__new(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct class *class = tag__alloc_with_spec(cu, sizeof(*class));

	if (class != NULL) {
		type__init(&class->type, die, cu, conf);
		INIT_LIST_HEAD(&class->vtable);
		class->nr_vtable_entries =
		  class->nr_holes =
		  class->nr_bit_holes =
		  class->padding =
		  class->bit_padding = 0;
		class->priv = NULL;
	}

	return class;
}

static void lexblock__init(struct lexblock *block, struct cu *cu,
			   Dwarf_Die *die)
{
	Dwarf_Off high_pc;

	if (!cu->has_addr_info || dwarf_lowpc(die, &block->ip.addr)) {
		block->ip.addr = 0;
		block->size = 0;
	} else if (dwarf_highpc(die, &high_pc))
		block->size = 0;
	else
		block->size = high_pc - block->ip.addr;

	INIT_LIST_HEAD(&block->tags);

	block->size_inline_expansions =
	block->nr_inline_expansions =
		block->nr_labels =
		block->nr_lexblocks =
		block->nr_variables = 0;
}

static struct lexblock *lexblock__new(Dwarf_Die *die, struct cu *cu)
{
	struct lexblock *block = tag__alloc(cu, sizeof(*block));

	if (block != NULL) {
		tag__init(&block->ip.tag, cu, die);
		lexblock__init(block, cu, die);
	}

	return block;
}

static void ftype__init(struct ftype *ftype, Dwarf_Die *die, struct cu *cu)
{
#ifndef NDEBUG
	const uint16_t tag = dwarf_tag(die);
	assert(tag == DW_TAG_subprogram || tag == DW_TAG_subroutine_type);
#endif
	tag__init(&ftype->tag, cu, die);
	INIT_LIST_HEAD(&ftype->parms);
	ftype->nr_parms	    = 0;
	ftype->unspec_parms = 0;
}

static struct ftype *ftype__new(Dwarf_Die *die, struct cu *cu)
{
	struct ftype *ftype = tag__alloc(cu, sizeof(*ftype));

	if (ftype != NULL)
		ftype__init(ftype, die, cu);

	return ftype;
}

static struct function *function__new(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct function *func = tag__alloc_with_spec(cu, sizeof(*func));

	if (func != NULL) {
		ftype__init(&func->proto, die, cu);
		lexblock__init(&func->lexblock, cu, die);
		func->name	      = attr_string(die, DW_AT_name, conf);
		func->linkage_name    = attr_string(die, DW_AT_MIPS_linkage_name, conf);
		func->inlined	      = attr_numeric(die, DW_AT_inline);
		func->declaration     = dwarf_hasattr(die, DW_AT_declaration);
		func->external	      = dwarf_hasattr(die, DW_AT_external);
		func->abstract_origin = dwarf_hasattr(die, DW_AT_abstract_origin);
		dwarf_tag__set_spec(func->proto.tag.priv,
				    attr_type(die, DW_AT_specification));
		func->accessibility   = attr_numeric(die, DW_AT_accessibility);
		func->virtuality      = attr_numeric(die, DW_AT_virtuality);
		INIT_LIST_HEAD(&func->vtable_node);
		INIT_LIST_HEAD(&func->annots);
		INIT_LIST_HEAD(&func->tool_node);
		func->vtable_entry    = -1;
		if (dwarf_hasattr(die, DW_AT_vtable_elem_location))
			func->vtable_entry = attr_offset(die, DW_AT_vtable_elem_location);
		func->cu_total_size_inline_expansions = 0;
		func->cu_total_nr_inline_expansions = 0;
		func->priv = NULL;
	}

	return func;
}

static uint64_t attr_upper_bound(Dwarf_Die *die)
{
	Dwarf_Attribute attr;

	if (dwarf_attr(die, DW_AT_upper_bound, &attr) != NULL) {
		Dwarf_Word num;

		if (dwarf_formudata(&attr, &num) == 0) {
			return (uintmax_t)num + 1;
		}
	} else if (dwarf_attr(die, DW_AT_count, &attr) != NULL) {
		Dwarf_Word num;

		if (dwarf_formudata(&attr, &num) == 0) {
			return (uintmax_t)num;
		}
	}

	return 0;
}

static void __cu__tag_not_handled(Dwarf_Die *die, const char *fn)
{
	uint32_t tag = dwarf_tag(die);

	fprintf(stderr, "%s: DW_TAG_%s (%#x) @ <%#llx> not handled!\n",
		fn, dwarf_tag_name(tag), tag,
		(unsigned long long)dwarf_dieoffset(die));
}

static struct tag unsupported_tag;

#define cu__tag_not_handled(die) __cu__tag_not_handled(die, __FUNCTION__)

static struct tag *__die__process_tag(Dwarf_Die *die, struct cu *cu,
				      int toplevel, const char *fn, struct conf_load *conf);

#define die__process_tag(die, cu, toplevel, conf_load) \
	__die__process_tag(die, cu, toplevel, __FUNCTION__, conf_load)

static struct tag *die__create_new_tag(Dwarf_Die *die, struct cu *cu)
{
	struct tag *tag = tag__new(die, cu);

	if (tag != NULL) {
		if (dwarf_haschildren(die))
			fprintf(stderr, "%s: %s WITH children!\n", __func__,
				dwarf_tag_name(tag->tag));
	}

	return tag;
}

static struct btf_type_tag_ptr_type *die__create_new_btf_type_tag_ptr_type(Dwarf_Die *die, struct cu *cu)
{
	struct btf_type_tag_ptr_type *tag;

	tag  = tag__alloc_with_spec(cu, sizeof(struct btf_type_tag_ptr_type));
	if (tag == NULL)
		return NULL;

	tag__init(&tag->tag, cu, die);
	tag->tag.has_btf_type_tag = true;
	INIT_LIST_HEAD(&tag->tags);
	return tag;
}

static struct btf_type_tag_type *die__create_new_btf_type_tag_type(Dwarf_Die *die, struct cu *cu,
								   struct conf_load *conf)
{
	struct btf_type_tag_type *tag;

	tag  = tag__alloc_with_spec(cu, sizeof(struct btf_type_tag_type));
	if (tag == NULL)
		return NULL;

	tag__init(&tag->tag, cu, die);
	tag->value = attr_string(die, DW_AT_const_value, conf);
	return tag;
}

static struct tag *die__create_new_pointer_tag(Dwarf_Die *die, struct cu *cu,
					       struct conf_load *conf)
{
	struct btf_type_tag_ptr_type *tag = NULL;
	struct btf_type_tag_type *annot;
	Dwarf_Die *cdie, child;
	const char *name;
	uint32_t id;

	/* If no child tags or skipping btf_type_tag encoding, just create a new tag
	 * and return
	 */
	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0 ||
	    conf->skip_encoding_btf_type_tag)
		return tag__new(die, cu);

	/* Otherwise, check DW_TAG_LLVM_annotation child tags */
	cdie = &child;
	do {
		if (dwarf_tag(cdie) != DW_TAG_LLVM_annotation)
			continue;

		/* Only check btf_type_tag annotations */
		name = attr_string(cdie, DW_AT_name, conf);
		if (strcmp(name, "btf_type_tag") != 0)
			continue;

		if (tag == NULL) {
			/* Create a btf_type_tag_ptr type. */
			tag = die__create_new_btf_type_tag_ptr_type(die, cu);
			if (!tag)
				return NULL;
		}

		/* Create a btf_type_tag type for this annotation. */
		annot = die__create_new_btf_type_tag_type(cdie, cu, conf);
		if (annot == NULL)
			return NULL;

		if (cu__table_add_tag(cu, &annot->tag, &id) < 0)
			return NULL;

		struct dwarf_tag *dtag = annot->tag.priv;
		dtag->small_id = id;
		cu__hash(cu, &annot->tag);

		/* For a list of DW_TAG_LLVM_annotation like tag1 -> tag2 -> tag3,
		 * the tag->tags contains tag3 -> tag2 -> tag1.
		 */
		list_add(&annot->node, &tag->tags);
	} while (dwarf_siblingof(cdie, cdie) == 0);

	return tag ? &tag->tag : tag__new(die, cu);
}

static struct tag *die__create_new_ptr_to_member_type(Dwarf_Die *die,
						      struct cu *cu)
{
	struct ptr_to_member_type *ptr = ptr_to_member_type__new(die, cu);

	return ptr ? &ptr->tag : NULL;
}

static int die__process_class(Dwarf_Die *die,
			      struct type *class, struct cu *cu, struct conf_load *conf);

static struct tag *die__create_new_class(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	Dwarf_Die child;
	struct class *class = class__new(die, cu, conf);

	if (class != NULL &&
	    dwarf_haschildren(die) != 0 &&
	    dwarf_child(die, &child) == 0) {
		if (die__process_class(&child, &class->type, cu, conf) != 0) {
			class__delete(class);
			class = NULL;
		}
	}

	return class ? &class->type.namespace.tag : NULL;
}

static int die__process_namespace(Dwarf_Die *die, struct namespace *namespace,
				  struct cu *cu, struct conf_load *conf);

static struct tag *die__create_new_namespace(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	Dwarf_Die child;
	struct namespace *namespace = namespace__new(die, cu, conf);

	if (namespace != NULL &&
	    dwarf_haschildren(die) != 0 &&
	    dwarf_child(die, &child) == 0) {
		if (die__process_namespace(&child, namespace, cu, conf) != 0) {
			namespace__delete(namespace);
			namespace = NULL;
		}
	}

	return namespace ? &namespace->tag : NULL;
}

static struct tag *die__create_new_union(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	Dwarf_Die child;
	struct type *utype = type__new(die, cu, conf);

	if (utype != NULL &&
	    dwarf_haschildren(die) != 0 &&
	    dwarf_child(die, &child) == 0) {
		if (die__process_class(&child, utype, cu, conf) != 0) {
			type__delete(utype);
			utype = NULL;
		}
	}

	return utype ? &utype->namespace.tag : NULL;
}

static struct tag *die__create_new_base_type(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct base_type *base = base_type__new(die, cu, conf);

	if (base == NULL)
		return NULL;

	if (dwarf_haschildren(die))
		fprintf(stderr, "%s: DW_TAG_base_type WITH children!\n",
			__func__);

	return &base->tag;
}

static struct tag *die__create_new_typedef(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct type *tdef = type__new(die, cu, conf);

	if (tdef == NULL)
		return NULL;

	if (add_child_llvm_annotations(die, -1, conf, &tdef->namespace.annots))
		return NULL;

	return &tdef->namespace.tag;
}

static struct tag *die__create_new_array(Dwarf_Die *die, struct cu *cu)
{
	Dwarf_Die child;
	/* "64 dimensions will be enough for everybody." acme, 2006 */
	const uint8_t max_dimensions = 64;
	uint32_t nr_entries[max_dimensions];
	struct array_type *array = array_type__new(die, cu);

	if (array == NULL)
		return NULL;

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0)
		return &array->tag;

	die = &child;
	do {
		if (dwarf_tag(die) == DW_TAG_subrange_type) {
			nr_entries[array->dimensions++] = attr_upper_bound(die);
			if (array->dimensions == max_dimensions) {
				fprintf(stderr, "%s: only %u dimensions are "
						"supported!\n",
					__FUNCTION__, max_dimensions);
				break;
			}
		} else
			cu__tag_not_handled(die);
	} while (dwarf_siblingof(die, die) == 0);

	array->nr_entries = memdup(nr_entries,
				   array->dimensions * sizeof(uint32_t), cu);
	if (array->nr_entries == NULL)
		goto out_free;

	return &array->tag;
out_free:
	free(array);
	return NULL;
}

static struct tag *die__create_new_string_type(Dwarf_Die *die, struct cu *cu)
{
	struct string_type *string = string_type__new(die, cu);

	if (string == NULL)
		return NULL;

	return &string->tag;
}

static struct tag *die__create_new_parameter(Dwarf_Die *die,
					     struct ftype *ftype,
					     struct lexblock *lexblock,
					     struct cu *cu, struct conf_load *conf,
					     int param_idx)
{
	struct parameter *parm = parameter__new(die, cu, conf);

	if (parm == NULL)
		return NULL;

	if (ftype != NULL) {
		ftype__add_parameter(ftype, parm);
		if (param_idx >= 0) {
			if (add_child_llvm_annotations(die, param_idx, conf, &(tag__function(&ftype->tag)->annots)))
				return NULL;
		}
	} else {
		/*
		 * DW_TAG_formal_parameters on a non DW_TAG_subprogram nor
		 * DW_TAG_subroutine_type tag happens sometimes, likely due to
		 * compiler optimizing away a inline expansion (at least this
		 * was observed in some cases, such as in the Linux kernel
		 * current_kernel_time function circa 2.6.20-rc5), keep it in
		 * the lexblock tag list because it can be referenced as an
		 * DW_AT_abstract_origin in another DW_TAG_formal_parameter.
		*/
		lexblock__add_tag(lexblock, &parm->tag);
	}

	return &parm->tag;
}

static struct tag *die__create_new_label(Dwarf_Die *die,
					 struct lexblock *lexblock,
					 struct cu *cu, struct conf_load *conf)
{
	struct label *label = label__new(die, cu, conf);

	if (label == NULL)
		return NULL;

	if (lexblock != NULL) {
		// asm CUs have labels and they will be in the cu top level tag list
		// See die__process_unit()
		lexblock__add_label(lexblock, label);
	}

	return &label->ip.tag;
}

static struct tag *die__create_new_variable(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct variable *var = variable__new(die, cu, conf);

	if (var == NULL || add_child_llvm_annotations(die, -1, conf, &var->annots))
		return NULL;

	return &var->ip.tag;
}

static struct tag *die__create_new_subroutine_type(Dwarf_Die *die,
						   struct cu *cu, struct conf_load *conf)
{
	Dwarf_Die child;
	struct ftype *ftype = ftype__new(die, cu);
	struct tag *tag;

	if (ftype == NULL)
		return NULL;

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0)
		goto out;

	die = &child;
	do {
		uint32_t id;

		switch (dwarf_tag(die)) {
		case DW_TAG_subrange_type: // ADA stuff
			tag__print_not_supported(dwarf_tag(die));
			continue;
		case DW_TAG_formal_parameter:
			tag = die__create_new_parameter(die, ftype, NULL, cu, conf, -1);
			break;
		case DW_TAG_unspecified_parameters:
			ftype->unspec_parms = 1;
			continue;
		default:
			tag = die__process_tag(die, cu, 0, conf);
			if (tag == NULL)
				goto out_delete;

			if (tag == &unsupported_tag) {
				tag__print_not_supported(dwarf_tag(die));
				continue;
			}

			if (cu__add_tag(cu, tag, &id) < 0)
				goto out_delete_tag;

			goto hash;
		}

		if (tag == NULL)
			goto out_delete;

		if (cu__table_add_tag(cu, tag, &id) < 0)
			goto out_delete_tag;
hash:
		cu__hash(cu, tag);
		struct dwarf_tag *dtag = tag->priv;
		dtag->small_id = id;
	} while (dwarf_siblingof(die, die) == 0);
out:
	return &ftype->tag;
out_delete_tag:
	tag__delete(tag);
out_delete:
	ftype__delete(ftype);
	return NULL;
}

static struct tag *die__create_new_enumeration(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	Dwarf_Die child;
	struct type *enumeration = type__new(die, cu, conf);

	if (enumeration == NULL)
		return NULL;

	if (enumeration->size == 0)
		enumeration->size = sizeof(int) * 8;
	else
		enumeration->size *= 8;

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0) {
		/* Seen on libQtCore.so.4.3.4.debug,
		 * class QAbstractFileEngineIterator, enum EntryInfoType */
		goto out;
	}

	die = &child;
	do {
		struct enumerator *enumerator;

		if (dwarf_tag(die) != DW_TAG_enumerator) {
			cu__tag_not_handled(die);
			continue;
		}
		enumerator = enumerator__new(die, cu, conf);
		if (enumerator == NULL)
			goto out_delete;

		enumeration__add(enumeration, enumerator);
	} while (dwarf_siblingof(die, die) == 0);
out:
	return &enumeration->namespace.tag;
out_delete:
	enumeration__delete(enumeration);
	return NULL;
}

static int die__process_class(Dwarf_Die *die, struct type *class,
			      struct cu *cu, struct conf_load *conf)
{
	const bool is_union = tag__is_union(&class->namespace.tag);
	int member_idx = 0;

	do {
		switch (dwarf_tag(die)) {
		case DW_TAG_subrange_type: // XXX: ADA stuff, its a type tho, will have other entries referencing it...
		case DW_TAG_variant_part: // XXX: Rust stuff
#ifdef STB_GNU_UNIQUE
		case DW_TAG_GNU_formal_parameter_pack:
		case DW_TAG_GNU_template_parameter_pack:
		case DW_TAG_GNU_template_template_param:
#endif
		case DW_TAG_template_type_parameter:
		case DW_TAG_template_value_parameter:
			/*
			 * FIXME: probably we'll have to attach this as a list of
			 * template parameters to use at class__fprintf time...
			 *
			 * See:
			 * https://gcc.gnu.org/wiki/TemplateParmsDwarf
			 */
			tag__print_not_supported(dwarf_tag(die));
			continue;
		case DW_TAG_inheritance:
		case DW_TAG_member: {
			struct class_member *member = class_member__new(die, cu, is_union, conf);

			if (member == NULL)
				return -ENOMEM;

			if (cu__is_c_plus_plus(cu)) {
				uint32_t id;

				if (cu__table_add_tag(cu, &member->tag, &id) < 0) {
					class_member__delete(member);
					return -ENOMEM;
				}

				struct dwarf_tag *dtag = member->tag.priv;
				dtag->small_id = id;
			}

			type__add_member(class, member);
			cu__hash(cu, &member->tag);
			if (add_child_llvm_annotations(die, member_idx, conf, &class->namespace.annots))
				return -ENOMEM;
			member_idx++;
		}
			continue;
		case DW_TAG_LLVM_annotation:
			if (add_llvm_annotation(die, -1, conf, &class->namespace.annots))
				return -ENOMEM;
			continue;
		default: {
			struct tag *tag = die__process_tag(die, cu, 0, conf);

			if (tag == NULL)
				return -ENOMEM;

			if (tag == &unsupported_tag) {
				tag__print_not_supported(dwarf_tag(die));
				continue;
			}

			uint32_t id;

			if (cu__table_add_tag(cu, tag, &id) < 0) {
				tag__delete(tag);
				return -ENOMEM;
			}

			struct dwarf_tag *dtag = tag->priv;
			dtag->small_id = id;

			namespace__add_tag(&class->namespace, tag);
			cu__hash(cu, tag);
			if (tag__is_function(tag)) {
				struct function *fself = tag__function(tag);

				if (fself->vtable_entry != -1)
					class__add_vtable_entry(type__class(class), fself);
			}
			continue;
		}
		}
	} while (dwarf_siblingof(die, die) == 0);

	return 0;
}

static int die__process_namespace(Dwarf_Die *die, struct namespace *namespace,
				  struct cu *cu, struct conf_load *conf)
{
	struct tag *tag;
	do {
		tag = die__process_tag(die, cu, 0, conf);
		if (tag == NULL)
			goto out_enomem;

		if (tag == &unsupported_tag) {
			tag__print_not_supported(dwarf_tag(die));
			continue;
		}

		uint32_t id;
		if (cu__table_add_tag(cu, tag, &id) < 0)
			goto out_delete_tag;

		struct dwarf_tag *dtag = tag->priv;
		dtag->small_id = id;

		namespace__add_tag(namespace, tag);
		cu__hash(cu, tag);
	} while (dwarf_siblingof(die, die) == 0);

	return 0;
out_delete_tag:
	tag__delete(tag);
out_enomem:
	return -ENOMEM;
}

static int die__process_function(Dwarf_Die *die, struct ftype *ftype,
				  struct lexblock *lexblock, struct cu *cu, struct conf_load *conf);

static int die__create_new_lexblock(Dwarf_Die *die,
				    struct cu *cu, struct lexblock *father, struct conf_load *conf)
{
	struct lexblock *lexblock = lexblock__new(die, cu);

	if (lexblock != NULL) {
		if (die__process_function(die, NULL, lexblock, cu, conf) != 0)
			goto out_delete;
	}
	if (father != NULL)
		lexblock__add_lexblock(father, lexblock);
	return 0;
out_delete:
	lexblock__delete(lexblock);
	return -ENOMEM;
}

static struct tag *die__create_new_inline_expansion(Dwarf_Die *die,
						    struct lexblock *lexblock,
						    struct cu *cu, struct conf_load *conf);

static int die__process_inline_expansion(Dwarf_Die *die, struct lexblock *lexblock, struct cu *cu, struct conf_load *conf)
{
	Dwarf_Die child;
	struct tag *tag;

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0)
		return 0;

	die = &child;
	do {
		uint32_t id;

		switch (dwarf_tag(die)) {
		case DW_TAG_call_site:
		case DW_TAG_call_site_parameter:
		case DW_TAG_GNU_call_site:
		case DW_TAG_GNU_call_site_parameter:
			/*
 			 * FIXME: read http://www.dwarfstd.org/ShowIssue.php?issue=100909.2&type=open
 			 * and write proper support.
			 *
			 * From a quick read there is not much we can use in
			 * the existing dwarves tools, so just stop warning the user,
			 * developers will find these notes if wanting to use in a
			 * new tool.
			 */
			continue;
		case DW_TAG_lexical_block:
			if (die__create_new_lexblock(die, cu, lexblock, conf) != 0)
				goto out_enomem;
			continue;
		case DW_TAG_formal_parameter:
			/*
			 * FIXME:
			 * So far DW_TAG_inline_routine had just an
			 * abstract origin, but starting with
			 * /usr/lib/openoffice.org/basis3.0/program/libdbalx.so
			 * I realized it really has to be handled as a
			 * DW_TAG_function... Lets just get the types
			 * for 1.8, then fix this properly.
			 *
			 * cu__tag_not_handled(die);
			 */
			continue;
		case DW_TAG_inlined_subroutine:
			tag = die__create_new_inline_expansion(die, lexblock, cu, conf);
			break;
		case DW_TAG_label:
			if (conf->ignore_labels)
				continue;
			tag = die__create_new_label(die, lexblock, cu, conf);
			break;
		default:
			tag = die__process_tag(die, cu, 0, conf);
			if (tag == NULL)
				goto out_enomem;

			if (tag == &unsupported_tag) {
				tag__print_not_supported(dwarf_tag(die));
				continue;
			}

			if (cu__add_tag(cu, tag, &id) < 0)
				goto out_delete_tag;
			goto hash;
		}

		if (tag == NULL)
			goto out_enomem;

		if (cu__table_add_tag(cu, tag, &id) < 0)
			goto out_delete_tag;
hash:
		cu__hash(cu, tag);
		struct dwarf_tag *dtag = tag->priv;
		dtag->small_id = id;
	} while (dwarf_siblingof(die, die) == 0);

	return 0;
out_delete_tag:
	tag__delete(tag);
out_enomem:
	return -ENOMEM;
}

static struct tag *die__create_new_inline_expansion(Dwarf_Die *die,
						    struct lexblock *lexblock,
						    struct cu *cu, struct conf_load *conf)
{
	struct inline_expansion *exp = inline_expansion__new(die, cu, conf);

	if (exp == NULL)
		return NULL;

	if (die__process_inline_expansion(die, lexblock, cu, conf) != 0) {
		free(exp);
		return NULL;
	}

	if (lexblock != NULL)
		lexblock__add_inline_expansion(lexblock, exp);
	return &exp->ip.tag;
}

static int die__process_function(Dwarf_Die *die, struct ftype *ftype,
				 struct lexblock *lexblock, struct cu *cu, struct conf_load *conf)
{
	int param_idx = 0;
	Dwarf_Die child;
	struct tag *tag;

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0)
		return 0;

	die = &child;
	do {
		uint32_t id;

		switch (dwarf_tag(die)) {
		case DW_TAG_call_site:
		case DW_TAG_call_site_parameter:
		case DW_TAG_GNU_call_site:
		case DW_TAG_GNU_call_site_parameter:
			/*
			 * XXX: read http://www.dwarfstd.org/ShowIssue.php?issue=100909.2&type=open
			 * and write proper support.
			 *
			 * From a quick read there is not much we can use in
			 * the existing dwarves tools, so just stop warning the user,
			 * developers will find these notes if wanting to use in a
			 * new tool.
			 */
			continue;
		case DW_TAG_dwarf_procedure:
			/*
			 * Ignore it, just scope expressions, that we have no use for (so far).
			 */
			continue;
#ifdef STB_GNU_UNIQUE
		case DW_TAG_GNU_formal_parameter_pack:
		case DW_TAG_GNU_template_parameter_pack:
		case DW_TAG_GNU_template_template_param:
#endif
		case DW_TAG_template_type_parameter:
		case DW_TAG_template_value_parameter:
			/* FIXME: probably we'll have to attach this as a list of
 			 * template parameters to use at class__fprintf time... 
 			 * See die__process_class */
			tag__print_not_supported(dwarf_tag(die));
			continue;
		case DW_TAG_formal_parameter:
			tag = die__create_new_parameter(die, ftype, lexblock, cu, conf, param_idx++);
			break;
		case DW_TAG_variable:
			tag = die__create_new_variable(die, cu, conf);
			if (tag == NULL)
				goto out_enomem;
			lexblock__add_variable(lexblock, tag__variable(tag));
			break;
		case DW_TAG_unspecified_parameters:
			if (ftype != NULL)
				ftype->unspec_parms = 1;
			continue;
		case DW_TAG_label:
			if (conf->ignore_labels)
				continue;
			tag = die__create_new_label(die, lexblock, cu, conf);
			break;
		case DW_TAG_inlined_subroutine:
			if (conf->ignore_inline_expansions)
				continue;
			tag = die__create_new_inline_expansion(die, lexblock, cu, conf);
			break;
		case DW_TAG_lexical_block:
			// lexblocks can contain types that are then referenced from outside.
			// Thus we can't ignore them without more surgery, i.e. by adding code
			// to just process types inside lexblocks, leave this for later.
			if (die__create_new_lexblock(die, cu, lexblock, conf) != 0)
				goto out_enomem;
			continue;
		case DW_TAG_LLVM_annotation:
			if (add_llvm_annotation(die, -1, conf, &(tag__function(&ftype->tag)->annots)))
				goto out_enomem;
			continue;
		default:
			tag = die__process_tag(die, cu, 0, conf);

			if (tag == NULL)
				goto out_enomem;

			if (tag == &unsupported_tag) {
				tag__print_not_supported(dwarf_tag(die));
				continue;
			}

			if (cu__add_tag(cu, tag, &id) < 0)
				goto out_delete_tag;

			goto hash;
		}

		if (tag == NULL)
			goto out_enomem;

		if (cu__table_add_tag(cu, tag, &id) < 0)
			goto out_delete_tag;
hash:
		cu__hash(cu, tag);
		struct dwarf_tag *dtag = tag->priv;
		dtag->small_id = id;
	} while (dwarf_siblingof(die, die) == 0);

	return 0;
out_delete_tag:
	tag__delete(tag);
out_enomem:
	return -ENOMEM;
}

static struct tag *die__create_new_function(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	struct function *function = function__new(die, cu, conf);

	if (function != NULL &&
	    die__process_function(die, &function->proto, &function->lexblock, cu, conf) != 0) {
		function__delete(function);
		function = NULL;
	}

	return function ? &function->proto.tag : NULL;
}

static struct tag *__die__process_tag(Dwarf_Die *die, struct cu *cu,
				      int top_level, const char *fn, struct conf_load *conf)
{
	struct tag *tag;

	switch (dwarf_tag(die)) {
	case DW_TAG_imported_unit:
		return NULL; // We don't support imported units yet, so to avoid segfaults
	case DW_TAG_array_type:
		tag = die__create_new_array(die, cu);		break;
	case DW_TAG_string_type: // FORTRAN stuff, looks like an array
		tag = die__create_new_string_type(die, cu);	break;
	case DW_TAG_base_type:
		tag = die__create_new_base_type(die, cu, conf);	break;
	case DW_TAG_const_type:
	case DW_TAG_imported_declaration:
	case DW_TAG_imported_module:
	case DW_TAG_reference_type:
	case DW_TAG_restrict_type:
	case DW_TAG_volatile_type:
	case DW_TAG_atomic_type:
		tag = die__create_new_tag(die, cu);		break;
	case DW_TAG_unspecified_type:
		cu->unspecified_type.tag =
			tag = die__create_new_tag(die, cu);     break;
	case DW_TAG_pointer_type:
		tag = die__create_new_pointer_tag(die, cu, conf);	break;
	case DW_TAG_ptr_to_member_type:
		tag = die__create_new_ptr_to_member_type(die, cu); break;
	case DW_TAG_enumeration_type:
		tag = die__create_new_enumeration(die, cu, conf); break;
	case DW_TAG_namespace:
		tag = die__create_new_namespace(die, cu, conf);	break;
	case DW_TAG_class_type:
	case DW_TAG_interface_type:
	case DW_TAG_structure_type:
		tag = die__create_new_class(die, cu, conf);	break;
	case DW_TAG_subprogram:
		tag = die__create_new_function(die, cu, conf);	break;
	case DW_TAG_subroutine_type:
		tag = die__create_new_subroutine_type(die, cu, conf); break;
	case DW_TAG_rvalue_reference_type:
	case DW_TAG_typedef:
		tag = die__create_new_typedef(die, cu, conf);	break;
	case DW_TAG_union_type:
		tag = die__create_new_union(die, cu, conf);	break;
	case DW_TAG_variable:
		tag = die__create_new_variable(die, cu, conf);	break;
	default:
		__cu__tag_not_handled(die, fn);
		/* fall thru */
	case DW_TAG_dwarf_procedure:
		/*
		 * Ignore it, just scope expressions, that we have no use for (so far).
		 */
		tag = &unsupported_tag;
		break;
	case DW_TAG_label:
		if (conf->ignore_labels)
			tag = &unsupported_tag; // callers will assume conf->ignore_labels is true
		else // We can have labels in asm CUs, no lexblock
			tag = die__create_new_label(die, NULL, cu, conf);
		break;
	}

	if (tag != NULL)
		tag->top_level = top_level;

	return tag;
}

static int die__process_unit(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	do {
		struct tag *tag = die__process_tag(die, cu, 1, conf);
		if (tag == NULL)
			return -ENOMEM;

		if (tag == &unsupported_tag) {
			// XXX special case DW_TAG_dwarf_procedure, appears when looking at a recent ~/bin/perf
			// Investigate later how to properly support this...
			if (dwarf_tag(die) != DW_TAG_dwarf_procedure &&
			    dwarf_tag(die) != DW_TAG_label) // conf->ignore_labels == true, see die__process_tag()
				tag__print_not_supported(dwarf_tag(die));
			continue;
		}

		uint32_t id;
		cu__add_tag(cu, tag, &id);
		cu__hash(cu, tag);
		struct dwarf_tag *dtag = tag->priv;
		dtag->small_id = id;
		if (tag->tag == DW_TAG_unspecified_type)
			cu->unspecified_type.type = id;
	} while (dwarf_siblingof(die, die) == 0);

	return 0;
}

static void ftype__recode_dwarf_types(struct tag *tag, struct cu *cu);

static int namespace__recode_dwarf_types(struct tag *tag, struct cu *cu)
{
	struct tag *pos;
	struct dwarf_cu *dcu = cu->priv;
	struct namespace *ns = tag__namespace(tag);

	namespace__for_each_tag(ns, pos) {
		struct dwarf_tag *dtype;
		struct dwarf_tag *dpos = pos->priv;

		if (tag__has_namespace(pos)) {
			if (namespace__recode_dwarf_types(pos, cu))
				return -1;
			continue;
		}

		switch (pos->tag) {
		case DW_TAG_member: {
			struct class_member *member = tag__class_member(pos);
			/*
			 * We may need to recode the type, possibly creating a
			 * suitably sized new base_type
			 */
			if (member->bitfield_size != 0 && !no_bitfield_type_recode) {
				if (class_member__dwarf_recode_bitfield(member, cu))
					return -1;
				continue;
			}
		}
			break;
		case DW_TAG_subroutine_type:
		case DW_TAG_subprogram:
			ftype__recode_dwarf_types(pos, cu);
			break;
		case DW_TAG_imported_module:
			dtype = dwarf_cu__find_tag_by_ref(dcu, &dpos->type);
			goto check_type;
		/* Can be for both types and non types */
		case DW_TAG_imported_declaration:
			dtype = dwarf_cu__find_tag_by_ref(dcu, &dpos->type);
			if (dtype != NULL)
				goto next;
			goto find_type;
		}

		if (dpos->type.off == 0) /* void */
			continue;
find_type:
		dtype = dwarf_cu__find_type_by_ref(dcu, &dpos->type);
check_type:
		if (dtype == NULL) {
			tag__print_type_not_found(pos);
			continue;
		}
next:
		pos->type = dtype->small_id;
	}
	return 0;
}

static void type__recode_dwarf_specification(struct tag *tag, struct cu *cu)
{
	struct dwarf_tag *dtype;
	struct type *t = tag__type(tag);
	dwarf_off_ref specification = dwarf_tag__spec(tag->priv);

	if (t->namespace.name != 0 || specification.off == 0)
		return;

	dtype = dwarf_cu__find_type_by_ref(cu->priv, &specification);
	if (dtype != NULL)
		t->namespace.name = tag__namespace(dtype->tag)->name;
	else {
		struct dwarf_tag *dtag = tag->priv;

		fprintf(stderr,
			"%s: couldn't find name for "
			"class %#llx, specification=%#llx\n", __func__,
			(unsigned long long)dtag->id,
			(unsigned long long)specification.off);
	}
}

static void __tag__print_abstract_origin_not_found(struct tag *tag,
						   const char *func)
{
	struct dwarf_tag *dtag = tag->priv;
	fprintf(stderr,
		"%s: couldn't find %#llx abstract_origin for %#llx (%s)!\n",
		func, (unsigned long long)dtag->abstract_origin.off,
		(unsigned long long)dtag->id,
		dwarf_tag_name(tag->tag));
}

#define tag__print_abstract_origin_not_found(tag ) \
	__tag__print_abstract_origin_not_found(tag, __func__)

static void ftype__recode_dwarf_types(struct tag *tag, struct cu *cu)
{
	struct parameter *pos;
	struct dwarf_cu *dcu = cu->priv;
	struct ftype *type = tag__ftype(tag);

	ftype__for_each_parameter(type, pos) {
		struct dwarf_tag *dpos = pos->tag.priv;
		struct dwarf_tag *dtype;

		if (dpos->type.off == 0) {
			if (dpos->abstract_origin.off == 0) {
				/* Function without parameters */
				pos->tag.type = 0;
				continue;
			}
			dtype = dwarf_cu__find_tag_by_ref(dcu, &dpos->abstract_origin);
			if (dtype == NULL) {
				tag__print_abstract_origin_not_found(&pos->tag);
				continue;
			}
			pos->name = tag__parameter(dtype->tag)->name;
			pos->tag.type = dtype->tag->type;
			continue;
		}

		dtype = dwarf_cu__find_type_by_ref(dcu, &dpos->type);
		if (dtype == NULL) {
			tag__print_type_not_found(&pos->tag);
			continue;
		}
		pos->tag.type = dtype->small_id;
	}
}

static void lexblock__recode_dwarf_types(struct lexblock *tag, struct cu *cu)
{
	struct tag *pos;
	struct dwarf_cu *dcu = cu->priv;

	list_for_each_entry(pos, &tag->tags, node) {
		struct dwarf_tag *dpos = pos->priv;
		struct dwarf_tag *dtype;

		switch (pos->tag) {
		case DW_TAG_lexical_block:
			lexblock__recode_dwarf_types(tag__lexblock(pos), cu);
			continue;
		case DW_TAG_inlined_subroutine:
			dtype = dwarf_cu__find_tag_by_ref(dcu, &dpos->type);
			if (dtype == NULL) {
				tag__print_type_not_found(pos);
				continue;
			}
			ftype__recode_dwarf_types(dtype->tag, cu);
			continue;

		case DW_TAG_formal_parameter:
			if (dpos->type.off != 0)
				break;

			struct parameter *fp = tag__parameter(pos);
			dtype = dwarf_cu__find_tag_by_ref(dcu,
							  &dpos->abstract_origin);
			if (dtype == NULL) {
				tag__print_abstract_origin_not_found(pos);
				continue;
			}
			fp->name = tag__parameter(dtype->tag)->name;
			pos->type = dtype->tag->type;
			continue;

		case DW_TAG_variable:
			if (dpos->type.off != 0)
				break;

			struct variable *var = tag__variable(pos);

			if (dpos->abstract_origin.off == 0) {
				/*
				 * DW_TAG_variable completely empty was
				 * found on libQtGui.so.4.3.4.debug
				 * <3><d6ea1>: Abbrev Number: 164 (DW_TAG_variable)
				 */
				continue;
			}

			dtype = dwarf_cu__find_tag_by_ref(dcu,
							  &dpos->abstract_origin);
			if (dtype == NULL) {
				tag__print_abstract_origin_not_found(pos);
				continue;
			}
			var->name = tag__variable(dtype->tag)->name;
			pos->type = dtype->tag->type;
			continue;

		case DW_TAG_label: {
			struct label *l = tag__label(pos);

			if (dpos->abstract_origin.off == 0)
				continue;

			dtype = dwarf_cu__find_tag_by_ref(dcu, &dpos->abstract_origin);
			if (dtype != NULL)
				l->name = tag__label(dtype->tag)->name;
			else
				tag__print_abstract_origin_not_found(pos);
		}
			continue;
		}

		dtype = dwarf_cu__find_type_by_ref(dcu, &dpos->type);
		if (dtype == NULL) {
			tag__print_type_not_found(pos);
			continue;
		}
		pos->type = dtype->small_id;
	}
}

static void dwarf_cu__recode_btf_type_tag_ptr(struct btf_type_tag_ptr_type *tag,
					      uint32_t pointee_type)
{
	struct btf_type_tag_type *annot;
	struct dwarf_tag *annot_dtag;
	struct tag *prev_tag;

	/* Given source like
	 *   int tag1 tag2 tag3 *p;
	 * the tag->tags contains tag3 -> tag2 -> tag1, the final type chain looks like:
	 *   pointer -> tag3 -> tag2 -> tag1 -> pointee
	 *
	 * Basically it means
	 *   - '*' applies to "int tag1 tag2 tag3"
	 *   - tag3 applies to "int tag1 tag2"
	 *   - tag2 applies to "int tag1"
	 *   - tag1 applies to "int"
	 *
	 * This also makes final source code (format c) easier as we can do
	 *   emit for "tag3 -> tag2 -> tag1 -> int"
	 *   emit '*'
	 *
	 * For 'tag3 -> tag2 -> tag1 -> int":
	 *   emit for "tag2 -> tag1 -> int"
	 *   emit tag3
	 *
	 * Eventually we can get the source code like
	 *   int tag1 tag2 tag3 *p;
	 * and this matches the user/kernel code.
	 */
	prev_tag = &tag->tag;
	list_for_each_entry(annot, &tag->tags, node) {
		annot_dtag = annot->tag.priv;
		prev_tag->type = annot_dtag->small_id;
		prev_tag = &annot->tag;
	}
	prev_tag->type = pointee_type;
}

static int tag__recode_dwarf_type(struct tag *tag, struct cu *cu)
{
	struct dwarf_tag *dtag = tag->priv;
	struct dwarf_tag *dtype;

	/* Check if this is an already recoded bitfield */
	if (dtag == NULL)
		return 0;

	if (tag__is_type(tag))
		type__recode_dwarf_specification(tag, cu);

	if (tag__has_namespace(tag))
		return namespace__recode_dwarf_types(tag, cu);

	switch (tag->tag) {
	case DW_TAG_subprogram: {
		struct function *fn = tag__function(tag);

		if (fn->name == 0)  {
			dwarf_off_ref specification = dwarf_tag__spec(dtag);
			if (dtag->abstract_origin.off == 0 &&
			    specification.off == 0) {
				/*
				 * Found on libQtGui.so.4.3.4.debug
				 *  <3><1423de>: Abbrev Number: 209 (DW_TAG_subprogram)
				 *      <1423e0>   DW_AT_declaration : 1
				 */
				return 0;
			}
			dtype = dwarf_cu__find_tag_by_ref(cu->priv, &dtag->abstract_origin);
			if (dtype == NULL)
				dtype = dwarf_cu__find_tag_by_ref(cu->priv, &specification);
			if (dtype != NULL)
				fn->name = tag__function(dtype->tag)->name;
			else {
				fprintf(stderr,
					"%s: couldn't find name for "
					"function %#llx, abstract_origin=%#llx,"
					" specification=%#llx\n", __func__,
					(unsigned long long)dtag->id,
					(unsigned long long)dtag->abstract_origin.off,
					(unsigned long long)specification.off);
			}
		}
		lexblock__recode_dwarf_types(&fn->lexblock, cu);
	}
		/* Fall thru */

	case DW_TAG_subroutine_type:
		ftype__recode_dwarf_types(tag, cu);
		/* Fall thru, for the function return type */
		break;

	case DW_TAG_lexical_block:
		lexblock__recode_dwarf_types(tag__lexblock(tag), cu);
		return 0;

	case DW_TAG_ptr_to_member_type: {
		struct ptr_to_member_type *pt = tag__ptr_to_member_type(tag);

		dtype = dwarf_cu__find_type_by_ref(cu->priv, &dtag->containing_type);
		if (dtype != NULL)
			pt->containing_type = dtype->small_id;
		else {
			fprintf(stderr,
				"%s: couldn't find type for "
				"containing_type %#llx, containing_type=%#llx\n",
				__func__,
				(unsigned long long)dtag->id,
				(unsigned long long)dtag->containing_type.off);
		}
	}
		break;

	case DW_TAG_namespace:
		return namespace__recode_dwarf_types(tag, cu);
	/* Damn, DW_TAG_inlined_subroutine is an special case
           as dwarf_tag->id is in fact an abtract origin, i.e. must be
	   looked up in the tags_table, not in the types_table.
	   The others also point to routines, so are in tags_table */
	case DW_TAG_inlined_subroutine:
	case DW_TAG_imported_module:
		dtype = dwarf_cu__find_tag_by_ref(cu->priv, &dtag->type);
		goto check_type;
	/* Can be for both types and non types */
	case DW_TAG_imported_declaration:
		dtype = dwarf_cu__find_tag_by_ref(cu->priv, &dtag->type);
		if (dtype != NULL)
			goto out;
		goto find_type;
	case DW_TAG_variable: {
		struct variable *var = tag__variable(tag);

		if (var->has_specification) {
			dwarf_off_ref specification = dwarf_tag__spec(dtag);

			if (specification.off) {
				dtype = dwarf_cu__find_tag_by_ref(cu->priv,
								  &specification);
				if (dtype)
					var->spec = tag__variable(dtype->tag);
			}
		}
	}

	}

	if (dtag->type.off == 0) {
		if (tag->tag != DW_TAG_pointer_type || !tag->has_btf_type_tag)
			tag->type = 0; /* void */
		else
			dwarf_cu__recode_btf_type_tag_ptr(tag__btf_type_tag_ptr(tag), 0);
		return 0;
	}

find_type:
	dtype = dwarf_cu__find_type_by_ref(cu->priv, &dtag->type);
check_type:
	if (dtype == NULL) {
		tag__print_type_not_found(tag);
		return 0;
	}
out:
	if (tag->tag != DW_TAG_pointer_type || !tag->has_btf_type_tag)
		tag->type = dtype->small_id;
	else
		dwarf_cu__recode_btf_type_tag_ptr(tag__btf_type_tag_ptr(tag), dtype->small_id);

	return 0;
}

static int cu__resolve_func_ret_types(struct cu *cu)
{
	struct ptr_table *pt = &cu->functions_table;
	uint32_t i;

	for (i = 0; i < pt->nr_entries; ++i) {
		struct tag *tag = pt->entries[i];

		if (tag == NULL || tag->type != 0)
			continue;

		struct function *fn = tag__function(tag);
		if (!fn->abstract_origin)
			continue;

		struct dwarf_tag *dtag = tag->priv;
		struct dwarf_tag *dfunc;
		dfunc = dwarf_cu__find_tag_by_ref(cu->priv, &dtag->abstract_origin);
		if (dfunc == NULL) {
			tag__print_abstract_origin_not_found(tag);
			return -1;
		}

		tag->type = dfunc->tag->type;
	}
	return 0;
}

static int cu__recode_dwarf_types_table(struct cu *cu,
					struct ptr_table *pt,
					uint32_t i)
{
	for (; i < pt->nr_entries; ++i) {
		struct tag *tag = pt->entries[i];

		if (tag != NULL) /* void, see cu__new */
			if (tag__recode_dwarf_type(tag, cu))
				return -1;
	}

	return 0;
}

static int cu__recode_dwarf_types(struct cu *cu)
{
	if (cu__recode_dwarf_types_table(cu, &cu->types_table, 1) ||
	    cu__recode_dwarf_types_table(cu, &cu->tags_table, 0) ||
	    cu__recode_dwarf_types_table(cu, &cu->functions_table, 0))
		return -1;
	return 0;
}

static const char *dwarf_tag__decl_file(const struct tag *tag,
					const struct cu *cu)
{
	struct dwarf_tag *dtag = tag->priv;
	return cu->extra_dbg_info ? dtag->decl_file : NULL;
}

static uint32_t dwarf_tag__decl_line(const struct tag *tag,
				     const struct cu *cu)
{
	struct dwarf_tag *dtag = tag->priv;
	return cu->extra_dbg_info ? dtag->decl_line : 0;
}

static unsigned long long dwarf_tag__orig_id(const struct tag *tag,
					       const struct cu *cu)
{
	struct dwarf_tag *dtag = tag->priv;
	return cu->extra_dbg_info ? dtag->id : 0;
}

struct debug_fmt_ops dwarf__ops;

static int die__process(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	Dwarf_Die child;
	const uint16_t tag = dwarf_tag(die);

	if (tag == DW_TAG_skeleton_unit) {
		static bool warned;

		if (!warned) {
			fprintf(stderr, "WARNING: DW_TAG_skeleton_unit used, please look for a .dwo file and use it instead.\n"
					"         A future version of pahole will support do this automagically.\n");
			warned = true;
		}
		return 0; // so that other units can be processed
	}

	if (tag == DW_TAG_partial_unit) {
		static bool warned;

		if (!warned) {
			fprintf(stderr, "WARNING: DW_TAG_partial_unit used, some types will not be considered!\n"
					"         Probably this was optimized using a tool like 'dwz'\n"
					"         A future version of pahole will support this.\n");
			warned = true;
		}
		return 0; // so that other units can be processed
	}

	if (tag != DW_TAG_compile_unit && tag != DW_TAG_type_unit) {
		fprintf(stderr, "%s: DW_TAG_compile_unit, DW_TAG_type_unit, DW_TAG_partial_unit or DW_TAG_skeleton_unit expected got %s (0x%x)!\n",
			__FUNCTION__, dwarf_tag_name(tag), tag);
		return -EINVAL;
	}

	cu->language = attr_numeric(die, DW_AT_language);

	if (dwarf_child(die, &child) == 0) {
		int err = die__process_unit(&child, cu, conf);
		if (err)
			return err;
	}

	if (dwarf_siblingof(die, die) == 0)
		fprintf(stderr, "%s: got %s unexpected tag after "
				"DW_TAG_compile_unit!\n",
			__FUNCTION__, dwarf_tag_name(tag));

	return 0;
}

static int die__process_and_recode(Dwarf_Die *die, struct cu *cu, struct conf_load *conf)
{
	int ret = die__process(die, cu, conf);
	if (ret != 0)
		return ret;
	ret = cu__recode_dwarf_types(cu);
	if (ret != 0)
		return ret;

	return cu__resolve_func_ret_types(cu);
}

static int class_member__cache_byte_size(struct tag *tag, struct cu *cu,
					 void *cookie)
{
	struct class_member *member = tag__class_member(tag);
	struct conf_load *conf_load = cookie;

	if (tag__is_class_member(tag)) {
		if (member->is_static)
			return 0;
	} else if (tag->tag != DW_TAG_inheritance) {
		return 0;
	}

	if (member->bitfield_size == 0) {
		member->byte_size = tag__size(tag, cu);
		member->bit_size = member->byte_size * 8;
		return 0;
	}

	/*
	 * Try to figure out byte size, if it's not directly provided in DWARF
	 */
	if (member->byte_size == 0) {
		struct tag *type = tag__strip_typedefs_and_modifiers(&member->tag, cu);
		member->byte_size = tag__size(type, cu);
		if (member->byte_size == 0) {
			int bit_size;
			if (tag__is_enumeration(type)) {
				bit_size = tag__type(type)->size;
			} else {
				struct base_type *bt = tag__base_type(type);
				bit_size = bt->bit_size ? bt->bit_size : base_type__name_to_size(bt, cu);
			}
			member->byte_size = (bit_size + 7) / 8 * 8;
		}
	}
	member->bit_size = member->byte_size * 8;

	/*
	 * XXX: after all the attempts to determine byte size, we might still
	 * be unsuccessful, because base_type__name_to_size doesn't know about
	 * the base_type name, so one has to add there when such base_type
	 * isn't found. pahole will put zero on the struct output so it should
	 * be easy to spot the name when such unlikely thing happens.
	 */
	if (member->byte_size == 0) {
		member->bitfield_offset = 0;
		return 0;
	}

	if (!member->has_bit_offset) {
		/*
		 * For little-endian architectures, DWARF data emitted by gcc/clang
		 * specifies bitfield offset as an offset from the highest-order bit
		 * of an underlying integral type (e.g., int) to a highest-order bit
		 * of a bitfield. E.g., for bitfield taking first 5 bits of int-backed
		 * bitfield, bit offset will be 27 (sizeof(int) - 0 offset - 5 bit
		 * size), which is very counter-intuitive and isn't a natural
		 * extension of byte offset, which on little-endian points to
		 * lowest-order byte. So here we re-adjust bitfield offset to be an
		 * offset from lowest-order bit of underlying integral type to
		 * a lowest-order bit of a bitfield. This makes bitfield offset
		 * a natural extension of byte offset for bitfields and is uniform
		 * with how big-endian bit offsets work.
		 */
		if (cu->little_endian)
			member->bitfield_offset = member->bit_size - member->bitfield_offset - member->bitfield_size;

		member->bit_offset = member->byte_offset * 8 + member->bitfield_offset;
	} else {
		// DWARF5 has DW_AT_data_bit_offset, offset in bits from the
		// start of the container type (struct, class, etc).
		member->byte_offset = member->bit_offset / 8;
		member->bitfield_offset = member->bit_offset - member->byte_offset * 8;
	}

	/* make sure bitfield offset is non-negative */
	if (member->bitfield_offset < 0) {
		member->bitfield_offset += member->bit_size;
		member->byte_offset -= member->byte_size;
		member->bit_offset = member->byte_offset * 8 + member->bitfield_offset;
	}
	/* align on underlying base type natural alignment boundary */
	member->bitfield_offset += (member->byte_offset % member->byte_size) * 8;
	member->byte_offset = member->bit_offset / member->bit_size * member->bit_size / 8;
	if (member->bitfield_offset >= member->bit_size) {
		member->bitfield_offset -= member->bit_size;
		member->byte_offset += member->byte_size;
	}

	if (conf_load && conf_load->fixup_silly_bitfields &&
	    member->byte_size == 8 * member->bitfield_size) {
		member->bitfield_size = 0;
		member->bitfield_offset = 0;
	}

	return 0;
}

static int cu__finalize(struct cu *cu, struct conf_load *conf, void *thr_data)
{
	cu__for_all_tags(cu, class_member__cache_byte_size, conf);
	if (conf && conf->steal) {
		return conf->steal(cu, conf, thr_data);
	}
	return LSK__KEEPIT;
}

static int cus__finalize(struct cus *cus, struct cu *cu, struct conf_load *conf, void *thr_data)
{
	int lsk = cu__finalize(cu, conf, thr_data);
	switch (lsk) {
	case LSK__DELETE:
		cu__delete(cu);
		break;
	case LSK__STOP_LOADING:
		break;
	case LSK__KEEPIT:
		cus__add(cus, cu);
		break;
	}
	return lsk;
}

static int cu__set_common(struct cu *cu, struct conf_load *conf,
			  Dwfl_Module *mod, Elf *elf)
{
	cu->uses_global_strings = true;
	cu->elf = elf;
	cu->dwfl = mod;
	cu->extra_dbg_info = conf ? conf->extra_dbg_info : 0;
	cu->has_addr_info = conf ? conf->get_addr_info : 0;

	GElf_Ehdr ehdr;
	if (gelf_getehdr(elf, &ehdr) == NULL)
		return DWARF_CB_ABORT;

	cu->little_endian = ehdr.e_ident[EI_DATA] == ELFDATA2LSB;
	return 0;
}

static int __cus__load_debug_types(struct conf_load *conf, Dwfl_Module *mod, Dwarf *dw, Elf *elf,
				   const char *filename, const unsigned char *build_id,
				   int build_id_len, struct cu **cup, struct dwarf_cu *dcup)
{
	Dwarf_Off off = 0, noff, type_off;
	size_t cuhl;
	uint8_t pointer_size, offset_size;
	uint64_t signature;

	*cup = NULL;

	while (dwarf_next_unit(dw, off, &noff, &cuhl, NULL, NULL, &pointer_size,
			       &offset_size, &signature, &type_off)
		== 0) {

		if (*cup == NULL) {
			struct cu *cu;

			cu = cu__new("", pointer_size, build_id,
				     build_id_len, filename, conf->use_obstack);
			if (cu == NULL ||
			    cu__set_common(cu, conf, mod, elf) != 0) {
				return DWARF_CB_ABORT;
			}

			if (dwarf_cu__init(dcup, cu) != 0)
				return DWARF_CB_ABORT;
			dcup->cu = cu;
			/* Funny hack.  */
			dcup->type_unit = dcup;
			cu->priv = dcup;
			cu->dfops = &dwarf__ops;

			*cup = cu;
		}

		Dwarf_Die die_mem;
		Dwarf_Die *cu_die = dwarf_offdie_types(dw, off + cuhl,
						       &die_mem);

		if (die__process(cu_die, *cup, conf) != 0)
			return DWARF_CB_ABORT;

		off = noff;
	}

	if (*cup != NULL && cu__recode_dwarf_types(*cup) != 0)
		return DWARF_CB_ABORT;

	return 0;
}

/* Match the define in linux:include/linux/elfnote.h */
#define LINUX_ELFNOTE_BUILD_LTO		0x101

static bool cus__merging_cu(Dwarf *dw, Elf *elf)
{
	Elf_Scn *section = NULL;
	while ((section = elf_nextscn(elf, section)) != 0) {
		GElf_Shdr header;
		if (!gelf_getshdr(section, &header))
			continue;

		if (header.sh_type != SHT_NOTE)
			continue;

		Elf_Data *data = NULL;
		while ((data = elf_getdata(section, data)) != 0) {
			size_t name_off, desc_off, offset = 0;
			GElf_Nhdr hdr;
			while ((offset = gelf_getnote(data, offset, &hdr, &name_off, &desc_off)) != 0) {
				if (hdr.n_type != LINUX_ELFNOTE_BUILD_LTO)
					continue;

				/* owner is Linux */
				if (strcmp((char *)data->d_buf + name_off, "Linux") != 0)
					continue;

				return *(int *)(data->d_buf + desc_off) != 0;
			}
		}
	}

	Dwarf_Off off = 0, noff;
	size_t cuhl;

	while (dwarf_nextcu (dw, off, &noff, &cuhl, NULL, NULL, NULL) == 0) {
		Dwarf_Die die_mem;
		Dwarf_Die *cu_die = dwarf_offdie(dw, off + cuhl, &die_mem);

		if (cu_die == NULL)
			break;

		Dwarf_Off offset = 0;
		while (true) {
			size_t length;
			Dwarf_Abbrev *abbrev = dwarf_getabbrev (cu_die, offset, &length);
			if (abbrev == NULL || abbrev == DWARF_END_ABBREV)
				break;

			size_t attrcnt;
			if (dwarf_getattrcnt (abbrev, &attrcnt) != 0)
				return false;

			unsigned int attr_num, attr_form;
			Dwarf_Off aboffset;
			size_t j;
			for (j = 0; j < attrcnt; ++j) {
				if (dwarf_getabbrevattr (abbrev, j, &attr_num, &attr_form,
							 &aboffset))
					return false;
				if (attr_form == DW_FORM_ref_addr)
					return true;
			}

			offset += length;
		}

		off = noff;
	}

	return false;
}

struct dwarf_cus {
	struct cus	    *cus;
	struct conf_load    *conf;
	Dwfl_Module	    *mod;
	Dwarf		    *dw;
	Elf		    *elf;
	const char	    *filename;
	Dwarf_Off	    off;
	const unsigned char *build_id;
	int		    build_id_len;
	int		    error;
	struct dwarf_cu	    *type_dcu;
};

struct dwarf_thread {
	struct dwarf_cus	*dcus;
	void			*data;
};

static int dwarf_cus__create_and_process_cu(struct dwarf_cus *dcus, Dwarf_Die *cu_die,
					    uint8_t pointer_size, void *thr_data)
{
	/*
	 * DW_AT_name in DW_TAG_compile_unit can be NULL, first seen in:
	 *
	 * /usr/libexec/gcc/x86_64-redhat-linux/4.3.2/ecj1.debug
	 */
	const char *name = attr_string(cu_die, DW_AT_name, dcus->conf);
	struct cu *cu = cu__new(name ?: "", pointer_size, dcus->build_id, dcus->build_id_len, dcus->filename, dcus->conf->use_obstack);
	if (cu == NULL || cu__set_common(cu, dcus->conf, dcus->mod, dcus->elf) != 0)
		return DWARF_CB_ABORT;

	struct dwarf_cu *dcu = dwarf_cu__new(cu);

	if (dcu == NULL)
		return DWARF_CB_ABORT;

	dcu->type_unit = dcus->type_dcu;
	cu->priv = dcu;
	cu->dfops = &dwarf__ops;

	if (die__process_and_recode(cu_die, cu, dcus->conf) != 0 ||
	    cus__finalize(dcus->cus, cu, dcus->conf, thr_data) == LSK__STOP_LOADING)
		return DWARF_CB_ABORT;

       return DWARF_CB_OK;
}

static int dwarf_cus__nextcu(struct dwarf_cus *dcus, Dwarf_Die *die_mem, Dwarf_Die **cu_die, uint8_t *pointer_size, uint8_t *offset_size)
{
	Dwarf_Off noff;
	size_t cuhl;
	int ret;

	cus__lock(dcus->cus);

	if (dcus->error) {
		ret = dcus->error;
		goto out_unlock;
	}

	ret = dwarf_nextcu(dcus->dw, dcus->off, &noff, &cuhl, NULL, pointer_size, offset_size);
	if (ret == 0) {
		*cu_die = dwarf_offdie(dcus->dw, dcus->off + cuhl, die_mem);
		if (*cu_die != NULL)
			dcus->off = noff;
	}

out_unlock:
	cus__unlock(dcus->cus);

	return ret;
}

static void *dwarf_cus__process_cu_thread(void *arg)
{
	struct dwarf_thread *dthr = arg;
	struct dwarf_cus *dcus = dthr->dcus;
	uint8_t pointer_size, offset_size;
	Dwarf_Die die_mem, *cu_die;

	while (dwarf_cus__nextcu(dcus, &die_mem, &cu_die, &pointer_size, &offset_size) == 0) {
		if (cu_die == NULL)
			break;

		if (dwarf_cus__create_and_process_cu(dcus, cu_die,
						     pointer_size, dthr->data) == DWARF_CB_ABORT)
			goto out_abort;
	}

	if (dcus->conf->thread_exit &&
	    dcus->conf->thread_exit(dcus->conf, dthr->data) != 0)
		goto out_abort;

	return (void *)DWARF_CB_OK;
out_abort:
	return (void *)DWARF_CB_ABORT;
}

static int dwarf_cus__threaded_process_cus(struct dwarf_cus *dcus)
{
	pthread_t threads[dcus->conf->nr_jobs];
	struct dwarf_thread dthr[dcus->conf->nr_jobs];
	void *thread_data[dcus->conf->nr_jobs];
	int res;
	int i;

	if (dcus->conf->threads_prepare) {
		res = dcus->conf->threads_prepare(dcus->conf, dcus->conf->nr_jobs, thread_data);
		if (res != 0)
			return res;
	} else {
		memset(thread_data, 0, sizeof(void *) * dcus->conf->nr_jobs);
	}

	for (i = 0; i < dcus->conf->nr_jobs; ++i) {
		dthr[i].dcus = dcus;
		dthr[i].data = thread_data[i];

		dcus->error = pthread_create(&threads[i], NULL,
					     dwarf_cus__process_cu_thread,
					     &dthr[i]);
		if (dcus->error)
			goto out_join;
	}

	dcus->error = 0;

out_join:
	while (--i >= 0) {
		void *res;
		int err = pthread_join(threads[i], &res);

		if (err == 0 && res != NULL)
			dcus->error = (long)res;
	}

	if (dcus->conf->threads_collect) {
		res = dcus->conf->threads_collect(dcus->conf, dcus->conf->nr_jobs,
						  thread_data, dcus->error);
		if (dcus->error == 0)
			dcus->error = res;
	}

	return dcus->error;
}

static int __dwarf_cus__process_cus(struct dwarf_cus *dcus)
{
	uint8_t pointer_size, offset_size;
	Dwarf_Off noff;
	size_t cuhl;

	while (dwarf_nextcu(dcus->dw, dcus->off, &noff, &cuhl, NULL, &pointer_size, &offset_size) == 0) {
		Dwarf_Die die_mem;
		Dwarf_Die *cu_die = dwarf_offdie(dcus->dw, dcus->off + cuhl, &die_mem);

		if (cu_die == NULL)
			break;

		if (dwarf_cus__create_and_process_cu(dcus, cu_die,
						     pointer_size, NULL) == DWARF_CB_ABORT)
			return DWARF_CB_ABORT;

		dcus->off = noff;
	}

	return 0;
}

static int dwarf_cus__process_cus(struct dwarf_cus *dcus)
{
	if (dcus->conf->nr_jobs > 1)
		return dwarf_cus__threaded_process_cus(dcus);

	return __dwarf_cus__process_cus(dcus);
}

static int cus__merge_and_process_cu(struct cus *cus, struct conf_load *conf,
				     Dwfl_Module *mod, Dwarf *dw, Elf *elf,
				     const char *filename,
				     const unsigned char *build_id,
				     int build_id_len,
				     struct dwarf_cu *type_dcu)
{
	uint8_t pointer_size, offset_size;
	struct dwarf_cu *dcu = NULL;
	Dwarf_Off off = 0, noff;
	struct cu *cu = NULL;
	size_t cuhl;

	while (dwarf_nextcu(dw, off, &noff, &cuhl, NULL, &pointer_size,
			    &offset_size) == 0) {
		Dwarf_Die die_mem;
		Dwarf_Die *cu_die = dwarf_offdie(dw, off + cuhl, &die_mem);

		if (cu_die == NULL)
			break;

		if (cu == NULL) {
			cu = cu__new("", pointer_size, build_id, build_id_len,
				     filename, conf->use_obstack);
			if (cu == NULL || cu__set_common(cu, conf, mod, elf) != 0)
				goto out_abort;

			dcu = zalloc(sizeof(*dcu));
			if (dcu == NULL)
				goto out_abort;

			/* Merged cu tends to need a lot more memory.
			 * Let us start with max_hashtags__bits and
			 * go down to find a proper hashtag bit value.
			 */
			uint32_t default_hbits = hashtags__bits;
			for (hashtags__bits = max_hashtags__bits;
			     hashtags__bits >= default_hbits;
			     hashtags__bits--) {
				if (dwarf_cu__init(dcu, cu) == 0)
					break;
			}
			if (hashtags__bits < default_hbits)
				goto out_abort;

			dcu->cu = cu;
			dcu->type_unit = type_dcu;
			cu->priv = dcu;
			cu->dfops = &dwarf__ops;
			cu->language = attr_numeric(cu_die, DW_AT_language);
		}

		Dwarf_Die child;
		if (dwarf_child(cu_die, &child) == 0) {
			if (die__process_unit(&child, cu, conf) != 0)
				goto out_abort;
		}

		off = noff;
	}

	if (cu == NULL)
		return 0;

	/* process merged cu */
	if (cu__recode_dwarf_types(cu) != LSK__KEEPIT)
		goto out_abort;

	/*
	 * for lto build, the function return type may not be
	 * resolved due to the return type of a subprogram is
	 * encoded in another subprogram through abstract_origin
	 * tag. Let us visit all subprograms again to resolve this.
	 */
	if (cu__resolve_func_ret_types(cu) != LSK__KEEPIT)
		goto out_abort;

	if (cus__finalize(cus, cu, conf, NULL) == LSK__STOP_LOADING)
		goto out_abort;

	return 0;

out_abort:
	dwarf_cu__delete(cu);
	cu__delete(cu);
	return DWARF_CB_ABORT;
}

static int cus__load_module(struct cus *cus, struct conf_load *conf,
			    Dwfl_Module *mod, Dwarf *dw, Elf *elf,
			    const char *filename)
{
	const unsigned char *build_id = NULL;
#ifdef HAVE_DWFL_MODULE_BUILD_ID
	GElf_Addr vaddr;
	int build_id_len = dwfl_module_build_id(mod, &build_id, &vaddr);
#else
	int build_id_len = 0;
#endif
	struct cu *type_cu;
	struct dwarf_cu type_dcu;
	int type_lsk = LSK__KEEPIT;

	int res = __cus__load_debug_types(conf, mod, dw, elf, filename, build_id, build_id_len, &type_cu, &type_dcu);
	if (res != 0) {
		return res;
	}

	if (type_cu != NULL) {
		type_lsk = cu__finalize(type_cu, conf, NULL);
		if (type_lsk == LSK__KEEPIT) {
			cus__add(cus, type_cu);
		}
	}

	if (cus__merging_cu(dw, elf)) {
		res = cus__merge_and_process_cu(cus, conf, mod, dw, elf, filename,
						build_id, build_id_len,
						type_cu ? &type_dcu : NULL);
	} else {
		struct dwarf_cus dcus = {
			.off      = 0,
			.cus      = cus,
			.conf     = conf,
			.mod      = mod,
			.dw       = dw,
			.elf      = elf,
			.filename = filename,
			.type_dcu = type_cu ? &type_dcu : NULL,
			.build_id = build_id,
			.build_id_len = build_id_len,
		};
		res = dwarf_cus__process_cus(&dcus);
	}

	if (res)
		return res;

	if (type_lsk == LSK__DELETE)
		cu__delete(type_cu);

	return DWARF_CB_OK;
}

struct process_dwflmod_parms {
	struct cus	 *cus;
	struct conf_load *conf;
	const char	 *filename;
	uint32_t	 nr_dwarf_sections_found;
};

static int cus__process_dwflmod(Dwfl_Module *dwflmod,
				void **userdata __maybe_unused,
				const char *name __maybe_unused,
				Dwarf_Addr base __maybe_unused,
				void *arg)
{
	struct process_dwflmod_parms *parms = arg;
	struct cus *cus = parms->cus;

	GElf_Addr dwflbias;
	/*
	 * Does the relocation and saves the elf for later processing
	 * by the stealer, such as pahole_stealer, so that it don't
	 * have to create another Elf instance just to do things like
	 * reading this ELF file symtab to do CTF encoding of the
	 * DW_TAG_suprogram tags (functions).
	 */
	Elf *elf = dwfl_module_getelf(dwflmod, &dwflbias);

	Dwarf_Addr dwbias;
	Dwarf *dw = dwfl_module_getdwarf(dwflmod, &dwbias);

	int err = DWARF_CB_OK;
	if (dw != NULL) {
		++parms->nr_dwarf_sections_found;
		err = cus__load_module(cus, parms->conf, dwflmod, dw, elf,
				       parms->filename);
	}
	/*
	 * XXX We will fall back to try finding other debugging
	 * formats (CTF), so no point in telling this to the user
	 * Use for debugging.
	 * else
	 *   fprintf(stderr,
	 *         "%s: can't get debug context descriptor: %s\n",
	 *	__func__, dwfl_errmsg(-1));
	 */

	return err;
}

static void dwarf_loader__exit(struct cus *cus)
{
	Dwfl *dwfl = cus__priv(cus);

	if (dwfl) {
		dwfl_end(dwfl);
		cus__set_priv(cus, NULL);
	}
}

static int cus__process_file(struct cus *cus, struct conf_load *conf, int fd,
			     const char *filename)
{
	/* Duplicate an fd for dwfl_report_offline to swallow.  */
	int dwfl_fd = dup(fd);

	if (dwfl_fd < 0)
		return -1;

	/*
	 * Use libdwfl in a trivial way to open the libdw handle for us.
	 * This takes care of applying relocations to DWARF data in ET_REL
	 * files.
	 */

	static const Dwfl_Callbacks callbacks = {
		.section_address = dwfl_offline_section_address,
		.find_debuginfo	 = dwfl_standard_find_debuginfo,
		/* We use this table for core files too.  */
		.find_elf	 = dwfl_build_id_find_elf,
	};

	Dwfl *dwfl = dwfl_begin(&callbacks);

	cus__set_priv(cus, dwfl);
	cus__set_loader_exit(cus, dwarf_loader__exit);

	if (dwfl_report_offline(dwfl, filename, filename, dwfl_fd) == NULL)
		return -1;

	dwfl_report_end(dwfl, NULL, NULL);

	struct process_dwflmod_parms parms = {
		.cus  = cus,
		.conf = conf,
		.filename = filename,
		.nr_dwarf_sections_found = 0,
	};

	/* Process the one or more modules gleaned from this file. */
	int err = dwfl_getmodules(dwfl, cus__process_dwflmod, &parms, 0);
	if (err < 0)
		return -1;

	// We can't call dwfl_end(dwfl) here, as we keep pointers to strings
	// allocated by libdw that will be freed at dwfl_end(), so leave this for
	// cus__delete().
	return parms.nr_dwarf_sections_found ? 0 : -1;
}

static int dwarf__load_file(struct cus *cus, struct conf_load *conf,
			    const char *filename)
{
	int fd, err;

	if (conf == NULL)
		return -1;

	if (conf->max_hashtable_bits != 0) {
		if (conf->max_hashtable_bits > 31)
			return -E2BIG;

		max_hashtags__bits = conf->max_hashtable_bits;
	}

	if (conf->hashtable_bits != 0) {
		if (conf->hashtable_bits > max_hashtags__bits)
			return -E2BIG;

		hashtags__bits = conf->hashtable_bits;
	} else if (hashtags__bits > max_hashtags__bits)
		return -EINVAL;

	elf_version(EV_CURRENT);

	fd = open(filename, O_RDONLY);

	if (fd == -1)
		return -1;

	err = cus__process_file(cus, conf, fd, filename);
	close(fd);

	return err;
}

struct debug_fmt_ops dwarf__ops = {
	.name		     = "dwarf",
	.load_file	     = dwarf__load_file,
	.tag__decl_file	     = dwarf_tag__decl_file,
	.tag__decl_line	     = dwarf_tag__decl_line,
	.tag__orig_id	     = dwarf_tag__orig_id,
	.cu__delete	     = dwarf_cu__delete,
	.has_alignment_info  = true,
};
