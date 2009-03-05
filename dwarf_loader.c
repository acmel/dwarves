/*
  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <assert.h>
#include <dirent.h>
#include <dwarf.h>
#include <elfutils/libdwfl.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libelf.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "list.h"
#include "dwarves.h"
#include "dutil.h"
#include "strings.h"
#include "hash.h"

#define hashtags__fn(key) hash_64(key, HASHTAGS__BITS)

struct dwarf_tag {
	struct hlist_node hash_node;
	Dwarf_Off	 type;
	Dwarf_Off	 id;
	struct tag	 *tag;
	strings_t        decl_file;
	uint16_t         decl_line;
	uint16_t         small_id;
};

#define HASHTAGS__BITS 8
#define HASHTAGS__SIZE (1UL << HASHTAGS__BITS)

struct dwarf_cu {
	struct hlist_head hash_tags[HASHTAGS__SIZE];
	struct hlist_head hash_types[HASHTAGS__SIZE];
	struct cu *cu;
};

static void dwarf_cu__init(struct dwarf_cu *self)
{
	unsigned int i;
	for (i = 0; i < HASHTAGS__SIZE; ++i) {
		INIT_HLIST_HEAD(&self->hash_tags[i]);
		INIT_HLIST_HEAD(&self->hash_types[i]);
	}
}

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
	uint16_t bucket = hashtags__fn(id);
	const struct hlist_head *head = hashtable + bucket;

	hlist_for_each_entry(tpos, pos, head, hash_node) {
		if (tpos->id == id)
			return tpos;
	}

	return NULL;
}

static void cu__hash(struct cu *self, struct tag *tag)
{
	struct dwarf_cu *dcu = self->priv;
	struct hlist_head *hashtable = tag__is_tag_type(tag) ?
							dcu->hash_types :
							dcu->hash_tags;
	hashtags__hash(hashtable, tag->priv);
}

static struct dwarf_tag *dwarf_cu__find_tag_by_id(const struct dwarf_cu *self,
						  const Dwarf_Off id)
{
	return self ? hashtags__find(self->hash_tags, id) : NULL;
}

static struct dwarf_tag *dwarf_cu__find_type_by_id(const struct dwarf_cu *self,
						   const Dwarf_Off id)
{
	return self ? hashtags__find(self->hash_types, id) : NULL;
}

extern struct strings *strings;

static void *memdup(const void *src, size_t len)
{
	void *s = malloc(len);
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
		return 1;
	default:
		fprintf(stderr, "DW_AT_<0x%x>=0x%x\n", name, form);
		break;
	}

	return 0;
}

static uint64_t dwarf_expr(const uint8_t *expr, uint32_t len __unused)
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

static Dwarf_Off attr_offset(Dwarf_Die *die, const uint32_t name)
{
	Dwarf_Attribute attr;
	Dwarf_Block block;

	if (dwarf_attr(die, name, &attr) != NULL &&
	    dwarf_formblock(&attr, &block) == 0)
		return dwarf_expr(block.data, block.length);

	return 0;
}

static const char *attr_string(Dwarf_Die *die, uint32_t name)
{
	Dwarf_Attribute attr;
	if (dwarf_attr(die, name, &attr) != NULL)
		return dwarf_formstring(&attr);
	return NULL;
}

static Dwarf_Off attr_type(Dwarf_Die *die, uint32_t attr_name)
{
	Dwarf_Attribute attr;
	if (dwarf_attr(die, attr_name, &attr) != NULL) {
		 Dwarf_Die type_die;
		 if (dwarf_formref_die(&attr, &type_die) != NULL)
		 	return dwarf_dieoffset(&type_die);

	}
	return 0;
}

static int attr_location(Dwarf_Die *die, Dwarf_Op **expr, size_t *exprlen)
{
	Dwarf_Attribute attr;
	if (dwarf_attr(die, DW_AT_location, &attr) != NULL) {
		if (dwarf_getlocation(&attr, expr, exprlen) == 0)
			return 0;
	}

	return 1;
}

static void *tag__alloc(size_t size)
{
	struct dwarf_tag *dtag;
	struct tag *self = malloc(size + sizeof(*dtag));

	if (self != NULL) {
		dtag = ((void *)self) + size;
		dtag->tag = self;
		self->priv = dtag;
		dtag->type = 0;
		self->type = 0;
		self->top_level = 0;
	}

	return self;
}

static void tag__init(struct tag *self, Dwarf_Die *die)
{
	struct dwarf_tag *dtag = self->priv;
	int32_t decl_line;
	const char *decl_file = dwarf_decl_file(die);
	static const char *last_decl_file;
	static uint32_t last_decl_file_idx;

	self->tag = dwarf_tag(die);

	dtag->id  = dwarf_dieoffset(die);

	if (self->tag == DW_TAG_imported_module ||
	    self->tag == DW_TAG_imported_declaration)
		dtag->type = attr_type(die, DW_AT_import);
	else
		dtag->type = attr_type(die, DW_AT_type);

	if (decl_file != last_decl_file) {
		last_decl_file_idx = strings__add(strings, decl_file);
		last_decl_file = decl_file;
	}

	dtag->decl_file = last_decl_file_idx;
	dwarf_decl_line(die, &decl_line);
	dtag->decl_line = decl_line;
	self->recursivity_level = 0;
	INIT_HLIST_NODE(&dtag->hash_node);
}

static struct tag *tag__new(Dwarf_Die *die)
{
	struct tag *self = tag__alloc(sizeof(*self));

	if (self != NULL)
		tag__init(self, die);

	return self;
}

static struct ptr_to_member_type *ptr_to_member_type__new(Dwarf_Die *die)
{
	struct ptr_to_member_type *self = tag__alloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->containing_type = attr_type(die, DW_AT_containing_type);
	}

	return self;
}

static struct base_type *base_type__new(Dwarf_Die *die)
{
	struct base_type *self = tag__alloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->name = strings__add(strings, attr_string(die, DW_AT_name));
		self->bit_size = attr_numeric(die, DW_AT_byte_size) * 8;
	}

	return self;
}

static struct array_type *array_type__new(Dwarf_Die *die)
{
	struct array_type *self = tag__alloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->dimensions = 0;
		self->nr_entries = NULL;
	}

	return self;
}

static void namespace__init(struct namespace *self, Dwarf_Die *die)
{
	tag__init(&self->tag, die);
	INIT_LIST_HEAD(&self->tags);
	self->name    = strings__add(strings, attr_string(die, DW_AT_name));
	self->nr_tags = 0;
}

static struct namespace *namespace__new(Dwarf_Die *die)
{
	struct namespace *self = tag__alloc(sizeof(*self));

	if (self != NULL)
		namespace__init(self, die);

	return self;
}

static void type__init(struct type *self, Dwarf_Die *die)
{
	namespace__init(&self->namespace, die);
	INIT_LIST_HEAD(&self->node);
	self->size		 = attr_numeric(die, DW_AT_byte_size);
	self->declaration	 = attr_numeric(die, DW_AT_declaration);
	self->specification	 = attr_type(die, DW_AT_specification);
	self->definition_emitted = 0;
	self->fwd_decl_emitted	 = 0;
	self->resized		 = 0;
	self->nr_members	 = 0;
}

static struct type *type__new(Dwarf_Die *die)
{
	struct type *self = tag__alloc(sizeof(*self));

	if (self != NULL)
		type__init(self, die);

	return self;
}

static struct enumerator *enumerator__new(Dwarf_Die *die)
{
	struct enumerator *self = tag__alloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->name = strings__add(strings, attr_string(die, DW_AT_name));
		self->value = attr_numeric(die, DW_AT_const_value);
	}

	return self;
}

static enum vlocation dwarf__location(Dwarf_Die *die)
{
	Dwarf_Op *expr;
	size_t exprlen;
	enum vlocation location = LOCATION_UNKNOWN;

	if (attr_location(die, &expr, &exprlen) != 0)
		location = LOCATION_OPTIMIZED;
	else if (exprlen != 0)
		switch (expr->atom) {
		case DW_OP_addr:
			location = LOCATION_GLOBAL;	break;
		case DW_OP_reg1 ... DW_OP_reg31:
		case DW_OP_breg0 ... DW_OP_breg31:
			location = LOCATION_REGISTER;	break;
		case DW_OP_fbreg:
			location = LOCATION_LOCAL;	break;
		}

	return location;
}

static struct variable *variable__new(Dwarf_Die *die)
{
	struct variable *self = tag__alloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->name = strings__add(strings, attr_string(die, DW_AT_name));
		self->abstract_origin = attr_type(die, DW_AT_abstract_origin);
		/* variable is visible outside of its enclosing cu */
		self->external = dwarf_hasattr(die, DW_AT_external);
		/* non-defining declaration of an object */
		self->declaration = dwarf_hasattr(die, DW_AT_declaration);
		self->location = LOCATION_UNKNOWN;
		if (!self->declaration)
			self->location = dwarf__location(die);
	}

	return self;
}

static struct class_member *class_member__new(Dwarf_Die *die)
{
	struct class_member *self = tag__alloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->name = strings__add(strings, attr_string(die, DW_AT_name));
		self->offset	 = attr_offset(die, DW_AT_data_member_location);
		self->bit_offset = attr_numeric(die, DW_AT_bit_offset);
		self->bit_size	 = attr_numeric(die, DW_AT_bit_size);
		self->bit_hole	 = 0;
		self->bitfield_end = 0;
		self->visited = 0;
		self->accessibility = attr_numeric(die, DW_AT_accessibility);
		self->virtuality    = attr_numeric(die, DW_AT_virtuality);
		self->hole = 0;
	}

	return self;
}

static struct parameter *parameter__new(Dwarf_Die *die)
{
	struct parameter *self = tag__alloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->name	      = strings__add(strings, attr_string(die,
								 DW_AT_name));
		self->abstract_origin = attr_type(die, DW_AT_abstract_origin);
	}

	return self;
}

static struct inline_expansion *inline_expansion__new(Dwarf_Die *die)
{
	struct inline_expansion *self = tag__alloc(sizeof(*self));

	if (self != NULL) {
		struct dwarf_tag *dtag = self->tag.priv;

		tag__init(&self->tag, die);
		dtag->decl_file =
			strings__add(strings, attr_string(die, DW_AT_call_file));
		dtag->decl_line = attr_numeric(die, DW_AT_call_line);
		dtag->type = attr_type(die, DW_AT_abstract_origin);

		if (dwarf_lowpc(die, &self->low_pc))
			self->low_pc = 0;
		if (dwarf_lowpc(die, &self->high_pc))
			self->high_pc = 0;

		self->size = self->high_pc - self->low_pc;
		if (self->size == 0) {
			Dwarf_Addr base, start;
			ptrdiff_t offset = 0;

			while (1) {
				offset = dwarf_ranges(die, offset, &base, &start,
						      &self->high_pc);
				start = (unsigned long)start;
				self->high_pc = (unsigned long)self->high_pc;
				if (offset <= 0)
					break;
				self->size += self->high_pc - start;
				if (self->low_pc == 0)
					self->low_pc = start;
			}
		}
	}

	return self;
}

static struct label *label__new(Dwarf_Die *die)
{
	struct label *self = tag__alloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->name = strings__add(strings, attr_string(die, DW_AT_name));
		self->abstract_origin = attr_type(die, DW_AT_abstract_origin);
		if (dwarf_lowpc(die, &self->low_pc))
			self->low_pc = 0;
	}

	return self;
}

static struct class *class__new(Dwarf_Die *die)
{
	struct class *self = tag__alloc(sizeof(*self));

	if (self != NULL) {
		type__init(&self->type, die);
		INIT_LIST_HEAD(&self->vtable);
		self->nr_vtable_entries =
		  self->nr_holes =
		  self->nr_bit_holes =
		  self->padding =
		  self->bit_padding = 0;
		self->priv = NULL;
	}

	return self;
}

static void lexblock__init(struct lexblock *self, Dwarf_Die *die)
{
	if (dwarf_highpc(die, &self->high_pc))
		self->high_pc = 0;
	if (dwarf_lowpc(die, &self->low_pc))
		self->low_pc = 0;

	INIT_LIST_HEAD(&self->tags);

	self->size_inline_expansions =
	self->nr_inline_expansions =
		self->nr_labels =
		self->nr_lexblocks = 
		self->nr_variables = 0;
}

static struct lexblock *lexblock__new(Dwarf_Die *die)
{
	struct lexblock *self = tag__alloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		lexblock__init(self, die);
	}

	return self;
}

static void ftype__init(struct ftype *self, Dwarf_Die *die)
{
	const uint16_t tag = dwarf_tag(die);
	assert(tag == DW_TAG_subprogram || tag == DW_TAG_subroutine_type);

	tag__init(&self->tag, die);
	INIT_LIST_HEAD(&self->parms);
	self->nr_parms	   = 0;
	self->unspec_parms = 0;
}

static struct ftype *ftype__new(Dwarf_Die *die)
{
	struct ftype *self = tag__alloc(sizeof(*self));

	if (self != NULL)
		ftype__init(self, die);

	return self;
}

static struct function *function__new(Dwarf_Die *die)
{
	struct function *self = tag__alloc(sizeof(*self));

	if (self != NULL) {
		ftype__init(&self->proto, die);
		lexblock__init(&self->lexblock, die);
		self->name     = strings__add(strings, attr_string(die, DW_AT_name));
		self->linkage_name = strings__add(strings, attr_string(die, DW_AT_MIPS_linkage_name));
		self->inlined  = attr_numeric(die, DW_AT_inline);
		self->external = dwarf_hasattr(die, DW_AT_external);
		self->abstract_origin = attr_type(die, DW_AT_abstract_origin);
		self->specification   = attr_type(die, DW_AT_specification);
		self->accessibility   = attr_numeric(die, DW_AT_accessibility);
		self->virtuality      = attr_numeric(die, DW_AT_virtuality);
		INIT_LIST_HEAD(&self->vtable_node);
		INIT_LIST_HEAD(&self->tool_node);
		self->vtable_entry    = -1;
		if (dwarf_hasattr(die, DW_AT_vtable_elem_location))
			self->vtable_entry = attr_offset(die, DW_AT_vtable_elem_location);
		self->cu_total_size_inline_expansions = 0;
		self->cu_total_nr_inline_expansions = 0;
		self->priv = NULL;
	}

	return self;
}

static void oom(const char *msg)
{
	fprintf(stderr, "libclasses: out of memory(%s)\n", msg);
	exit(EXIT_FAILURE);
}

static uint64_t attr_upper_bound(Dwarf_Die *die)
{
	Dwarf_Attribute attr;

	if (dwarf_attr(die, DW_AT_upper_bound, &attr) != NULL) {
		Dwarf_Word num;

		if (dwarf_formudata(&attr, &num) == 0) {
			return (uintmax_t)num + 1;
		}
	}

	return 0;
}

static void __cu__tag_not_handled(Dwarf_Die *die, const char *fn)
{
	fprintf(stderr, "%s: DW_TAG_%s @ <%#llx> not handled!\n",
		fn, dwarf_tag_name(dwarf_tag(die)),
		(unsigned long long)dwarf_dieoffset(die));
}

#define cu__tag_not_handled(die) __cu__tag_not_handled(die, __FUNCTION__)

static struct tag *__die__process_tag(Dwarf_Die *die, struct cu *cu,
				      int toplevel, const char *fn);

#define die__process_tag(die, cu, toplevel) \
	__die__process_tag(die, cu, toplevel, __FUNCTION__)

static struct tag *die__create_new_tag(Dwarf_Die *die)
{
	struct tag *self = tag__new(die);

	if (self == NULL)
		oom("tag__new");

	if (dwarf_haschildren(die))
		fprintf(stderr, "%s: %s WITH children!\n", __FUNCTION__,
			dwarf_tag_name(self->tag));

	return self;
}

static struct tag *die__create_new_ptr_to_member_type(Dwarf_Die *die)
{
	struct ptr_to_member_type *self = ptr_to_member_type__new(die);

	if (self == NULL)
		oom("ptr_to_member_type__new");

	return &self->tag;
}

static void die__process_class(Dwarf_Die *die,
			       struct type *class, struct cu *cu);

static struct tag *die__create_new_class(Dwarf_Die *die, struct cu *cu)
{
	Dwarf_Die child;
	struct class *class = class__new(die);

	if (class == NULL)
		oom("class__new");

	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		die__process_class(&child, &class->type, cu);

	return &class->type.namespace.tag;
}

static void die__process_namespace(Dwarf_Die *die,
				   struct namespace *namespace,
				   struct cu *cu);

static struct tag *die__create_new_namespace(Dwarf_Die *die, struct cu *cu)
{
	Dwarf_Die child;
	struct namespace *namespace = namespace__new(die);

	if (namespace == NULL)
		oom("namespace__new");

	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		die__process_namespace(&child, namespace, cu);

	return &namespace->tag;
}

static struct tag *die__create_new_union(Dwarf_Die *die, struct cu *cu)
{
	Dwarf_Die child;
	struct type *utype = type__new(die);

	if (utype == NULL)
		oom("type__new");

	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		die__process_class(&child, utype, cu);

	return &utype->namespace.tag;
}

static struct tag *die__create_new_base_type(Dwarf_Die *die)
{
	struct base_type *base = base_type__new(die);

	if (base == NULL)
		oom("base_type__new");

	if (dwarf_haschildren(die))
		fprintf(stderr, "%s: DW_TAG_base_type WITH children!\n",
			__FUNCTION__);

	return &base->tag;
}

static struct tag *die__create_new_typedef(Dwarf_Die *die)
{
	struct type *tdef = type__new(die);

	if (tdef == NULL)
		oom("type__new");

	if (dwarf_haschildren(die))
		fprintf(stderr, "%s: DW_TAG_typedef WITH children!\n",
			__FUNCTION__);

	return &tdef->namespace.tag;
}

static struct tag *die__create_new_array(Dwarf_Die *die)
{
	Dwarf_Die child;
	/* "64 dimensions will be enough for everybody." acme, 2006 */
	const uint8_t max_dimensions = 64;
	uint32_t nr_entries[max_dimensions];
	struct array_type *array = array_type__new(die);

	if (array == NULL)
		oom("array_type__new");

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0) {
		struct dwarf_tag *dtag = array->tag.priv;
		fprintf(stderr,
			"%s: DW_TAG_array_type %#llx with no children!\n",
			__func__, (unsigned long long)dtag->id);
		return NULL;
	}

	die = &child;
	array->dimensions = 0;
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
				   array->dimensions * sizeof(uint32_t));
	if (array->nr_entries == NULL)
		oom("memdup(array.nr_entries)");

	return &array->tag;
}

static struct tag *die__create_new_parameter(Dwarf_Die *die,
					     struct ftype *ftype,
					     struct lexblock *lexblock)
{
	struct parameter *parm = parameter__new(die);

	if (parm == NULL)
		oom("parameter__new");

	if (ftype != NULL)
		ftype__add_parameter(ftype, parm);
	else {
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
					 struct lexblock *lexblock)
{
	struct label *label = label__new(die);

	if (label == NULL)
		oom("label__new");

	lexblock__add_label(lexblock, label);
	return &label->tag;
}

static struct tag *die__create_new_variable(Dwarf_Die *die)
{
	struct variable *var = variable__new(die);
	if (var == NULL)
		oom("variable__new");

	return &var->tag;
}

static struct tag *die__create_new_subroutine_type(Dwarf_Die *die,
						   struct cu *cu)
{
	Dwarf_Die child;
	struct ftype *ftype = ftype__new(die);

	if (ftype == NULL)
		oom("ftype__new");

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0)
		goto out;

	die = &child;
	do {
		long id = -1;
		struct tag *tag;

		switch (dwarf_tag(die)) {
		case DW_TAG_formal_parameter:
			tag = die__create_new_parameter(die, ftype, NULL);
			break;
		case DW_TAG_unspecified_parameters:
			ftype->unspec_parms = 1;
			continue;
		case DW_TAG_typedef:
			/*
			 * First seen in inkscape
			 */
			tag = die__create_new_typedef(die);

			if (cu__add_tag(cu, tag, &id) < 0)
				oom("die__create_new_subroutine_type:2");

			goto hash;
		default:
			cu__tag_not_handled(die);
			continue;
		}

		if (cu__table_add_tag(cu, tag, &id) < 0)
			oom("die__create_new_subroutine_type");
hash:
		cu__hash(cu, tag);
		struct dwarf_tag *dtag = tag->priv;
		dtag->small_id = id;
	} while (dwarf_siblingof(die, die) == 0);
out:
	return &ftype->tag;
}

static struct tag *die__create_new_enumeration(Dwarf_Die *die)
{
	Dwarf_Die child;
	struct type *enumeration = type__new(die);

	if (enumeration == NULL)
		oom("class__new");

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
		enumerator = enumerator__new(die);
		if (enumerator == NULL)
			oom("enumerator__new");

		enumeration__add(enumeration, enumerator);
	} while (dwarf_siblingof(die, die) == 0);
out:
	return &enumeration->namespace.tag;
}

static void die__process_class(Dwarf_Die *die, struct type *class,
			       struct cu *cu)
{
	do {
		switch (dwarf_tag(die)) {
		case DW_TAG_inheritance:
		case DW_TAG_member: {
			struct class_member *member = class_member__new(die);

			if (member == NULL)
				oom("class_member__new");

			type__add_member(class, member);
			cu__hash(cu, &member->tag);
		}
			continue;
		default: {
			struct tag *tag = die__process_tag(die, cu, 0);

			if (tag != NULL) {
				long id = -1;

				if (cu__table_add_tag(cu, tag, &id) < 0)
					oom("die__process_class:2");

				struct dwarf_tag *dtag = tag->priv;
				dtag->small_id = id;

				namespace__add_tag(&class->namespace, tag);
				cu__hash(cu, tag);
				if (tag->tag == DW_TAG_subprogram) {
					struct function *fself = tag__function(tag);

					if (fself->vtable_entry != -1)
						class__add_vtable_entry(type__class(class), fself);
				}
			}
			continue;
		}
		}
	} while (dwarf_siblingof(die, die) == 0);
}

static void die__process_namespace(Dwarf_Die *die,
				   struct namespace *namespace,
				   struct cu *cu)
{
	do {
		struct tag *tag = die__process_tag(die, cu, 0);

		if (tag != NULL) {
			long id = -1;
			if (cu__table_add_tag(cu, tag, &id) < 0)
				oom("die__process_namespace");

			struct dwarf_tag *dtag = tag->priv;
			dtag->small_id = id;

			namespace__add_tag(namespace, tag);
			cu__hash(cu, tag);
		}
	} while (dwarf_siblingof(die, die) == 0);
}

static void die__process_function(Dwarf_Die *die, struct ftype *ftype,
				  struct lexblock *lexblock, struct cu *cu);

static void die__create_new_lexblock(Dwarf_Die *die,
				     struct cu *cu, struct lexblock *father)
{
	struct lexblock *lexblock = lexblock__new(die);

	if (lexblock == NULL)
		oom("lexblock__new");
	die__process_function(die, NULL, lexblock, cu);
	lexblock__add_lexblock(father, lexblock);
}

static struct tag *die__create_new_inline_expansion(Dwarf_Die *die,
						    struct lexblock *lexblock)
{
	struct inline_expansion *exp = inline_expansion__new(die);

	if (exp == NULL)
		oom("inline_expansion__new");

	lexblock__add_inline_expansion(lexblock, exp);
	return &exp->tag;
}

static void die__process_function(Dwarf_Die *die, struct ftype *ftype,
				  struct lexblock *lexblock, struct cu *cu)
{
	Dwarf_Die child;

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0)
		return;

	die = &child;
	do {
		long id = -1;
		struct tag *tag;

		switch (dwarf_tag(die)) {
		case DW_TAG_formal_parameter:
			tag = die__create_new_parameter(die, ftype, lexblock);
			break;
		case DW_TAG_variable:
			tag = die__create_new_variable(die);
			lexblock__add_variable(lexblock, tag__variable(tag));
			break;
		case DW_TAG_unspecified_parameters:
			if (ftype != NULL)
				ftype->unspec_parms = 1;
			continue;
		case DW_TAG_label:
			tag = die__create_new_label(die, lexblock);
			break;
		case DW_TAG_inlined_subroutine:
			tag = die__create_new_inline_expansion(die, lexblock);
			break;
		case DW_TAG_lexical_block:
			die__create_new_lexblock(die, cu, lexblock);
			continue;
		default:
			tag = die__process_tag(die, cu, 0);
			if (tag == NULL)
				oom("die__process_function");

			if (cu__add_tag(cu, tag, &id) < 0)
				oom("die__process_function");

			goto hash;
		}

		if (cu__table_add_tag(cu, tag, &id) < 0)
			oom("die__process_function");
hash:
		cu__hash(cu, tag);
		struct dwarf_tag *dtag = tag->priv;
		dtag->small_id = id;
	} while (dwarf_siblingof(die, die) == 0);
}

static struct tag *die__create_new_function(Dwarf_Die *die, struct cu *cu)
{
	struct function *function = function__new(die);

	if (function == NULL)
		oom("function__new");
	die__process_function(die, &function->proto, &function->lexblock, cu);
	return &function->proto.tag;
}

static struct tag *__die__process_tag(Dwarf_Die *die, struct cu *cu,
				      int top_level, const char *fn)
{
	struct tag *tag;

	switch (dwarf_tag(die)) {
	case DW_TAG_array_type:
		tag = die__create_new_array(die);		break;
	case DW_TAG_base_type:
		tag = die__create_new_base_type(die);		break;
	case DW_TAG_const_type:
	case DW_TAG_imported_declaration:
	case DW_TAG_imported_module:
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type:
	case DW_TAG_volatile_type:
		tag = die__create_new_tag(die);			break;
	case DW_TAG_ptr_to_member_type:
		tag = die__create_new_ptr_to_member_type(die);	break;
	case DW_TAG_enumeration_type:
		tag = die__create_new_enumeration(die);		break;
	case DW_TAG_namespace:
		tag = die__create_new_namespace(die, cu);	break;
	case DW_TAG_class_type:
	case DW_TAG_structure_type:
		tag = die__create_new_class(die, cu);		break;
	case DW_TAG_subprogram:
		tag = die__create_new_function(die, cu);	break;
	case DW_TAG_subroutine_type:
		tag = die__create_new_subroutine_type(die, cu);	break;
	case DW_TAG_typedef:
		tag = die__create_new_typedef(die);		break;
	case DW_TAG_union_type:
		tag = die__create_new_union(die, cu);		break;
	case DW_TAG_variable:
		tag = die__create_new_variable(die);		break;
	default:
		__cu__tag_not_handled(die, fn);
		tag = NULL;
		break;
	}

	if (tag != NULL)
		tag->top_level = top_level;

	return tag;
}

static void die__process_unit(Dwarf_Die *die, struct cu *cu)
{
	do {
		struct tag *tag = die__process_tag(die, cu, 1);
		if (tag != NULL) {
			long id = -1;
			cu__add_tag(cu, tag, &id);
			cu__hash(cu, tag);
			struct dwarf_tag *dtag = tag->priv;
			dtag->small_id = id;
			
		}
	} while (dwarf_siblingof(die, die) == 0);
}

static void __tag__print_type_not_found(struct tag *self, const char *func)
{
	struct dwarf_tag *dtag = self->priv;
	fprintf(stderr, "%s: couldn't find %#llx type for %#llx (%s)!\n", func,
		(unsigned long long)dtag->type, (unsigned long long)dtag->id,
		dwarf_tag_name(self->tag));
}

#define tag__print_type_not_found(self) \
	__tag__print_type_not_found(self, __func__)

static void ftype__recode_dwarf_types(struct tag *self, struct cu *cu);

static void namespace__recode_dwarf_types(struct tag *self, struct cu *cu)
{
	struct tag *pos;
	struct dwarf_cu *dcu = cu->priv;
	struct namespace *ns = tag__namespace(self);

	namespace__for_each_tag(ns, pos) {
		struct dwarf_tag *dtype;
		struct dwarf_tag *dpos = pos->priv;

		if (tag__has_namespace(pos)) {
			namespace__recode_dwarf_types(pos, cu);
			continue;
		}

		switch (pos->tag) {
		case DW_TAG_subroutine_type:
		case DW_TAG_subprogram:
			ftype__recode_dwarf_types(pos, cu);
			break;
		case DW_TAG_imported_module:
			dtype = dwarf_cu__find_tag_by_id(dcu, dpos->type);
			goto check_type;
		/* Can be for both types and non types */
		case DW_TAG_imported_declaration:
			dtype = dwarf_cu__find_tag_by_id(dcu, dpos->type);
			if (dtype != NULL)
				goto next;
			goto find_type;
		}

		if (dpos->type == 0) /* void */
			continue;
find_type:
		dtype = dwarf_cu__find_type_by_id(dcu, dpos->type);
check_type:
		if (dtype == NULL) {
			tag__print_type_not_found(pos);
			continue;
		}
next:
		pos->type = dtype->small_id;
	}
}

static void type__recode_dwarf_specification(struct tag *self, struct cu *cu)
{
	struct dwarf_tag *dtype;
	struct type *t = tag__type(self);

	if (t->namespace.name != 0 || t->specification == 0)
		return;

	dtype = dwarf_cu__find_type_by_id(cu->priv, t->specification);
	if (dtype != NULL)
		t->namespace.name = tag__namespace(dtype->tag)->name;
	else {
		struct dwarf_tag *dtag = self->priv;

		fprintf(stderr,
			"%s: couldn't find name for "
			"class %#llx, specification=%#llx\n", __func__,
			(unsigned long long)dtag->id,
			(unsigned long long)t->specification);
	}
}

static void __tag__print_abstract_origin_not_found(struct tag *self,
						   unsigned long long abstract_origin,
						   const char *func)
{
	struct dwarf_tag *dtag = self->priv;
	fprintf(stderr,
		"%s: couldn't find %#llx abstract_origin for %#llx (%s)!\n",
		func, abstract_origin, (unsigned long long)dtag->id,
		dwarf_tag_name(self->tag));
}

#define tag__print_abstract_origin_not_found(self, abstract_origin) \
	__tag__print_abstract_origin_not_found(self, abstract_origin, __func__)

static void ftype__recode_dwarf_types(struct tag *self, struct cu *cu)
{
	struct parameter *pos;
	struct dwarf_cu *dcu = cu->priv;
	struct ftype *type = tag__ftype(self);

	ftype__for_each_parameter(type, pos) {
		struct dwarf_tag *dpos = pos->tag.priv;
		struct dwarf_tag *dtype;

		if (dpos->type == 0) {
			if (pos->abstract_origin == 0) {
				/* Function without parameters */
				pos->tag.type = 0;
				continue;
			}
			dtype = dwarf_cu__find_tag_by_id(dcu, pos->abstract_origin);
			if (dtype == NULL) {
				tag__print_abstract_origin_not_found(&pos->tag,
								     pos->abstract_origin);
				continue;
			}
			pos->name = tag__parameter(dtype->tag)->name;
			pos->tag.type = dtype->tag->type;
			continue;
		}

		dtype = dwarf_cu__find_type_by_id(dcu, dpos->type);
		if (dtype == NULL) {
			tag__print_type_not_found(&pos->tag);
			continue;
		}
		pos->tag.type = dtype->small_id;
	}
}

static void lexblock__recode_dwarf_types(struct lexblock *self, struct cu *cu)
{
	struct tag *pos;
	struct dwarf_cu *dcu = cu->priv;

	list_for_each_entry(pos, &self->tags, node) {
		struct dwarf_tag *dpos = pos->priv;
		struct dwarf_tag *dtype;

		switch (pos->tag) {
		case DW_TAG_lexical_block:
			lexblock__recode_dwarf_types(tag__lexblock(pos), cu);
			continue;
		case DW_TAG_inlined_subroutine:
			dtype = dwarf_cu__find_tag_by_id(dcu, dpos->type);
			if (dtype == NULL) {
				tag__print_type_not_found(pos);
				continue;
			}
			ftype__recode_dwarf_types(dtype->tag, cu);
			continue;

		case DW_TAG_formal_parameter:
			if (dpos->type != 0)
				break;

			struct parameter *fp = tag__parameter(pos);
			dtype = dwarf_cu__find_tag_by_id(dcu,
							 fp->abstract_origin);
			if (dtype == NULL) {
				tag__print_abstract_origin_not_found(pos,
								     fp->abstract_origin);
				continue;
			}
			fp->name = tag__parameter(dtype->tag)->name;
			pos->type = dtype->tag->type;
			continue;

		case DW_TAG_variable:
			if (dpos->type != 0)
				break;

			struct variable *var = tag__variable(pos);
			
			if (var->abstract_origin == 0) {
				/*
				 * DW_TAG_variable completely empty was
				 * found on libQtGui.so.4.3.4.debug
				 * <3><d6ea1>: Abbrev Number: 164 (DW_TAG_variable)
				 */
				continue;
			}

			dtype = dwarf_cu__find_tag_by_id(dcu,
							 var->abstract_origin);
			if (dtype == NULL) {
				tag__print_abstract_origin_not_found(pos,
								     var->abstract_origin);
				continue;
			}
			var->name = tag__variable(dtype->tag)->name;
			pos->type = dtype->tag->type;
			continue;

		case DW_TAG_label: {
			struct label *l = tag__label(pos);

			if (l->abstract_origin == 0)
				continue;

			dtype = dwarf_cu__find_tag_by_id(dcu, l->abstract_origin);
			if (dtype != NULL)
				l->name = tag__label(dtype->tag)->name;
			else
				tag__print_abstract_origin_not_found(pos,
								     l->abstract_origin);
		}
			continue;
		}

		dtype = dwarf_cu__find_type_by_id(dcu, dpos->type);
		if (dtype == NULL) {
			tag__print_type_not_found(pos);
			continue;
		}
		pos->type = dtype->small_id;
	}
}

static void tag__recode_dwarf_type(struct tag *self, struct cu *cu)
{
	struct dwarf_tag *dtag = self->priv;
	struct dwarf_tag *dtype;

	if (tag__is_type(self))
		type__recode_dwarf_specification(self, cu);

	if (tag__has_namespace(self)) {
		namespace__recode_dwarf_types(self, cu);
		return;
	}

	switch (self->tag) {
	case DW_TAG_subprogram: {
		struct function *fn = tag__function(self);

		if (fn->name == 0)  {
			if (fn->abstract_origin == 0 &&
			    fn->specification == 0) {
				/*
				 * Found on libQtGui.so.4.3.4.debug
				 *  <3><1423de>: Abbrev Number: 209 (DW_TAG_subprogram)
				 *      <1423e0>   DW_AT_declaration : 1
				 */
				return;
			}
			dtype = dwarf_cu__find_tag_by_id(cu->priv, fn->abstract_origin);
			if (dtype == NULL)
				dtype = dwarf_cu__find_tag_by_id(cu->priv, fn->specification);
			if (dtype != NULL)
				fn->name = tag__function(dtype->tag)->name;
			else {
				fprintf(stderr,
					"%s: couldn't find name for "
					"function %#llx, abstract_origin=%#llx,"
					" specification=%#llx\n", __func__,
					(unsigned long long)dtag->id,
					(unsigned long long)fn->abstract_origin,
					(unsigned long long)fn->specification);
			}
		}
		lexblock__recode_dwarf_types(&fn->lexblock, cu);
	}
		/* Fall thru */

	case DW_TAG_subroutine_type:
		ftype__recode_dwarf_types(self, cu);
		/* Fall thru, for the function return type */
		break;

	case DW_TAG_lexical_block:
		lexblock__recode_dwarf_types(tag__lexblock(self), cu);
		return;

	case DW_TAG_ptr_to_member_type: {
		struct ptr_to_member_type *pt = tag__ptr_to_member_type(self);

		dtype = dwarf_cu__find_type_by_id(cu->priv, pt->containing_type);
		if (dtype != NULL)
			pt->containing_type = dtype->small_id;
		else {
			fprintf(stderr,
				"%s: couldn't find type for "
				"containing_type %#llx, containing_type=%#llx\n",
				__func__,
				(unsigned long long)dtag->id,
				(unsigned long long)pt->containing_type);
		}
	}
		break;

	case DW_TAG_namespace:
		namespace__recode_dwarf_types(self, cu);
		return;
	/* Damn, DW_TAG_inlined_subroutine is an special case
           as dwarf_tag->id is in fact an abtract origin, i.e. must be
	   looked up in the tags_table, not in the types_table.
	   The others also point to routines, so are in tags_table */
	case DW_TAG_inlined_subroutine:
	case DW_TAG_imported_module:
		dtype = dwarf_cu__find_tag_by_id(cu->priv, dtag->type);
		goto check_type;
	/* Can be for both types and non types */
	case DW_TAG_imported_declaration:
		dtype = dwarf_cu__find_tag_by_id(cu->priv, dtag->type);
		if (dtype != NULL)
			goto out;
		goto find_type;
	}

	if (dtag->type == 0) {
		self->type = 0; /* void */
		return;
	}

find_type:
	dtype = dwarf_cu__find_type_by_id(cu->priv, dtag->type);
check_type:
	if (dtype == NULL) {
		tag__print_type_not_found(self);
		return;
	}
out:
	self->type = dtype->small_id;
}

static void cu__recode_dwarf_types_table(struct cu *self, struct ptr_table *pt)
{
	uint32_t i;

	for (i = 1; i < pt->nr_entries; ++i) {
		struct tag *tag = pt->entries[i];

		if (tag != NULL) /* void, see cu__new */
			tag__recode_dwarf_type(tag, self);
	}
}

static void cu__recode_dwarf_types(struct cu *self)
{
	cu__recode_dwarf_types_table(self, &self->types_table);
	cu__recode_dwarf_types_table(self, &self->tags_table);
}

static const char *dwarf_tag__decl_file(const struct tag *self,
					const struct cu *cu __unused)
{
	struct dwarf_tag *dtag = self->priv;
	return dtag ? strings__ptr(strings, dtag->decl_file) : NULL;
}

static uint32_t dwarf_tag__decl_line(const struct tag *self,
				     const struct cu *cu __unused)
{
	struct dwarf_tag *dtag = self->priv;
	return dtag ? dtag->decl_line : 0;
}

static unsigned long long dwarf_tag__orig_id(const struct tag *self,
					       const struct cu *cu __unused)
{
	struct dwarf_tag *dtag = self->priv;
	return dtag ? dtag->id : 0;
}

static unsigned long long dwarf_tag__orig_type(const struct tag *self,
					       const struct cu *cu __unused)
{
	struct dwarf_tag *dtag = self->priv;
	return dtag ? dtag->type : 0;
}

static struct cu_orig_info dwarf_orig_info_ops = {
	.tag__decl_file	= dwarf_tag__decl_file,
	.tag__decl_line	= dwarf_tag__decl_line,
	.tag__orig_id	= dwarf_tag__orig_id,
	.tag__orig_type	= dwarf_tag__orig_type,
};

static void die__process(Dwarf_Die *die, struct cu *cu)
{
	Dwarf_Die child;
	const uint16_t tag = dwarf_tag(die);

	if (tag != DW_TAG_compile_unit) {
		fprintf(stderr, "%s: DW_TAG_compile_unit expected got %s!\n",
			__FUNCTION__, dwarf_tag_name(tag));
		return;
	}

	cu->language = attr_numeric(die, DW_AT_language);

	struct dwarf_cu dcu;

	dwarf_cu__init(&dcu);
	cu->priv = &dcu;
	cu->orig_info = &dwarf_orig_info_ops;

	if (dwarf_child(die, &child) == 0)
		die__process_unit(&child, cu);

	if (dwarf_siblingof(die, die) == 0)
		fprintf(stderr, "%s: got %s unexpected tag after "
				"DW_TAG_compile_unit!\n",
			__FUNCTION__, dwarf_tag_name(tag));

	cu__recode_dwarf_types(cu);
}

static void cus__load_module(struct cus *self, Dwfl_Module *mod, Dwarf *dw)
{
	Dwarf_Off off = 0, noff;
	size_t cuhl;
	GElf_Addr vaddr;
	const unsigned char *build_id = NULL;

#ifdef HAVE_DWFL_MODULE_BUILD_ID
	int build_id_len = dwfl_module_build_id(mod, &build_id, &vaddr);
#else
	int build_id_len = 0;
#endif
	while (dwarf_nextcu(dw, off, &noff, &cuhl, NULL, NULL, NULL) == 0) {
		Dwarf_Die die_mem, tmp;
		Dwarf_Die *cu_die = dwarf_offdie(dw, off + cuhl, &die_mem);
		struct cu *cu;
		uint8_t pointer_size, offset_size;

		dwarf_diecu(cu_die, &tmp, &pointer_size, &offset_size);

		cu = cu__new(attr_string(cu_die, DW_AT_name), pointer_size,
			     build_id, build_id_len);
		if (cu == NULL)
			oom("cu__new");
		die__process(cu_die, cu);
		cus__add(self, cu);
		off = noff;
	}
}

static int cus__process_dwflmod(Dwfl_Module *dwflmod,
				void **userdata __unused,
				const char *name __unused,
				Dwarf_Addr base __unused,
				void *arg)
{
	struct cus *self = arg;
	/*
	 * WARNING: Don't remove the seemingly useless call to
	 * dwfl_module_getelf, as it will change dwflmod internal state in a
	 * way that is required by dwfl_module_getdwarf.
 	 */
	GElf_Addr dwflbias;
	dwfl_module_getelf(dwflmod, &dwflbias);

	Dwarf_Addr dwbias;
	Dwarf *dw = dwfl_module_getdwarf(dwflmod, &dwbias);

	if (dw != NULL)
		cus__load_module(self, dwflmod, dw);
	/*
	 * XXX We will fall back to try finding other debugging
	 * formats (CTF), so no point in telling this to the user
	 * Use for debugging.
	 * else
	 *   fprintf(stderr,
	 *         "%s: can't get debug context descriptor: %s\n",
	 *	__func__, dwfl_errmsg(-1));
	 */

	return DWARF_CB_OK;
}

static int cus__process_file(struct cus *self, int fd, const char *filename)
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

	if (dwfl_report_offline(dwfl, filename, filename, dwfl_fd) == NULL)
		return -1;

	dwfl_report_end(dwfl, NULL, NULL);

	/* Process the one or more modules gleaned from this file. */
	dwfl_getmodules(dwfl, cus__process_dwflmod, self, 0);
	dwfl_end(dwfl);
	return 0;
}

int dwarf__load_filename(struct cus *self, const char *filename)
{
	Dwarf_Off offset, last_offset, abbrev_offset;
	uint8_t addr_size, offset_size;
	size_t hdr_size;
	Dwarf *dwarf;
	int fd = open(filename, O_RDONLY);	
	int err;

	if (fd < 0) {
		err = errno;
		goto out;
	}

	err = -EINVAL;
	dwarf = dwarf_begin(fd, DWARF_C_READ);
	if (dwarf == NULL)
		goto out_close;

	offset = last_offset = 0;
	while (dwarf_nextcu(dwarf, offset, &offset, &hdr_size,
			    &abbrev_offset, &addr_size, &offset_size) == 0) {
		Dwarf_Die die;

		if (dwarf_offdie(dwarf, last_offset + hdr_size, &die) != NULL) {
			struct cu *cu = cu__new(attr_string(&die, DW_AT_name),
						addr_size, NULL, 0);
			if (cu == NULL)
				oom("cu__new");
			die__process(&die, cu);
			cus__add(self, cu);
		}

		last_offset = offset;
	}

	dwarf_end(dwarf);
	err = 0;
out_close:
	close(fd);
out:
	return err;
}

int dwarf__load(struct cus *self, char *filenames[], bool parsed __unused)
{
	int err = 0, i = 0;

	elf_version(EV_CURRENT);

	while (filenames[i] != NULL) {
		int fd = open(filenames[i], O_RDONLY);

		if (fd == -1) {
			fprintf(stderr, "%s: couldn't open %s\n", __func__,
				filenames[i]);
			++i;
			continue;
		}
		cus__process_file(self, fd, filenames[i]);
		close(fd);
		++i;
	}

	return err;
}
