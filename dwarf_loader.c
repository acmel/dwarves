/*
  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <assert.h>
#include <dirent.h>
#include <dwarf.h>
#include <argp.h>
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

static void *zalloc(const size_t size)
{
	void *s = malloc(size);
	if (s != NULL)
		memset(s, 0, size);
	return s;
}

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

static void tag__init(struct tag *self, Dwarf_Die *die)
{
	int32_t decl_line;

	self->tag = dwarf_tag(die);
	self->id  = dwarf_dieoffset(die);

	if (self->tag == DW_TAG_imported_module ||
	    self->tag == DW_TAG_imported_declaration)
		self->type = attr_type(die, DW_AT_import);
	else
		self->type = attr_type(die, DW_AT_type);

	self->decl_file = strings__add(dwarf_decl_file(die));
	dwarf_decl_line(die, &decl_line);
	self->decl_line = decl_line;
	self->recursivity_level = 0;
	INIT_LIST_HEAD(&self->hash_node);
}

static struct tag *tag__new(Dwarf_Die *die)
{
	struct tag *self = malloc(sizeof(*self));

	if (self != NULL)
		tag__init(self, die);

	return self;
}

static struct base_type *base_type__new(Dwarf_Die *die)
{
	struct base_type *self = zalloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->name = strings__add(attr_string(die, DW_AT_name));
		self->bit_size = attr_numeric(die, DW_AT_byte_size) * 8;
	}

	return self;
}

static struct array_type *array_type__new(Dwarf_Die *die)
{
	struct array_type *self = zalloc(sizeof(*self));

	if (self != NULL)
		tag__init(&self->tag, die);

	return self;
}

static void namespace__init(struct namespace *self, Dwarf_Die *die)
{
	tag__init(&self->tag, die);
	INIT_LIST_HEAD(&self->tags);
	self->name    = strings__add(attr_string(die, DW_AT_name));
	self->nr_tags = 0;
}

static struct namespace *namespace__new(Dwarf_Die *die)
{
	struct namespace *self = malloc(sizeof(*self));

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
	struct type *self = malloc(sizeof(*self));

	if (self != NULL)
		type__init(self, die);

	return self;
}

static struct enumerator *enumerator__new(Dwarf_Die *die)
{
	struct enumerator *self = zalloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->name = strings__add(attr_string(die, DW_AT_name));
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
	struct variable *self = malloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->name = strings__add(attr_string(die, DW_AT_name));
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
	struct class_member *self = zalloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->offset	 = attr_offset(die, DW_AT_data_member_location);
		self->bit_size	 = attr_numeric(die, DW_AT_bit_size);
		self->bit_offset = attr_numeric(die, DW_AT_bit_offset);
		self->accessibility = attr_numeric(die, DW_AT_accessibility);
		self->virtuality    = attr_numeric(die, DW_AT_virtuality);
		self->name = strings__add(attr_string(die, DW_AT_name));
	}

	return self;
}

static struct parameter *parameter__new(Dwarf_Die *die)
{
	struct parameter *self = zalloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->name	      = strings__add(attr_string(die,
								 DW_AT_name));
		self->abstract_origin = attr_type(die, DW_AT_abstract_origin);
	}

	return self;
}

static struct inline_expansion *inline_expansion__new(Dwarf_Die *die)
{
	struct inline_expansion *self = zalloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->tag.decl_file =
			strings__add(attr_string(die, DW_AT_call_file));
		self->tag.decl_line = attr_numeric(die, DW_AT_call_line);
		self->tag.type	    = attr_type(die, DW_AT_abstract_origin);

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
	struct label *self = malloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->name = strings__add(attr_string(die, DW_AT_name));
		if (dwarf_lowpc(die, &self->low_pc))
			self->low_pc = 0;
	}

	return self;
}

static struct class *class__new(Dwarf_Die *die)
{
	struct class *self = zalloc(sizeof(*self));

	if (self != NULL) {
		type__init(&self->type, die);
		INIT_LIST_HEAD(&self->vtable);
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

	self->nr_inline_expansions =
		self->nr_labels =
		self->nr_lexblocks = 
		self->nr_variables = 0;
}

static struct lexblock *lexblock__new(Dwarf_Die *die)
{
	struct lexblock *self = malloc(sizeof(*self));

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
	struct ftype *self = malloc(sizeof(*self));

	if (self != NULL)
		ftype__init(self, die);

	return self;
}

static struct function *function__new(Dwarf_Die *die)
{
	struct function *self = zalloc(sizeof(*self));

	if (self != NULL) {
		ftype__init(&self->proto, die);
		lexblock__init(&self->lexblock, die);
		self->name     = strings__add(attr_string(die, DW_AT_name));
		self->linkage_name = strings__add(attr_string(die, DW_AT_MIPS_linkage_name));
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
				      const char *fn);

#define die__process_tag(die, cu) __die__process_tag(die, cu, __FUNCTION__)

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
				   struct namespace *namespace, struct cu *cu);

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
		fprintf(stderr, "%s: DW_TAG_array_type with no children!\n",
			__FUNCTION__);
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

static void die__create_new_parameter(Dwarf_Die *die, struct ftype *ftype,
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

}

static void die__create_new_label(Dwarf_Die *die, struct lexblock *lexblock)
{
	struct label *label = label__new(die);

	if (label == NULL)
		oom("label__new");

	lexblock__add_label(lexblock, label);
}

static struct tag *die__create_new_variable(Dwarf_Die *die)
{
	struct variable *var = variable__new(die);
	if (var == NULL)
		oom("variable__new");

	return &var->tag;
}

static struct tag *die__create_new_subroutine_type(Dwarf_Die *die)
{
	Dwarf_Die child;
	struct ftype *ftype = ftype__new(die);

	if (ftype == NULL)
		oom("ftype__new");

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0)
		goto out;

	die = &child;
	do {
		switch (dwarf_tag(die)) {
		case DW_TAG_formal_parameter:
			die__create_new_parameter(die, ftype, NULL);
			break;
		case DW_TAG_unspecified_parameters:
			ftype->unspec_parms = 1;
			break;
		default:
			cu__tag_not_handled(die);
			break;
		}
	} while (dwarf_siblingof(die, die) == 0);
out:
	return &ftype->tag;
}

static struct tag *die__create_new_enumeration(Dwarf_Die *die, struct cu *cu)
{
	Dwarf_Die child;
	struct type *enumeration = type__new(die);

	if (enumeration == NULL)
		oom("class__new");

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0) {
		fprintf(stderr, "%s: DW_TAG_enumeration_type with no "
				"children!\n", __FUNCTION__);
		return NULL;
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
		hashtags__hash(cu->hash_tags, &enumerator->tag);
	} while (dwarf_siblingof(die, die) == 0);

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
			hashtags__hash(cu->hash_tags, &member->tag);
		}
			continue;
		default: {
			struct tag *tag = die__process_tag(die, cu);

			if (tag != NULL) {
				namespace__add_tag(&class->namespace, tag);
				hashtags__hash(cu->hash_tags, tag);
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
				   struct namespace *namespace, struct cu *cu)
{
	do {
		struct tag *tag = die__process_tag(die, cu);

		if (tag != NULL) {
			namespace__add_tag(namespace, tag);
			hashtags__hash(cu->hash_tags, tag);
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

static void die__create_new_inline_expansion(Dwarf_Die *die,
					     struct lexblock *lexblock)
{
	struct inline_expansion *exp = inline_expansion__new(die);

	if (exp == NULL)
		oom("inline_expansion__new");

	lexblock__add_inline_expansion(lexblock, exp);
}

static void die__process_function(Dwarf_Die *die, struct ftype *ftype,
				  struct lexblock *lexblock, struct cu *cu)
{
	Dwarf_Die child;

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0)
		return;

	die = &child;
	do {
		switch (dwarf_tag(die)) {
		case DW_TAG_formal_parameter:
			die__create_new_parameter(die, ftype, lexblock);
			continue;
		case DW_TAG_variable: {
			struct tag *tag = die__create_new_variable(die);
			lexblock__add_variable(lexblock, tag__variable(tag));
		}
			continue;
		case DW_TAG_unspecified_parameters:
			if (ftype != NULL)
				ftype->unspec_parms = 1;
			continue;
		case DW_TAG_label:
			die__create_new_label(die, lexblock);
			continue;
		case DW_TAG_inlined_subroutine:
			die__create_new_inline_expansion(die, lexblock);
			continue;
		case DW_TAG_lexical_block:
			die__create_new_lexblock(die, cu, lexblock);
			continue;
		default: {
			struct tag *tag = die__process_tag(die, cu);
			if (tag != NULL)
				cu__add_tag(cu, tag);
		}
		}
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
				      const char *fn)
{
	switch (dwarf_tag(die)) {
	case DW_TAG_array_type:
		return die__create_new_array(die);
	case DW_TAG_base_type:
		return die__create_new_base_type(die);
	case DW_TAG_const_type:
	case DW_TAG_imported_declaration:
	case DW_TAG_imported_module:
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type:
	case DW_TAG_volatile_type:
		return die__create_new_tag(die);
	case DW_TAG_enumeration_type:
		return die__create_new_enumeration(die, cu);
	case DW_TAG_namespace:
		return die__create_new_namespace(die, cu);
	case DW_TAG_structure_type:
		return die__create_new_class(die, cu);
	case DW_TAG_subprogram:
		return die__create_new_function(die, cu);
	case DW_TAG_subroutine_type:
		return die__create_new_subroutine_type(die);
	case DW_TAG_typedef:
		return die__create_new_typedef(die);
	case DW_TAG_union_type:
		return die__create_new_union(die, cu);
	case DW_TAG_variable:
		return die__create_new_variable(die);
	default:
		__cu__tag_not_handled(die, fn);
	}

	return NULL;
}

static void die__process_unit(Dwarf_Die *die, struct cu *cu)
{
	do {
		struct tag *tag = die__process_tag(die, cu);
		if (tag != NULL)
			cu__add_tag(cu, tag);
	} while (dwarf_siblingof(die, die) == 0);
}

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

	if (dwarf_child(die, &child) == 0)
		die__process_unit(&child, cu);

	if (dwarf_siblingof(die, die) == 0)
		fprintf(stderr, "%s: got %s unexpected tag after "
				"DW_TAG_compile_unit!\n",
			__FUNCTION__, dwarf_tag_name(tag));
}

static int cus__load_module(Dwfl_Module *mod, void **userdata __unused,
			    const char *name __unused, Dwarf_Addr base __unused,
			    Dwarf *dw, Dwarf_Addr bias __unused, void *self)
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

	return DWARF_CB_OK;
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

static int with_executable_option(int argc, char *argv[])
{
	while (--argc != 0)
		if (strcmp(argv[argc], "--help") == 0 ||
		    strcmp(argv[argc], "-?") == 0 ||
		    strcmp(argv[argc], "-h") == 0 ||
		    strcmp(argv[argc], "--usage") == 0 ||
		    strcmp(argv[argc], "--executable") == 0 ||
		    (argv[argc][0] == '-' && argv[argc][1] != '-' &&
		     strchr(argv[argc] + 1, 'e') != NULL))
			return 1;
	return 0;
}

int dwarf__load(struct cus *self, struct argp *argp, int argc, char *argv[])
{
	Dwfl *dwfl = NULL;
	char **new_argv = NULL;
	ptrdiff_t offset;
	int err = -1;

	if (argc == 1) {
		argp_help(argp ? : dwfl_standard_argp(), stderr,
			  ARGP_HELP_SEE, argv[0]);
		return -1;
	}

	if (!with_executable_option(argc, argv)) {
		new_argv = malloc((argc + 2) * sizeof(char *));
		if (new_argv == NULL) {
			fprintf(stderr, "%s: not enough memory!\n", __func__);
			return -1;
		}
		memcpy(new_argv, argv, (argc - 1) * sizeof(char *));
		new_argv[argc - 1] = "-e";
		new_argv[argc] = argv[argc - 1];
		new_argv[argc + 1] = NULL;
		argv = new_argv;
		argc++;
	}

	if (argp != NULL) {
		const struct argp_child argp_children[] = {
			{ .argp = dwfl_standard_argp(), },
			{ .argp = NULL }
		};
		argp->children = argp_children;
		argp_parse(argp, argc, argv, 0, NULL, &dwfl);
	} else
		argp_parse(dwfl_standard_argp(), argc, argv, 0, NULL, &dwfl);

	if (dwfl == NULL)
		goto out;

	offset = 0;
	do {
		offset = dwfl_getdwarf(dwfl, cus__load_module, self, offset);
	} while (offset > 0);

	dwfl_end(dwfl);
	err = 0;
out:
	free(new_argv);
	return err;
}
