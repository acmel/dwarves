/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Red Hat Inc.
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <dwarf.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libelf.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "list.h"
#include "dwarves.h"

static const char *dwarf_tag_names[] = {
	[DW_TAG_array_type]		  = "array_type",
	[DW_TAG_class_type]		  = "class_type",
	[DW_TAG_entry_point]		  = "entry_point",
	[DW_TAG_enumeration_type]	  = "enumeration_type",
	[DW_TAG_formal_parameter]	  = "formal_parameter",
	[DW_TAG_imported_declaration]	  = "imported_declaration",
	[DW_TAG_label]			  = "label",
	[DW_TAG_lexical_block]		  = "lexical_block",
	[DW_TAG_member]			  = "member",
	[DW_TAG_pointer_type]		  = "pointer_type",
	[DW_TAG_reference_type]		  = "reference_type",
	[DW_TAG_compile_unit]		  = "compile_unit",
	[DW_TAG_string_type]		  = "string_type",
	[DW_TAG_structure_type]		  = "structure_type",
	[DW_TAG_subroutine_type]	  = "subroutine_type",
	[DW_TAG_typedef]		  = "typedef",
	[DW_TAG_union_type]		  = "union_type",
	[DW_TAG_unspecified_parameters]	  = "unspecified_parameters",
	[DW_TAG_variant]		  = "variant",
	[DW_TAG_common_block]		  = "common_block",
	[DW_TAG_common_inclusion]	  = "common_inclusion",
	[DW_TAG_inheritance]		  = "inheritance",
	[DW_TAG_inlined_subroutine]	  = "inlined_subroutine",
	[DW_TAG_module]			  = "module",
	[DW_TAG_ptr_to_member_type]	  = "ptr_to_member_type",
	[DW_TAG_set_type]		  = "set_type",
	[DW_TAG_subrange_type]		  = "subrange_type",
	[DW_TAG_with_stmt]		  = "with_stmt",
	[DW_TAG_access_declaration]	  = "access_declaration",
	[DW_TAG_base_type]		  = "base_type",
	[DW_TAG_catch_block]		  = "catch_block",
	[DW_TAG_const_type]		  = "const_type",
	[DW_TAG_constant]		  = "constant",
	[DW_TAG_enumerator]		  = "enumerator",
	[DW_TAG_file_type]		  = "file_type",
	[DW_TAG_friend]			  = "friend",
	[DW_TAG_namelist]		  = "namelist",
	[DW_TAG_namelist_item]		  = "namelist_item",
	[DW_TAG_packed_type]		  = "packed_type",
	[DW_TAG_subprogram]		  = "subprogram",
	[DW_TAG_template_type_parameter]  = "template_type_parameter",
	[DW_TAG_template_value_parameter] = "template_value_parameter",
	[DW_TAG_thrown_type]		  = "thrown_type",
	[DW_TAG_try_block]		  = "try_block",
	[DW_TAG_variant_part]		  = "variant_part",
	[DW_TAG_variable]		  = "variable",
	[DW_TAG_volatile_type]		  = "volatile_type",
	[DW_TAG_dwarf_procedure]	  = "dwarf_procedure",
	[DW_TAG_restrict_type]		  = "restrict_type",
	[DW_TAG_interface_type]		  = "interface_type",
	[DW_TAG_namespace]		  = "namespace",
	[DW_TAG_imported_module]	  = "imported_module",
	[DW_TAG_unspecified_type]	  = "unspecified_type",
	[DW_TAG_partial_unit]		  = "partial_unit",
	[DW_TAG_imported_unit]		  = "imported_unit",
	[DW_TAG_mutable_type]		  = "mutable_type",
	[DW_TAG_condition]		  = "condition",
	[DW_TAG_shared_type]		  = "shared_type",
};

const char *dwarf_tag_name(const uint32_t tag)
{
	if (tag >= DW_TAG_array_type && tag <= DW_TAG_shared_type)
		return dwarf_tag_names[tag];
	return "INVALID";
}

static const char tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

static size_t cacheline_size;

static void *zalloc(const size_t size)
{
	void *s = malloc(size);
	if (s != NULL)
		memset(s, 0, size);
	return s;
}

void *memdup(const void *src, size_t len)
{
	void *s = malloc(len);
	if (s != NULL)
		memcpy(s, src, len);
	return s;
}

static void *strings;

static int strings__compare(const void *a, const void *b)
{
	return strcmp(a, b);
}

static char *strings__add(const char *str)
{
	char **s;

	if (str == NULL)
		return NULL;

	s = tsearch(str, &strings, strings__compare);
	if (s != NULL) {
		if (*s == str) {
			char *dup = strdup(str);
			if (dup != NULL)
				*s = dup;
			else {
				tdelete(str, &strings, strings__compare);
				return NULL;
			}
		}
	} else
		return NULL;

	return *s;
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

static Dwarf_Off attr_offset(Dwarf_Die *die)
{
	Dwarf_Attribute attr;

	if (dwarf_attr(die, DW_AT_data_member_location, &attr) != NULL) {
		Dwarf_Block block;

		if (dwarf_formblock(&attr, &block) == 0) {
			uint64_t uleb;
			const uint8_t *data = block.data + 1;
			get_uleb128(uleb, data);
			return uleb;
		}
	}

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

	self->tag	= dwarf_tag(die);
	self->id	= dwarf_dieoffset(die);
	self->type	= attr_type(die, DW_AT_type);
	self->decl_file = strings__add(dwarf_decl_file(die));
	dwarf_decl_line(die, &decl_line);
	self->decl_line = decl_line;
}

static struct tag *tag__new(Dwarf_Die *die)
{
	struct tag *self = malloc(sizeof(*self));

	if (self != NULL)
		tag__init(self, die);

	return self;
}

size_t tag__nr_cachelines(const struct tag *self, const struct cu *cu)
{
	return (tag__size(self, cu) + cacheline_size - 1) / cacheline_size;
}

static void __tag__type_not_found(const struct tag *self, const char *fn)
{
	fprintf(stderr, "%s: %#llx type not found for %s (id=%#llx)\n",
		fn, self->type, dwarf_tag_name(self->tag), self->id);
	fflush(stdout);
}

#define tag__type_not_found(self) __tag__type_not_found(self, __func__)

static void tag__print_decl_info(const struct tag *self, FILE *fp)
{
	fprintf(fp, "/* <%llx> %s:%u */\n",
		self->id, self->decl_file, self->decl_line);
}

static struct base_type *base_type__new(Dwarf_Die *die)
{
	struct base_type *self = zalloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->name = strings__add(attr_string(die, DW_AT_name));
		self->size = attr_numeric(die, DW_AT_byte_size);
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

static size_t array_type__fprintf(const struct tag *tag_self,
				  const struct cu *cu, const char *name,
				  size_t type_spacing, FILE *fp)
{
	struct array_type *self = tag__array_type(tag_self);
	char tbf[128];
	int i;
	size_t n = fprintf(fp, "%-*s %s", type_spacing,
			   tag__name(tag_self, cu, tbf, sizeof(tbf)), name);

	for (i = 0; i < self->dimensions; ++i)
		n += fprintf(fp, "[%u]", self->nr_entries[i]);
	return n;
}

static void type__init(struct type *self, Dwarf_Die *die)
{
	tag__init(&self->tag, die);
	INIT_LIST_HEAD(&self->node);
	INIT_LIST_HEAD(&self->members);
	self->name		 = strings__add(attr_string(die, DW_AT_name));
	self->size		 = attr_numeric(die, DW_AT_byte_size);
	self->declaration	 = attr_numeric(die, DW_AT_declaration);
	self->definition_emitted = 0;
	self->fwd_decl_emitted	 = 0;
	self->nr_members	 = 0;
}

static struct type *type__new(Dwarf_Die *die)
{
	struct type *self = malloc(sizeof(*self));

	if (self != NULL)
		type__init(self, die);

	return self;
}

static void typedef__print(const struct tag *tag_self, const struct cu *cu,
			   FILE *fp)
{
	const struct type *self = tag__type(tag_self);
	const struct tag *type = cu__find_tag_by_id(cu, tag_self->type);
	const struct tag *ptr_type;
	char bf[512];
	int is_pointer = 0;

	if (type == NULL) {
		tag__type_not_found(tag_self);
		return;
	}

	switch (type->tag) {
	case DW_TAG_array_type:
		fputs("typedef ", fp);
		array_type__fprintf(type, cu, self->name, 0, fp);
		return;
	case DW_TAG_pointer_type:
		if (type->type == 0) /* void pointer */
			break;
		ptr_type = cu__find_tag_by_id(cu, type->type);
		if (ptr_type == NULL) {
			tag__type_not_found(type);
			return;
		}
		if (ptr_type->tag != DW_TAG_subroutine_type)
			break;
		type = ptr_type;
		is_pointer = 1;
		/* Fall thru */
	case DW_TAG_subroutine_type:
		fputs("typedef ", fp);
		ftype__fprintf(tag__ftype(type), cu, self->name, 0,
			       is_pointer, 0, fp);
		return;
	case DW_TAG_structure_type: {
		const struct type *ctype = tag__type(type);

		if (ctype->name != NULL) {
			fprintf(fp, "typedef struct %s %s",
				ctype->name, self->name);
			return;
		}
	}
	}

	fprintf(fp, "typedef %s %s", tag__name(type, cu, bf, sizeof(bf)),
		self->name);
}

static size_t enumeration__fprintf(const struct tag *tag_self,
				   const char *suffix, uint8_t indent,
				   FILE *fp)
{
	const struct type *self = tag__type(tag_self);
	struct enumerator *pos;
	size_t n;

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;

	n = fprintf(fp, "enum%s%s {\n", self->name ? " " : "",
		    self->name ?: "");
	list_for_each_entry(pos, &self->members, tag.node)
		n += fprintf(fp, "%.*s\t%s = %u,\n", indent, tabs,
			     pos->name, pos->value);

	return n + fprintf(fp, "%.*s}%s%s", indent, tabs,
			   suffix ? " " : "", suffix ?: "");
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

static void cus__add(struct cus *self, struct cu *cu)
{
	list_add_tail(&cu->node, &self->cus);
}

static struct cu *cu__new(const char *name, uint8_t addr_size)
{
	struct cu *self = malloc(sizeof(*self));

	if (self != NULL) {
		INIT_LIST_HEAD(&self->tags);
		INIT_LIST_HEAD(&self->tool_list);

		self->name	= strings__add(name);
		self->addr_size = addr_size;

		self->nr_inline_expansions   = 0;
		self->size_inline_expansions = 0;
		self->nr_structures_changed    = 0;
		self->nr_functions_changed     = 0;
		self->max_len_changed_item     = 0;
		self->function_bytes_added     = 0;
		self->function_bytes_removed   = 0;
	}

	return self;
}

static void cu__add_tag(struct cu *self, struct tag *tag)
{
	list_add_tail(&tag->node, &self->tags);
}

static const char *tag__prefix(const struct cu *cu, const uint32_t tag)
{
	switch (tag) {
	case DW_TAG_enumeration_type:	return "enum ";
	case DW_TAG_structure_type:
		return cu->language == DW_LANG_C_plus_plus ? "class " :
							     "struct ";
	case DW_TAG_union_type:		return "union ";
	case DW_TAG_pointer_type:	return " *";
	case DW_TAG_reference_type:	return " &";
	}

	return "";
}

struct tag *cu__find_tag_by_id(const struct cu *self, const Dwarf_Off id)
{
	struct tag *pos;

	if (id == 0)
		return NULL;

	list_for_each_entry(pos, &self->tags, node)
		if (pos->id == id)
			return pos;

	return NULL;
}

struct tag *cu__find_first_typedef_of_type(const struct cu *self,
					   const Dwarf_Off type)
{
	struct tag *pos;

	if (type == 0)
		return NULL;

	list_for_each_entry(pos, &self->tags, node)
		if (pos->tag == DW_TAG_typedef && pos->type == type)
			return pos;

	return NULL;
}

struct tag *cu__find_base_type_by_name(const struct cu *self, const char *name)
{
	struct tag *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, &self->tags, node) {
		if (pos->tag == DW_TAG_base_type &&
		    strcmp(tag__base_type(pos)->name, name) == 0)
			return pos;
	}

	return NULL;
}

struct tag *cu__find_struct_by_name(const struct cu *self, const char *name)
{
	struct tag *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, &self->tags, node) {
		struct type *type;

		if (pos->tag != DW_TAG_structure_type)
			continue;

		type = tag__type(pos);
		if (!type->declaration &&
		    type->name != NULL &&
		    strcmp(type->name, name) == 0)
			return pos;
	}

	return NULL;
}

struct tag *cus__find_struct_by_name(const struct cus *self,
				     struct cu **cu, const char *name)
{
	struct cu *pos;

	list_for_each_entry(pos, &self->cus, node) {
		struct tag *tag = cu__find_struct_by_name(pos, name);

		if (tag != NULL) {
			if (cu != NULL)
				*cu = pos;
			return tag;
		}
	}

	return NULL;
}

struct tag *cus__find_function_by_name(const struct cus *self,
				       struct cu **cu, const char *name)
{
	struct cu *pos;

	list_for_each_entry(pos, &self->cus, node) {
		struct tag *function = cu__find_function_by_name(pos, name);

		if (function != NULL) {
			if (cu != NULL)
				*cu = pos;
			return function;
		}
	}

	return NULL;
}

struct cu *cus__find_cu_by_name(const struct cus *self, const char *name)
{
	struct cu *pos;

	list_for_each_entry(pos, &self->cus, node)
		if (strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

struct type *cus__find_definition(const struct cus *self, const char *name)
{
	struct type *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, self->definitions, node)
		if (pos->name != NULL && strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

struct type *cus__find_fwd_decl(const struct cus *self, const char *name)
{
	struct type *pos;

	list_for_each_entry(pos, self->fwd_decls, node)
		if (strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

static void cus__add_definition(struct cus *self, struct type *type)
{
	type->definition_emitted = 1;
	if (!list_empty(&type->node))
		list_del(&type->node);
	list_add_tail(&type->node, self->definitions);
}

static void cus__add_fwd_decl(struct cus *self, struct type *type)
{
	type->fwd_decl_emitted = 1;
	if (list_empty(&type->node))
		list_add_tail(&type->node, self->fwd_decls);
}

struct tag *cu__find_function_by_name(const struct cu *self, const char *name)
{
	struct tag *pos;
	struct function *fpos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, &self->tags, node) {
		if (pos->tag != DW_TAG_subprogram)
			continue;
		fpos = tag__function(pos);
		if (fpos->name != NULL && strcmp(fpos->name, name) == 0)
			return pos;
	}

	return NULL;
}

static struct tag *lexblock__find_tag_by_id(const struct lexblock *self,
					    const Dwarf_Off id)
{
	struct tag *pos;

	list_for_each_entry(pos, &self->tags, node) {
		/* Allow find DW_TAG_lexical_block tags */
		if (pos->id == id)
			return pos;
		/*
		 * Oh, not looking for DW_TAG_lexical_block tags? So lets look
		 * inside this lexblock:
		 */
		if (pos->tag == DW_TAG_lexical_block) {
			const struct lexblock *child = tag__lexblock(pos);
			struct tag *tag = lexblock__find_tag_by_id(child, id);

			if (tag != NULL)
				return tag;
		}
	}

	return NULL;
}

static struct variable *cu__find_variable_by_id(const struct cu *self,
						const Dwarf_Off id)
{
	struct tag *pos;

	list_for_each_entry(pos, &self->tags, node) {
		/* Look at global variables first */
		if (pos->id == id)
			return (struct variable *)(pos);

		/* Now look inside function lexical blocks */
		if (pos->tag == DW_TAG_subprogram) {
			struct function *fn = tag__function(pos);
			struct tag *tag =
				lexblock__find_tag_by_id(&fn->lexblock, id);

			if (tag != NULL)
				return (struct variable *)(tag);
		}
	}

	return NULL;
}

static struct tag *ftype__find_parm_by_id(const struct ftype *self,
					  const Dwarf_Off id)
{
	struct tag *pos;

	list_for_each_entry(pos, &self->parms, node)
		if (pos->id == id)
			return pos;
	return 0;
}

static struct parameter *cu__find_parameter_by_id(const struct cu *self,
						  const Dwarf_Off id)
{
	struct tag *pos;

	list_for_each_entry(pos, &self->tags, node) {
		/*
		 * There can't be any at the top level CU tags list,
		 * it'll be in the ftype->parms list or in the lexblock->tags
		 * list, see comment in die__create_new_parameter to see why
		 * the later is possible.
		 */
		if (pos->tag == DW_TAG_subprogram) {
			struct function *fn = tag__function(pos);
			struct tag *tag = ftype__find_parm_by_id(&fn->proto,
								 id);
			if (tag != NULL) {
				tag = lexblock__find_tag_by_id(&fn->lexblock,
							       id);
				if (tag != NULL)
					return tag__parameter(tag);
			}
		}
	}

	return NULL;
}

static size_t array_type__nr_entries(const struct array_type *self)
{
	int i;
	size_t nr_entries = 1;

	for (i = 0; i < self->dimensions; ++i)
		nr_entries *= self->nr_entries[i];

	return nr_entries;
}

size_t tag__size(const struct tag *self, const struct cu *cu)
{
	size_t size;

	switch (self->tag) {
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type:	return cu->addr_size;
	case DW_TAG_base_type:		return tag__base_type(self)->size;
	case DW_TAG_enumeration_type:	return tag__type(self)->size;
	}

	if (self->type == 0) /* struct class: unions, structs */
		size = tag__type(self)->size;
	else {
		const struct tag *type = cu__find_tag_by_id(cu, self->type);

		if (type == NULL) {
			tag__type_not_found(self);
			return -1;
		}
		size = tag__size(type, cu);
	}

	if (self->tag == DW_TAG_array_type)
		return size * array_type__nr_entries(tag__array_type(self));

	return size;
}

static const char *tag__ptr_name(const struct tag *self, const struct cu *cu,
				 char *bf, size_t len, char ptr_char)
{
	if (self->type == 0) /* No type == void */
		snprintf(bf, len, "void %c", ptr_char);
	else {
		const struct tag *type = cu__find_tag_by_id(cu, self->type);

		if (type == NULL) {
			tag__type_not_found(self);
			snprintf(bf, len,
				 "<ERROR: type not found!> %c", ptr_char);
		} else {
			char tmpbf[512];
			snprintf(bf, len, "%s %c",
				 tag__name(type, cu,
					   tmpbf, sizeof(tmpbf)), ptr_char);
		}
	}

	return bf;
}

const char *tag__name(const struct tag *self, const struct cu *cu,
		      char *bf, size_t len)
{
	struct tag *type;

	if (self == NULL)
		strncpy(bf, "void", len);
	else switch (self->tag) {
	case DW_TAG_base_type:
		strncpy(bf, tag__base_type(self)->name, len);
		break;
	case DW_TAG_subprogram:
		strncpy(bf, function__name(tag__function(self), cu), len);
		break;
	case DW_TAG_pointer_type:
		return tag__ptr_name(self, cu, bf, len, '*');
	case DW_TAG_reference_type:
		return tag__ptr_name(self, cu, bf, len, '&');
	case DW_TAG_volatile_type:
	case DW_TAG_const_type:
		type = cu__find_tag_by_id(cu, self->type);
		if (type == NULL && self->type != 0) {
			tag__type_not_found(self);
			strncpy(bf, "<ERROR>", len);
		} else {
			char tmpbf[128];
			snprintf(bf, len, "%s %s ",
				 self->tag == DW_TAG_volatile_type ?
				 	"volatile" : "const",
				 tag__name(type, cu, tmpbf, sizeof(tmpbf)));
		}
		break;
	case DW_TAG_array_type:
		type = cu__find_tag_by_id(cu, self->type);
		if (type == NULL) {
			tag__type_not_found(self);
			strncpy(bf, "<ERROR>", len);
		} else
			return tag__name(type, cu, bf, len);
		break;
	case DW_TAG_subroutine_type: {
		FILE *bfp = fmemopen(bf, len, "w");
		if (bfp != NULL) {
			ftype__fprintf(tag__ftype(self), cu, NULL, 0, 0, 0, bfp);
			fclose(bfp);
		} else
			strncpy(bf, "<ERROR>", len);
	}
		break;
	default:
		snprintf(bf, len, "%s%s", tag__prefix(cu, self->tag),
			 tag__type(self)->name ?: "");
		break;
	}

	return bf;
}

static struct tag *variable__type(const struct variable *self,
				  const struct cu *cu)
{
	struct variable *var;

	if (self->tag.type != 0)
		return cu__find_tag_by_id(cu, self->tag.type);
	else if (self->abstract_origin != 0) {
		var = cu__find_variable_by_id(cu, self->abstract_origin);
		if (var)
			return variable__type(var, cu);
	}

	return NULL;
}

const char *variable__type_name(const struct variable *self,
				const struct cu *cu,
				char *bf, size_t len)
{
	const struct tag *tag = variable__type(self, cu);
	return tag != NULL ? tag__name(tag, cu, bf, len) : NULL;
}

const char *variable__name(const struct variable *self, const struct cu *cu)
{
	if (self->name != NULL)
		return self->name;

	if (self->abstract_origin != 0) {
		struct variable *var =
			cu__find_variable_by_id(cu, self->abstract_origin);
		if (var != NULL)
			return var->name;
	}
	return NULL;
}

static const char *variable__prefix(const struct variable *var)
{
	switch (var->location) {
	case LOCATION_REGISTER:
		return "register ";
	case LOCATION_UNKNOWN:
		if (var->external && var->declaration)
			return "extern ";
		break;
	case LOCATION_GLOBAL:
		if (!var->external)
			return "static ";
		break;
	case LOCATION_LOCAL:
	case LOCATION_OPTIMIZED:
		break;
	}
	return NULL;
}

static struct class_member *class_member__new(Dwarf_Die *die)
{
	struct class_member *self = zalloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, die);
		self->offset	 = attr_offset(die);
		self->bit_size	 = attr_numeric(die, DW_AT_bit_size);
		self->bit_offset = attr_numeric(die, DW_AT_bit_offset);
		self->name = strings__add(attr_string(die, DW_AT_name));
	}

	return self;
}

void class_member__delete(struct class_member *self)
{
	free(self);
}

static struct class_member *class_member__clone(const struct class_member *from)
{
	struct class_member *self = malloc(sizeof(*self));

	if (self != NULL)
		memcpy(self, from, sizeof(*self));

	return self;
}

size_t class_member__size(const struct class_member *self,
			  const struct cu *cu)
{
	struct tag *type = cu__find_tag_by_id(cu, self->tag.type);
	if (type == NULL) {
		tag__type_not_found(&self->tag);
		return -1;
	}
	return tag__size(type, cu);
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

const char *parameter__name(struct parameter *self, const struct cu *cu)
{
	/* Check if the tag doesn't comes with a DW_AT_name attribute... */
	if (self->name == NULL && self->abstract_origin != 0) {
		/* No? Does it have a DW_AT_abstract_origin? */
		struct parameter *alias =
			cu__find_parameter_by_id(cu, self->abstract_origin);
		if (alias == NULL) {
			tag__type_not_found(&self->tag);
			return NULL;
		}
		/* Now cache the result in this tag ->name field */
		self->name = alias->name;
	}

	return self->name;
}

Dwarf_Off parameter__type(struct parameter *self, const struct cu *cu)
{
	/* Check if the tag doesn't comes with a DW_AT_type attribute... */
	if (self->tag.type == 0 && self->abstract_origin != 0) {
		/* No? Does it have a DW_AT_abstract_origin? */
		struct parameter *alias =
			cu__find_parameter_by_id(cu, self->abstract_origin);
		if (alias == NULL) {
			tag__type_not_found(&self->tag);
			return 0;
		}
		/* Now cache the result in this tag ->name and type fields */
		self->name = alias->name;
		self->tag.type = alias->tag.type;
	}

	return self->tag.type;
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

static size_t union__fprintf(const struct type *self, const struct cu *cu,
			     const char *prefix, const char *suffix,
			     uint8_t expand_types, uint8_t indent,
			     size_t type_spacing, size_t name_spacing,
			     FILE *fp);

static size_t type__fprintf(struct tag *type, const char *name,
			    const struct cu *cu, uint8_t expand_types,
			    size_t indent, size_t type_spacing,
			    size_t name_spacing, FILE *fp)
{
	char tbf[128];
	struct type *ctype;

	if (type == NULL)
		return fprintf(fp, "%-*s %s", type_spacing, "<ERROR>", name);

	switch (type->tag) {
	case DW_TAG_pointer_type:
		if (type->type != 0) {
			struct tag *ptype = cu__find_tag_by_id(cu, type->type);
			if (ptype->tag == DW_TAG_subroutine_type)
				return ftype__fprintf(tag__ftype(ptype), cu,
						      name, 0, 1, type_spacing,
						      fp);
		}
		break;
	case DW_TAG_subroutine_type:
		return ftype__fprintf(tag__ftype(type), cu, name, 0, 0,
				      type_spacing, fp);
	case DW_TAG_array_type:
		return array_type__fprintf(type, cu, name, type_spacing, fp);
	case DW_TAG_structure_type:
		ctype = tag__type(type);

		if (ctype->name != NULL && !expand_types)
			return fprintf(fp, "struct %-*s %s",
				       type_spacing - 7, ctype->name, name);
		return class__fprintf(tag__class(type), cu, NULL, name,
				      expand_types, indent,
				      type_spacing - 8, name_spacing, 0, fp);
	case DW_TAG_union_type:
		ctype = tag__type(type);

		if (ctype->name != NULL && !expand_types)
			return fprintf(fp, "union %-*s %s", type_spacing - 6,
				       ctype->name, name);
		return union__fprintf(ctype, cu, NULL, name, expand_types,
				      indent, type_spacing - 8, name_spacing,
				      fp);
	case DW_TAG_enumeration_type:
		ctype = tag__type(type);

		if (ctype->name != NULL)
			return fprintf(fp, "enum %-*s %s", type_spacing - 5,
				       ctype->name, name);
		return enumeration__fprintf(type, name, indent, fp);
	}

	return fprintf(fp, "%-*s %s", type_spacing,
		       tag__name(type, cu, tbf, sizeof(tbf)), name);
}

static size_t struct_member__fprintf(struct class_member *self,
				     struct tag *type, const struct cu *cu,
				     uint8_t expand_types, size_t indent,
				     size_t type_spacing, size_t name_spacing,
				     FILE *fp)
{
	ssize_t spacing;
	const size_t size = tag__size(type, cu);
	size_t n = type__fprintf(type, self->name, cu, expand_types,
				 indent, type_spacing, name_spacing, fp);
	
	if (self->bit_size != 0)
		n += fprintf(fp, ":%u;", self->bit_size);
	else {
		fputc(';', fp);
		++n;
	}

	if ((type->tag == DW_TAG_union_type ||
	     type->tag == DW_TAG_enumeration_type ||
	     type->tag == DW_TAG_structure_type) &&
		/* Look if is a type defined inline */
	    tag__type(type)->name == NULL) {
		/* Check if this is a anonymous union */
		const size_t slen = self->name != NULL ?
					strlen(self->name) : (size_t)-1;
		return n + fprintf(fp, "%*s/* %5u %5u */",
				   type_spacing + name_spacing - slen - 3, " ",
				   self->offset, size);
	}
	spacing = type_spacing + name_spacing - n;
	return n + fprintf(fp, "%*s/* %5u %5u */",
			   spacing > 0 ? spacing : 0, " ", self->offset, size);
}

static size_t union_member__fprintf(struct class_member *self,
				    struct tag *type, const struct cu *cu,
				    uint8_t expand_types, size_t indent,
				    size_t type_spacing, size_t name_spacing,
				    FILE *fp)
{
	ssize_t spacing;
	const size_t size = tag__size(type, cu);
	size_t n = type__fprintf(type, self->name, cu, expand_types,
				 indent, type_spacing, name_spacing, fp);
	
	if ((type->tag == DW_TAG_union_type ||
	     type->tag == DW_TAG_enumeration_type ||
	     type->tag == DW_TAG_structure_type) &&
		/* Look if is a type defined inline */
	    tag__type(type)->name == NULL) {
		/* Check if this is a anonymous union */
		const size_t slen = self->name != NULL ?
					strlen(self->name) : (size_t)-1;
		/*
		 * Add the comment with the union size after padding the
		 * '} member_name;' last line of the type printed in the
		 * above call to type__fprintf.
		 */
		return n + fprintf(fp, ";%*s/* %11u */",
				   type_spacing + name_spacing - slen - 3, " ",
				   size);
	}
	spacing = type_spacing + name_spacing - (n + 1);
	return n + fprintf(fp, ";%*s/* %11u */", spacing > 0 ? spacing : 0,
			   " ", size);
}

static size_t union__fprintf(const struct type *self, const struct cu *cu,
			     const char *prefix, const char *suffix,
			     uint8_t expand_types, uint8_t indent,
			     size_t type_spacing, size_t name_spacing,
			     FILE *fp)
{
	struct class_member *pos;
	size_t n = 0;

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;

	if (prefix != NULL)
		n += fprintf(fp, "%s ", prefix);
	n += fprintf(fp, "union%s%s {\n", self->name ? " " : "",
		     self->name ?: "");
	list_for_each_entry(pos, &self->members, tag.node) {
		struct tag *type = cu__find_tag_by_id(cu, pos->tag.type);

		n += fprintf(fp, "%.*s", indent + 1, tabs);
		n += union_member__fprintf(pos, type, cu, expand_types,
					   indent + 1, type_spacing,
					   name_spacing, fp);
		fputc('\n', fp);
		++n;
	}

	return n + fprintf(fp, "%.*s}%s%s", indent, tabs,
			   suffix ? " " : "", suffix ?: "");
}

static struct class *class__new(Dwarf_Die *die)
{
	struct class *self = zalloc(sizeof(*self));

	if (self != NULL)
		type__init(&self->type, die);

	return self;
}

void class__delete(struct class *self)
{
	struct class_member *pos, *next;

	list_for_each_entry_safe(pos, next, &self->type.members, tag.node)
		class_member__delete(pos);

	free(self);
}

static void type__add_member(struct type *self, struct class_member *member)
{
	++self->nr_members;
	list_add_tail(&member->tag.node, &self->members);
}

static int type__clone_members(struct type *self, const struct type *from)
{
	struct class_member *pos;

	self->nr_members = 0;
	INIT_LIST_HEAD(&self->members);

	list_for_each_entry(pos, &from->members, tag.node) {
		struct class_member *member_clone = class_member__clone(pos);

		if (member_clone == NULL)
			return -1;
		type__add_member(self, member_clone);
	}

	return 0;
}

struct class *class__clone(const struct class *from,
			   const char *new_class_name)
{
	struct class *self = zalloc(sizeof(*self));

	 if (self != NULL) {
		memcpy(self, from, sizeof(*self));
		if (type__clone_members(&self->type, &from->type) != 0) {
			class__delete(self);
			self = NULL;
		}
		if (new_class_name != NULL)
			self->type.name = strings__add(new_class_name);
	}

	return self;
}

static void enumeration__add(struct type *self, struct enumerator *enumerator)
{
	++self->nr_members;
	list_add_tail(&enumerator->tag.node, &self->members);
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

static void lexblock__add_lexblock(struct lexblock *self,
				   struct lexblock *child)
{
	++self->nr_lexblocks;
	list_add_tail(&child->tag.node, &self->tags);
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
		self->inlined  = attr_numeric(die, DW_AT_inline);
		self->external = dwarf_hasattr(die, DW_AT_external);
		self->abstract_origin = attr_type(die, DW_AT_abstract_origin);
		self->specification   = attr_type(die, DW_AT_specification);
	}

	return self;
}

const char *function__name(struct function *self, const struct cu *cu)
{
	/* Check if the tag doesn't comes with a DW_AT_name attribute... */
	if (self->name == NULL) {
		/* No? So it must have a DW_AT_abstract_origin... */
		struct tag *tag = cu__find_tag_by_id(cu,
						     self->abstract_origin);
		if (tag == NULL) {
			/* ... or a DW_TAG_specification... */
			tag = cu__find_tag_by_id(cu, self->specification);
			if (tag == NULL) {
				tag__type_not_found(&self->proto.tag);
				return NULL;
			}
		}
		/* ... and now we cache the result in this tag ->name field */
		self->name = tag__function(tag)->name;
	}

	return self->name;
}

int ftype__has_parm_of_type(const struct ftype *self, const struct tag *target,
			    const struct cu *cu)
{
	struct parameter *pos;

	list_for_each_entry(pos, &self->parms, tag.node) {
		struct tag *type =
			cu__find_tag_by_id(cu, parameter__type(pos, cu));

		if (type != NULL && type->tag == DW_TAG_pointer_type) {
			type = cu__find_tag_by_id(cu, type->type);
			if (type != NULL && type->id == target->id)
				return 1;
		}
	}
	return 0;
}

static void ftype__add_parameter(struct ftype *self, struct parameter *parm)
{
	++self->nr_parms;
	list_add_tail(&parm->tag.node, &self->parms);
}

static void lexblock__add_tag(struct lexblock *self, struct tag *tag)
{
	list_add_tail(&tag->node, &self->tags);
}

static void lexblock__add_inline_expansion(struct lexblock *self,
					   struct inline_expansion *exp)
{
	++self->nr_inline_expansions;
	self->size_inline_expansions += exp->size;
	lexblock__add_tag(self, &exp->tag);
}

static void lexblock__add_variable(struct lexblock *self, struct variable *var)
{
	++self->nr_variables;
	lexblock__add_tag(self, &var->tag);
}

static void lexblock__add_label(struct lexblock *self, struct label *label)
{
	++self->nr_labels;
	lexblock__add_tag(self, &label->tag);
}

const struct class_member *class__find_bit_hole(const struct class *self,
					    const struct class_member *trailer,
						const size_t bit_hole_size)
{
	struct class_member *pos;
	const size_t byte_hole_size = bit_hole_size / 8;

	list_for_each_entry(pos, &self->type.members, tag.node)
		if (pos == trailer)
			break;
		else if (pos->hole >= byte_hole_size ||
			 pos->bit_hole >= bit_hole_size)
			return pos;

	return NULL;
}

void class__find_holes(struct class *self, const struct cu *cu)
{
	const struct type *ctype = &self->type;
	struct class_member *pos, *last = NULL;
	size_t last_size = 0, size;
	uint32_t bit_sum = 0;

	self->nr_holes = 0;
	self->nr_bit_holes = 0;

	list_for_each_entry(pos, &ctype->members, tag.node) {
		if (last != NULL) {
			const ssize_t cc_last_size = pos->offset - last->offset;

			/*
			 * If the offset is the same this better be a bitfield
			 * or an empty struct (see rwlock_t in the Linux kernel
			 * sources when compiled for UP) or...
			 */
			if (cc_last_size > 0) {
				/*
				 * Check if the DWARF byte_size info is smaller
				 * than the size used by the compiler, i.e.
				 * when combining small bitfields with the next
				 * member.
				*/
				if ((size_t)cc_last_size < last_size)
					last_size = cc_last_size;

				last->hole = cc_last_size - last_size;
				if (last->hole > 0)
					++self->nr_holes;

				if (bit_sum != 0) {
					last->bit_hole = (last_size * 8) -
							 bit_sum;
					if (last->bit_hole != 0)
						++self->nr_bit_holes;

					bit_sum = 0;
				}
			}
		}

		bit_sum += pos->bit_size;
		size = class_member__size(pos, cu);

		/*
		 * check for bitfields, accounting for only the biggest of the
		 * byte_size in the fields in each bitfield set.
		 */

		if (last == NULL || last->offset != pos->offset ||
		    pos->bit_size == 0 || last->bit_size == 0) {
			last_size = size;
		} else if (size > last_size)
			last_size = size;

		last = pos;
	}

	if (last != NULL) {
		if (last->offset + last_size != ctype->size)
			self->padding = ctype->size -
					(last->offset + last_size);
		if (last->bit_size != 0)
			self->bit_padding = (last_size * 8) - bit_sum;
	}
}

struct class_member *type__find_member_by_name(const struct type *self,
					       const char *name)
{
	if (name != NULL) {
		struct class_member *pos;
		list_for_each_entry(pos, &self->members, tag.node)
			if (pos->name != NULL && strcmp(pos->name, name) == 0)
				return pos;
	}

	return NULL;
}

static void lexblock__account_inline_expansions(struct lexblock *self,
						const struct cu *cu)
{
	struct tag *pos, *type;

	if (self->nr_inline_expansions == 0)
		return;

	list_for_each_entry(pos, &self->tags, node) {
		if (pos->tag == DW_TAG_lexical_block) {
			lexblock__account_inline_expansions(tag__lexblock(pos),
							    cu);
			continue;
		} else if (pos->tag != DW_TAG_inlined_subroutine)
			continue;

		type = cu__find_tag_by_id(cu, pos->type);
		if (type != NULL) {
			struct function *ftype = tag__function(type);

			ftype->cu_total_nr_inline_expansions++;
			ftype->cu_total_size_inline_expansions +=
					tag__inline_expansion(pos)->size;
		}

	}
}

void cu__account_inline_expansions(struct cu *self)
{
	struct tag *pos;
	struct function *fpos;

	list_for_each_entry(pos, &self->tags, node) {
		if (pos->tag != DW_TAG_subprogram)
			continue;
		fpos = tag__function(pos);
		lexblock__account_inline_expansions(&fpos->lexblock, self);
		self->nr_inline_expansions   += fpos->lexblock.nr_inline_expansions;
		self->size_inline_expansions += fpos->lexblock.size_inline_expansions;
	}
}

static void function__tag_print(const struct tag *tag, const struct cu *cu,
				uint16_t indent, FILE *fp)
{
	char bf[512];
	const void *vtag = tag;
	int c;

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;
	c = indent * 8;

	switch (tag->tag) {
	case DW_TAG_inlined_subroutine: {
		const struct inline_expansion *exp = vtag;
		const struct tag *talias =
				cu__find_tag_by_id(cu, exp->tag.type);
		struct function *alias = tag__function(talias);

		if (alias == NULL) {
			tag__type_not_found(&exp->tag);
			break;
		}
		fprintf(fp, "%.*s", indent, tabs);
		c += fprintf(fp, "%s(); /* low_pc=%#llx */",
			     function__name(alias, cu), exp->low_pc);
	}
		break;
	case DW_TAG_variable:
		fprintf(fp, "%.*s", indent, tabs);
		c += fprintf(fp, "%s %s;",
			     variable__type_name(vtag, cu, bf, sizeof(bf)),
			     variable__name(vtag, cu));
		break;
	case DW_TAG_label: {
		const struct label *label = vtag;
		fprintf(fp, "%.*s", indent, tabs);
		fputc('\n', fp);
		c = fprintf(fp, "%s:", label->name);
	}
		break;
	case DW_TAG_lexical_block:
		lexblock__print(vtag, cu, indent, fp);
		return;
	default:
		fprintf(fp, "%.*s", indent, tabs);
		c += fprintf(fp, "%s <%llx>",
			     dwarf_tag_name(tag->tag), tag->id);
		break;
	}

	fprintf(fp, "%-*.*s// %5u\n", 70 - c, 70 - c, " ", tag->decl_line);
}

void lexblock__print(const struct lexblock *self, const struct cu *cu,
		    uint16_t indent, FILE *fp)
{
	struct tag *pos;

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;
	fprintf(fp, "%.*s{\n", indent, tabs);
	list_for_each_entry(pos, &self->tags, node)
		function__tag_print(pos, cu, indent + 1, fp);
	fprintf(fp, "%.*s}\n", indent, tabs);
}

size_t ftype__fprintf(const struct ftype *self, const struct cu *cu,
		      const char *name, const int inlined,
		      const int is_pointer, size_t type_spacing, FILE *fp)
{
	struct parameter *pos;
	struct tag *type = cu__find_tag_by_id(cu, self->tag.type);
	int first_parm = 1;
	char sbf[128];
	const char *stype = tag__name(type, cu, sbf, sizeof(sbf));
	size_t n = fprintf(fp, "%s%-*s %s%s%s%s(", inlined ? "inline " : "",
			   type_spacing, stype,
			   self->tag.tag == DW_TAG_subroutine_type ? "(" : "",
			   is_pointer ? "*" : "", name ?: "",
			   self->tag.tag == DW_TAG_subroutine_type ? ")" : "");

	list_for_each_entry(pos, &self->parms, tag.node) {
		const char *name;

		if (!first_parm)
			n += fprintf(fp, ", ");
		else
			first_parm = 0;
		name = parameter__name(pos, cu);
		type = cu__find_tag_by_id(cu, parameter__type(pos, cu));
		if (type == NULL) {
			stype = "<ERROR>";
			goto print_it;
		}
		if (type->tag == DW_TAG_pointer_type) {
			if (type->type != 0) {
				struct tag *ptype =
					cu__find_tag_by_id(cu, type->type);
				if (ptype == NULL) {
					n += fprintf(fp, ">>>ERROR: type for "
						     "%s not found!", name);
					continue;
				}
				if (ptype->tag == DW_TAG_subroutine_type) {
					n += ftype__fprintf(tag__ftype(ptype),
							    cu, name, 0, 1, 0,
							    fp);
					continue;
				}
			}
		} else if (type->tag == DW_TAG_subroutine_type) {
			n += ftype__fprintf(tag__ftype(type), cu,
					    name, 0, 0, 0, fp);
			continue;
		}
print_it:
		stype = tag__name(type, cu, sbf, sizeof(sbf));
		n += fprintf(fp, "%s%s%s", stype, name ? " " : "", name ?: "");
	}

	/* No parameters? */
	if (first_parm)
		n += fprintf(fp, "void)");
	else if (self->unspec_parms)
		n += fprintf(fp, ", ...)");
	else
		n += fprintf(fp, ")");
	return n;
}

static void function__print(const struct tag *tag_self, const struct cu *cu,
			    FILE *fp)
{
	struct function *self = tag__function(tag_self);

	ftype__fprintf(&self->proto, cu, function__name(self, cu),
		       function__declared_inline(self), 0, 0, fp);
}

void function__print_stats(const struct tag *tag_self, const struct cu *cu,
			   FILE *fp)
{
	struct function *self = tag__function(tag_self);

	lexblock__print(&self->lexblock, cu, 0, fp);

	fprintf(fp, "/* size: %u", function__size(self));
	if (self->lexblock.nr_variables > 0)
		fprintf(fp, ", variables: %u", self->lexblock.nr_variables);
	if (self->lexblock.nr_labels > 0)
		fprintf(fp, ", goto labels: %u", self->lexblock.nr_labels);
	if (self->lexblock.nr_inline_expansions > 0)
		fprintf(fp, ", inline expansions: %u (%u bytes)",
			self->lexblock.nr_inline_expansions,
			self->lexblock.size_inline_expansions);
	fputs(" */\n", fp);
}

void class__subtract_offsets_from(struct class *self, const struct cu *cu,
				  struct class_member *from,
				  const uint16_t size)
{
	struct class_member *member =
		list_prepare_entry(from, &self->type.members, tag.node);

	list_for_each_entry_continue(member, &self->type.members, tag.node)
		member->offset -= size;

	if (self->padding != 0) {
		struct class_member *last_member =
			list_entry(self->type.members.prev,
				   struct class_member, tag.node);
		const size_t last_member_size =
			class_member__size(last_member, cu);
		const ssize_t new_padding =
			(class__size(self) -
			 (last_member->offset + last_member_size));
		if (new_padding > 0)
			self->padding = new_padding;
		else
			self->padding = 0;
	}
}

static struct class_member *
	class__find_next_hole_of_size(struct class *class,
				      struct class_member *from,
				      const struct cu *cu, size_t size)
{
	struct class_member *member =
		list_prepare_entry(from, &class->type.members, tag.node);
	struct class_member *bitfield_head = NULL;

	list_for_each_entry_continue(member, &class->type.members, tag.node) {
		if (member->bit_size != 0) {
			if (bitfield_head == NULL)
				bitfield_head = member;
		} else
			bitfield_head = NULL;
		if (member->hole != 0 &&
		    class_member__size(member, cu) <= size)
		    return bitfield_head ? : member;
	}

	return NULL;
}

static struct class_member *
	class__find_next_bit_hole_of_size(const struct class *class,
					  struct class_member *from,
					  size_t size)
{
	struct class_member *member =
		list_prepare_entry(from, &class->type.members, tag.node);

	list_for_each_entry_continue(member, &class->type.members, tag.node)
		if (member->bit_hole != 0 &&
		    member->bit_size <= size)
		    return member;

	/*
	 * Now look if the last member is a one member bitfield,
	 * i.e. if we have bit_padding
	 */
	if (class->bit_padding != 0)
		return list_entry(class->type.members.prev,
				  struct class_member, tag.node);

	return NULL;
}

static void class__move_member(struct class *class, struct class_member *dest,
			       struct class_member *from, const struct cu *cu,
			       int from_padding, const int verbose, FILE *fp)
{
	const size_t from_size = class_member__size(from, cu);
	const size_t dest_size = class_member__size(dest, cu);
	struct class_member *tail_from = from;
	struct class_member *from_prev = list_entry(from->tag.node.prev,
						    struct class_member,
						    tag.node);
	uint16_t orig_tail_from_hole = tail_from->hole;
	const uint16_t orig_from_offset = from->offset;
	/*
	 * Align 'from' after 'dest':
	 */
	const uint16_t offset = dest->hole % from_size;
	/*
	 * Set new 'from' offset, after 'dest->offset', aligned
	 */
	const uint16_t new_from_offset = dest->offset + dest_size + offset;

	if (verbose)
		fputs("/* Moving", fp);

	if (from->bit_size != 0) {
		struct class_member *pos =
				list_prepare_entry(from, &class->type.members,
						   tag.node);
		struct class_member *tmp;
		uint8_t orig_tail_from_bit_hole;
		LIST_HEAD(from_list);

		if (verbose)
			fprintf(fp, " bitfield('%s' ... ", from->name);
		list_for_each_entry_safe_from(pos, tmp, &class->type.members,
					      tag.node) {
			/*
			 * Have we reached the end of the bitfield?
			 */
			if (pos->offset != orig_from_offset)
				break;
			tail_from = pos;
			orig_tail_from_hole = tail_from->hole;
			orig_tail_from_bit_hole = tail_from->bit_hole;
			pos->offset = new_from_offset;
			pos->hole = 0;
			pos->bit_hole = 0;
			list_move_tail(&pos->tag.node, &from_list);
		}
		tail_from->bit_hole = orig_tail_from_bit_hole;
		list_splice(&from_list, &dest->tag.node);
		if (verbose)
			fprintf(fp, "'%s')", tail_from->name);
	} else {
		if (verbose)
			fprintf(fp, " '%s'", from->name);
		/*
		 *  Remove 'from' from the list
		 */
		list_del(&from->tag.node);
		/*
		 * Add 'from' after 'dest':
		 */
		__list_add(&from->tag.node, &dest->tag.node,
			   dest->tag.node.next);
		from->offset = new_from_offset;
	}
		
	if (verbose)
		fprintf(fp, " from after '%s' to after '%s' */\n",
		       from_prev->name, dest->name);

	if (from_padding) {
		/*
		 * Check if we're eliminating the need for padding:
		 */
		if (orig_from_offset % cu->addr_size == 0) {
			/*
			 * Good, no need for padding anymore:
			 */
			class->type.size -= from_size + class->padding;
			class->padding = 0;
		} else {
			/*
			 * No, so just add from_size to the padding:
			 */
			class->padding += from_size;
			fprintf(fp, "/* adding %zd bytes from %s to "
				"the padding */\n", from_size, from->name);
		}
	} else {
		/*
		 * See if we are adding a new hole that is bigger than
		 * sizeof(long), this may have problems with explicit alignment
		 * made by the programmer, perhaps we need A switch that allows
		 * us to avoid realignment, just using existing holes but
		 * keeping the existing alignment, anyway the programmer has to
		 * check the resulting rerganization before using it, and for
		 * automatic stuff such as the one that will be used for struct
		 * "views" in tools such as ctracer we are more interested in
		 * packing the subset as tightly as possible.
		 */
		if (orig_tail_from_hole + from_size >= cu->addr_size) {
			class->type.size -= cu->addr_size;
			class__subtract_offsets_from(class, cu, from_prev,
						     cu->addr_size);
		} else {
			/*
			 * Add the hole after 'from' + its size to the member
			 * before it:
			 */
			from_prev->hole += orig_tail_from_hole + from_size;
		}
		/*
		 * Check if we have eliminated a hole
		 */
		if (dest->hole == from_size)
			class->nr_holes--;
	}

	tail_from->hole = dest->hole - (from_size + offset);
	dest->hole = offset;

	if (verbose > 1) {
		class__fprintf(class, cu, NULL, NULL, 0, 0, 26, 23, 1, fp);
		fputc('\n', fp);
	}
}

static void class__move_bit_member(struct class *class, const struct cu *cu,
				   struct class_member *dest,
				   struct class_member *from,
				   const int verbose, FILE *fp)
{
	struct class_member *from_prev = list_entry(from->tag.node.prev,
						    struct class_member,
						    tag.node);
	const uint8_t is_last_member = (from->tag.node.next ==
					&class->type.members);

	if (verbose)
		fprintf(fp, "/* Moving '%s:%u' from after '%s' to "
			"after '%s:%u' */\n",
			from->name, from->bit_size, from_prev->name,
			dest->name, dest->bit_size);
	/*
	 *  Remove 'from' from the list
	 */
	list_del(&from->tag.node);
	/*
	 * Add from after dest:
	 */
	__list_add(&from->tag.node,
		   &dest->tag.node,
		   dest->tag.node.next);

	/* Check if this was the last entry in the bitfield */
	if (from_prev->bit_size == 0) {
		size_t from_size = class_member__size(from, cu);
		/*
		 * Are we shrinking the struct?
		 */
		if (from_size + from->hole >= cu->addr_size) {
			class->type.size -= from_size + from->hole;
			class__subtract_offsets_from(class, cu, from_prev,
						     from_size + from->hole);
		} else if (is_last_member)
			class->padding += from_size;
		else
			from_prev->hole += from_size + from->hole;
		if (is_last_member) {
			/*
			 * Now we don't have bit_padding anymore
			 */
			class->bit_padding = 0;
		} else
			class->nr_bit_holes--;
	} else {
		/*
		 * Add add the holes after from + its size to the member
		 * before it:
		 */
		from_prev->bit_hole += from->bit_hole + from->bit_size;
		from_prev->hole = from->hole;
	}
	from->bit_hole = dest->bit_hole - from->bit_size;
	/*
	 * Tricky, what are the rules for bitfield layouts on this arch?
	 * Assume its IA32
	 */
	from->bit_offset = dest->bit_offset + dest->bit_size;
	/*
	 * Now both have the some offset:
	 */
	from->offset = dest->offset;
	dest->bit_hole = 0;
	from->hole = dest->hole;
	dest->hole = 0;
	if (verbose > 1) {
		class__fprintf(class, cu, NULL, NULL, 0, 0, 26, 23, 1, fp);
		fputc('\n', fp);
	}
}

static void class__demote_bitfield_members(struct class *class,
					   struct class_member *from,
					   struct class_member *to,
					   const struct base_type *old_type,
					   const struct base_type *new_type)
{
	const uint8_t bit_diff = (old_type->size - new_type->size) * 8;
	struct class_member *member =
		list_prepare_entry(from, &class->type.members, tag.node);

	list_for_each_entry_from(member, &class->type.members, tag.node) {
		/*
		 * Assume IA32 bitfield layout
		 */
		member->bit_offset -= bit_diff;
		member->tag.type = new_type->tag.id;
		if (member == to)
			break;
		member->bit_hole = 0;
	}
}

static struct tag *cu__find_base_type_of_size(const struct cu *cu,
					      const size_t size)
{
	const char *type_name;

	switch (size) {
	case sizeof(unsigned char):
		type_name = "unsigned char"; break;
	case sizeof(unsigned short int):
		type_name = "short unsigned int"; break;
	case sizeof(unsigned int):
		type_name = "unsigned int"; break;
	default:
		return NULL;
	}

	return cu__find_base_type_by_name(cu, type_name);
}

static int class__demote_bitfields(struct class *class, const struct cu *cu,
				   const int verbose, FILE *fp)
{
	struct class_member *member;
	struct class_member *bitfield_head;
	const struct tag *old_type_tag, *new_type_tag;
	size_t current_bitfield_size, size, bytes_needed, new_size;
	int some_was_demoted = 0;

	list_for_each_entry(member, &class->type.members, tag.node) {
		/*
		 * Check if we are moving away from a bitfield
		 */
		if (member->bit_size == 0) {
			current_bitfield_size = 0;
			bitfield_head = NULL;
		} else {
			if (bitfield_head == NULL)
				bitfield_head = member;
			current_bitfield_size += member->bit_size;
		}

		/*
		 * Have we got to the end of a bitfield with holes?
		 */
		if (member->bit_hole == 0)
			continue;

		size = class_member__size(member, cu);
	    	bytes_needed = (current_bitfield_size + 7) / 8;
		if (bytes_needed == size)
			continue;

		old_type_tag = cu__find_tag_by_id(cu, member->tag.type);
		new_type_tag = cu__find_base_type_of_size(cu, bytes_needed);
		if (verbose)
			fprintf(fp, "/* Demoting bitfield ('%s' ... '%s') "
				"from '%s' to '%s' */\n",
				bitfield_head->name, member->name,
				tag__base_type(old_type_tag)->name,
				tag__base_type(new_type_tag)->name);

		class__demote_bitfield_members(class,
					       bitfield_head, member,	
					       tag__base_type(old_type_tag),
					       tag__base_type(new_type_tag));
		new_size = class_member__size(member, cu);
		member->hole = size - new_size;
		if (member->hole != 0)
			++class->nr_holes;
		member->bit_hole = new_size * 8 - current_bitfield_size;
		some_was_demoted = 1;
		/*
		 * Have we packed it so that there are no hole now?
		*/
		if (member->bit_hole == 0)
			--class->nr_bit_holes;
		if (verbose > 1) {
			class__fprintf(class, cu, NULL, NULL, 0, 0,
				       26, 23, 1, fp);
			fputc('\n', fp);
		}
	}
	/*
	 * Now look if we have bit padding, i.e. if the the last member
	 * is a bitfield and its the sole member in this bitfield, i.e.
	 * if it wasn't already demoted as part of a bitfield of more than
	 * one member:
	 */
	member = list_entry(class->type.members.prev,
			    struct class_member, tag.node);
	if (class->bit_padding != 0 && bitfield_head == member) {
		size = class_member__size(member, cu);
	    	bytes_needed = (member->bit_size + 7) / 8;
		if (bytes_needed < size) {
			old_type_tag =
				cu__find_tag_by_id(cu, member->tag.type);
			new_type_tag =
				cu__find_base_type_of_size(cu, bytes_needed);

			if (verbose)
				fprintf(fp, "/* Demoting bitfield ('%s') "
					"from '%s' to '%s' */\n",
					member->name,
					tag__base_type(old_type_tag)->name,
					tag__base_type(new_type_tag)->name);
			class__demote_bitfield_members(class,
						       member, member,	
						 tag__base_type(old_type_tag),
						 tag__base_type(new_type_tag));
			new_size = class_member__size(member, cu);
			member->hole = 0;
			/*
			 * Do we need byte padding?
			 */
			if (member->offset + new_size < class__size(class)) {
				class->padding = (class__size(class) -
						  (member->offset + new_size));
				class->bit_padding = 0;
				member->bit_hole = (new_size * 8 -
						    member->bit_size);
			} else {
				class->padding = 0;
				class->bit_padding = (new_size * 8 -
						      member->bit_size);
				member->bit_hole = 0;
			}
			some_was_demoted = 1;
			if (verbose > 1) {
				class__fprintf(class, cu, NULL, NULL, 0, 0,
					       26, 23, 1, fp);
				fputc('\n', fp);
			}
		}
	}

	return some_was_demoted;
}

static void class__reorganize_bitfields(struct class *class,
					const struct cu *cu,
					const int verbose, FILE *fp)
{
	struct class_member *member, *brother;
restart:
	list_for_each_entry(member, &class->type.members, tag.node) {
		/* See if we have a hole after this member */
		if (member->bit_hole != 0) {
			/*
			 * OK, try to find a member that has a bit hole after
			 * it and that has a size that fits the current hole:
			*/
			brother =
			   class__find_next_bit_hole_of_size(class, member,
							     member->bit_hole);
			if (brother != NULL) {
				class__move_bit_member(class, cu,
						       member, brother,
						       verbose, fp);
				goto restart;
			}
		}
	}
}

static void class__fixup_bitfield_types(const struct class *self,
					struct class_member *from,
					struct class_member *to_before,
					Dwarf_Off type)
{
	struct class_member *member =
		list_prepare_entry(from, &self->type.members, tag.node);

	list_for_each_entry_from(member, &self->type.members, tag.node) {
		if (member == to_before)
			break;
		member->tag.type = type;
	}
}

/*
 * Think about this pahole output a bit:
 *
 * [filo examples]$ pahole swiss_cheese cheese
 * / * <11b> /home/acme/git/pahole/examples/swiss_cheese.c:3 * /
 * struct cheese {
 * <SNIP>
 *       int         bitfield1:1;   / * 64 4 * /
 *       int         bitfield2:1;   / * 64 4 * /
 *
 *       / * XXX 14 bits hole, try to pack * /
 *       / * Bitfield WARNING: DWARF size=4, real size=2 * /
 *
 *       short int   d;             / * 66 2 * /
 * <SNIP>
 * 
 * The compiler (gcc 4.1.1 20070105 (Red Hat 4.1.1-51) in the above example),
 * Decided to combine what was declared as an int (4 bytes) bitfield but doesn't
 * uses even one byte with the next field, that is a short int (2 bytes),
 * without demoting the type of the bitfield to short int (2 bytes), so in terms
 * of alignment the real size is 2, not 4, to make things easier for the rest of
 * the reorganizing routines we just do the demotion ourselves, fixing up the
 * sizes.
*/
static void class__fixup_member_types(const struct class *self,
				      const struct cu *cu,
				      const uint8_t verbose, FILE *fp)
{
	struct class_member *pos, *bitfield_head = NULL;
	uint8_t fixup_was_done = 0;

	list_for_each_entry(pos, &self->type.members, tag.node) {
		/*
		 * Is this bitfield member?
		 */
		if (pos->bit_size != 0) {
			/*
			 * The first entry in a bitfield?
			 */
			if (bitfield_head == NULL)
				bitfield_head = pos;
			continue;
		}
		/*
		 * OK, not a bitfield member, but have we just passed
		 * by a bitfield?
		 */
		if (bitfield_head != NULL) {
			const uint16_t real_size = (pos->offset -
						  bitfield_head->offset);
			const size_t size = class_member__size(bitfield_head,
							       cu);
			if (real_size != size) {
				struct tag *new_type_tag =
					cu__find_base_type_of_size(cu,
								   real_size);
				if (new_type_tag == NULL) {
					fprintf(stderr, "pahole: couldn't find"
						" a base_type of %d bytes!\n",
						real_size);
					continue;
				}
				class__fixup_bitfield_types(self,
							    bitfield_head, pos,
							    new_type_tag->id);
				fixup_was_done = 1;
			}
		}
		bitfield_head = NULL;
	}
	if (verbose && fixup_was_done) {
		fprintf(fp, "/* bitfield types were fixed */\n");
		if (verbose > 1) {
			class__fprintf(self, cu, NULL, NULL, 0, 0,
				       26, 23, 1, fp);
			fputc('\n', fp);
		}
	}
}

struct class *class__reorganize(struct class *self, const struct cu *cu,
				const int verbose, FILE *fp)
{
	struct class_member *member, *brother, *last_member;
	size_t last_member_size;

	class__fixup_member_types(self, cu, verbose, fp);
	while (class__demote_bitfields(self, cu, verbose, fp))
		class__reorganize_bitfields(self, cu, verbose, fp);
restart:
	last_member = list_entry(self->type.members.prev,
				 struct class_member, tag.node);
	last_member_size = class_member__size(last_member, cu);

	list_for_each_entry(member, &self->type.members, tag.node) {
		/* See if we have a hole after this member */
		if (member->hole != 0) {
			/*
			 * OK, try to find a member that has a hole after it
			 * and that has a size that fits the current hole:
			*/
			brother = class__find_next_hole_of_size(self, member,
								cu,
								member->hole);
			if (brother != NULL) {
				class__move_member(self, member, brother,
						   cu, 0, verbose, fp);
				goto restart;
			}
			/*
			 * OK, but is there padding? If so the last member
			 * has a hole, if we are not at the last member and
			 * it has a size that is smaller than the current hole
			 * we can move it after the current member, reducing
			 * the padding or eliminating it altogether.
			 */
			if (self->padding > 0 &&
			    member != last_member &&
			    last_member_size <= member->hole) {
				class__move_member(self, member, last_member,
						   cu, 1, verbose, fp);
				goto restart;
			}
		}
	}

	return self;
}

static size_t class__fprintf_cacheline_boundary(uint32_t last_cacheline,
						size_t sum, size_t sum_holes,
						uint8_t *newline,
						uint32_t *cacheline,
						size_t indent, FILE *fp)
{
	const size_t real_sum = sum + sum_holes;
	size_t n = 0;

	*cacheline = real_sum / cacheline_size;

	if (*cacheline > last_cacheline) {
		const uint32_t cacheline_pos = real_sum % cacheline_size;
		const uint32_t cacheline_in_bytes = real_sum - cacheline_pos;

		if (*newline) {
			fputc('\n', fp);
			*newline = 0;
			++n;
		}

		n += fprintf(fp, "%.*s", indent, tabs);

		if (cacheline_pos == 0)
			n += fprintf(fp, "/* --- cacheline %u boundary "
				    "(%u bytes) --- */\n", *cacheline,
				    cacheline_in_bytes);
		else
			n += fprintf(fp, "/* --- cacheline %u boundary "
				     "(%u bytes) was %u bytes ago --- */\n",
				     *cacheline, cacheline_in_bytes,
				     cacheline_pos);
	}
	return n;
}

size_t class__fprintf(const struct class *self, const struct cu *cu,
		      const char *prefix, const char *suffix,
		      uint8_t expand_types, uint8_t indent,
		      size_t type_spacing, size_t name_spacing,
		      int emit_stats, FILE *fp)
{
	const struct type *tself = &self->type;
	size_t last_size = 0, size;
	size_t last_bit_size = 0;
	uint8_t newline = 0;
	uint16_t nr_paddings = 0;
	uint32_t sum = 0;
	uint32_t sum_holes = 0;
	uint32_t sum_paddings = 0;
	uint32_t sum_bit_holes = 0;
	uint32_t last_cacheline = 0;
	int last_offset = -1;
	struct class_member *pos;
	size_t n = fprintf(fp, "%s%sstruct%s%s {\n",
			   prefix ?: "", prefix ? " " : "",
			   tself->name ? " " : "", tself->name ?: "");

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;

	list_for_each_entry(pos, &tself->members, tag.node) {
		struct tag *type;
		const ssize_t cc_last_size = pos->offset - last_offset;

		n += class__fprintf_cacheline_boundary(last_cacheline, sum,
						       sum_holes, &newline,
						       &last_cacheline,
						       indent + 1, fp);
		if (last_offset != -1) {
			if (cc_last_size > 0 &&
			    (size_t)cc_last_size < last_size) {
				if (!newline++) {
					fputc('\n', fp);
					++n;
				}
				n += fprintf(fp, "%.*s/* Bitfield WARNING: "
					     "DWARF size=%u, real size=%u "
					     "*/\n", indent + 1, tabs,
					     last_size, cc_last_size);
				sum -= last_size - cc_last_size;
				/*
				 * Confusing huh? think about this case then,
				 * should clarify:
				 */
#if 0
			struct foo {
				int   a:1;   /*     0     4 */

				/* XXX 7 bits hole, try to pack */
				/* WARNING: DWARF size: 4, compiler size: 1 */

				char  b;     /*     1     1 */
			}; /* size: 4, cachelines: 1 */
			   /* bit holes: 1, sum bit holes: 7 bits */
			   /* padding: 2 */
			   /* last cacheline: 4 bytes */
#endif
				/*
				 * Yeah, this could somehow be simplified,
				 * send me a patch 8-)
				 */
			}
		}

		if (newline) {
			fputc('\n', fp);
			newline = 0;
			++n;
		}

		type = cu__find_tag_by_id(cu, pos->tag.type);
		if (type == NULL) {
			tag__type_not_found(&pos->tag);
			n += fprintf(fp, "%.*s>>>ERROR: type for %s not "
				     "found!\n", indent + 1, tabs, pos->name);
			continue;
		}

		size = tag__size(type, cu);
		n += fprintf(fp, "%.*s", indent + 1, tabs);
		n += struct_member__fprintf(pos, type, cu, expand_types,
					    indent + 1, type_spacing,
					    name_spacing, fp);

		if (type->tag == DW_TAG_structure_type) {
			const uint16_t padding = tag__class(type)->padding;
			if (padding > 0) {
				++nr_paddings;
				sum_paddings += padding; 
				if (!newline++) {
					fputc('\n', fp);
					++n;
				}

				n += fprintf(fp, "\n%.*s/* XXX last struct has"
					     " %d byte%s of padding */",
					     indent + 1, tabs, padding,
					     padding != 1 ? "s" : "");
			}
		}

		if (pos->bit_hole != 0) {
			if (!newline++) {
				fputc('\n', fp);
				++n;
			}
			n += fprintf(fp, "\n%.*s/* XXX %d bit%s hole, try to "
				     "pack */", indent + 1, tabs,
				     pos->bit_hole,
				     pos->bit_hole != 1 ? "s" : "");
			sum_bit_holes += pos->bit_hole;
		}

		if (pos->hole > 0) {
			if (!newline++) {
				fputc('\n', fp);
				++n;
			}
			n += fprintf(fp, "\n%.*s/* XXX %d byte%s hole, try to "
				     "pack */", indent + 1, tabs,
				     pos->hole, pos->hole != 1 ? "s" : "");
			sum_holes += pos->hole;
		}

		fputc('\n', fp);
		++n;
		/*
		 * check for bitfields, accounting for only the biggest
		 * of the byte_size in the fields in each bitfield set.
		 */
		if (last_offset != pos->offset ||
		    pos->bit_size == 0 || last_bit_size == 0) {
			last_size = size;
			sum += last_size;
		} else if (size > last_size) {
			sum += size - last_size;
			last_size = size;
		}

		last_offset = pos->offset;
		last_bit_size = pos->bit_size;
	}

	n += class__fprintf_cacheline_boundary(last_cacheline, sum,
					       sum_holes, &newline,
					       &last_cacheline, indent + 1, fp);
	n += fprintf(fp, "%.*s}%s%s", indent, tabs,
		     suffix ? " ": "", suffix ?: "");
	if (!emit_stats)
		goto out;

	n += fprintf(fp, "; /* size: %u, cachelines: %u */\n", tself->size,
		     tag__nr_cachelines(class__tag(self), cu));
	if (sum_holes > 0)
		n += fprintf(fp, "%.*s   /* sum members: %u, "
			     "holes: %d, sum holes: %u */\n", indent, tabs,
			     sum, self->nr_holes, sum_holes);
	if (sum_bit_holes > 0)
		n += fprintf(fp, "%.*s   /* bit holes: %d, sum "
			     "bit holes: %u bits */\n", indent, tabs,
			     self->nr_bit_holes, sum_bit_holes);
	if (self->padding > 0)
		n += fprintf(fp, "%.*s   /* padding: %u */\n", indent, tabs,
			     self->padding);
	if (nr_paddings > 0)
		n += fprintf(fp, "%.*s   /* paddings: %u, "
			     "sum paddings: %u */\n",
			     indent, tabs, nr_paddings, sum_paddings);
	if (self->bit_padding > 0)
		n += fprintf(fp, "%.*s   /* bit_padding: %u bits */\n",
			     indent, tabs, self->bit_padding);
	last_cacheline = tself->size % cacheline_size;
	if (last_cacheline != 0)
		n += fprintf(fp, "%.*s   /* last cacheline: %u bytes */\n",
			     indent, tabs, last_cacheline);

	if (sum + sum_holes != tself->size - self->padding)
		n += fprintf(fp, "\n%.*s/* BRAIN FART ALERT! %u != "
			     "%u + %u(holes), diff = %u */\n\n", indent, tabs,
			     tself->size, sum, sum_holes,
			     tself->size - (sum + sum_holes));
out:
	return n;
}

static size_t variable__fprintf(const struct tag *tag, const struct cu *cu,
				uint8_t expand_types, FILE *fp)
{
	const struct variable *var = tag__variable(tag);
	const char *name = variable__name(var, cu);
	size_t n = 0;

	if (name != NULL) {
		struct tag *type = variable__type(var, cu);
		if (type != NULL) {
			const char *varprefix = variable__prefix(var);

			if (varprefix != NULL)
				n += fprintf(fp, "%s", varprefix);
			n += type__fprintf(type, name, cu, expand_types,
					   0, 0, 0, fp);
		}
	}
	return n;
}

void tag__fprintf(const struct tag *self, const struct cu *cu,
		  const char *prefix, const char *suffix,
		  uint8_t expand_types, FILE *fp)
{
	tag__print_decl_info(self, fp);

	switch (self->tag) {
	case DW_TAG_enumeration_type:
		enumeration__fprintf(self, suffix, 0, fp);
		break;
	case DW_TAG_typedef:
		typedef__print(self, cu, fp);
		break;
	case DW_TAG_structure_type:
		class__fprintf(tag__class(self), cu, prefix, suffix,
			       expand_types, 0, 26, expand_types ? 55 : 23, 1,
			       fp);
		break;
	case DW_TAG_subprogram:
		function__print(self, cu, fp);
		break;
	case DW_TAG_union_type:
		union__fprintf(tag__type(self), cu, prefix, suffix,
			       expand_types, 0,
			       26, expand_types ? 55 : 21, fp);
		break;
	case DW_TAG_variable:
		variable__fprintf(self, cu, expand_types, fp);
		break;
	default:
		fprintf(fp, "%s: %s tag not supported!\n", __func__,
			dwarf_tag_name(self->tag));
		break;
	}
}

int cu__for_each_tag(struct cu *self,
		     int (*iterator)(struct tag *tag, struct cu *cu,
			     	     void *cookie),
		     void *cookie,
		     struct tag *(*filter)(struct tag *tag, struct cu *cu,
			     		   void *cookie))
{
	struct tag *pos;

	list_for_each_entry(pos, &self->tags, node) {
		struct tag *tag = pos;
		if (filter != NULL) {
			tag = filter(pos, self, cookie);
			if (tag == NULL)
				continue;
		}
		if (iterator(tag, self, cookie))
			return 1;
	}
	return 0;
}

void cus__for_each_cu(struct cus *self,
		      int (*iterator)(struct cu *cu, void *cookie),
		      void *cookie,
		      struct cu *(*filter)(struct cu *cu))
{
	struct cu *pos;

	list_for_each_entry(pos, &self->cus, node) {
		struct cu *cu = pos;
		if (filter != NULL) {
			cu = filter(pos);
			if (cu == NULL)
				continue;
		}
		if (iterator(cu, cookie))
			break;
	}
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
		fn, dwarf_tag_name(dwarf_tag(die)), dwarf_dieoffset(die));
}

#define cu__tag_not_handled(die) __cu__tag_not_handled(die, __FUNCTION__)

static void __die__process_tag(Dwarf_Die *die, struct cu *cu, const char *fn);

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

	return &class->type.tag;
}

static struct tag *die__create_new_union(Dwarf_Die *die, struct cu *cu)
{
	Dwarf_Die child;
	struct type *utype = type__new(die);

	if (utype == NULL)
		oom("type__new");

	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		die__process_class(&child, utype, cu);

	return &utype->tag;
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

	return &tdef->tag;
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

static struct tag *die__create_new_enumeration(Dwarf_Die *die)
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
	} while (dwarf_siblingof(die, die) == 0);

	return &enumeration->tag;
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
		}
			continue;
		default:
			die__process_tag(die, cu);
			continue;
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
		default:
			die__process_tag(die, cu);
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

static void __die__process_tag(Dwarf_Die *die, struct cu *cu, const char *fn)
{
	struct tag *new_tag = NULL;

	switch (dwarf_tag(die)) {
	case DW_TAG_array_type:
		new_tag = die__create_new_array(die);		break;
	case DW_TAG_base_type:
		new_tag = die__create_new_base_type(die);	break;
	case DW_TAG_const_type:
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type:
	case DW_TAG_volatile_type:
		new_tag = die__create_new_tag(die);		break;
	case DW_TAG_enumeration_type:
		new_tag = die__create_new_enumeration(die);	break;
	case DW_TAG_structure_type:
		new_tag = die__create_new_class(die, cu);	break;
	case DW_TAG_subprogram:
		new_tag = die__create_new_function(die, cu);	break;
	case DW_TAG_subroutine_type:
		new_tag = die__create_new_subroutine_type(die);	break;
	case DW_TAG_typedef:
		new_tag = die__create_new_typedef(die);		break;
	case DW_TAG_union_type:
		new_tag = die__create_new_union(die, cu);	break;
	case DW_TAG_variable:
		new_tag = die__create_new_variable(die);	break;
	default:
		__cu__tag_not_handled(die, fn);			return;
	}

	if (new_tag != NULL)
		cu__add_tag(cu, new_tag);
}

static void die__process_unit(Dwarf_Die *die, struct cu *cu)
{
	do {
		die__process_tag(die, cu);
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

int cus__load_dir(struct cus *self, const char *dirname,
		  const char *filename_mask, const int recursive)
{
	struct dirent *entry;
	int err = -1;
	DIR *dir = opendir(dirname);

	if (dir == NULL)
		goto out;

	err = 0;
	while ((entry = readdir(dir)) != NULL) {
		char pathname[PATH_MAX];
		struct stat st;

		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
		    continue;

		snprintf(pathname, sizeof(pathname), "%s/%s",
			 dirname, entry->d_name);

		err = lstat(pathname, &st);
		if (err != 0)
			break;

		if (S_ISDIR(st.st_mode)) {
			if (!recursive)
				continue;

			err = cus__load_dir(self, pathname,
					    filename_mask, recursive);
			if (err != 0)
				break;
		} else if (fnmatch(filename_mask, entry->d_name, 0) == 0) {
			err = cus__load(self, pathname);
			if (err != 0)
				break;
		}
	}

	if (err == -1)
		puts(dirname);
	closedir(dir);
out:
	return err;
}

int cus__load(struct cus *self, const char *filename)
{
	Dwarf_Off offset, last_offset, abbrev_offset;
	uint8_t addr_size, offset_size;
	size_t hdr_size;
	Dwarf *dwarf;
	int err = -1;
	int fd = open(filename, O_RDONLY);	

	if (fd < 0)
		goto out;

	dwarf = dwarf_begin(fd, DWARF_C_READ);
	if (dwarf == NULL)
		goto out_close;

	offset = last_offset = 0;
	while (dwarf_nextcu(dwarf, offset, &offset, &hdr_size,
			    &abbrev_offset, &addr_size, &offset_size) == 0) {
		Dwarf_Die die;

		if (dwarf_offdie(dwarf, last_offset + hdr_size, &die) != NULL) {
			struct cu *cu = cu__new(attr_string(&die, DW_AT_name),
						addr_size);
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

struct cus *cus__new(struct list_head *definitions,
		     struct list_head *fwd_decls)
{
	struct cus *self = malloc(sizeof(*self));

	if (self != NULL) {
		INIT_LIST_HEAD(&self->cus);
		INIT_LIST_HEAD(&self->priv_definitions);
		INIT_LIST_HEAD(&self->priv_fwd_decls);
		self->definitions = definitions ?: &self->priv_definitions;
		self->fwd_decls = fwd_decls ?: &self->priv_fwd_decls;
	}

	return self;
}

static int cus__emit_enumeration_definitions(struct cus *self, struct tag *tag,
					     const char *suffix, FILE *fp)
{
	struct type *etype = tag__type(tag);

	/* Have we already emitted this in this CU? */
	if (etype->definition_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (cus__find_definition(self, etype->name) != NULL) {
		/*
		 * Yes, so lets mark it visited on this CU too,
		 * to speed up the lookup.
		 */
		etype->definition_emitted = 1;
		return 0;
	}

	enumeration__fprintf(tag, suffix, 0, fp);
	fputs(";", fp);
	cus__add_definition(self, etype);
	return 1;
}

static int cus__emit_tag_definitions(struct cus *self, struct cu *cu,
				     struct tag *tag, FILE *fp);

static int cus__emit_typedef_definitions(struct cus *self, struct cu *cu,
					 struct tag *tdef, FILE *fp)
{
	struct type *def = tag__type(tdef);
	struct tag *type, *ptr_type;
	int is_pointer = 0;

	/* Have we already emitted this in this CU? */
	if (def->definition_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (cus__find_definition(self, def->name) != NULL) {
		/*
		 * Yes, so lets mark it visited on this CU too,
		 * to speed up the lookup.
		 */
		def->definition_emitted = 1;
		return 0;
	}

	type = cu__find_tag_by_id(cu, tdef->type);

	switch (type->tag) {
	case DW_TAG_array_type:
		cus__emit_tag_definitions(self, cu, type, fp);
		break;
	case DW_TAG_typedef:
		cus__emit_typedef_definitions(self, cu, type, fp);
		break;
	case DW_TAG_pointer_type:
		ptr_type = cu__find_tag_by_id(cu, type->type);
		if (ptr_type->tag != DW_TAG_subroutine_type)
			break;
		type = ptr_type;
		is_pointer = 1;
		/* Fall thru */
	case DW_TAG_subroutine_type:
		cus__emit_ftype_definitions(self, cu, tag__ftype(type), fp);
		break;
	case DW_TAG_enumeration_type: {
		const struct type *ctype = tag__type(type);

		tag__print_decl_info(type, fp);
		if (ctype->name == NULL) {
			fputs("typedef ", fp);
			cus__emit_enumeration_definitions(self, type,
							  def->name, fp);
			goto out;
		} else 
			cus__emit_enumeration_definitions(self, type,
							  NULL, fp);
	}
		break;
	case DW_TAG_structure_type:
	case DW_TAG_union_type: {
		const struct type *ctype = tag__type(type);

		if (ctype->name == NULL) {
			if (cus__emit_type_definitions(self, cu, type, fp))
				type__emit(type, cu, "typedef", def->name, fp);
			goto out;
		} else if (cus__emit_type_definitions(self, cu, type, fp))
			type__emit(type, cu, NULL, NULL, fp);
	}
	}

	/*
	 * Recheck if the typedef was emitted, as there are cases, like
	 * wait_queue_t in the Linux kernel, that is against struct
	 * __wait_queue, that has a wait_queue_func_t member, a function
	 * typedef that has as one of its parameters a... wait_queue_t, that
	 * will thus be emitted before the function typedef, making a no go to
	 * redefine the typedef after struct __wait_queue.
	 */
	if (!def->definition_emitted) {
		typedef__print(tdef, cu, fp);
		fputs(";", fp);
	}
out:
	cus__add_definition(self, def);
	return 1;
}

int cus__emit_fwd_decl(struct cus *self, struct type *ctype, FILE *fp)
{
	/* Have we already emitted this in this CU? */
	if (ctype->fwd_decl_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (cus__find_fwd_decl(self, ctype->name) != NULL) {
		/*
		 * Yes, so lets mark it visited on this CU too,
		 * to speed up the lookup.
		 */
		ctype->fwd_decl_emitted = 1;
		return 0;
	}

	fprintf(fp, "%s %s;\n",
		ctype->tag.tag == DW_TAG_union_type ? "union" : "struct",
		ctype->name);
	cus__add_fwd_decl(self, ctype);
	return 1;
}

static int cus__emit_tag_definitions(struct cus *self, struct cu *cu,
				     struct tag *tag, FILE *fp)
{
	struct tag *type = cu__find_tag_by_id(cu, tag->type);
	int pointer = 0;

	if (type == NULL)
		return 0;
next_indirection:
	switch (type->tag) {
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type:
		pointer = 1;
		/* Fall thru */
	case DW_TAG_array_type:
	case DW_TAG_const_type:
	case DW_TAG_volatile_type:
		type = cu__find_tag_by_id(cu, type->type);
		if (type == NULL)
			return 0;
		goto next_indirection;
	case DW_TAG_typedef:
		return cus__emit_typedef_definitions(self, cu, type, fp);
	case DW_TAG_enumeration_type:
		if (tag__type(type)->name != NULL) {
			tag__print_decl_info(type, fp);
			return cus__emit_enumeration_definitions(self, type,
								 NULL, fp);
		}
		break;
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
		if (pointer)
			return cus__emit_fwd_decl(self, tag__type(type), fp);
		if (cus__emit_type_definitions(self, cu, type, fp))
			type__emit(type, cu, NULL, NULL, fp);
		return 1;
	case DW_TAG_subroutine_type:
		return cus__emit_ftype_definitions(self, cu,
						   tag__ftype(type), fp);
	}

	return 0;
}

int cus__emit_ftype_definitions(struct cus *self, struct cu *cu,
				struct ftype *ftype, FILE *fp)
{
	struct parameter *pos;
	/* First check the function return type */
	int printed = cus__emit_tag_definitions(self, cu, &ftype->tag, fp);

	/* Then its parameters */
	list_for_each_entry(pos, &ftype->parms, tag.node)
		if (cus__emit_tag_definitions(self, cu, &pos->tag, fp))
			printed = 1;

	if (printed)
		fputc('\n', fp);
	return printed;
}

int cus__emit_type_definitions(struct cus *self, struct cu *cu,
			       struct tag *tag, FILE *fp)
{
	struct type *ctype = tag__type(tag);
	struct class_member *pos;
	int printed = 0;

	if (ctype->definition_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (cus__find_definition(self, ctype->name) != NULL) {
		ctype->definition_emitted = 1;
		return 0;
	}

	cus__add_definition(self, ctype);

	list_for_each_entry(pos, &ctype->members, tag.node)
		if (cus__emit_tag_definitions(self, cu, &pos->tag, fp))
			printed = 1;

	if (printed)
		fputc('\n', fp);
	return 1;
}

void type__emit(struct tag *tag_self, struct cu *cu,
		const char *prefix, const char *suffix, FILE *fp)
{
	struct type *ctype = tag__type(tag_self);

	if (tag_self->tag == DW_TAG_structure_type)
		class__find_holes(tag__class(tag_self), cu);

	if (ctype->name != NULL || suffix != NULL || prefix != NULL) {
		tag__fprintf(tag_self, cu, prefix, suffix, 0, fp);

		if (tag_self->tag != DW_TAG_structure_type)
			fputc(';', fp);
		fputc('\n', fp);
	}
}

void dwarves__init(size_t user_cacheline_size)
{
	if (user_cacheline_size == 0) {
		long sys_cacheline_size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);

		if (sys_cacheline_size > 0)
			cacheline_size = sys_cacheline_size;
		else
			cacheline_size = 64; /* Fall back to a sane value */
	} else
		cacheline_size = user_cacheline_size;
}
