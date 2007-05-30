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

static const struct conf_fprintf conf_fprintf__defaults = {
	.name_spacing = 23,
	.type_spacing = 26,
	.emit_stats   = 1,
};

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

static uint64_t dwarf_expr(const uint8_t *expr, uint32_t len __unused)
{
	/* Common case: offset from start of the class */
	if (expr[0] == DW_OP_plus_uconst) {
		uint64_t result;
		++expr;
		get_uleb128(result, expr);
		return result;
	}

	fprintf(stderr, "%s: unhandled %#x DW_OP_ operation\n",
		__func__, *expr);
	return UINT64_MAX;
}

static Dwarf_Off attr_offset(Dwarf_Die *die)
{
	Dwarf_Attribute attr;
	Dwarf_Block block;

	if (dwarf_attr(die, DW_AT_data_member_location, &attr) != NULL &&
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
}

static struct tag *tag__new(Dwarf_Die *die)
{
	struct tag *self = malloc(sizeof(*self));

	if (self != NULL)
		tag__init(self, die);

	return self;
}

static const char *tag__accessibility(const struct tag *self)
{
	int a;

	switch (self->tag) {
	case DW_TAG_inheritance:
	case DW_TAG_member:
		a = tag__class_member(self)->accessibility;
		break;
	case DW_TAG_subprogram:
		a = tag__function(self)->accessibility;
		break;
	default:
		return NULL;
	}

	switch (a) {
	case DW_ACCESS_public:	  return "public";
	case DW_ACCESS_private:	  return "private";
	case DW_ACCESS_protected: return "protected";
	}

	return NULL;
}

size_t tag__nr_cachelines(const struct tag *self, const struct cu *cu)
{
	return (tag__size(self, cu) + cacheline_size - 1) / cacheline_size;
}

static void __tag__id_not_found(const struct tag *self,
				unsigned long long id, const char *fn)
{
	fprintf(stderr, "%s: %#llx id not found for %s (id=%#llx)\n",
		fn, (unsigned long long)id, dwarf_tag_name(self->tag), self->id);
	fflush(stderr);
}

#define tag__id_not_found(self, id) __tag__id_not_found(self, id, __func__)

#define tag__type_not_found(self) __tag__id_not_found(self, (self)->type, __func__)

size_t tag__fprintf_decl_info(const struct tag *self, FILE *fp)
{
	return fprintf(fp, "/* <%llx> %s:%u */\n",
		       (unsigned long long)self->id,
		       self->decl_file, self->decl_line);
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
				  int type_spacing, FILE *fp)
{
	struct array_type *self = tag__array_type(tag_self);
	char tbf[128];
	int i;
	size_t printed = fprintf(fp, "%-*s %s", type_spacing,
				 tag__name(tag_self, cu, tbf, sizeof(tbf)),
				 name);
	for (i = 0; i < self->dimensions; ++i)
		printed += fprintf(fp, "[%u]", self->nr_entries[i]);
	return printed;
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
	self->nr_members	 = 0;
}

static struct type *type__new(Dwarf_Die *die)
{
	struct type *self = malloc(sizeof(*self));

	if (self != NULL)
		type__init(self, die);

	return self;
}

const char *type__name(struct type *self, const struct cu *cu)
{
	/* Check if the tag doesn't comes with a DW_AT_name attribute... */
	if (self->namespace.name == NULL &&
	    /* No? So it can have a DW_TAG_specification... */
	    self->specification != 0 &&
	    cu != NULL) {
		struct tag *tag = cu__find_tag_by_id(cu, self->specification);
		if (tag == NULL) {
			tag__id_not_found(&self->namespace.tag, self->specification);
			return NULL;
		}
		/* ... and now we cache the result in this tag ->name field */
		self->namespace.name = tag__type(tag)->namespace.name;
	}

	return self->namespace.name;
}

size_t typedef__fprintf(const struct tag *tag_self, const struct cu *cu,
			FILE *fp)
{
	struct type *self = tag__type(tag_self);
	const struct tag *type;
	const struct tag *ptr_type;
	char bf[512];
	int is_pointer = 0;
	size_t printed;

	/*
	 * Check for void (humm, perhaps we should have a fake void tag instance
	 * to avoid all these checks?
	 */
	if (tag_self->type == 0)
		return fprintf(fp, "typedef void %s", type__name(self, cu));

	type = cu__find_tag_by_id(cu, tag_self->type);
	if (type == NULL) {
		tag__type_not_found(tag_self);
		return 0;
	}

	switch (type->tag) {
	case DW_TAG_array_type:
		printed = fprintf(fp, "typedef ");
		return printed + array_type__fprintf(type, cu,
						     type__name(self, cu),
						     0, fp);
	case DW_TAG_pointer_type:
		if (type->type == 0) /* void pointer */
			break;
		ptr_type = cu__find_tag_by_id(cu, type->type);
		if (ptr_type == NULL) {
			tag__type_not_found(type);
			return 0;
		}
		if (ptr_type->tag != DW_TAG_subroutine_type)
			break;
		type = ptr_type;
		is_pointer = 1;
		/* Fall thru */
	case DW_TAG_subroutine_type:
		printed = fprintf(fp, "typedef ");
		return printed + ftype__fprintf(tag__ftype(type), cu,
						type__name(self, cu),
						0, is_pointer, 0,
						fp);
	case DW_TAG_structure_type: {
		struct type *ctype = tag__type(type);

		if (type__name(ctype, cu) != NULL)
			return fprintf(fp, "typedef struct %s %s",
				       type__name(ctype, cu),
				       type__name(self, cu));
	}
	}

	return fprintf(fp, "typedef %s %s",
		       tag__name(type, cu, bf, sizeof(bf)),
		       		 type__name(self, cu));
}

static size_t imported_declaration__fprintf(const struct tag *self,
					    const struct cu *cu, FILE *fp)
{
	char bf[512];
	const struct tag *decl = cu__find_tag_by_id(cu, self->type);

	return fprintf(fp, "using ::%s", tag__name(decl, cu, bf, sizeof(bf)));
}

static size_t imported_module__fprintf(const struct tag *self,
				       const struct cu *cu, FILE *fp)
{
	const struct tag *module = cu__find_tag_by_id(cu, self->type);
	const char *name = "<IMPORTED MODULE ERROR!>";

	if (module->tag == DW_TAG_namespace)
		name = tag__namespace(module)->name;

	return fprintf(fp, "using namespace %s", name);
}

size_t enumeration__fprintf(const struct tag *tag_self, const struct cu *cu,
			    const struct conf_fprintf *conf, FILE *fp)
{
	struct type *self = tag__type(tag_self);
	struct enumerator *pos;
	size_t printed = fprintf(fp, "enum%s%s {\n",
				 type__name(self, cu) ? " " : "",
				 type__name(self, cu) ?: "");
	size_t indent = conf->indent;

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;

	type__for_each_enumerator(self, pos)
		printed += fprintf(fp, "%.*s\t%s = %u,\n", indent, tabs,
				   pos->name, pos->value);

	return printed + fprintf(fp, "%.*s}%s%s", indent, tabs,
				 conf->suffix ? " " : "", conf->suffix ?: "");
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

static struct tag *namespace__find_tag_by_id(const struct namespace *self,
					     const Dwarf_Off id)
{
	struct tag *pos;

	if (id == 0)
		return NULL;

	namespace__for_each_tag(self, pos) {
		if (pos->id == id)
			return pos;

		/* Look for nested namespaces */
		if (pos->tag == DW_TAG_structure_type ||
		    pos->tag == DW_TAG_union_type ||
		    pos->tag == DW_TAG_namespace) {
			 struct tag *tag =
			    namespace__find_tag_by_id(tag__namespace(pos), id);
			if (tag != NULL)
				return tag;
		}
	}

	return NULL;
}

struct tag *cu__find_tag_by_id(const struct cu *self, const Dwarf_Off id)
{
	struct tag *pos;

	if (id == 0)
		return NULL;

	list_for_each_entry(pos, &self->tags, node) {
		if (pos->id == id)
			return pos;

		/* Look for nested namespaces */
		if (pos->tag == DW_TAG_structure_type ||
		    pos->tag == DW_TAG_union_type ||
		    pos->tag == DW_TAG_namespace) {
			 struct tag *tag =
			    namespace__find_tag_by_id(tag__namespace(pos), id);
			if (tag != NULL)
				return tag;
		}
	}

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
		    type__name(type, self) != NULL &&
		    strcmp(type__name(type, self), name) == 0)
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

struct tag *cus__find_tag_by_id(const struct cus *self,
				struct cu **cu, const Dwarf_Off id)
{
	struct cu *pos;

	list_for_each_entry(pos, &self->cus, node) {
		struct tag *tag = cu__find_tag_by_id(pos, id);

		if (tag != NULL) {
			if (cu != NULL)
				*cu = pos;
			return tag;
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

static struct tag *list__find_tag_by_id(const struct list_head *self,
					const Dwarf_Off id)
{
	struct tag *pos, *tag;

	list_for_each_entry(pos, self, node) {
		if (pos->id == id)
			return pos;

		switch (pos->tag) {
		case DW_TAG_namespace:
		case DW_TAG_structure_type:
		case DW_TAG_union_type:
			tag = list__find_tag_by_id(&tag__namespace(pos)->tags, id);
			break;
		case DW_TAG_subprogram:
			tag = list__find_tag_by_id(&tag__ftype(pos)->parms, id);
			if (tag == NULL)
				tag = list__find_tag_by_id(&tag__function(pos)->lexblock.tags, id);
			break;
		default:
			continue;
		}

		if (tag != NULL)
			return tag;
	}

	return NULL;
}

static struct tag *cu__find_parameter_by_id(const struct cu *self,
					    const Dwarf_Off id)
{
	return list__find_tag_by_id(&self->tags, id);
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
			 type__name(tag__type(self), cu) ?: "");
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
		self->accessibility = attr_numeric(die, DW_AT_accessibility);
		self->virtuality    = attr_numeric(die, DW_AT_virtuality);
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
		struct tag *alias =
			cu__find_parameter_by_id(cu, self->abstract_origin);
		if (alias == NULL) {
			tag__id_not_found(&self->tag, self->abstract_origin);
			return NULL;
		}
		/* Now cache the result in this tag ->name field */
		self->name = tag__parameter(alias)->name;
	}

	return self->name;
}

Dwarf_Off parameter__type(struct parameter *self, const struct cu *cu)
{
	/* Check if the tag doesn't comes with a DW_AT_type attribute... */
	if (self->tag.type == 0 && self->abstract_origin != 0) {
		/* No? Does it have a DW_AT_abstract_origin? */
		struct tag *alias =
			cu__find_parameter_by_id(cu, self->abstract_origin);
		if (alias == NULL) {
			tag__id_not_found(&self->tag, self->abstract_origin);
			return 0;
		}
		/* Now cache the result in this tag ->name and type fields */
		self->name = tag__parameter(alias)->name;
		self->tag.type = tag__parameter(alias)->tag.type;
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

static size_t union__fprintf(struct type *self, const struct cu *cu,
			     const struct conf_fprintf *conf, FILE *fp);

static size_t type__fprintf(struct tag *type, const struct cu *cu,
			    const char *name, const struct conf_fprintf *conf,
			    FILE *fp)
{
	char tbf[128];
	struct type *ctype;
	struct conf_fprintf tconf;
	size_t printed = 0;

	if (type == NULL)
		goto out_type_not_found;

	if (conf->expand_types) {
		int typedef_expanded = 0;

		while (type->tag == DW_TAG_typedef) {
			ctype = tag__type(type);
			if (typedef_expanded)
				printed += fprintf(fp, " -> %s",
						   type__name(ctype, cu));
			else {
				printed += fprintf(fp, "/* typedef %s",
						   type__name(ctype, cu));
				typedef_expanded = 1;
			}
			type = cu__find_tag_by_id(cu, type->type);
			if (type == NULL)
				goto out_type_not_found;
		}
		if (typedef_expanded)
			printed += fprintf(fp, " */ ");
	}

	if (type->tag == DW_TAG_structure_type ||
	    type->tag == DW_TAG_union_type ||
	    type->tag == DW_TAG_enumeration_type) {
		tconf = *conf;
		tconf.type_spacing -= 8;
		tconf.prefix	   = NULL;
		tconf.suffix	   = name;
		tconf.emit_stats   = 0;
	}

	switch (type->tag) {
	case DW_TAG_pointer_type:
		if (type->type != 0) {
			struct tag *ptype = cu__find_tag_by_id(cu, type->type);
			if (ptype == NULL)
				goto out_type_not_found;
			if (ptype->tag == DW_TAG_subroutine_type)
				return (printed +
					ftype__fprintf(tag__ftype(ptype), cu,
						      name, 0, 1, conf->type_spacing,
						      fp));
		}
		break;
	case DW_TAG_subroutine_type:
		return printed + ftype__fprintf(tag__ftype(type), cu, name,
						0, 0, conf->type_spacing, fp);
	case DW_TAG_array_type:
		return printed + array_type__fprintf(type, cu, name,
						     conf->type_spacing, fp);
	case DW_TAG_structure_type:
		ctype = tag__type(type);

		if (type__name(ctype, cu) != NULL && !conf->expand_types)
			return fprintf(fp, "struct %-*s %s",
				       conf->type_spacing - 7,
				       type__name(ctype, cu), name);
		return printed + class__fprintf(tag__class(type), cu, &tconf, fp);
	case DW_TAG_union_type:
		ctype = tag__type(type);

		if (type__name(ctype, cu) != NULL && !conf->expand_types)
			return fprintf(fp, "union %-*s %s",
				       conf->type_spacing - 6,
				       type__name(ctype, cu), name);
		return printed + union__fprintf(ctype, cu, &tconf, fp);
	case DW_TAG_enumeration_type:
		ctype = tag__type(type);

		if (type__name(ctype, cu) != NULL)
			return printed + fprintf(fp, "enum %-*s %s",
						 conf->type_spacing - 5,
						 type__name(ctype, cu), name);
		return printed + enumeration__fprintf(type, cu, &tconf, fp);
	}

	return printed + fprintf(fp, "%-*s %s", conf->type_spacing,
				 tag__name(type, cu, tbf, sizeof(tbf)), name);
out_type_not_found:
	return fprintf(fp, "%-*s %s", conf->type_spacing, "<ERROR>", name);
}

static size_t struct_member__fprintf(struct class_member *self,
				     struct tag *type, const struct cu *cu,
				     const struct conf_fprintf *conf, FILE *fp)
{
	int spacing;
	const int size = tag__size(type, cu);
	struct conf_fprintf sconf = *conf;
	uint32_t offset = self->offset;
	size_t printed = 0;
	const char *name = self->name;
	
	if (!sconf.rel_offset) {
		sconf.base_offset += self->offset;
		offset = sconf.base_offset;
	}

	if (self->tag.tag == DW_TAG_inheritance) {
		name = "<ancestor>";
		printed += fprintf(fp, "/* ");
	}

	printed += type__fprintf(type, cu, name, &sconf, fp);

	if (self->bit_size != 0)
		printed += fprintf(fp, ":%u;", self->bit_size);
	else {
		fputc(';', fp);
		++printed;
	}

	if ((type->tag == DW_TAG_union_type ||
	     type->tag == DW_TAG_enumeration_type ||
	     type->tag == DW_TAG_structure_type) &&
		/* Look if is a type defined inline */
	    type__name(tag__type(type), cu) == NULL) {
		/* Check if this is a anonymous union */
		const int slen = self->name != NULL ?
					(int)strlen(self->name) : -1;
		return printed + fprintf(fp, "%*s/* %5u %5u */",
					 (sconf.type_spacing +
					  sconf.name_spacing - slen - 3),
					 " ", offset, size);
	}
	spacing = sconf.type_spacing + sconf.name_spacing - printed;
	if (self->tag.tag == DW_TAG_inheritance) {
		const size_t p = fprintf(fp, " */");
		printed += p;
		spacing -= p;
	}
	return printed + fprintf(fp, "%*s/* %5u %5u */",
				 spacing > 0 ? spacing : 0, " ",
				 offset, size);
}

static size_t union_member__fprintf(struct class_member *self,
				    struct tag *type, const struct cu *cu,
				    const struct conf_fprintf *conf, FILE *fp)
{
	int spacing;
	const size_t size = tag__size(type, cu);
	size_t printed = type__fprintf(type, cu, self->name, conf, fp);
	
	if ((type->tag == DW_TAG_union_type ||
	     type->tag == DW_TAG_enumeration_type ||
	     type->tag == DW_TAG_structure_type) &&
		/* Look if is a type defined inline */
	    type__name(tag__type(type), cu) == NULL) {
		/* Check if this is a anonymous union */
		const int slen = self->name != NULL ? (int)strlen(self->name) : -1;
		/*
		 * Add the comment with the union size after padding the
		 * '} member_name;' last line of the type printed in the
		 * above call to type__fprintf.
		 */
		return printed + fprintf(fp, ";%*s/* %11zd */",
					 (conf->type_spacing +
					  conf->name_spacing - slen - 3),
					 " ", size);
	}
	spacing = conf->type_spacing + conf->name_spacing - (printed + 1);
	return printed + fprintf(fp, ";%*s/* %11zd */",
				 spacing > 0 ? spacing : 0, " ", size);
}

static size_t union__fprintf(struct type *self, const struct cu *cu,
			     const struct conf_fprintf *conf, FILE *fp)
{
	struct class_member *pos;
	size_t printed = 0;
	size_t indent = conf->indent;
	struct conf_fprintf uconf;

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;

	if (conf->prefix != NULL)
		printed += fprintf(fp, "%s ", conf->prefix);
	printed += fprintf(fp, "union%s%s {\n", type__name(self, cu) ? " " : "",
			   type__name(self, cu) ?: "");

	uconf = *conf;
	uconf.indent = indent + 1;
	type__for_each_member(self, pos) {
		struct tag *type = cu__find_tag_by_id(cu, pos->tag.type);

		printed += fprintf(fp, "%.*s", uconf.indent, tabs);
		printed += union_member__fprintf(pos, type, cu, &uconf, fp);
		fputc('\n', fp);
		++printed;
	}

	return printed + fprintf(fp, "%.*s}%s%s", indent, tabs,
				 conf->suffix ? " " : "", conf->suffix ?: "");
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

	type__for_each_member_safe(&self->type, pos, next)
		class_member__delete(pos);

	free(self);
}

static void namespace__add_tag(struct namespace *self, struct tag *tag)
{
	++self->nr_tags;
	list_add_tail(&tag->node, &self->tags);
}

static void type__add_member(struct type *self, struct class_member *member)
{
	++self->nr_members;
	namespace__add_tag(&self->namespace, &member->tag);
}

struct class_member *type__last_member(struct type *self)
{
	struct class_member *pos;

	list_for_each_entry_reverse(pos, &self->namespace.tags, tag.node)
		if (pos->tag.tag == DW_TAG_member)
			return pos;
	return NULL;
}

static int type__clone_members(struct type *self, const struct type *from)
{
	struct class_member *pos;

	self->nr_members = 0;
	INIT_LIST_HEAD(&self->namespace.tags);

	type__for_each_member(from, pos) {
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
			self->type.namespace.name = strings__add(new_class_name);
	}

	return self;
}

static void enumeration__add(struct type *self, struct enumerator *enumerator)
{
	++self->nr_members;
	namespace__add_tag(&self->namespace, &enumerator->tag);
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
		self->accessibility   = attr_numeric(die, DW_AT_accessibility);
		self->virtuality      = attr_numeric(die, DW_AT_virtuality);
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
				tag__id_not_found(&self->proto.tag,
						  self->specification);
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

	type__for_each_data_member(&self->type, pos)
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

	type__for_each_member(ctype, pos) {
		/* XXX for now just skip these */
		if (pos->tag.tag == DW_TAG_inheritance &&
		    pos->virtuality == DW_VIRTUALITY_virtual)
			continue;

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
	} else
		self->padding = ctype->size;
}

/** class__has_hole_ge - check if class has a hole greater or equal to @size
 * @self - class instance
 * @size - hole size to check
 */
int class__has_hole_ge(const struct class *self, const uint16_t size)
{
	struct class_member *pos;

	if (self->nr_holes == 0)
		return 0;

	type__for_each_data_member(&self->type, pos)
		if (pos->hole >= size)
			return 1;

	return 0;
}

struct class_member *type__find_member_by_name(const struct type *self,
					       const char *name)
{
	if (name != NULL) {
		struct class_member *pos;
		type__for_each_data_member(self, pos)
			if (pos->name != NULL && strcmp(pos->name, name) == 0)
				return pos;
	}

	return NULL;
}

uint32_t type__nr_members_of_type(const struct type *self, const Dwarf_Off type)
{
	struct class_member *pos;
	uint32_t nr_members_of_type = 0;

	type__for_each_member(self, pos)
		if (pos->tag.type == type)
			++nr_members_of_type;

	return nr_members_of_type;
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

static size_t ftype__fprintf_parms(const struct ftype *self,
				   const struct cu *cu, size_t indent,
				   FILE *fp)
{
	struct parameter *pos;
	int first_parm = 1;
	char sbf[128];
	struct tag *type;
	const char *name, *stype;
	size_t printed = fprintf(fp, "(");

	list_for_each_entry(pos, &self->parms, tag.node) {
		if (!first_parm) {
			if (indent == 0)
				printed += fprintf(fp, ", ");
			else
				printed += fprintf(fp, ",\n%.*s",
						   indent, tabs);
		} else
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
					printed += fprintf(fp, ">>>ERROR: type "
							   "for %s not found!",
							   name);
					continue;
				}
				if (ptype->tag == DW_TAG_subroutine_type) {
					printed +=
					     ftype__fprintf(tag__ftype(ptype),
							    cu, name, 0, 1, 0,
							    fp);
					continue;
				}
			}
		} else if (type->tag == DW_TAG_subroutine_type) {
			printed += ftype__fprintf(tag__ftype(type), cu, name,
						  0, 0, 0, fp);
			continue;
		}
print_it:
		stype = tag__name(type, cu, sbf, sizeof(sbf));
		printed += fprintf(fp, "%s%s%s", stype, name ? " " : "",
				   name ?: "");
	}

	/* No parameters? */
	if (first_parm)
		printed += fprintf(fp, "void)");
	else if (self->unspec_parms)
		printed += fprintf(fp, ", ...)");
	else
		printed += fprintf(fp, ")");
	return printed;
}

static size_t function__tag_fprintf(const struct tag *tag, const struct cu *cu,
				    uint16_t indent, FILE *fp)
{
	char bf[512];
	size_t printed = 0, n;
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
		const char *name;

		if (alias == NULL) {
			tag__type_not_found(&exp->tag);
			break;
		}
		printed = fprintf(fp, "%.*s", indent, tabs);
		name = function__name(alias, cu);
		n = fprintf(fp, "%s", name);
		n += ftype__fprintf_parms(&alias->proto, cu,
					  indent + (strlen(name) + 7) / 8,
					  fp);
		n += fprintf(fp, "; /* size=%zd, low_pc=%#llx */",
			     exp->size, (unsigned long long)exp->low_pc);
#if 0
		n = fprintf(fp, "%s(); /* size=%zd, low_pc=%#llx */",
			    function__name(alias, cu), exp->size,
			    (unsigned long long)exp->low_pc);
#endif
		c = 69;
		printed += n;
	}
		break;
	case DW_TAG_variable:
		printed = fprintf(fp, "%.*s", indent, tabs);
		n = fprintf(fp, "%s %s;",
			    variable__type_name(vtag, cu, bf, sizeof(bf)),
			    variable__name(vtag, cu));
		c += n;
		printed += n;
		break;
	case DW_TAG_label: {
		const struct label *label = vtag;
		printed = fprintf(fp, "%.*s", indent, tabs);
		fputc('\n', fp);
		++printed;
		c = fprintf(fp, "%s:", label->name);
		printed += c;
	}
		break;
	case DW_TAG_lexical_block:
		return lexblock__fprintf(vtag, cu, indent, fp);
	default:
		printed = fprintf(fp, "%.*s", indent, tabs);
		n = fprintf(fp, "%s <%llx>", dwarf_tag_name(tag->tag),
			    (unsigned long long)tag->id);
		c += n;
		printed += n;
		break;
	}

	return printed + fprintf(fp, "%-*.*s// %5u\n", 70 - c, 70 - c, " ",
				 tag->decl_line);
}

size_t lexblock__fprintf(const struct lexblock *self, const struct cu *cu,
			 uint16_t indent, FILE *fp)
{
	struct tag *pos;
	size_t printed;

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;
	printed = fprintf(fp, "%.*s{\n", indent, tabs);
	list_for_each_entry(pos, &self->tags, node)
		printed += function__tag_fprintf(pos, cu, indent + 1, fp);
	return printed + fprintf(fp, "%.*s}\n", indent, tabs);
}

size_t ftype__fprintf(const struct ftype *self, const struct cu *cu,
		      const char *name, const int inlined,
		      const int is_pointer, int type_spacing, FILE *fp)
{
	struct tag *type = cu__find_tag_by_id(cu, self->tag.type);
	char sbf[128];
	const char *stype = tag__name(type, cu, sbf, sizeof(sbf));
	size_t printed = fprintf(fp, "%s%-*s %s%s%s%s",
				 inlined ? "inline " : "",
				 type_spacing, stype,
				 self->tag.tag == DW_TAG_subroutine_type ?
				 	"(" : "",
				 is_pointer ? "*" : "", name ?: "",
				 self->tag.tag == DW_TAG_subroutine_type ?
				 	")" : "");

	return printed + ftype__fprintf_parms(self, cu, 0, fp);
}

static size_t function__fprintf(const struct tag *tag_self,
				const struct cu *cu, FILE *fp)
{
	struct function *self = tag__function(tag_self);

	return ftype__fprintf(&self->proto, cu, function__name(self, cu),
			      function__declared_inline(self), 0, 0, fp);
}

size_t function__fprintf_stats(const struct tag *tag_self,
			       const struct cu *cu, FILE *fp)
{
	struct function *self = tag__function(tag_self);
	size_t printed = lexblock__fprintf(&self->lexblock, cu, 0, fp);

	printed += fprintf(fp, "/* size: %zd", function__size(self));
	if (self->lexblock.nr_variables > 0)
		printed += fprintf(fp, ", variables: %u",
				   self->lexblock.nr_variables);
	if (self->lexblock.nr_labels > 0)
		printed += fprintf(fp, ", goto labels: %u",
				   self->lexblock.nr_labels);
	if (self->lexblock.nr_inline_expansions > 0)
		printed += fprintf(fp, ", inline expansions: %u (%zd bytes)",
			self->lexblock.nr_inline_expansions,
			self->lexblock.size_inline_expansions);
	return printed + fprintf(fp, " */\n");
}

static size_t class__fprintf_cacheline_boundary(uint32_t last_cacheline,
						size_t sum, size_t sum_holes,
						uint8_t *newline,
						uint32_t *cacheline,
						int indent, FILE *fp)
{
	const size_t real_sum = sum + sum_holes;
	size_t printed = 0;

	*cacheline = real_sum / cacheline_size;

	if (*cacheline > last_cacheline) {
		const uint32_t cacheline_pos = real_sum % cacheline_size;
		const uint32_t cacheline_in_bytes = real_sum - cacheline_pos;

		if (*newline) {
			fputc('\n', fp);
			*newline = 0;
			++printed;
		}

		printed += fprintf(fp, "%.*s", indent, tabs);

		if (cacheline_pos == 0)
			printed += fprintf(fp, "/* --- cacheline %u boundary "
					   "(%u bytes) --- */\n", *cacheline,
					   cacheline_in_bytes);
		else
			printed += fprintf(fp, "/* --- cacheline %u boundary "
					   "(%u bytes) was %u bytes ago --- "
					   "*/\n", *cacheline,
					   cacheline_in_bytes, cacheline_pos);
	}
	return printed;
}

size_t class__fprintf(struct class *self, const struct cu *cu,
		      const struct conf_fprintf *conf, FILE *fp)
{
	struct type *tself = &self->type;
	size_t last_size = 0, size;
	size_t last_bit_size = 0;
	uint8_t newline = 0;
	uint16_t nr_paddings = 0;
	uint32_t sum = 0;
	uint32_t sum_holes = 0;
	uint32_t sum_paddings = 0;
	uint32_t sum_bit_holes = 0;
	uint32_t last_cacheline = 0;
	int last_offset = -1, first = 1;
	struct class_member *pos;
	struct tag *tag_pos;
	const char *current_accessibility = NULL;
	struct conf_fprintf cconf = conf ? *conf : conf_fprintf__defaults;
	size_t printed = fprintf(fp, "%s%sstruct%s%s",
				 cconf.prefix ?: "", cconf.prefix ? " " : "",
				 type__name(tself, cu) ? " " : "",
				 type__name(tself, cu) ?: "");
	size_t indent = cconf.indent;

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;

	cconf.indent = indent + 1;

	/* First look if we have DW_TAG_inheritance */
	type__for_each_tag(tself, tag_pos) {
		struct tag *type;
		const char *accessibility;

		if (tag_pos->tag != DW_TAG_inheritance)
			continue;

		if (first) {
			printed += fprintf(fp, " :");
			first = 0;
		} else
			printed += fprintf(fp, ",");

		pos = tag__class_member(tag_pos);

		if (pos->virtuality == DW_VIRTUALITY_virtual)
			printed += fprintf(fp, " virtual");

		accessibility = tag__accessibility(tag_pos);
		if (accessibility != NULL)
			printed += fprintf(fp, " %s", accessibility);

		type = cu__find_tag_by_id(cu, tag_pos->type);
		printed += fprintf(fp, " %s", type__name(tag__type(type), cu));
	}

	printed += fprintf(fp, " {\n");

	type__for_each_tag(tself, tag_pos) {
		struct tag *type;
		const char *accessibility = tag__accessibility(tag_pos);

		if (accessibility != NULL &&
		    accessibility != current_accessibility) {
			current_accessibility = accessibility;
			printed += fprintf(fp, "%.*s%s:\n\n",
					   cconf.indent - 1, tabs,
					   accessibility);
		}

		if (tag_pos->tag != DW_TAG_member &&
		    tag_pos->tag != DW_TAG_inheritance) {
		    	if (!cconf.show_only_data_members) {
				printed += tag__fprintf(tag_pos, cu, &cconf, fp);
				if (tag_pos->tag != DW_TAG_structure_type)
					printed += fprintf(fp, ";\n");
				printed += fprintf(fp, "\n");
			}
			continue;
		}
		pos = tag__class_member(tag_pos);

		if ((int)pos->offset != last_offset)
			printed +=
			    class__fprintf_cacheline_boundary(last_cacheline,
							      sum, sum_holes,
							      &newline,
							      &last_cacheline,
							      cconf.indent,
							      fp);
		/*
		 * These paranoid checks doesn't make much sense on
		 * DW_TAG_inheritance, have to understand why virtual public
		 * ancestors make the offset go backwards...
		 */
		if (last_offset != -1 && tag_pos->tag == DW_TAG_member) {
			const ssize_t cc_last_size = pos->offset - last_offset;

			if ((int)pos->offset < last_offset) {
				if (!newline++) {
					fputc('\n', fp);
					++printed;
				}
				printed += fprintf(fp, "%.*s/* WARNING: DWARF"
						   " offset=%zd, real offset="
						   "%zd */\n",
						   cconf.indent, tabs,
						   pos->offset,
						   last_offset + last_size);
			} else if (cc_last_size > 0 &&
			    (size_t)cc_last_size < last_size) {
				if (!newline++) {
					fputc('\n', fp);
					++printed;
				}
				printed += fprintf(fp, "%.*s/* Bitfield "
						   "WARNING: DWARF size=%zd, "
						   "real size=%zd */\n",
						   cconf.indent, tabs,
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
			++printed;
		}

		type = cu__find_tag_by_id(cu, pos->tag.type);
		if (type == NULL) {
			tag__type_not_found(&pos->tag);
			printed += fprintf(fp, "%.*s>>>ERROR: type for %s not "
				     "found!\n", cconf.indent, tabs, pos->name);
			continue;
		}

		size = tag__size(type, cu);
		printed += fprintf(fp, "%.*s", cconf.indent, tabs);
		printed += struct_member__fprintf(pos, type, cu, &cconf, fp);

		if (type->tag == DW_TAG_structure_type) {
			const uint16_t padding = tag__class(type)->padding;
			if (padding > 0) {
				++nr_paddings;
				sum_paddings += padding; 
				if (!newline++) {
					fputc('\n', fp);
					++printed;
				}

				printed += fprintf(fp, "\n%.*s/* XXX last "
						   "struct has %d byte%s of "
						   "padding */", cconf.indent,
						   tabs, padding,
						   padding != 1 ? "s" : "");
			}
		}

		if (pos->bit_hole != 0) {
			if (!newline++) {
				fputc('\n', fp);
				++printed;
			}
			printed += fprintf(fp, "\n%.*s/* XXX %d bit%s hole, "
					   "try to pack */", cconf.indent, tabs,
					   pos->bit_hole,
					   pos->bit_hole != 1 ? "s" : "");
			sum_bit_holes += pos->bit_hole;
		}

		if (pos->hole > 0) {
			if (!newline++) {
				fputc('\n', fp);
				++printed;
			}
			printed += fprintf(fp, "\n%.*s/* XXX %d byte%s hole, "
					   "try to pack */",
					   cconf.indent, tabs, pos->hole,
					   pos->hole != 1 ? "s" : "");
			sum_holes += pos->hole;
		}

		fputc('\n', fp);
		++printed;

		/* XXX for now just skip these */
		if (tag_pos->tag == DW_TAG_inheritance &&
		    pos->virtuality == DW_VIRTUALITY_virtual)
			continue;
		/*
		 * check for bitfields, accounting for only the biggest
		 * of the byte_size in the fields in each bitfield set.
		 */
		if (last_offset != (int)pos->offset ||
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

	printed += class__fprintf_cacheline_boundary(last_cacheline, sum,
						     sum_holes, &newline,
						     &last_cacheline,
						     cconf.indent, fp);
	printed += fprintf(fp, "%.*s}%s%s", indent, tabs,
			   cconf.suffix ? " ": "", cconf.suffix ?: "");
	if (!cconf.emit_stats)
		goto out;

	printed += fprintf(fp, "; /* size: %zd, cachelines: %zd */\n",
			   tself->size, tag__nr_cachelines(class__tag(self),
			   cu));
	if (sum_holes > 0)
		printed += fprintf(fp, "%.*s   /* sum members: %u, holes: %d, "
				   "sum holes: %u */\n", indent, tabs, sum,
				   self->nr_holes, sum_holes);
	if (sum_bit_holes > 0)
		printed += fprintf(fp, "%.*s   /* bit holes: %d, sum bit "
				   "holes: %u bits */\n", indent, tabs,
				   self->nr_bit_holes, sum_bit_holes);
	if (self->padding > 0)
		printed += fprintf(fp, "%.*s   /* padding: %u */\n", indent,
				   tabs, self->padding);
	if (nr_paddings > 0)
		printed += fprintf(fp, "%.*s   /* paddings: %u, sum paddings: "
				   "%u */\n", indent, tabs, nr_paddings,
				   sum_paddings);
	if (self->bit_padding > 0)
		printed += fprintf(fp, "%.*s   /* bit_padding: %u bits */\n",
				   indent, tabs, self->bit_padding);
	last_cacheline = tself->size % cacheline_size;
	if (last_cacheline != 0)
		printed += fprintf(fp, "%.*s   /* last cacheline: %u bytes "
				   "*/\n", indent, tabs, last_cacheline);

	if (sum + sum_holes != tself->size - self->padding)
		printed += fprintf(fp, "\n%.*s/* BRAIN FART ALERT! %zd != %u "
				   "+ %u(holes), diff = %zd */\n\n",
				   indent, tabs, tself->size, sum, sum_holes,
				   tself->size - (sum + sum_holes));
out:
	return printed;
}

static size_t variable__fprintf(const struct tag *tag, const struct cu *cu,
				const struct conf_fprintf *conf, FILE *fp)
{
	const struct variable *var = tag__variable(tag);
	const char *name = variable__name(var, cu);
	size_t printed = 0;

	if (name != NULL) {
		struct tag *type = variable__type(var, cu);
		if (type != NULL) {
			const char *varprefix = variable__prefix(var);

			if (varprefix != NULL)
				printed += fprintf(fp, "%s", varprefix);
			printed += type__fprintf(type, cu, name, conf, fp);
		}
	}
	return printed;
}

static size_t namespace__fprintf(const struct tag *tself, const struct cu *cu,
				 const struct conf_fprintf *conf, FILE *fp)
{
	struct namespace *self = tag__namespace(tself);
	struct conf_fprintf cconf = *conf;
	size_t printed = fprintf(fp, "namespace %s {\n", self->name);
	struct tag *pos;

	++cconf.indent;

	namespace__for_each_tag(self, pos) {
		printed += tag__fprintf(pos, cu, &cconf, fp);
		if (pos->tag != DW_TAG_structure_type)
			printed += fprintf(fp, ";\n");
		printed += fprintf(fp, "\n");
	}

	return printed + fprintf(fp, "};\n");
}

size_t tag__fprintf(const struct tag *self, const struct cu *cu,
		    const struct conf_fprintf *conf, FILE *fp)
{
	size_t printed = 0;
	struct conf_fprintf tconf;
	const struct conf_fprintf *pconf = conf;

	if (conf == NULL) {
		tconf = conf_fprintf__defaults;
		pconf = &tconf; 

		if (tconf.expand_types)
			tconf.name_spacing = 55;
		else if (self->tag == DW_TAG_union_type)
			tconf.name_spacing = 21;
	} else if (conf->name_spacing == 0 || conf->type_spacing == 0) {
		tconf = *conf;
		pconf = &tconf; 

		if (tconf.name_spacing == 0) {
			if (tconf.expand_types)
				tconf.name_spacing = 55;
			else
				tconf.name_spacing =
				     self->tag == DW_TAG_union_type ? 21 : 23;
		}
		if (tconf.type_spacing == 0)
			tconf.type_spacing = 26;
	}

	if (pconf->show_decl_info) {
		printed += fprintf(fp, "%.*s", pconf->indent, tabs);
		printed += tag__fprintf_decl_info(self, fp);
	}
	printed += fprintf(fp, "%.*s", pconf->indent, tabs);

	switch (self->tag) {
	case DW_TAG_enumeration_type:
		printed += enumeration__fprintf(self, cu, pconf, fp);
		break;
	case DW_TAG_typedef:
		printed += typedef__fprintf(self, cu, fp);
		break;
	case DW_TAG_structure_type:
		printed += class__fprintf(tag__class(self), cu, pconf, fp);
		break;
	case DW_TAG_namespace:
		printed += namespace__fprintf(self, cu, pconf, fp);
		break;
	case DW_TAG_subprogram:
		printed += function__fprintf(self, cu, fp);
		break;
	case DW_TAG_union_type:
		printed += union__fprintf(tag__type(self), cu, pconf, fp);
		break;
	case DW_TAG_variable:
		printed += variable__fprintf(self, cu, pconf, fp);
		break;
	case DW_TAG_imported_declaration:
		printed += imported_declaration__fprintf(self, cu, fp);
		break;
	case DW_TAG_imported_module:
		printed += imported_module__fprintf(self, cu, fp);
		break;
	default:
		printed += fprintf(fp, "/* %s: %s tag not supported! */", __func__,
				   dwarf_tag_name(self->tag));
		break;
	}

	return printed;
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
		}
			continue;
		default: {
			struct tag *tag = die__process_tag(die, cu);

			if (tag != NULL)
				namespace__add_tag(&class->namespace, tag);
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

		if (tag != NULL)
			namespace__add_tag(namespace, tag);
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
		return die__create_new_enumeration(die);
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

int cus__loadfl(struct cus *self, struct argp *argp, int argc, char *argv[])
{
	Dwfl *dwfl = NULL;
	Dwarf_Die *cu_die = NULL;
	Dwarf_Addr dwbias;
	char **new_argv = NULL;
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

	while ((cu_die = dwfl_nextcu(dwfl, cu_die, &dwbias)) != NULL) {
		Dwarf_Die tmp;
		struct cu *cu;
		uint8_t pointer_size, offset_size;

		dwarf_diecu(cu_die, &tmp, &pointer_size, &offset_size);

		cu = cu__new(attr_string(cu_die, DW_AT_name), pointer_size);
		if (cu == NULL)
			oom("cu__new");
		die__process(cu_die, cu);
		cus__add(self, cu);
	}

	dwfl_end(dwfl);
	err = 0;
out:
	free(new_argv);
	return err;
}

void cus__print_error_msg(const char *progname, const char *filename,
			  const int err)
{
	if (err == -EINVAL)
		fprintf(stderr, "%s: couldn't load DWARF info from %s\n",
		       progname, filename);
	else
		fprintf(stderr, "%s: %s\n", progname, strerror(err));
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
