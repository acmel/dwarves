/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

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
#include "classes.h"

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

size_t cacheline_size = DEFAULT_CACHELINE_SIZE;

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
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	case DW_FORM_ref_addr:
	case DW_FORM_ref_udata: {
		Dwarf_Off ref;
		if (dwarf_formref(&attr, &ref) == 0)
			return (uintmax_t)ref;
	}
	case DW_FORM_flag:
		return 1;
	default:
		printf("DW_AT_<0x%x>=0x%x\n", name, form);
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

static const char *attr_string(Dwarf_Die *die, uint32_t name,
			       Dwarf_Attribute *attr)
{
	if (dwarf_attr(die, name, attr) != NULL)
		return dwarf_formstring(attr);
	return NULL;
}

static void tag__init(struct tag *self, Dwarf_Die *die)
{
	uint32_t decl_line;

	self->tag	= dwarf_tag(die);
	self->id	= dwarf_cuoffset(die);
	self->type	= attr_numeric(die, DW_AT_type);
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

static struct base_type *base_type__new(Dwarf_Die *die)
{
	struct base_type *self = zalloc(sizeof(*self));

	if (self != NULL) {
		Dwarf_Attribute attr_name;

		tag__init(&self->tag, die);
		self->name = strings__add(attr_string(die, DW_AT_name,
						      &attr_name));
		self->size = attr_numeric(die, DW_AT_byte_size);
	}

	return self;
}

static size_t enumeration__snprintf(const struct class *self,
				    char *bf, size_t len,
				    const char *suffix, uint8_t ntabs)
{
	struct enumerator *pos;
	char *s = bf;
	size_t printed = 0, n;

	if (ntabs >= sizeof(tabs))
		ntabs = sizeof(tabs) - 1;

	n = snprintf(s, len, "enum%s%s {\n",
		     self->name ? " " : "", self->name ?: "");
	s += n;
	len -= n;
	printed += n;
	list_for_each_entry(pos, &self->members, tag.node) {
		n = snprintf(s, len, "%.*s\t%s = %u,\n", ntabs, tabs,
			     pos->name, pos->value);
		s += n;
		len -= n;
		printed += n;
	}

	n = snprintf(s, len, "%.*s}%s%s;", ntabs, tabs,
		     suffix ? " " : "", suffix ?: "");
	return printed + n;
}

static void enumeration__print(const struct class *self, const char *suffix,
			       uint8_t ntabs)
{
	char bf[4096];

	if (ntabs >= sizeof(tabs))
		ntabs = sizeof(tabs) - 1;

	printf("%.*s/* %s:%u */\n", ntabs, tabs,
	       self->tag.decl_file, self->tag.decl_line);
	enumeration__snprintf(self, bf, sizeof(bf), suffix, ntabs);
	printf("%s\n", bf);
}

static struct enumerator *enumerator__new(Dwarf_Die *die)
{
	struct enumerator *self = zalloc(sizeof(*self));

	if (self != NULL) {
		Dwarf_Attribute attr_name;

		tag__init(&self->tag, die);
		self->name = strings__add(attr_string(die, DW_AT_name,
						      &attr_name));
		self->value = attr_numeric(die, DW_AT_const_value);
	}

	return self;
}

static struct variable *variable__new(Dwarf_Die *die)
{
	struct variable *self = malloc(sizeof(*self));

	if (self != NULL) {
		Dwarf_Attribute attr_name;

		tag__init(&self->tag, die);
		self->name = strings__add(attr_string(die, DW_AT_name,
						      &attr_name));
		self->abstract_origin = attr_numeric(die,
					 	     DW_AT_abstract_origin);
	}

	return self;
}

static size_t union__snprintf(const struct class *self,
			      char *bf, size_t len,
			      const char *suffix, uint8_t ntabs)
{
	char class_name[4096];
	char member_name[128];
	struct class_member *pos;
	char *s = bf;
	size_t printed = 0, n;

	if (ntabs >= sizeof(tabs))
		ntabs = sizeof(tabs) - 1;

	n = snprintf(s, len, "union%s%s {\n",
		     self->name ? " " : "", self->name ?: "");
	s += n;
	len -= n;
	printed += n;
	list_for_each_entry(pos, &self->members, tag.node) {
		const size_t size = class_member__names(NULL, pos, class_name,
							sizeof(class_name),
							member_name,
							sizeof(member_name));
		n = snprintf(s, len, "%.*s\t%-18s %-21s /* %11u */\n",
			     ntabs, tabs, class_name, member_name, size);
		s += n;
		len -= n;
		printed += n;
	}

	n = snprintf(s, len, "%.*s}%s%s;", ntabs, tabs,
		     suffix ? " " : "", suffix ?: "");
	return printed + n;
}

static void union__print(const struct class *self, const char *suffix,
			 uint8_t ntabs)
{
	struct enumerator *pos;
	char bf[4096];

	if (ntabs >= sizeof(tabs))
		ntabs = sizeof(tabs) - 1;

	printf("%.*s/* %s:%u */\n", ntabs, tabs,
	       self->tag.decl_file, self->tag.decl_line);
	union__snprintf(self, bf, sizeof(bf), suffix, ntabs);
	printf("%s\n", bf);
}

static void cus__add(struct cus *self, struct cu *cu)
{
	list_add_tail(&cu->node, &self->cus);
}

static struct cu *cu__new(uint32_t cu, const char *name, uint8_t addr_size)
{
	struct cu *self = malloc(sizeof(*self));

	if (self != NULL) {
		INIT_LIST_HEAD(&self->tags);
		INIT_LIST_HEAD(&self->variables);
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

static void cu__add_function(struct cu *self, struct function *function)
{
	list_add_tail(&function->proto.tag.node, &self->tags);
}

static void cu__add_variable(struct cu *self, struct variable *variable)
{
	list_add_tail(&variable->cu_node, &self->variables);
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

struct class *cu__find_class_by_name(const struct cu *self, const char *name)
{
	struct tag *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, &self->tags, node) {
		struct class *class;

		if (pos->tag != DW_TAG_structure_type)
			continue;

		class = tag__class(pos);
		if (class->name != NULL && strcmp(class->name, name) == 0)
			return class;
	}

	return NULL;
}

struct class *cus__find_class_by_name(const struct cus *self,
				      struct cu **cu, const char *name)
{
	struct cu *pos;

	list_for_each_entry(pos, &self->cus, node) {
		struct class *class = cu__find_class_by_name(pos, name);

		if (class != NULL) {
			if (cu != NULL)
				*cu = pos;
			return class;
		}
	}

	return NULL;
}

struct function *cus__find_function_by_name(const struct cus *self,
					    struct cu **cu, const char *name)
{
	struct cu *pos;

	list_for_each_entry(pos, &self->cus, node) {
		struct function *function = cu__find_function_by_name(pos, name);

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

struct class *cus__find_definition(const struct cus *self, const char *name)
{
	struct class *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, self->definitions, node)
		if (pos->name != NULL && strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

struct class *cus__find_fwd_decl(const struct cus *self, const char *name)
{
	struct class *pos;

	list_for_each_entry(pos, self->fwd_decls, node)
		if (strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

static void cus__add_definition(struct cus *self, struct class *class)
{
	class->visited = 1;
	if (!list_empty(&class->node))
		list_del(&class->node);
	list_add_tail(&class->node, self->definitions);
}

static void cus__add_fwd_decl(struct cus *self, struct class *class)
{
	class->fwd_decl_emitted = 1;
	if (list_empty(&class->node))
		list_add_tail(&class->node, self->fwd_decls);
}

struct function *cu__find_function_by_name(const struct cu *self,
					   const char *name)
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
			return fpos;
	}

	return NULL;
}

struct variable *cu__find_variable_by_id(const struct cu *self, const Dwarf_Off id)
{
	struct variable *pos;

	list_for_each_entry(pos, &self->variables, cu_node)
		if (pos->tag.id == id)
			return pos;

	return NULL;
}

int tag__is_struct(const struct tag *self, struct tag **typedef_alias,
		   const struct cu *cu)
{
	*typedef_alias = NULL;
	if (self->tag == DW_TAG_typedef) {
		*typedef_alias = cu__find_tag_by_id(cu, self->type);
		if (*typedef_alias == NULL)
			return 0;
		
		return (*typedef_alias)->tag == DW_TAG_structure_type;
	}

	return self->tag == DW_TAG_structure_type;
}

static size_t array_type__nr_entries(const struct array_type *self)
{
	int i;
	size_t nr_entries = 1;

	for (i = 0; i < self->dimensions; ++i)
		nr_entries *= self->nr_entries[i];

	return nr_entries;
}

static size_t tag__size(const struct tag *self, const struct cu *cu)
{
	size_t size;

	switch (self->tag) {
	case DW_TAG_pointer_type: return cu->addr_size;
	case DW_TAG_base_type:	  return tag__base_type(self)->size;
	}

	if (self->type == 0) /* struct class: enums, unions, structs */
		size = tag__class(self)->size;
	else {
		const struct tag *type = cu__find_tag_by_id(cu, self->type);

		assert(type != NULL);
		size = tag__size(type, cu);
	}

	if (self->tag == DW_TAG_array_type)
		return size * array_type__nr_entries(tag__array_type(self));

	return size;
}

const char *tag__name(const struct tag *self, const struct cu *cu,
		      char *bf, size_t len)
{
	struct tag *type;
	char tmpbf[128];

	if (self == NULL)
		strncpy(bf, "void", len);
	else if (self->tag == DW_TAG_base_type)
		strncpy(bf, tag__base_type(self)->name, len);
	else if (self->tag == DW_TAG_pointer_type) {
		if (self->type == 0) /* No type == void */
			strncpy(bf, "void *", len);
		else {
			type = cu__find_tag_by_id(cu, self->type);
			snprintf(bf, len, "%s *", tag__name(type, cu, tmpbf,
							    sizeof(tmpbf)));
		}
	} else if (self->tag == DW_TAG_volatile_type ||
		   self->tag == DW_TAG_const_type) {
		type = cu__find_tag_by_id(cu, self->type);
		snprintf(bf, len, "%s %s ",
			 self->tag == DW_TAG_volatile_type ? "volatile" :
			 				     "const",
			 tag__name(type, cu, tmpbf, sizeof(tmpbf)));
	} else if (self->tag == DW_TAG_array_type) {
		type = cu__find_tag_by_id(cu, self->type);
		return tag__name(type, cu, bf, len);
	} else
		snprintf(bf, len, "%s%s", tag__prefix(cu, self->tag),
			 tag__class(self)->name ?: "");
	return bf;
}

const char *variable__type_name(const struct variable *self,
				const struct cu *cu,
				char *bf, size_t len)
{
	if (self->tag.type != 0) {
		struct tag *tag = cu__find_tag_by_id(cu, self->tag.type);
		return tag__name(tag, cu, bf, len);
	} else if (self->abstract_origin != 0) {
		struct variable *var;

		var = cu__find_variable_by_id(cu, self->abstract_origin);
		if (var != NULL)
		       return variable__type_name(var, cu, bf, len);
	}
	
	return NULL;
}

const char *variable__name(const struct variable *self, const struct cu *cu)
{
	if (self->name == NULL) {
		if (self->abstract_origin == 0)
			return NULL;
		else {
			struct variable *var;

			var = cu__find_variable_by_id(cu,
						      self->abstract_origin);
			return var == NULL ? NULL : var->name;
		}
	}
	
	return self->name;
}

static struct class_member *class_member__new(Dwarf_Die *die)
{
	struct class_member *self = zalloc(sizeof(*self));

	if (self != NULL) {
		Dwarf_Attribute attr_name;

		tag__init(&self->tag, die);
		self->offset	 = attr_offset(die);
		self->bit_size	 = attr_numeric(die, DW_AT_bit_size);
		self->bit_offset = attr_numeric(die, DW_AT_bit_offset);
		self->name = strings__add(attr_string(die, DW_AT_name,
						      &attr_name));
	}

	return self;
}

static size_t class_member__size(const struct class_member *self)
{
	struct tag *type = cu__find_tag_by_id(self->class->cu, self->tag.type);
	assert(type != NULL);
	return tag__size(type, self->class->cu);
}

size_t class_member__names(const struct tag *type,
			   const struct class_member *self,
			   char *class_name, size_t class_name_size,
			   char *member_name, size_t member_name_size)
{
	size_t size = -1;

	if (type == NULL)
		type = cu__find_tag_by_id(self->class->cu, self->tag.type);
	snprintf(member_name, member_name_size, "%s;", self->name ?: "");

	if (type == NULL)
		snprintf(class_name, class_name_size, "<%llx>",
			 self->tag.type);
	else {
		if (type->tag == DW_TAG_const_type)
			type = cu__find_tag_by_id(self->class->cu, type->type);
		size = tag__size(type, self->class->cu);

		/* Is it a function pointer? */
		if (type->tag == DW_TAG_pointer_type) {
			struct tag *ptype =
			      cu__find_tag_by_id(self->class->cu, type->type);

			if (ptype != NULL &&
			    ptype->tag == DW_TAG_subroutine_type) {
				/* function has no return value (void) */
				if (ptype->type == 0)
					snprintf(class_name,
						 class_name_size, "void");
				else {
					struct tag *ret_type =
					   cu__find_tag_by_id(self->class->cu,
							      ptype->type);

					tag__name(ret_type, self->class->cu,
						  class_name,
						  class_name_size);
				}
				snprintf(member_name, member_name_size,
					 "(*%s)(void /* FIXME: add parm list */);",
					 self->name ?: "");
				goto out;
			}
		}

		tag__name(type, self->class->cu, class_name, class_name_size);
		if (type->tag == DW_TAG_array_type) {
			struct array_type *array = tag__array_type(type);
			int i = 0;
			size_t n = snprintf(member_name, member_name_size,
					    "%s", self->name);
			member_name += n;
			member_name_size -= n;

			for (i = 0; i < array->dimensions; ++i) {
				n = snprintf(member_name, member_name_size,
					     "[%u]", array->nr_entries[i]);
				member_name += n;
				member_name_size -= n;
			}
			strncat(member_name, ";", member_name_size);
		} else if (self->bit_size != 0)
			snprintf(member_name, member_name_size,
				 "%s:%d;", self->name ?: "",
				 self->bit_size);
	}
out:
	return size;
}

size_t parameter__names(const struct parameter *self, const struct cu *cu,
			char *class_name, size_t class_name_size,
			char *parameter_name, size_t parameter_name_size)
{
	struct tag *type = cu__find_tag_by_id(cu, self->tag.type);
	size_t size = -1;

	snprintf(parameter_name, parameter_name_size, "%s", self->name ?: "");

	if (type == NULL)
		snprintf(class_name, class_name_size, "<%llx>",
			 self->tag.type);
	else {
		if (type->tag == DW_TAG_const_type)
			type = cu__find_tag_by_id(cu, type->type);
		size = tag__size(type, cu);

		/* Is it a function pointer? */
		if (type->tag == DW_TAG_pointer_type) {
			struct tag *ptype = cu__find_tag_by_id(cu, type->type);

			if (ptype != NULL &&
			    ptype->tag == DW_TAG_subroutine_type) {
				/* function has no return value (void) */
				if (ptype->type == 0)
					snprintf(class_name,
						 class_name_size, "void");
				else {
					struct tag *ret_type =
					cu__find_tag_by_id(cu, ptype->type);

					tag__name(ret_type, cu,
						  class_name, class_name_size);
				}
				snprintf(parameter_name, parameter_name_size,
					 "(*%s)(void /* FIXME: add "
					 "parameter list */)",
					 self->name ?: "");
				goto out;
			}
		}

		tag__name(type, cu, class_name, class_name_size);
		if (type->tag == DW_TAG_array_type) {
			struct array_type *array = tag__array_type(type);
			int i = 0;
			size_t n = snprintf(parameter_name,
					    parameter_name_size,
					    "%s", self->name);
			parameter_name += n;
			parameter_name_size -= n;

			for (i = 0; i < array->dimensions; ++i) {
				n = snprintf(parameter_name,
					     parameter_name_size, "[%u]",
					     array->nr_entries[i]);
				parameter_name += n;
				parameter_name_size -= n;
			}
		}
	}
out:
	return size;
}

static size_t class_member__print(struct class_member *self)
{
	size_t size;
	char class_name[4096];
	char member_name[128];
	struct tag *type = cu__find_tag_by_id(self->class->cu, self->tag.type);

	assert(type != NULL);
	if (type->tag == DW_TAG_enumeration_type) {
		const struct class *ctype = tag__class(type);
		size = ctype->size;

		if (ctype->name != NULL) {
			snprintf(class_name, sizeof(class_name), "enum %s",
				 ctype->name);
			snprintf(member_name, sizeof(member_name), "%s;",
				 self->name);
		} else {
			const size_t spacing = 45 - strlen(self->name);
			enumeration__snprintf(ctype, class_name,
					      sizeof(class_name),
					      self->name, 1);

			printf("%s %*.*s/* %5u %5u */",
			       class_name, spacing, spacing, " ",
			       self->offset, size);
			goto out;
		}
	} else if (type->tag == DW_TAG_union_type) {
		const struct class *ctype = tag__class(type);
		size = ctype->size;

		if (ctype->name != NULL) {
			snprintf(class_name, sizeof(class_name), "union %s",
				 ctype->name);
			snprintf(member_name, sizeof(member_name), "%s;",
				 self->name);
		} else {
			const size_t spacing = 45 - (self->name ?
						     strlen(self->name) : -1);
			union__snprintf(ctype, class_name, sizeof(class_name),
					self->name, 1);
			printf("%s %*.*s/* %5u %5u */",
			       class_name, spacing, spacing, " ",
			       self->offset, size);
			goto out;
		}
	} else if (type->tag == DW_TAG_pointer_type &&
		   type->type != 0) { /* make sure its not a void pointer */
		struct tag *ptype = cu__find_tag_by_id(self->class->cu, type->type);

		if (ptype->tag != DW_TAG_subroutine_type)
			goto class_member_fmt;

		size = self->class->cu->addr_size;
		ftype__snprintf(tag__ftype(ptype), self->class->cu,
				class_name, sizeof(class_name),
				self->name, 0, 1, 26);
		printf("%s; /* %5u %5u */", class_name, self->offset, size);
		goto out;
	} else {
class_member_fmt:
		size = class_member__names(type, self, class_name,
					   sizeof(class_name),
					   member_name, sizeof(member_name));
	}

	if (self->tag.tag == DW_TAG_inheritance) {
		snprintf(member_name, sizeof(member_name),
			 "/* ancestor class */");
		strncat(class_name, ";", sizeof(class_name));
	}

	printf("%-26s %-21s /* %5u %5u */",
	       class_name, member_name, self->offset, size);
out:
	return size;
}

static struct parameter *parameter__new(Dwarf_Die *die)
{
	struct parameter *self = zalloc(sizeof(*self));

	if (self != NULL) {
		Dwarf_Attribute attr_name;

		tag__init(&self->tag, die);
		self->name = strings__add(attr_string(die, DW_AT_name,
						      &attr_name));
	}

	return self;
}

static struct inline_expansion *inline_expansion__new(Dwarf_Die *die)
{
	struct inline_expansion *self = zalloc(sizeof(*self));

	if (self != NULL) {
		Dwarf_Attribute attr_call_file;

		tag__init(&self->tag, die);
		self->tag.decl_file =
			strings__add(attr_string(die, DW_AT_call_file,
						 &attr_call_file));
		self->tag.decl_line = attr_numeric(die, DW_AT_call_line);
		self->tag.type	    = attr_numeric(die, DW_AT_abstract_origin);

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
		Dwarf_Attribute attr_name;

		tag__init(&self->tag, die);
		self->name = strings__add(attr_string(die, DW_AT_name,
						      &attr_name));
		if (dwarf_lowpc(die, &self->low_pc))
			self->low_pc = 0;
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

static struct class *class__new(Dwarf_Die *die)
{
	struct class *self = zalloc(sizeof(*self));

	if (self != NULL) {
		Dwarf_Attribute attr_name;

		tag__init(&self->tag, die);
		INIT_LIST_HEAD(&self->members);
		INIT_LIST_HEAD(&self->node);
		self->size = attr_numeric(die, DW_AT_byte_size);
		self->name = strings__add(attr_string(die, DW_AT_name,
						      &attr_name));
		self->declaration = attr_numeric(die, DW_AT_declaration);
	}

	return self;
}

static void class__add_member(struct class *self, struct class_member *member)
{
	++self->nr_members;
	member->class = self;
	list_add_tail(&member->tag.node, &self->members);
}

static void enumeration__add(struct class *self,
			     struct enumerator *enumerator)
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

static ftype__init(struct ftype *self, Dwarf_Die *die)
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
		Dwarf_Attribute attr_name;

		ftype__init(&self->proto, die);
		lexblock__init(&self->lexblock, die);
		self->name = strings__add(attr_string(die,
						      DW_AT_name, &attr_name));
		self->inlined  = attr_numeric(die, DW_AT_inline);
		self->external = dwarf_hasattr(die, DW_AT_external);
	}

	return self;
}

int ftype__has_parm_of_type(const struct ftype *self, const struct tag *target,
			    const struct cu *cu)
{
	struct parameter *pos;

	list_for_each_entry(pos, &self->parms, tag.node) {
		struct tag *type = cu__find_tag_by_id(cu, pos->tag.type);

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

static void lexblock__add_inline_expansion(struct lexblock *self,
					   struct inline_expansion *exp)
{
	++self->nr_inline_expansions;
	self->size_inline_expansions += exp->size;
	list_add_tail(&exp->tag.node, &self->tags);
}

static void lexblock__add_variable(struct lexblock *self, struct variable *var)
{
	++self->nr_variables;
	list_add_tail(&var->tag.node, &self->tags);
}

static void lexblock__add_label(struct lexblock *self, struct label *label)
{
	++self->nr_labels;
	list_add_tail(&label->tag.node, &self->tags);
}

const struct class_member *class__find_bit_hole(const struct class *self,
					    const struct class_member *trailer,
						const size_t bit_hole_size)
{
	struct class_member *pos;
	const size_t byte_hole_size = bit_hole_size / 8;

	list_for_each_entry(pos, &self->members, tag.node)
		if (pos == trailer)
			break;
		else if (pos->hole >= byte_hole_size ||
			 pos->bit_hole >= bit_hole_size)
			return pos;

	return NULL;
}

void class__find_holes(struct class *self)
{
	struct class_member *pos, *last = NULL;
	size_t last_size = 0, size;
	uint32_t bit_sum = 0;

	self->nr_holes = 0;
	self->nr_bit_holes = 0;

	list_for_each_entry(pos, &self->members, tag.node) {
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
				if (cc_last_size < last_size)
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
		size = class_member__size(pos);

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
		if (last->offset + last_size != self->size)
			self->padding = self->size - (last->offset + last_size);
		if (last->bit_size != 0)
			self->bit_padding = (last_size * 8) - bit_sum;
	}
}

struct class_member *class__find_member_by_name(const struct class *self,
						const char *name)
{
	struct class_member *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, &self->members, tag.node)
		if (pos->name != NULL && strcmp(pos->name, name) == 0)
			return pos;

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

static int tags__compare(const void *a, const void *b)
{
	const struct tag *ta = a, *tb = b;

	if (a == b)
		return 0;
	if (ta->decl_line < tb->decl_line)
		return -1;
	if (ta->decl_line > tb->decl_line)
		return 1;
	if (ta->tag == DW_TAG_inlined_subroutine)
		return -1;
	return 1;
}

static void tags__free(void *a)
{
}

static void tags__add(void *tags, const struct tag *tag)
{
	tsearch(tag, tags, tags__compare);
}

static void lexblock__print(const struct lexblock *self, const struct cu *cu,
			    int indent);

static void function__tag_print(const struct tag *tag, const struct cu *cu,
				int indent)
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
		const struct function *alias = tag__function(talias);

		assert(alias != NULL);
		printf("%.*s", indent, tabs);
		c += printf("%s(); /* low_pc=%#llx */",
			    alias->name, exp->low_pc);
	}
		break;
	case DW_TAG_variable:
		printf("%.*s", indent, tabs);
		c += printf("%s %s;", variable__type_name(vtag, cu,
							  bf, sizeof(bf)),
			    variable__name(vtag, cu));
		break;
	case DW_TAG_label: {
		const struct label *label = vtag;
		printf("%.*s", indent, tabs);
		putchar('\n');
		c = printf("%s:", label->name);
	}
		break;
	case DW_TAG_lexical_block:
		lexblock__print(vtag, cu, indent);
		return;
	default:
		printf("%.*s", indent, tabs);
		c += printf("%s <%llx>", dwarf_tag_name(tag->tag), tag->id);
		break;
	}

	printf("%-*.*s// %5u\n", 70 - c, 70 - c, " ",  tag->decl_line);
}

static void lexblock__print(const struct lexblock *self, const struct cu *cu,
			    int indent)
{
	struct tag *pos;

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;
	printf("%.*s{\n", indent, tabs);
	list_for_each_entry(pos, &self->tags, node)
		function__tag_print(pos, cu, indent + 1);
	printf("%.*s}\n", indent, tabs);
}

size_t ftype__snprintf(const struct ftype *self, const struct cu *cu,
		       char *bf, const size_t len,
		       const char *name, const int inlined,
		       const int is_pointer, size_t type_spacing)
{
	struct parameter *pos;
	struct tag *type = cu__find_tag_by_id(cu, self->tag.type);
	int first_parm = 1;
	char *s = bf, sbf[128];
	size_t l = len;
	const char *stype = tag__name(type, cu, sbf, sizeof(sbf));
	size_t n = snprintf(s, l, "%s%-*s %s%s%s%s(", inlined ? "inline " : "",
			    type_spacing, stype,
			    self->tag.tag == DW_TAG_subroutine_type ? "(" : "",
			    is_pointer ? "*" : "", name ?: "",
			    self->tag.tag == DW_TAG_subroutine_type ? ")" : "");
	s += n; l -= n;

	list_for_each_entry(pos, &self->parms, tag.node) {
		if (!first_parm) {
			n = snprintf(s, l, ", ");
			s += n; l -= n;
		} else
			first_parm = 0;
		type = cu__find_tag_by_id(cu, pos->tag.type);
		if (type->tag == DW_TAG_pointer_type) {
			if (type->type != 0) {
				struct tag *ptype =
					cu__find_tag_by_id(cu, type->type);
				if (ptype->tag == DW_TAG_subroutine_type) {
					n = ftype__snprintf(tag__ftype(ptype),
							    cu, s, l,
							    pos->name, 0, 1, 0);
					goto next;
				}
			}
		} else if (type->tag == DW_TAG_subroutine_type) {
			n = ftype__snprintf(tag__ftype(type), cu, s, l,
					    pos->name, 0, 0, 0);
			goto next;
		}
		stype = tag__name(type, cu, sbf, sizeof(sbf));
		n = snprintf(s, l, "%s%s%s", stype,
			     pos->name ? " " : "", pos->name ?: "");
	next:
		s += n; l -= n;
	}

	/* No parameters? */
	if (first_parm)
		n = snprintf(s, l, "void)");
	else if (self->unspec_parms)
		n = snprintf(s, l, ", ...)");
	else
		n = snprintf(s, l, ")");
	return len - (l - n);
}

void function__print(const struct function *self, const struct cu *cu,
		     int show_stats, const int show_variables,
		     const int show_inline_expansions)
{
	char bf[2048];
	struct tag *class_type;
	const char *type = "<ERROR>";

	printf("/* %s:%u */\n", self->proto.tag.decl_file,
				self->proto.tag.decl_line);

	ftype__snprintf(&self->proto, cu, bf, sizeof(bf),
			self->name, function__declared_inline(self), 0, 0);
	fputs(bf, stdout);

	if (show_variables || show_inline_expansions) {
		putchar('\n');
		lexblock__print(&self->lexblock, cu, 0);
	} else 
		puts(";");

	if (show_stats) {
		printf("/* size: %u", function__size(self));
		if (self->lexblock.nr_variables > 0)
			printf(", variables: %u", self->lexblock.nr_variables);
		if (self->lexblock.nr_labels > 0)
			printf(", goto labels: %u", self->lexblock.nr_labels);
		if (self->lexblock.nr_inline_expansions > 0)
			printf(", inline expansions: %u (%u bytes)",
			       self->lexblock.nr_inline_expansions,
			       self->lexblock.size_inline_expansions);
		fputs(" */\n", stdout);
	}
}

static int class__print_cacheline_boundary(uint32_t last_cacheline,
					   size_t sum, size_t sum_holes,
					   uint8_t *newline)
{
	const size_t real_sum = sum + sum_holes;
	const size_t cacheline = real_sum / cacheline_size;

	if (cacheline > last_cacheline) {
		const uint32_t cacheline_pos = real_sum % cacheline_size;
		const uint32_t cacheline_in_bytes = real_sum - cacheline_pos;

		if (*newline) {
			putchar('\n');
			*newline = 0;
		}

		if (cacheline_pos == 0)
			printf("        /* --- cacheline "
				"%u boundary (%u bytes) --- */\n",
				cacheline, cacheline_in_bytes);
		else
			printf("        /* --- cacheline "
				"%u boundary (%u bytes) was %u "
				"bytes ago --- */\n",
				cacheline, cacheline_in_bytes,
				cacheline_pos);
	}

	return cacheline;
}

static void class__print_struct(const struct tag *tag,
				const char *prefix, const char *suffix)
{
	struct class *self = tag__class(tag);
	uint32_t sum = 0;
	uint32_t sum_holes = 0;
	struct class_member *pos;
	size_t last_size = 0, size;
	uint32_t last_cacheline = 0;
	size_t last_bit_size = 0;
	int last_offset = -1;
	uint8_t newline = 0;
	uint32_t sum_bit_holes = 0;

	printf("%s%sstruct%s%s {\n", prefix ?: "", prefix ? " " : "",
	       self->name ? " " : "", self->name ?: "");
	list_for_each_entry(pos, &self->members, tag.node) {
		const ssize_t cc_last_size = pos->offset - last_offset;

		last_cacheline = class__print_cacheline_boundary(last_cacheline,
								 sum,
								 sum_holes,
								 &newline);

		if (last_offset != -1) {
			if (cc_last_size < last_size && cc_last_size > 0) {
				if (!newline++)
					putchar('\n');
				printf("        /* Bitfield WARNING: DWARF "
				       "size=%u, real size=%u */\n",
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
			putchar('\n');
			newline = 0;
		}

		fputs("        ", stdout);
		size = class_member__print(pos);

		if (pos->bit_hole != 0) {
			if (!newline++)
				putchar('\n');
			printf("\n        /* XXX %d bit%s hole, "
			       "try to pack */",
			       pos->bit_hole,
			       pos->bit_hole != 1 ? "s" : "");
			sum_bit_holes += pos->bit_hole;
		}

		if (pos->hole > 0) {
			if (!newline++)
				putchar('\n');
			printf("\n        /* XXX %d byte%s hole, "
			       "try to pack */",
			       pos->hole, pos->hole != 1 ? "s" : "");
			sum_holes += pos->hole;
		}

		putchar('\n');
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

	class__print_cacheline_boundary(last_cacheline, sum, sum_holes,
					&newline);

	printf("}%s%s; /* size: %u, cachelines: %u */\n",
	       suffix ? " ": "", suffix ?: "", self->size,
	       (self->size + cacheline_size - 1) / cacheline_size);
	if (sum_holes > 0)
		printf("   /* sum members: %lu, holes: %d, sum holes: %lu */\n",
		       sum, self->nr_holes, sum_holes);
	if (sum_bit_holes > 0)
		printf("   /* bit holes: %d, sum bit holes: %u bits */\n",
		       self->nr_bit_holes, sum_bit_holes);
	if (self->padding > 0)
		printf("   /* padding: %u */\n", self->padding);
	if (self->bit_padding > 0)
		printf("   /* bit_padding: %u bits */\n", self->bit_padding);
	last_cacheline = self->size % cacheline_size;
	if (last_cacheline != 0)
		printf("   /* last cacheline: %u bytes */\n", last_cacheline);

	if (sum + sum_holes != self->size - self->padding)
		printf("\n/* BRAIN FART ALERT! %u != "
		       "%u + %u(holes), diff = %u */\n\n",
		       self->size, sum, sum_holes,
		       self->size - (sum + sum_holes));
}

void tag__print(const struct tag *self, const struct cu *cu,
		const char *prefix, const char *suffix)
{
	printf("/* %s:%u */\n", self->decl_file, self->decl_line);

	switch (self->tag) {
	case DW_TAG_structure_type:
		class__print_struct(self, prefix, suffix);
		break;
	default:
		printf("%s: %s tag not supported!\n", __FUNCTION__,
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

static void cu__create_new_tag(Dwarf_Die *die, struct cu *cu)
{
	struct tag *self = tag__new(die);

	if (self == NULL)
		oom("tag__new");

	if (dwarf_haschildren(die))
		fprintf(stderr, "%s: %s WITH children!\n", __FUNCTION__,
			dwarf_tag_name(self->tag));

	cu__add_tag(cu, self);
}

static void cu__process_class(Dwarf_Die *die,
			      struct class *class, struct cu *cu);

static void cu__create_new_class(Dwarf_Die *die, struct cu *cu)
{
	Dwarf_Die child;
	struct class *class = class__new(die);

	if (class == NULL)
		oom("class__new");

	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		cu__process_class(&child, class, cu);
	class->cu = cu;
	cu__add_tag(cu, &class->tag);
}

static void cu__create_new_base_type(Dwarf_Die *die, struct cu *cu)
{
	struct base_type *base = base_type__new(die);

	if (base == NULL)
		oom("base_type__new");

	if (dwarf_haschildren(die))
		fprintf(stderr, "%s: DW_TAG_base_type WITH children!\n",
			__FUNCTION__);

	cu__add_tag(cu, &base->tag);
}

static void cu__create_new_array(Dwarf_Die *die, struct cu *cu)
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
		return;
	}

	die = &child;
	array->dimensions = 0;
	do {
		const uint16_t tag = dwarf_tag(die);

		if (tag == DW_TAG_subrange_type) {
			nr_entries[array->dimensions++] = attr_upper_bound(die);
			if (array->dimensions == max_dimensions) {
				fprintf(stderr, "%s: only %u dimensions are "
						"supported!\n",
					__FUNCTION__, max_dimensions);
				break;
			}
		} else
			fprintf(stderr, "%s: DW_TAG_%s not handled!\n",
				__FUNCTION__, dwarf_tag_name(tag));
	} while (dwarf_siblingof(die, die) == 0);

	array->nr_entries = memdup(nr_entries,
				   array->dimensions * sizeof(uint32_t));
	if (array->nr_entries == NULL)
		oom("memdup(array.nr_entries)");

	cu__add_tag(cu, &array->tag);
}

static void cu__create_new_parameter(Dwarf_Die *die, struct ftype *ftype)
{
	struct parameter *parm = parameter__new(die);

	if (parm == NULL)
		oom("parameter__new");

	ftype__add_parameter(ftype, parm);
}

static void cu__create_new_label(Dwarf_Die *die, struct lexblock *lexblock)
{
	struct label *label = label__new(die);

	if (label == NULL)
		oom("label__new");

	lexblock__add_label(lexblock, label);
}

static void cu__create_new_variable(struct cu *cu, Dwarf_Die *die,
				    struct lexblock *lexblock)
{
	struct variable *var = variable__new(die);
	if (var == NULL)
		oom("variable__new");

	lexblock__add_variable(lexblock, var);
	cu__add_variable(cu, var);
}

static void cu__create_new_subroutine_type(Dwarf_Die *die, struct cu *cu)
{
	Dwarf_Die child;
	struct ftype *ftype = ftype__new(die);

	if (ftype == NULL)
		oom("ftype__new");

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0)
		goto out;

	die = &child;
	do {
		const uint16_t tag = dwarf_tag(die);

		if (tag != DW_TAG_formal_parameter) {
			fprintf(stderr, "%s: DW_TAG_%s not handled!\n",
				__FUNCTION__, dwarf_tag_name(tag));
			continue;
		}

		cu__create_new_parameter(die, ftype);
	} while (dwarf_siblingof(die, die) == 0);
out:
	cu__add_tag(cu, &ftype->tag);
}

static void cu__process_class(Dwarf_Die *die, struct class *class,
			      struct cu *cu)
{
	Dwarf_Die child;
	const uint16_t tag = dwarf_tag(die);

	switch (tag) {
	case DW_TAG_invalid:
		return;
	case DW_TAG_inheritance:
	case DW_TAG_member: {
		struct class_member *member = class_member__new(die);

		if (member == NULL)
			oom("class_member__new");

		class__add_member(class, member);
	}
		break;
	case DW_TAG_formal_parameter:
		/* Discard for now */
		goto next_sibling;
	case DW_TAG_structure_type:
		/*
		 * structs within structs: C++
		 *
		 * FIXME: For now classes defined within classes are being
		 * visible externally, in a flat namespace. This ins not so
		 * much of a problem as every class has a different id, the
		 * cu_offset, but we need to have namespaces, so that we
		 * can properly print it in class__print_struct and so that
		 * we can specify 'pahole QDebug::Stream' as in the example
		 * that led to supporting classes within classes.
		 */
	default: /*
		  * Fall thru, enums, etc can also be defined inside
		  * C++ classes
		 */
		cu__create_new_class(die, cu);
		goto next_sibling;
	}

	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		cu__process_class(&child, class, cu);
next_sibling:
	if (dwarf_siblingof(die, die) == 0)
		cu__process_class(die, class, cu);
}

static void cu__process_function(Dwarf_Die *die,
				 struct cu *cu, struct ftype *ftype,
				 struct lexblock *lexblock);

static void cu__create_new_lexblock(Dwarf_Die *die,
				    struct cu *cu, struct lexblock *father)
{
	struct lexblock *lexblock = lexblock__new(die);

	if (lexblock == NULL)
		oom("lexblock__new");
	cu__process_function(die, cu, NULL, lexblock);
	lexblock__add_lexblock(father, lexblock);
}

static void cu__create_new_inline_expansion(struct cu *cu, Dwarf_Die *die,
					    struct lexblock *lexblock)
{
	struct inline_expansion *exp = inline_expansion__new(die);

	if (exp == NULL)
		oom("inline_expansion__new");

	lexblock__add_inline_expansion(lexblock, exp);
}

static void cu__process_function(Dwarf_Die *die,
				 struct cu *cu, struct ftype *ftype,
				 struct lexblock *lexblock)
{
	Dwarf_Die child;

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0)
		return;

	die = &child;
	do {
		const uint16_t tag = dwarf_tag(die);

		switch (tag) {
		case DW_TAG_formal_parameter:
			if (ftype != NULL)
				cu__create_new_parameter(die, ftype);
			break;
		case DW_TAG_variable:
			cu__create_new_variable(cu, die, lexblock);
			break;
		case DW_TAG_unspecified_parameters:
			if (ftype != NULL)
				ftype->unspec_parms = 1;
			break;
		case DW_TAG_label:
			cu__create_new_label(die, lexblock);
			break;
		case DW_TAG_inlined_subroutine:
			cu__create_new_inline_expansion(cu, die, lexblock);
			break;
		case DW_TAG_lexical_block:
			cu__create_new_lexblock(die, cu, lexblock);
			break;
		case DW_TAG_structure_type:
		case DW_TAG_union_type:
			cu__create_new_class(die, cu);
			break;
		}
	} while (dwarf_siblingof(die, die) == 0);
}

static void cu__create_new_function(Dwarf_Die *die, struct cu *cu)
{
	Dwarf_Attribute attr_name;
	struct function *function;
	Dwarf_Addr high_pc, low_pc;
	uint32_t decl_line;

	if (dwarf_highpc(die, &high_pc))
		high_pc = 0;
	if (dwarf_lowpc(die, &low_pc))
		low_pc = 0;

	dwarf_decl_line(die, &decl_line);
	function = function__new(die);
	if (function == NULL)
		oom("function__new");
	cu__process_function(die, cu, &function->proto, &function->lexblock);
	cu__add_function(cu, function);
}

static void cu__create_new_enumeration(Dwarf_Die *die, struct cu *cu)
{
	Dwarf_Die child;
	struct class *enumeration = class__new(die);

	if (enumeration == NULL)
		oom("class__new");

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0) {
		fprintf(stderr, "%s: DW_TAG_enumeration_type with no "
				"children!\n", __FUNCTION__);
		return;
	}

	die = &child;
	do {
		struct enumerator *enumerator;
		const uint16_t tag = dwarf_tag(die);

		if (tag != DW_TAG_enumerator) {
			fprintf(stderr, "%s: DW_TAG_%s not handled!\n",
				__FUNCTION__, dwarf_tag_name(tag));
			continue;
		}
		enumerator = enumerator__new(die);
		if (enumerator == NULL)
			oom("enumerator__new");

		enumeration__add(enumeration, enumerator);
	} while (dwarf_siblingof(die, die) == 0);

	enumeration->cu = cu;
	cu__add_tag(cu, &enumeration->tag);
}

static void cu__process_die(Dwarf_Die *die, struct cu *cu)
{
	Dwarf_Die child;

	switch (dwarf_tag(die)) {
	case DW_TAG_invalid:
		return;
	case DW_TAG_compile_unit:
		cu->language = attr_numeric(die, DW_AT_language);
		break;
	case DW_TAG_variable:
		/* Handle global variables later */
		break;
	case DW_TAG_subprogram:
		cu__create_new_function(die, cu);
		goto next_sibling;
	case DW_TAG_const_type:
	case DW_TAG_pointer_type:
	case DW_TAG_volatile_type:
		cu__create_new_tag(die, cu);
		goto next_sibling;
	case DW_TAG_base_type:
		cu__create_new_base_type(die, cu);
		goto next_sibling;
	case DW_TAG_array_type:
		cu__create_new_array(die, cu);
		goto next_sibling;
	case DW_TAG_subroutine_type:
		cu__create_new_subroutine_type(die, cu);
		goto next_sibling;
	case DW_TAG_enumeration_type:
		cu__create_new_enumeration(die, cu);
		goto next_sibling;
	default:
		cu__create_new_class(die, cu);
		goto next_sibling;
	}

	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		cu__process_die(&child, cu);
next_sibling:
	if (dwarf_siblingof(die, die) == 0)
		cu__process_die(die, cu);
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
	uint32_t cu_id;
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
	cu_id = 0;
	while (dwarf_nextcu(dwarf, offset, &offset, &hdr_size,
			    &abbrev_offset, &addr_size, &offset_size) == 0) {
		Dwarf_Die die;

		if (dwarf_offdie(dwarf, last_offset + hdr_size, &die) != NULL) {
			Dwarf_Attribute name;
			struct cu *cu = cu__new(cu_id,
						attr_string(&die, DW_AT_name,
							    &name),
						addr_size);
			if (cu == NULL)
				oom("cu__new");
			++cu_id;
			cu__process_die(&die, cu);
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

static int cus__emit_typedef_definitions(struct cus *self, struct tag *tdef)
{
	struct class *class = tag__class(tdef);
	struct tag *type, *ptr_type;
	int is_pointer = 0;
	char bf[512];

	/* Have we already emitted this in this CU? */
	if (class->visited)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (cus__find_definition(self, class->name) != NULL) {
		/*
		 * Yes, so lets mark it visited on this CU too,
		 * to speed up the lookup.
		 */
		class->visited = 1;
		return 0;
	}
	type = cu__find_tag_by_id(class->cu, class->tag.type);

	if (type->tag == DW_TAG_typedef)
		cus__emit_typedef_definitions(self, type);

	switch (type->tag) {
	case DW_TAG_pointer_type:
		ptr_type = cu__find_tag_by_id(class->cu, type->type);
		if (ptr_type->tag != DW_TAG_subroutine_type)
			break;
		type = ptr_type;
		is_pointer = 1;
		/* Fall thru */
	case DW_TAG_subroutine_type:
		cus__emit_ftype_definitions(self, class->cu, tag__ftype(type));
		ftype__snprintf(tag__ftype(type), class->cu, bf, sizeof(bf),
				class->name, 0, is_pointer, 0);
		fputs("typedef ", stdout);
		printf("%s;\n", bf);
		goto out;
	case DW_TAG_structure_type: {
		struct class *ctype = tag__class(type);

		if (ctype->name == NULL)
			cus__emit_struct_definitions(self, ctype,
						     "typedef", class->name);
		else
			printf("typedef struct %s %s;\n",
			       ctype->name, class->name);
	}
		goto out;
	}
	printf("typedef %s %s;\n", tag__name(type, class->cu, bf, sizeof(bf)),
	       class->name);
out:
	cus__add_definition(self, class);
	return 1;
}

static int cus__emit_enumeration_definitions(struct cus *self,
					     struct class *enumeration)
{
	/* Have we already emitted this in this CU? */
	if (enumeration->visited)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (cus__find_definition(self, enumeration->name) != NULL) {
		/*
		 * Yes, so lets mark it visited on this CU too,
		 * to speed up the lookup.
		 */
		enumeration->visited = 1;
		return 0;
	}
	enumeration__print(enumeration, NULL, 0);
	enumeration->visited = 1;
	return 1;
}

int cus__emit_fwd_decl(struct cus *self, struct class *class)
{
	struct class *type;
	char bf[256];

	/* Have we already emitted this in this CU? */
	if (class->fwd_decl_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (cus__find_fwd_decl(self, class->name) != NULL) {
		/*
		 * Yes, so lets mark it visited on this CU too,
		 * to speed up the lookup.
		 */
		class->fwd_decl_emitted = 1;
		return 0;
	}

	printf("struct %s;\n", class->name);
	cus__add_fwd_decl(self, class);
	return 1;
}

static int cus__emit_tag_definitions(struct cus *self, struct cu *cu,
				     struct tag *tag)
{
	struct tag *type = cu__find_tag_by_id(cu, tag->type);
	struct class *ctype;
	int pointer = 0;

	if (type == NULL)
		return 0;
next_indirection:
	if (type->tag == DW_TAG_pointer_type ||
	    type->tag == DW_TAG_array_type ||
	    type->tag == DW_TAG_const_type ||
	    type->tag == DW_TAG_volatile_type) {
		pointer = 1;
		type = cu__find_tag_by_id(cu, type->type);
		if (type == NULL)
			return 0;
		goto next_indirection;
	}

	ctype = tag__class(type);

	switch (type->tag) {
	case DW_TAG_typedef:
		return cus__emit_typedef_definitions(self, type);
	case DW_TAG_enumeration_type:
		if (tag__class(type)->name != NULL)
			return cus__emit_enumeration_definitions(self, ctype);
		break;
	case DW_TAG_structure_type:
		if (pointer)
			return cus__emit_fwd_decl(self, ctype);
		return cus__emit_struct_definitions(self, ctype, NULL, NULL);
	case DW_TAG_subroutine_type:
		return cus__emit_tag_definitions(self, cu, type);
	}

	return 0;
}

int cus__emit_ftype_definitions(struct cus *self, struct cu *cu,
				struct ftype *ftype)
{
	struct parameter *pos;
	/* First check the function return type */
	int printed = cus__emit_tag_definitions(self, cu, &ftype->tag);

	/* Then its parameters */
	list_for_each_entry(pos, &ftype->parms, tag.node)
		if (cus__emit_tag_definitions(self, cu, &pos->tag))
			printed = 1;

	if (printed)
		putchar('\n');
	return printed;
}

int cus__emit_struct_definitions(struct cus *self, struct class *class,
				 const char *prefix, const char *suffix)
{
	struct class_member *pos;
	int printed = 0;

	if (class->visited)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (cus__find_definition(self, class->name) != NULL) {
		class->visited = 1;
		return 0;
	}

	cus__add_definition(self, class);

	list_for_each_entry(pos, &class->members, tag.node)
		if (cus__emit_tag_definitions(self, class->cu, &pos->tag))
			printed = 1;

	if (printed)
		putchar('\n');

	class__find_holes(class);
	tag__print(&class->tag, class->cu, prefix, suffix);
	class->visited = 1;
	putchar('\n');
	return 1;
}
