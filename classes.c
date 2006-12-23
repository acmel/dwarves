/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#define _GNU_SOURCE
#include <dwarf.h>
#include <fcntl.h>
#include <elfutils/libdw.h>
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

const char *dwarf_tag_name(const unsigned int tag)
{
	if (tag >= DW_TAG_array_type && tag <= DW_TAG_shared_type)
		return dwarf_tag_names[tag];
	return "INVALID";
}

unsigned int cacheline_size = DEFAULT_CACHELINE_SIZE;

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

static void tag__init(struct tag *self, uint16_t tag,
		      uint64_t id, uint64_t type,
		      const char *decl_file, uint32_t decl_line)
{
	self->tag	= tag;
	self->id	= id;
	self->type	= type;
	self->decl_file = strings__add(decl_file);
	self->decl_line = decl_line;
}

static struct variable *variable__new(const char *name, uint64_t id,
				      uint64_t type,
				      const char *decl_file,
				      uint32_t decl_line,
				      uint64_t abstract_origin)
{
	struct variable *self = malloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, DW_TAG_variable, id, type,
			  decl_file, decl_line);
		self->name	      = strings__add(name);
		self->abstract_origin = abstract_origin;
	}

	return self;
}

static void cus__add(struct cus *self, struct cu *cu)
{
	list_add_tail(&cu->node, &self->cus);
}

static struct cu *cu__new(unsigned int cu, const char *name)
{
	struct cu *self = malloc(sizeof(*self));

	if (self != NULL) {
		INIT_LIST_HEAD(&self->classes);
		INIT_LIST_HEAD(&self->functions);
		INIT_LIST_HEAD(&self->variables);
		INIT_LIST_HEAD(&self->tool_list);
		self->name = strings__add(name);
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

static void cu__add_class(struct cu *self, struct class *class)
{
	class->cu = self;
	list_add_tail(&class->tag.node, &self->classes);
}

static void cu__add_function(struct cu *self, struct function *function)
{
	function->cu = self;
	list_add_tail(&function->tag.node, &self->functions);
}

static void cu__add_variable(struct cu *self, struct variable *variable)
{
	variable->cu = self;
	list_add_tail(&variable->cu_node, &self->variables);
}

static const char *tag_name(const struct cu *cu, const unsigned int tag)
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

int tag__fwd_decl(const struct cu *cu, const struct tag *tag)
{
	struct class *type = cu__find_class_by_id(cu, tag->type);

	/* void ? */
	if (type == NULL)
		return 0;

	if (type->tag.tag == DW_TAG_enumeration_type)
		goto out;

	if (type->tag.tag != DW_TAG_pointer_type)
		return 0;

next_indirection:
	type = cu__find_class_by_id(cu, type->tag.type);
	if (type != NULL && type->tag.tag == DW_TAG_pointer_type)
		goto next_indirection;

	if (type == NULL || type->tag.tag != DW_TAG_structure_type)
		return 0;

	if (type->visited)
		return 0;
out:
	type->visited = 1;
	printf("%s%s;\n", tag_name(cu, type->tag.tag), type->name);

	return 1;
}

struct class *cu__find_class_by_name(const struct cu *self, const char *name)
{
	struct class *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, &self->classes, tag.node)
		if (pos->name != NULL &&
		    /* FIXME: here there shouldn't be anything other
		     * than DW_TAG_structure types anyway...  */
		    pos->tag.tag == DW_TAG_structure_type &&
		    strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

struct class *cus__find_class_by_name(const struct cus *self, const char *name)
{
	struct cu *pos;

	list_for_each_entry(pos, &self->cus, node) {
		struct class *class = cu__find_class_by_name(pos, name);

		if (class != NULL)
			return class;
	}

	return NULL;
}

struct function *cus__find_function_by_name(const struct cus *self,
					    const char *name)
{
	struct cu *pos;

	list_for_each_entry(pos, &self->cus, node) {
		struct function *function = cu__find_function_by_name(pos, name);

		if (function != NULL)
			return function;
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

	list_for_each_entry(pos, &self->definitions, node)
		if (strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

struct class *cus__find_fwd_decl(const struct cus *self, const char *name)
{
	struct class *pos;

	list_for_each_entry(pos, &self->fwd_decls, node)
		if (strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

static void cus__add_definition(struct cus *self, struct class *class)
{
	list_add_tail(&class->node, &self->definitions);
}

static void cus__add_fwd_decl(struct cus *self, struct class *class)
{
	list_add_tail(&class->node, &self->fwd_decls);
}

struct class *cu__find_class_by_id(const struct cu *self, const uint64_t id)
{
	struct class *pos;

	if (id == 0)
		return NULL;

	list_for_each_entry(pos, &self->classes, tag.node)
		if (pos->tag.id == id)
			return pos;

	return NULL;
}

struct function *cu__find_function_by_name(const struct cu *self,
					   const char *name)
{
	struct function *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, &self->functions, tag.node)
		if (pos->name != NULL && strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

struct function *cu__find_function_by_id(const struct cu *self,
					 const uint64_t id)
{
	struct function *pos;

	list_for_each_entry(pos, &self->functions, tag.node)
		if (pos->tag.id == id)
			return pos;

	return NULL;
}

struct variable *cu__find_variable_by_id(const struct cu *self, const uint64_t id)
{
	struct variable *pos;

	list_for_each_entry(pos, &self->variables, cu_node)
		if (pos->tag.id == id)
			return pos;

	return NULL;
}

int class__is_struct(const struct class *self,
		     struct class **typedef_alias)
{
	*typedef_alias = NULL;
	if (self->tag.tag == DW_TAG_typedef) {
		*typedef_alias = cu__find_class_by_id(self->cu, self->tag.type);
		if (*typedef_alias == NULL)
			return 0;
		
		return (*typedef_alias)->tag.tag == DW_TAG_structure_type;
	}

	return self->tag.tag == DW_TAG_structure_type;
}

static size_t class__array_nr_entries(const struct class *self)
{
	int i;
	size_t nr_entries = 1;

	for (i = 0; i < self->array.dimensions; ++i)
		nr_entries *= self->array.nr_entries[i];

	return nr_entries;
}

static uint64_t class__size(const struct class *self)
{
	uint64_t size = self->size;

	if (self->tag.tag != DW_TAG_pointer_type && self->tag.type != 0) {
		struct class *class = cu__find_class_by_id(self->cu,
							   self->tag.type);
		if (class != NULL)
			size = class__size(class);
	}

	if (self->tag.tag == DW_TAG_array_type)
		size *= class__array_nr_entries(self);

	return size;
}

const char *class__name(const struct class *self, char *bf, size_t len)
{
	if (self == NULL)
		strncpy(bf, "void", len);
	else if (self->tag.tag == DW_TAG_pointer_type) {
		if (self->tag.type == 0) /* No type == void */
			strncpy(bf, "void *", len);
		else {
			struct class *ptr_class =
					cu__find_class_by_id(self->cu,
							     self->tag.type);
			char ptr_class_name[128];
			snprintf(bf, len, "%s *",
				 class__name(ptr_class, ptr_class_name,
					     sizeof(ptr_class_name)));
		}
	} else if (self->tag.tag == DW_TAG_volatile_type ||
		   self->tag.tag == DW_TAG_const_type) {
		struct class *vol_class = cu__find_class_by_id(self->cu,
							       self->tag.type);
		char vol_class_name[128];
		snprintf(bf, len, "%s %s ",
			 self->tag.tag == DW_TAG_volatile_type ?
				"volatile" : "const",
			 class__name(vol_class, vol_class_name,
				     sizeof(vol_class_name)));
	} else if (self->tag.tag == DW_TAG_array_type) {
		struct class *ptr_class = cu__find_class_by_id(self->cu,
							       self->tag.type);
		return class__name(ptr_class, bf, len);
	} else
		snprintf(bf, len, "%s%s", tag_name(self->cu, self->tag.tag),
			 self->name ?: "");
	return bf;
}

const char *variable__type_name(const struct variable *self,
				char *bf, size_t len)
{
	if (self->tag.type != 0) {
		struct class *class = cu__find_class_by_id(self->cu,
							   self->tag.type);
		return class__name(class, bf, len);
	} else if (self->abstract_origin != 0) {
		struct variable *var;

		var = cu__find_variable_by_id(self->cu,
					      self->abstract_origin);
		if (var != NULL)
		       return variable__type_name(var, bf, len);
	}
	
	return NULL;
}

const char *variable__name(const struct variable *self)
{
	if (self->name == NULL) {
		if (self->abstract_origin == 0)
			return NULL;
		else {
			struct variable *var;

			var = cu__find_variable_by_id(self->cu,
						      self->abstract_origin);
			return var == NULL ? NULL : var->name;
		}
	}
	
	return self->name;
}

static struct class_member *class_member__new(uint64_t id,
					      uint16_t tag,
					      uint64_t type,
					      const char *decl_file,
					      uint32_t decl_line,
					      const char *name,
					      uint64_t offset,
					      unsigned int bit_size,
					      unsigned int bit_offset)
{
	struct class_member *self = zalloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, tag, id, type,
			  decl_file, decl_line);
		self->offset	  = offset;
		self->bit_size	  = bit_size;
		self->bit_offset  = bit_offset;
		self->name	  = strings__add(name);
	}

	return self;
}

static int class_member__size(const struct class_member *self)
{
	struct class *class = cu__find_class_by_id(self->class->cu,
						   self->tag.type);
	return class != NULL ? class__size(class) : -1;
}

uint64_t class_member__names(const struct class_member *self,
			     char *class_name, size_t class_name_size,
			     char *member_name, size_t member_name_size)
{
	struct class *class = cu__find_class_by_id(self->class->cu,
						   self->tag.type);
	uint64_t size = -1;

	snprintf(member_name, member_name_size, "%s;", self->name ?: "");

	if (class == NULL)
		snprintf(class_name, class_name_size, "<%llx>",
			 self->tag.type);
	else {
		if (class->tag.tag == DW_TAG_const_type)
			class = cu__find_class_by_id(class->cu,
						     class->tag.type);
		size = class__size(class);

		/* Is it a function pointer? */
		if (class->tag.tag == DW_TAG_pointer_type) {
			struct class *ptr_class =
				   cu__find_class_by_id(self->class->cu,
							class->tag.type);

			if (ptr_class != NULL &&
			    ptr_class->tag.tag == DW_TAG_subroutine_type) {
				/* function has no return value (void) */
				if (ptr_class->tag.type == 0)
					snprintf(class_name,
						 class_name_size, "void");
				else {
					struct class *ret_class =
				     cu__find_class_by_id(self->class->cu,
							  ptr_class->tag.type);

					class__name(ret_class, class_name,
						    class_name_size);
				}
				snprintf(member_name, member_name_size,
					 "(*%s)();", self->name ?: "");
				goto out;
			}
		}

		class__name(class, class_name, class_name_size);
		if (class->tag.tag == DW_TAG_array_type) {
			int i = 0;
			size_t n = snprintf(member_name, member_name_size,
					    "%s", self->name);
			member_name += n;
			member_name_size -= n;

			for (i = 0; i < class->array.dimensions; ++i) {
				n = snprintf(member_name, member_name_size,
					     "[%u]",
					     class->array.nr_entries[i]);
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

size_t parameter__names(const struct parameter *self,
			char *class_name, size_t class_name_size,
			char *parameter_name, size_t parameter_name_size)
{
	struct class *class = cu__find_class_by_id(self->function->cu,
						   self->tag.type);
	size_t size = -1;

	snprintf(parameter_name, parameter_name_size, "%s", self->name ?: "");

	if (class == NULL)
		snprintf(class_name, class_name_size, "<%llx>",
			 self->tag.type);
	else {
		if (class->tag.tag == DW_TAG_const_type)
			class = cu__find_class_by_id(class->cu,
						     class->tag.type);
		size = class__size(class);

		/* Is it a function pointer? */
		if (class->tag.tag == DW_TAG_pointer_type) {
			struct class *ptr_class =
				   cu__find_class_by_id(self->function->cu,
							class->tag.type);

			if (ptr_class != NULL &&
			    ptr_class->tag.tag == DW_TAG_subroutine_type) {
				/* function has no return value (void) */
				if (ptr_class->tag.type == 0)
					snprintf(class_name,
						 class_name_size, "void");
				else {
					struct class *ret_class =
				     cu__find_class_by_id(self->function->cu,
							  ptr_class->tag.type);

					class__name(ret_class, class_name,
						    class_name_size);
				}
				snprintf(parameter_name, parameter_name_size,
					 "(*%s)(void /* FIXME: add "
					 "parameter list */)",
					 self->name ?: "");
				goto out;
			}
		}

		class__name(class, class_name, class_name_size);
		if (class->tag.tag == DW_TAG_array_type) {
			int i = 0;
			size_t n = snprintf(parameter_name,
					    parameter_name_size,
					    "%s", self->name);
			parameter_name += n;
			parameter_name_size -= n;

			for (i = 0; i < class->array.dimensions; ++i) {
				n = snprintf(parameter_name,
					     parameter_name_size, "[%u]",
					     class->array.nr_entries[i]);
				parameter_name += n;
				parameter_name_size -= n;
			}
		}
	}
out:
	return size;
}

static uint64_t class_member__print(struct class_member *self)
{
	uint64_t size;
	char class_name[128];
	char member_name[128];

	size = class_member__names(self, class_name, sizeof(class_name),
				   member_name, sizeof(member_name));

	if (self->tag.tag == DW_TAG_inheritance) {
		snprintf(member_name, sizeof(member_name),
			 "/* ancestor class */");
		strncat(class_name, ";", sizeof(class_name));
	}

	printf("%-26s %-21s /* %5llu %5llu */",
	       class_name, member_name, self->offset, size);
	return size;
}

static struct parameter *parameter__new(uint64_t id, uint64_t type,
					const char *decl_file,
					uint32_t decl_line,
					const char *name)
{
	struct parameter *self = zalloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, DW_TAG_formal_parameter, id, type,
			  decl_file, decl_line);
		self->name	  = strings__add(name);
	}

	return self;
}

static struct inline_expansion *inline_expansion__new(uint64_t id,
						      uint64_t type,
						      const char *decl_file,
						      uint32_t decl_line,
						      uint32_t size)
{
	struct inline_expansion *self = zalloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, DW_TAG_inlined_subroutine, id, type,
			  decl_file, decl_line);
		self->size = size;
	}

	return self;
}

static struct label *label__new(uint64_t id, uint64_t type,
				const char *decl_file, uint32_t decl_line,
				const char *name, uint64_t low_pc)
{
	struct label *self = malloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, DW_TAG_label, id, type,
			  decl_file, decl_line);
		self->name   = strings__add(name);
		self->low_pc = low_pc;
	}

	return self;
}

static struct class *class__new(const unsigned int tag,
				uint64_t id, uint64_t type,
				const char *name, uint64_t size,
				const char *decl_file, unsigned int decl_line,
				unsigned char declaration)
{
	struct class *self = zalloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, tag, id, type, decl_file, decl_line);
		INIT_LIST_HEAD(&self->members);
		self->size = size;
		self->name = strings__add(name);
		self->declaration = declaration;
	}

	return self;
}

static void class__add_member(struct class *self, struct class_member *member)
{
	++self->nr_members;
	member->class = self;
	list_add_tail(&member->tag.node, &self->members);
}

static void lexblock__init(struct lexblock *self)
{
	INIT_LIST_HEAD(&self->labels);
	INIT_LIST_HEAD(&self->variables);
	INIT_LIST_HEAD(&self->inline_expansions);

	self->nr_labels =
		self->nr_variables =
		self->nr_inline_expansions = 0;
}

static struct function *function__new(uint64_t id, uint64_t type,
				      const char *decl_file,
				      unsigned int decl_line,
				      const char *name,
				      unsigned short inlined, char external,
				      uint64_t low_pc, uint64_t high_pc)
{
	struct function *self = zalloc(sizeof(*self));

	if (self != NULL) {
		tag__init(&self->tag, DW_TAG_subprogram,
			  id, type, decl_file, decl_line);

		INIT_LIST_HEAD(&self->parameters);
		lexblock__init(&self->lexblock);
		self->name     = strings__add(name);
		self->inlined  = inlined;
		self->external = external;
		self->low_pc   = low_pc;
		self->high_pc  = high_pc;
	}

	return self;
}

int function__has_parameter_of_type(const struct function *self,
				    const struct class *target)
{
	struct class_member *pos;

	list_for_each_entry(pos, &self->parameters, tag.node) {
		struct class *class = cu__find_class_by_id(self->cu,
							   pos->tag.type);

		if (class != NULL && class->tag.tag == DW_TAG_pointer_type) {
			class = cu__find_class_by_id(self->cu, class->tag.type);
			if (class != NULL &&
			    class->tag.id == target->tag.id)
				return 1;
		}
	}
	return 0;
}

static void function__add_parameter(struct function *self,
				    struct parameter *parameter)
{
	++self->nr_parameters;
	parameter->function = self;
	list_add_tail(&parameter->tag.node, &self->parameters);
}

static void lexblock__add_inline_expansion(struct lexblock *self,
					   struct inline_expansion *exp)
{
	++self->nr_inline_expansions;
	self->size_inline_expansions += exp->size;
	list_add_tail(&exp->tag.node, &self->inline_expansions);
}

static void lexblock__add_variable(struct lexblock *self, struct variable *var)
{
	++self->nr_variables;
	list_add_tail(&var->tag.node, &self->variables);
}

static void lexblock__add_label(struct lexblock *self, struct label *label)
{
	++self->nr_labels;
	list_add_tail(&label->tag.node, &self->labels);
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
	uint64_t last_size = 0, size;
	unsigned int bit_sum = 0;

	self->nr_holes = 0;
	self->nr_bit_holes = 0;

	list_for_each_entry(pos, &self->members, tag.node) {
		if (last != NULL) {
			const int cc_last_size = pos->offset - last->offset;

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

static void function__account_inline_expansions(struct function *self)
{
	struct function *type;
	struct inline_expansion *pos;

	if (self->lexblock.nr_inline_expansions == 0)
		return;

	list_for_each_entry(pos, &self->lexblock.inline_expansions, tag.node) {
		type = cu__find_function_by_id(self->cu, pos->tag.type);
		if (type != NULL) {
			type->cu_total_nr_inline_expansions++;
			type->cu_total_size_inline_expansions += pos->size;
		}

	}
}

void cu__account_inline_expansions(struct cu *self)
{
	struct function *pos;

	list_for_each_entry(pos, &self->functions, tag.node) {
		function__account_inline_expansions(pos);
		self->nr_inline_expansions   += pos->lexblock.nr_inline_expansions;
		self->size_inline_expansions += pos->lexblock.size_inline_expansions;
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

static void tag__print(const struct tag *tag)
{
	char bf[512];
	const void *vtag = tag;
	int c = 8;

	switch (tag->tag) {
	case DW_TAG_inlined_subroutine: {
		const struct inline_expansion *exp = vtag;
		const struct function *alias =
				cu__find_function_by_id(exp->function->cu,
							exp->tag.type);

		fputs("        ", stdout);
		c += printf("%s();", alias != NULL ? alias->name : "<ERROR>");
	}
		break;
	case DW_TAG_variable:
		fputs("        ", stdout);
		c += printf("%s %s;", variable__type_name(vtag, bf, sizeof(bf)),
			    variable__name(vtag));
		break;
	case DW_TAG_label: {
		const struct label *label = vtag;
		putchar('\n');
		c = printf("%s:", label->name);
	}
		break;
	default:
		fputs("        ", stdout);
		c += printf("%s <%llx>", dwarf_tag_name(tag->tag), tag->id);
		break;
	}

	printf("%-*.*s// %5u\n", 70 - c, 70 - c, " ",  tag->decl_line);
}

static void tags__action(const void *nodep, const VISIT which, const int depth)
{
	if (which == postorder || which == leaf) {
		const struct tag *tag = *(struct tag **)nodep;
		tag__print(tag);
	}
}

static void function__print_body(const struct function *self,
				 const int show_variables,
				 const int show_inline_expansions,
				 const int show_labels)
{
	void *tags = NULL;
	struct tag *pos;

	if (show_variables)
		list_for_each_entry(pos, &self->lexblock.variables, node) {
			/* FIXME! this test shouln't be needed at all */
			if (pos->decl_line >= self->tag.decl_line)
				tags__add(&tags, pos);
		}

	if (show_inline_expansions)
		list_for_each_entry(pos, &self->lexblock.inline_expansions, node) {
			/* FIXME! this test shouln't be needed at all */
			if (pos->decl_line >= self->tag.decl_line)
				tags__add(&tags, pos);
		}

	if (show_labels)
		list_for_each_entry(pos, &self->lexblock.labels, node) {
			/* FIXME! this test shouln't be needed at all */
			if (pos->decl_line >= self->tag.decl_line)
				tags__add(&tags, pos);
		}

	puts("{");
	twalk(tags, tags__action);
	puts("}\n");

	tdestroy(tags, tags__free);
}

void function__print(const struct function *self, int show_stats,
		     const int show_variables,
		     const int show_inline_expansions)
{
	char bf[256];
	struct class *class_type;
	const char *type = "<ERROR>";
	struct parameter *pos;
	int first_parameter = 1;

	class_type = cu__find_class_by_id(self->cu, self->tag.type);
	type = class__name(class_type, bf, sizeof(bf));

	printf("/* %s:%u */\n", self->tag.decl_file, self->tag.decl_line);
	printf("%s%s %s(", function__declared_inline(self) ? "inline " : "",
	       type, self->name ?: "");
	list_for_each_entry(pos, &self->parameters, tag.node) {
		if (!first_parameter)
			fputs(", ", stdout);
		else
			first_parameter = 0;
		type = "<ERROR>";
		class_type = cu__find_class_by_id(self->cu, pos->tag.type);
		type = class__name(class_type, bf, sizeof(bf));
		printf("%s %s", type, pos->name ?: "");
	}

	/* No parameters? */
	if (first_parameter)
		fputs("void", stdout);
	else if (self->unspecified_parameters)
		fputs(", ...", stdout);
	fputs(");\n", stdout);

	if (show_variables || show_inline_expansions)
		function__print_body(self, show_variables,
				     show_inline_expansions, 1);

	if (show_stats) {
		printf("/* size: %llu", self->high_pc - self->low_pc);
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
	const unsigned int real_sum = sum + sum_holes;
	const unsigned int cacheline = real_sum / cacheline_size;

	if (cacheline > last_cacheline) {
		const unsigned int cacheline_pos = real_sum % cacheline_size;
		const unsigned cacheline_in_bytes = real_sum - cacheline_pos;

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

static void class__print_struct(const struct class *self,
				const char *prefix, const char *suffix)
{
	unsigned long sum = 0;
	unsigned long sum_holes = 0;
	struct class_member *pos;
	char name[128];
	uint64_t last_size = 0, size;
	unsigned int last_cacheline = 0;
	int last_bit_size = 0;
	int last_offset = -1;
	uint8_t newline = 0;
	unsigned int sum_bit_holes = 0;

	printf("%s%s {\n", prefix ? : "",
	       class__name(self, name, sizeof(name)));
	list_for_each_entry(pos, &self->members, tag.node) {
		const int cc_last_size = pos->offset - last_offset;

		last_cacheline = class__print_cacheline_boundary(last_cacheline,
								 sum,
								 sum_holes,
								 &newline);

		if (last_offset != -1) {
			if (cc_last_size < last_size && cc_last_size > 0) {
				if (!newline++)
					putchar('\n');
				printf("        /* Bitfield WARNING: DWARF "
				       "size=%llu, real size=%u */\n",
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

	printf("}%s; /* size: %llu, cachelines: %llu */\n",
	       suffix ?: "", self->size,
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
		printf("\n/* BRAIN FART ALERT! %llu != "
		       "%lu + %lu(holes), diff = %llu */\n\n",
		       self->size, sum, sum_holes,
		       self->size - (sum + sum_holes));
}

void class__print(const struct class *self,
		  const char *prefix, const char *suffix)
{
	printf("/* %s:%u */\n", self->tag.decl_file, self->tag.decl_line);

	switch (self->tag.tag) {
	case DW_TAG_structure_type:
		class__print_struct(self, prefix, suffix);
		break;
	default:
		printf("%s%s;\n", tag_name(self->cu, self->tag.tag),
		       self->name ?: "");
		break;
	}
}

int cu__for_each_class(struct cu *self,
		       int (*iterator)(struct class *class, void *cookie),
		       void *cookie,
		       struct class *(*filter)(struct class *class))
{
	struct class *pos;

	list_for_each_entry(pos, &self->classes, tag.node) {
		struct class *class = pos;
		if (filter != NULL) {
			class = filter(pos);
			if (class == NULL)
				continue;
		}
		if (iterator(class, cookie))
			return 1;
	}
	return 0;
}

int cu__for_each_function(struct cu *cu,
			  int (*iterator)(struct function *func, void *cookie),
			  void *cookie,
			  struct function *(*filter)(struct function *function,
				  		     void *cookie))
{

	struct function *pos;

	list_for_each_entry(pos, &cu->functions, tag.node) {
		struct function *function = pos;
		if (filter != NULL) {
			function = filter(pos, cookie);
			if (function == NULL)
				continue;
		}
		if (iterator(function, cookie))
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
	fprintf(stderr, "pahole: out of memory(%s)\n", msg);
	exit(EXIT_FAILURE);
}

static const char *attr_string(Dwarf_Die *die, unsigned int name,
			       Dwarf_Attribute *attr)
{
	if (dwarf_attr(die, name, attr) != NULL)
		return dwarf_formstring(attr);
	return NULL;
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

static uint64_t __libdw_get_uleb128(uint64_t acc, unsigned int i,
				    const unsigned char **addrp)
{
	unsigned char __b;
	get_uleb128_rest_return (acc, i, addrp);
}

#define get_uleb128(var, addr)					\
	do {							\
		unsigned char __b;				\
		var = 0;					\
		get_uleb128_step(var, addr, 0, break);		\
		var = __libdw_get_uleb128 (var, 1, &(addr));	\
	} while (0)


static uint64_t attr_offset(Dwarf_Die *die)
{
	Dwarf_Attribute attr;

	if (dwarf_attr(die, DW_AT_data_member_location, &attr) != NULL) {
		Dwarf_Block block;

		if (dwarf_formblock(&attr, &block) == 0) {
			uint64_t uleb;
			const unsigned char *data = block.data + 1;
			get_uleb128(uleb, data);
			return uleb;
		}
	}

	return 0;
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

static uint64_t attr_numeric(Dwarf_Die *die, unsigned int name)
{
	Dwarf_Attribute attr;
	unsigned int form;

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

static void cu__process_class(Dwarf *dwarf, Dwarf_Die *die,
			      struct class *class, struct cu *cu);

static void cu__create_new_class(Dwarf *dwarf, Dwarf_Die *die, struct cu *cu,
				 unsigned int tag, Dwarf_Off cu_offset,
				 const char *name, uint64_t type,
				 const char *decl_file, int decl_line)
{
	Dwarf_Die child;
	uint64_t size = attr_numeric(die, DW_AT_byte_size);
	struct class *class = class__new(tag, cu_offset, type, name, size,
					 decl_file, decl_line,
					 attr_numeric(die, DW_AT_declaration));
	if (class == NULL)
		oom("class__new");
	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		cu__process_class(dwarf, &child, class, cu);
	cu__add_class(cu, class);
}

static void cu__create_new_array(Dwarf *dwarf, Dwarf_Die *die, struct cu *cu,
				 Dwarf_Off cu_offset, uint64_t type,
				 const char *decl_file, int decl_line)
{
	Dwarf_Die child;
	/* "64 dimensions will be enough for everybody." acme, 2006 */
	const uint8_t max_dimensions = 64;
	uint32_t nr_entries[max_dimensions];
	const uint64_t size = attr_numeric(die, DW_AT_byte_size);
	struct class *class = class__new(DW_TAG_array_type, cu_offset, type,
					 NULL, size, decl_file, decl_line, 0);
	if (class == NULL)
		oom("class__new");

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0) {
		fprintf(stderr, "%s: DW_TAG_array_type with no children!\n",
			__FUNCTION__);
		return;
	}

	die = &child;
	class->array.dimensions = 0;
	do {
		const uint16_t tag = dwarf_tag(die);

		if (tag == DW_TAG_subrange_type) {
			nr_entries[class->array.dimensions++] = attr_upper_bound(die);
			if (class->array.dimensions == max_dimensions) {
				fprintf(stderr, "%s: only %u dimensions are "
						"supported!\n",
					__FUNCTION__, max_dimensions);
				break;
			}
		} else
			fprintf(stderr, "%s: DW_TAG_%s not handled!\n",
				__FUNCTION__, dwarf_tag_name(tag));
	} while (dwarf_siblingof(die, die) == 0);

	class->array.nr_entries = memdup(nr_entries,
					 (class->array.dimensions *
					  sizeof(uint32_t)));
	if (class->array.nr_entries == NULL)
		oom("memdup(array.nr_entries)");

	cu__add_class(cu, class);
}

static void cu__process_class(Dwarf *dwarf, Dwarf_Die *die, struct class *class,
			      struct cu *cu)
{
	Dwarf_Die child;
	Dwarf_Off cu_offset;
	Dwarf_Attribute attr_name;
	const char *decl_file, *name;
	uint64_t type;
	int decl_line = 0;
	unsigned int tag = dwarf_tag(die);

	if (tag == DW_TAG_invalid)
		return;

	cu_offset = dwarf_cuoffset(die);
	decl_file = dwarf_decl_file(die);
	type	  = attr_numeric(die, DW_AT_type);
	name	  = attr_string(die, DW_AT_name, &attr_name);

	dwarf_decl_line(die, &decl_line);

	switch (tag) {
	case DW_TAG_inheritance:
	case DW_TAG_member: {
		struct class_member *member;
		
		member = class_member__new(cu_offset, tag, type,
					   decl_file, decl_line,
					   name, attr_offset(die),
					   attr_numeric(die, DW_AT_bit_size),
					   attr_numeric(die, DW_AT_bit_offset));
		if (member == NULL)
			oom("class_member__new");

		class__add_member(class, member);
	}
		break;
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
		cu__create_new_class(dwarf, die, cu, tag, cu_offset,
				     name, type, decl_file, decl_line);
		goto next_sibling;
	}

	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		cu__process_class(dwarf, &child, class, cu);
next_sibling:
	if (dwarf_siblingof(die, die) == 0)
		cu__process_class(dwarf, die, class, cu);
}

static void cu__process_function(Dwarf *dwarf, Dwarf_Die *die,
				 struct cu *cu, struct function *function,
				 struct lexblock *lexblock)
{
	Dwarf_Die child;
	Dwarf_Off cu_offset;
	Dwarf_Attribute attr_name;
	const char *decl_file;
	int decl_line = 0;
	const char *name;
	uint64_t type;
	unsigned int tag = dwarf_tag(die);

	if (tag == DW_TAG_invalid)
		return;

	cu_offset = dwarf_cuoffset(die);
	name	  = attr_string(die, DW_AT_name, &attr_name);
	type	  = attr_numeric(die, DW_AT_type);
	decl_file = dwarf_decl_file(die);

	dwarf_decl_line(die, &decl_line);

	switch (tag) {
	case DW_TAG_formal_parameter: {
		struct parameter *parameter;
		
		parameter = parameter__new(cu_offset, type,
					   decl_file, decl_line, name);
		if (parameter == NULL)
			oom("parameter__new");

		function__add_parameter(function, parameter);
	}
		break;
	case DW_TAG_variable: {
		uint64_t abstract_origin = attr_numeric(die,
							DW_AT_abstract_origin);
		struct variable *variable;

		variable = variable__new(name, cu_offset,
					 type, decl_file, decl_line,
					 abstract_origin);
		if (variable == NULL)
			oom("variable__new");

		lexblock__add_variable(lexblock, variable);
		cu__add_variable(cu, variable);
	}
		break;
	case DW_TAG_unspecified_parameters:
		function->unspecified_parameters = 1;
		break;
	case DW_TAG_label: {
		struct label *label;
		Dwarf_Addr low_pc;

		if (dwarf_lowpc(die, &low_pc))
			low_pc = 0;

		label = label__new(cu_offset, type, decl_file, decl_line,
				   name, low_pc);
		if (label == NULL)
			oom("label__new");

		lexblock__add_label(lexblock, label);
	}
		break;
	case DW_TAG_inlined_subroutine: {
		Dwarf_Addr high_pc, low_pc;
		Dwarf_Attribute attr_call_file;
		const uint64_t type = attr_numeric(die, DW_AT_abstract_origin);
		struct inline_expansion *exp;
		uint32_t size;

		if (dwarf_highpc(die, &high_pc))
			high_pc = 0;
		if (dwarf_lowpc(die, &low_pc))
			low_pc = 0;

		size = high_pc - low_pc;
		if (size == 0) {
			Dwarf_Addr base, start, end;
			ptrdiff_t offset = 0;

			while (1) {
				offset = dwarf_ranges(die, offset, &base, &start, &end);
				if (offset <= 0)
					break;
				size += end - start;
			}
		}

		decl_file = attr_string(die, DW_AT_call_file, &attr_call_file);
		decl_line = attr_numeric(die, DW_AT_call_line);

		exp = inline_expansion__new(cu_offset, type,
					    decl_file, decl_line, size);
		if (exp == NULL)
			oom("inline_expansion__new");

		lexblock__add_inline_expansion(lexblock, exp);
		exp->function = function;
	}
		goto next_sibling;
	case DW_TAG_lexical_block:
		/*
		 * Not handled right now,
		 * will be used for stack size calculation
		 */
		break;
	}

	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		cu__process_function(dwarf, &child, cu, function, lexblock);
next_sibling:
	if (dwarf_siblingof(die, die) == 0)
		cu__process_function(dwarf, die, cu, function, lexblock);
}

static void cu__process_die(Dwarf *dwarf, Dwarf_Die *die, struct cu *cu)
{
	Dwarf_Die child;
	Dwarf_Off cu_offset;
	Dwarf_Attribute attr_name;
	const char *decl_file;
	int decl_line = 0;
	const char *name;
	uint64_t type;
	unsigned int tag = dwarf_tag(die);

	if (tag == DW_TAG_invalid)
		return;

	if (tag == DW_TAG_compile_unit) {
		cu->language = attr_numeric(die, DW_AT_language);
		goto children;
	}

	cu_offset = dwarf_cuoffset(die);
	name	  = attr_string(die, DW_AT_name, &attr_name);
	type	  = attr_numeric(die, DW_AT_type);
	decl_file = dwarf_decl_file(die);

	dwarf_decl_line(die, &decl_line);

	switch (tag) {
	case DW_TAG_variable:
		/* Handle global variables later */
		break;
	case DW_TAG_subprogram: {
		struct function *function;
		const unsigned short inlined = attr_numeric(die, DW_AT_inline);
		const char external = dwarf_hasattr(die, DW_AT_external);
		Dwarf_Addr high_pc, low_pc;

		if (dwarf_highpc(die, &high_pc))
			high_pc = 0;
		if (dwarf_lowpc(die, &low_pc))
			low_pc = 0;

		function = function__new(cu_offset, type,
					 decl_file, decl_line,
					 name, inlined, external,
					 low_pc, high_pc);
		if (function == NULL)
			oom("function__new");
		if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
			cu__process_function(dwarf, &child, cu, function,
					     &function->lexblock);
		cu__add_function(cu, function);
	}
		goto next_sibling;
	case DW_TAG_array_type:
		cu__create_new_array(dwarf, die, cu, cu_offset, type,
				     decl_file, decl_line);
		goto next_sibling;
	default:
		cu__create_new_class(dwarf, die, cu, tag, cu_offset,
				     name, type, decl_file, decl_line);
		goto next_sibling;
	}

children:
	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		cu__process_die(dwarf, &child, cu);
next_sibling:
	if (dwarf_siblingof(die, die) == 0)
		cu__process_die(dwarf, die, cu);
}

int cus__load(struct cus *self, const char *filename)
{
	Dwarf_Off offset, last_offset, abbrev_offset;
	uint8_t addr_size, offset_size;
	unsigned int cu_id;
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
							    &name));
			if (cu == NULL)
				oom("cu__new");
			++cu_id;
			cu__process_die(dwarf, &die, cu);
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

struct cus *cus__new(void)
{
	struct cus *self = malloc(sizeof(*self));

	if (self != NULL) {
		INIT_LIST_HEAD(&self->cus);
		INIT_LIST_HEAD(&self->definitions);
		INIT_LIST_HEAD(&self->fwd_decls);
	}

	return self;
}

const char *class__subroutine_ptr_mask(const struct class *self,
				       char *bf, size_t len)
{
	char ret_type_name[128];

	if (self->tag.type == 0)
		snprintf(ret_type_name, sizeof(ret_type_name), "void");
	else {
		struct class *ret_class = cu__find_class_by_id(self->cu,
							       self->tag.type);

		class__name(ret_class, ret_type_name, sizeof(ret_type_name));
	}
	snprintf(bf, len, "%s (*%%s)(void /* FIXME: add parm list */)",
		 ret_type_name);
	return bf;
}

static int cus__emit_typedef_definitions(struct cus *self, struct class *class)
{
	struct class *type;
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
	type = cu__find_class_by_id(class->cu, class->tag.type);

	if (type->tag.tag == DW_TAG_typedef)
		cus__emit_typedef_definitions(self, type);

	switch (type->tag.tag) {
	case DW_TAG_pointer_type: {
		struct class *ptr_type = cu__find_class_by_id(type->cu, type->tag.type);
		if (ptr_type->tag.tag == DW_TAG_subroutine_type) {
			class__subroutine_ptr_mask(ptr_type, bf, sizeof(bf));
			fputs("typedef ", stdout);
			printf(bf, class->name);
			puts(";");
			goto out;
		}
		break;
	}
	case DW_TAG_structure_type:
		cus__emit_struct_definitions(self, type,
					     "typedef ", class->name);
		goto out;
	}
	printf("typedef %s %s;\n", class__name(type, bf, sizeof(bf)),
	       class->name);
out:
	cus__add_definition(self, class);
	return 1;
}

static int cus__emit_fwd_decl(struct cus *self, struct class *class)
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
	struct class *type = cu__find_class_by_id(cu, tag->type);
	int pointer = 0;

	if (type == NULL)
		return 0;
next_indirection:
	if (type->tag.tag == DW_TAG_pointer_type) {
		pointer = 1;
		type = cu__find_class_by_id(cu, type->tag.type);
		if (type == NULL)
			return 0;
		goto next_indirection;
	}

	switch (type->tag.tag) {
	case DW_TAG_typedef:
		return cus__emit_typedef_definitions(self, type);
	case DW_TAG_structure_type:
		if (pointer)
			return cus__emit_fwd_decl(self, type);
		else
			return cus__emit_struct_definitions(self, type,
							    NULL, NULL);
	}

	return 0;
}

int cus__emit_function_definitions(struct cus *self,
				   struct function *function)
{
	struct parameter *pos;
	/* First check the function return type */
	int printed = cus__emit_tag_definitions(self, function->cu, &function->tag);

	/* Then its parameters */
	list_for_each_entry(pos, &function->parameters, tag.node)
		if (cus__emit_tag_definitions(self, function->cu, &pos->tag))
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

	list_for_each_entry(pos, &class->members, tag.node)
		if (cus__emit_tag_definitions(self, class->cu, &pos->tag))
			printed = 1;

	if (printed)
		putchar('\n');

	class__find_holes(class);
	class__print(class, prefix, suffix);
	putchar('\n');
	return 1;
}
