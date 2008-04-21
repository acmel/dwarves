/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Red Hat Inc.
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <assert.h>
#include <dirent.h>
#include <dwarf.h>
#include <argp.h>
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
#include "ctf_loader.h"
#include "dwarf_loader.h"
#include "list.h"
#include "dwarves.h"
#include "dutil.h"

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

static void *strings;

static int strings__compare(const void *a, const void *b)
{
	return strcmp(a, b);
}

char *strings__add(const char *str)
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

void tag__delete(struct tag *self)
{
	assert(list_empty(&self->node));
	free(self);
}

void tag__not_found_die(const char *file, int line, const char *func)
{
	fprintf(stderr, "%s::%s(%d): tag not found, please report to "
			"acme@ghostprotocols.net\n", file, func, line);
	exit(1);
}

struct tag *tag__follow_typedef(struct tag *tag, const struct cu *cu)
{
	struct tag *type = cu__find_tag_by_id(cu, tag->type);

	if (type != NULL && type->tag == DW_TAG_typedef)
		return tag__follow_typedef(type, cu);

	return type;
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

static size_t __tag__id_not_found_snprintf(char *bf, size_t len, Dwarf_Off id,
					   const char *fn)
{
	return snprintf(bf, len, "<ERROR(%s): %#llx not found!>", fn,
			(unsigned long long)id);
}

#define tag__id_not_found_snprintf(bf, len, id) \
	__tag__id_not_found_snprintf(bf, len, id, __func__)

static size_t __tag__id_not_found_fprintf(FILE *fp, Dwarf_Off id,
					  const char *fn)
{
	return fprintf(fp, "<ERROR(%s): %#llx not found!>", fn,
		       (unsigned long long)id);
}

#define tag__id_not_found_fprintf(fp, id) \
	__tag__id_not_found_fprintf(fp, id, __func__)

size_t tag__fprintf_decl_info(const struct tag *self, FILE *fp)
{
	return fprintf(fp, "/* <%llx> %s:%u */\n",
		       (unsigned long long)self->id,
		       self->decl_file, self->decl_line);
}

static size_t type__fprintf(struct tag *type, const struct cu *cu,
			    const char *name, const struct conf_fprintf *conf,
			    FILE *fp);

static size_t array_type__fprintf(const struct tag *tag_self,
				  const struct cu *cu, const char *name,
				  const struct conf_fprintf *conf,
				  FILE *fp)
{
	struct array_type *self = tag__array_type(tag_self);
	struct tag *type = cu__find_tag_by_id(cu, tag_self->type);
	size_t printed;
	int i;

	if (type == NULL)
		return tag__id_not_found_fprintf(fp, tag_self->type);

	printed = type__fprintf(type, cu, name, conf, fp);
	for (i = 0; i < self->dimensions; ++i)
		printed += fprintf(fp, "[%u]", self->nr_entries[i]);
	return printed;
}

void namespace__delete(struct namespace *self)
{
	struct tag *pos, *n;

	namespace__for_each_tag_safe(self, pos, n) {
		list_del_init(&pos->node);

		/* Look for nested namespaces */
		if (tag__is_struct(pos)    ||
		    tag__is_union(pos)	   ||
		    tag__is_namespace(pos) ||
		    tag__is_enumeration(pos))
		    	namespace__delete(tag__namespace(pos));
		tag__delete(pos);
	}

	tag__delete(&self->tag);
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
			tag__id_not_found_fprintf(stderr, self->specification);
			return NULL;
		}
		/* ... and now we cache the result in this tag ->name field */
		self->namespace.name = tag__type(tag)->namespace.name;
	}

	return self->namespace.name;
}

struct class_member *
	type__find_first_biggest_size_base_type_member(struct type *self,
						       const struct cu *cu)
{
	struct class_member *pos, *result = NULL;
	size_t result_size = 0;

	type__for_each_data_member(self, pos) {
		struct tag *type = cu__find_tag_by_id(cu, pos->tag.type);
		size_t member_size = 0, power2;
		struct class_member *inner = NULL;

		if (type == NULL) {
			tag__id_not_found_fprintf(stderr, pos->tag.type);
			continue;
		}
reevaluate:
		switch (type->tag) {
		case DW_TAG_base_type:
			member_size = base_type__size(type);
			break;
		case DW_TAG_pointer_type:
		case DW_TAG_reference_type:
			member_size = cu->addr_size;
			break;
		case DW_TAG_class_type:
		case DW_TAG_union_type:
		case DW_TAG_structure_type:
			if (tag__type(type)->nr_members == 0)
				continue;
			inner = type__find_first_biggest_size_base_type_member(tag__type(type), cu);
			member_size = class_member__size(inner, cu);
			break;
		case DW_TAG_array_type:
		case DW_TAG_const_type:
		case DW_TAG_typedef:
		case DW_TAG_volatile_type: {
			const struct tag *tag = type;

			type = cu__find_tag_by_id(cu, type->id);
			if (type == NULL) {
				tag__id_not_found_fprintf(stderr, tag->id);
				continue;
			}
		}
			goto reevaluate;
		case DW_TAG_enumeration_type:
			member_size = tag__type(type)->size;
			break;
		}
		
		/* long long */
		if (member_size > cu->addr_size)
			return pos;

		for (power2 = cu->addr_size; power2 > result_size; power2 /= 2)
			if (member_size >= power2) {
				if (power2 == cu->addr_size)
					return inner ?: pos;
				result_size = power2;
				result = inner ?: pos;
			}
	}

	return result;
}

size_t typedef__fprintf(const struct tag *tag_self, const struct cu *cu,
			const struct conf_fprintf *conf, FILE *fp)
{
	struct type *self = tag__type(tag_self);
	const struct conf_fprintf *pconf = conf ?: &conf_fprintf__defaults;
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
		printed = fprintf(fp, "typedef ");
		printed += tag__id_not_found_fprintf(fp, tag_self->type);
		return printed + fprintf(fp, " %s", type__name(self, cu));
	}

	switch (type->tag) {
	case DW_TAG_array_type:
		printed = fprintf(fp, "typedef ");
		return printed + array_type__fprintf(type, cu,
						     type__name(self, cu),
						     pconf, fp);
	case DW_TAG_pointer_type:
		if (type->type == 0) /* void pointer */
			break;
		ptr_type = cu__find_tag_by_id(cu, type->type);
		if (ptr_type == NULL) {
			printed = fprintf(fp, "typedef ");
			printed += tag__id_not_found_fprintf(fp, type->type);
			return printed + fprintf(fp, " *%s", type__name(self, cu));
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
	case DW_TAG_class_type:
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
	size_t printed = fprintf(fp, "using ::");
	const struct tag *decl = cu__find_tag_by_id(cu, self->type);

	if (decl == NULL)
		return printed + tag__id_not_found_fprintf(fp, self->type);

	return printed + fprintf(fp, "%s", tag__name(decl, cu, bf, sizeof(bf)));
}

static size_t imported_module__fprintf(const struct tag *self,
				       const struct cu *cu, FILE *fp)
{
	const struct tag *module = cu__find_tag_by_id(cu, self->type);
	const char *name = "<IMPORTED MODULE ERROR!>";

	if (tag__is_namespace(module))
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
	int indent = conf->indent;

	if (indent >= (int)sizeof(tabs))
		indent = sizeof(tabs) - 1;

	type__for_each_enumerator(self, pos)
		printed += fprintf(fp, "%.*s\t%s = %u,\n", indent, tabs,
				   pos->name, pos->value);

	return printed + fprintf(fp, "%.*s}%s%s", indent, tabs,
				 conf->suffix ? " " : "", conf->suffix ?: "");
}

void cus__add(struct cus *self, struct cu *cu)
{
	list_add_tail(&cu->node, &self->cus);
}

struct cu *cu__new(const char *name, uint8_t addr_size,
		   const unsigned char *build_id,
		   int build_id_len)
{
	struct cu *self = malloc(sizeof(*self) + build_id_len);

	if (self != NULL) {
		uint32_t i;

		for (i = 0; i < HASHTAGS__SIZE; ++i)
			INIT_LIST_HEAD(&self->hash_tags[i]);

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
		self->build_id_len	       = build_id_len;
		if (build_id_len > 0)
			memcpy(self->build_id, build_id, build_id_len);
	}

	return self;
}

void cu__delete(struct cu *self)
{
	struct tag *pos, *n;

	list_for_each_entry_safe(pos, n, &self->tags, node) {
		list_del_init(&pos->node);

		/* Look for nested namespaces */
		if (tag__is_struct(pos)    ||
		    tag__is_union(pos)	   ||
		    tag__is_namespace(pos) ||
		    tag__is_enumeration(pos)) {
		    	namespace__delete(tag__namespace(pos));
		}
	}
	free(self);
}

void hashtags__hash(struct list_head *hashtable, struct tag *tag)
{
	struct list_head *head = hashtable + hashtags__fn(tag->id);

	list_add_tail(&tag->hash_node, head);
}

void cu__add_tag(struct cu *self, struct tag *tag)
{
	list_add_tail(&tag->node, &self->tags);
	hashtags__hash(self->hash_tags, tag);
}

bool cu__same_build_id(const struct cu *self, const struct cu *other)
{
	return self->build_id_len != 0 &&
	       self->build_id_len == other->build_id_len &&
	       memcmp(self->build_id, other->build_id, self->build_id_len) == 0;
}

static const char *tag__prefix(const struct cu *cu, const uint32_t tag)
{
	switch (tag) {
	case DW_TAG_enumeration_type:	return "enum ";
	case DW_TAG_structure_type:
		return cu->language == DW_LANG_C_plus_plus ? "class " :
							     "struct ";
	case DW_TAG_class_type:		return "class";
	case DW_TAG_union_type:		return "union ";
	case DW_TAG_pointer_type:	return " *";
	case DW_TAG_reference_type:	return " &";
	}

	return "";
}

struct tag *cu__find_tag_by_id(const struct cu *self, const Dwarf_Off id)
{
	struct tag *pos;
	const struct list_head *head;

	if (self == NULL || id == 0)
		return NULL;

	head = &self->hash_tags[hashtags__fn(id)];

	list_for_each_entry(pos, head, hash_node)
		if (pos->id == id)
			return pos;

	return NULL;
}

struct tag *cu__find_first_typedef_of_type(const struct cu *self,
					   const Dwarf_Off type)
{
	struct tag *pos;

	if (self == NULL || type == 0)
		return NULL;

	list_for_each_entry(pos, &self->tags, node)
		if (pos->tag == DW_TAG_typedef && pos->type == type)
			return pos;

	return NULL;
}

struct tag *cu__find_base_type_by_name(const struct cu *self, const char *name)
{
	struct tag *pos;

	if (self == NULL || name == NULL)
		return NULL;

	list_for_each_entry(pos, &self->tags, node)
		if (pos->tag == DW_TAG_base_type) {
			const struct base_type *bt = tag__base_type(pos);

			if (bt->name != NULL && strcmp(bt->name, name) == 0)
				return pos;
		}

	return NULL;
}

struct tag *cu__find_struct_by_name(const struct cu *self, const char *name,
				    const int include_decls)
{
	struct tag *pos;

	if (self == NULL || name == NULL)
		return NULL;

	list_for_each_entry(pos, &self->tags, node) {
		struct type *type;

		if (!tag__is_struct(pos))
			continue;

		type = tag__type(pos);
		if (type__name(type, self) != NULL &&
		    strcmp(type__name(type, self), name) == 0) {
			if (type->declaration) {
				if (include_decls)
					return pos;
			} else
				return pos;
		}
	}

	return NULL;
}

struct tag *cus__find_struct_by_name(const struct cus *self,
				     struct cu **cu, const char *name,
				     const int include_decls)
{
	struct cu *pos;

	list_for_each_entry(pos, &self->cus, node) {
		struct tag *tag = cu__find_struct_by_name(pos, name,
							  include_decls);
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

	if (self == NULL || name == NULL)
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

	if (self == NULL)
		return NULL;

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
		case DW_TAG_class_type:
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
	if (self == NULL)
		return NULL;
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
	case DW_TAG_base_type:		return base_type__size(self);
	case DW_TAG_enumeration_type:	return tag__type(self)->size;
	}

	if (self->type == 0) /* struct class: unions, structs */
		size = tag__type(self)->size;
	else {
		const struct tag *type = cu__find_tag_by_id(cu, self->type);

		if (type == NULL) {
			tag__id_not_found_fprintf(stderr, self->type);
			return -1;
		}
		size = tag__size(type, cu);
	}

	if (self->tag == DW_TAG_array_type)
		return size * array_type__nr_entries(tag__array_type(self));

	return size;
}

static const char *tag__ptr_name(const struct tag *self, const struct cu *cu,
				 char *bf, size_t len, const char *ptr_suffix)
{
	if (self->type == 0) /* No type == void */
		snprintf(bf, len, "void %s", ptr_suffix);
	else {
		const struct tag *type = cu__find_tag_by_id(cu, self->type);

		if (type == NULL) {
			size_t l = tag__id_not_found_snprintf(bf, len,
							      self->type);
			snprintf(bf + l, len - l, " %s", ptr_suffix);
		} else {
			char tmpbf[1024];
			snprintf(bf, len, "%s %s",
				 tag__name(type, cu,
					   tmpbf, sizeof(tmpbf)), ptr_suffix);
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
	case DW_TAG_base_type: {
		const struct base_type *bt = tag__base_type(self);
		const char *s = "nameless base type!";

		if (bt->name != NULL)
			s = bt->name;

		strncpy(bf, s, len);
	}
		break;
	case DW_TAG_subprogram:
		strncpy(bf, function__name(tag__function(self), cu), len);
		break;
	case DW_TAG_pointer_type:
		return tag__ptr_name(self, cu, bf, len, "*");
	case DW_TAG_reference_type:
		return tag__ptr_name(self, cu, bf, len, "&");
	case DW_TAG_ptr_to_member_type: {
		char suffix[512];
		Dwarf_Off id = tag__ptr_to_member_type(self)->containing_type;

		type = cu__find_tag_by_id(cu, id);
		if (type != NULL)
			snprintf(suffix, sizeof(suffix), "%s::*",
				 class__name(tag__class(type), cu));
		else {
			size_t l = tag__id_not_found_snprintf(suffix,
							      sizeof(suffix),
							      id);
			snprintf(suffix + l, sizeof(suffix) - l, "::*");
		}

		return tag__ptr_name(self, cu, bf, len, suffix);
	}
	case DW_TAG_volatile_type:
	case DW_TAG_const_type:
		type = cu__find_tag_by_id(cu, self->type);
		if (type == NULL && self->type != 0)
			tag__id_not_found_snprintf(bf, len, self->type);
		else {
			char tmpbf[128];
			snprintf(bf, len, "%s %s ",
				 self->tag == DW_TAG_volatile_type ?
				 	"volatile" : "const",
				 tag__name(type, cu, tmpbf, sizeof(tmpbf)));
		}
		break;
	case DW_TAG_array_type:
		type = cu__find_tag_by_id(cu, self->type);
		if (type == NULL)
			tag__id_not_found_snprintf(bf, len, self->type);
		else
			return tag__name(type, cu, bf, len);
		break;
	case DW_TAG_subroutine_type: {
		FILE *bfp = fmemopen(bf, len, "w");
		if (bfp != NULL) {
			ftype__fprintf(tag__ftype(self), cu, NULL, 0, 0, 0, bfp);
			fclose(bfp);
		} else
			snprintf(bf, len, "<ERROR(%s): fmemopen failed!>",
				 __func__);
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
		tag__id_not_found_fprintf(stderr, self->tag.type);
		return -1;
	}
	return tag__size(type, cu);
}

const char *parameter__name(struct parameter *self, const struct cu *cu)
{
	/* Check if the tag doesn't comes with a DW_AT_name attribute... */
	if (self->name == NULL && self->abstract_origin != 0) {
		/* No? Does it have a DW_AT_abstract_origin? */
		struct tag *alias =
			cu__find_parameter_by_id(cu, self->abstract_origin);
		if (alias == NULL) {
			tag__id_not_found_fprintf(stderr, self->abstract_origin);
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
			tag__id_not_found_fprintf(stderr, self->abstract_origin);
			return 0;
		}
		/* Now cache the result in this tag ->name and type fields */
		self->name = tag__parameter(alias)->name;
		self->tag.type = tag__parameter(alias)->tag.type;
	}

	return self->tag.type;
}

static size_t union__fprintf(struct type *self, const struct cu *cu,
			     const struct conf_fprintf *conf, FILE *fp);

static size_t type__fprintf(struct tag *type, const struct cu *cu,
			    const char *name, const struct conf_fprintf *conf,
			    FILE *fp)
{
	char tbf[128];
	char namebf[256];
	struct type *ctype;
	struct conf_fprintf tconf;
	size_t printed = 0;
	int expand_types = conf->expand_types;
	int suppress_offset_comment = conf->suppress_offset_comment;

	if (type == NULL)
		goto out_type_not_found;

	if (conf->expand_pointers) {
		int nr_indirections = 0;

		while (type->tag == DW_TAG_pointer_type && type->type != 0) {
			type = cu__find_tag_by_id(cu, type->type);
			if (type == NULL)
				goto out_type_not_found;
			++nr_indirections;
		}

		if (nr_indirections > 0) {
			const size_t len = strlen(name);
			if (len + nr_indirections >= sizeof(namebf))
				goto out_type_not_found;
			memset(namebf, '*', nr_indirections);
			memcpy(namebf + nr_indirections, name, len);
			namebf[len + nr_indirections] = '\0';
			name = namebf;
		}

		expand_types = nr_indirections;
		if (!suppress_offset_comment)
			suppress_offset_comment = !!nr_indirections;

		/* Avoid loops */
		if (type->recursivity_level != 0)
			expand_types = 0;
		++type->recursivity_level;
	}

	if (expand_types) {
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

	if (tag__is_struct(type) || tag__is_union(type) ||
	    tag__is_enumeration(type)) {
		tconf = *conf;
		tconf.type_spacing -= 8;
		tconf.prefix	   = NULL;
		tconf.suffix	   = name;
		tconf.emit_stats   = 0;
		tconf.suppress_offset_comment = suppress_offset_comment;
	}

	switch (type->tag) {
	case DW_TAG_pointer_type:
		if (type->type != 0) {
			struct tag *ptype = cu__find_tag_by_id(cu, type->type);
			if (ptype == NULL)
				goto out_type_not_found;
			if (ptype->tag == DW_TAG_subroutine_type) {
				printed += ftype__fprintf(tag__ftype(ptype),
							  cu, name, 0, 1,
							  conf->type_spacing,
							  fp);
				break;
			}
		}
		/* Fall Thru */
	default:
		printed += fprintf(fp, "%-*s %s", conf->type_spacing,
				   tag__name(type, cu, tbf, sizeof(tbf)), name);
		break;
	case DW_TAG_subroutine_type:
		printed += ftype__fprintf(tag__ftype(type), cu, name, 0, 0,
					  conf->type_spacing, fp);
		break;
	case DW_TAG_array_type:
		printed += array_type__fprintf(type, cu, name, conf, fp);
		break;
	case DW_TAG_class_type:
	case DW_TAG_structure_type:
		ctype = tag__type(type);

		if (type__name(ctype, cu) != NULL && !expand_types)
			printed += fprintf(fp, "%s %-*s %s",
					   type->tag == DW_TAG_class_type ? "class" : "struct",
					   conf->type_spacing - 7,
					   type__name(ctype, cu), name);
		else {
			struct class *class = tag__class(type);

			class__find_holes(class, cu);
			printed += class__fprintf(class, cu, &tconf, fp);
		}
		break;
	case DW_TAG_union_type:
		ctype = tag__type(type);

		if (type__name(ctype, cu) != NULL && !expand_types)
			printed += fprintf(fp, "union %-*s %s",
					   conf->type_spacing - 6,
					   type__name(ctype, cu), name);
		else
			printed += union__fprintf(ctype, cu, &tconf, fp);
		break;
	case DW_TAG_enumeration_type:
		ctype = tag__type(type);

		if (type__name(ctype, cu) != NULL)
			printed += fprintf(fp, "enum %-*s %s",
					   conf->type_spacing - 5,
					   type__name(ctype, cu), name);
		else
			printed += enumeration__fprintf(type, cu, &tconf, fp);
		break;
	}
out:
	if (conf->expand_types)
		--type->recursivity_level;

	return printed;
out_type_not_found:
	printed = fprintf(fp, "%-*s %s", conf->type_spacing, "<ERROR>", name);
	goto out;
}

static size_t struct_member__fprintf(struct class_member *self,
				     struct tag *type, const struct cu *cu,
				     const struct conf_fprintf *conf, FILE *fp)
{
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

	if ((tag__is_union(type) || tag__is_struct(type) ||
	     tag__is_enumeration(type)) &&
		/* Look if is a type defined inline */
	    type__name(tag__type(type), cu) == NULL) {
		if (!sconf.suppress_offset_comment) {
			/* Check if this is a anonymous union */
			const int slen = self->name != NULL ?
						(int)strlen(self->name) : -1;
			printed += fprintf(fp, "%*s/* %5u %5u */",
					   (sconf.type_spacing +
					    sconf.name_spacing - slen - 3),
					   " ", offset, size);
		}
	} else {
		int spacing = sconf.type_spacing + sconf.name_spacing - printed;

		if (self->tag.tag == DW_TAG_inheritance) {
			const size_t p = fprintf(fp, " */");
			printed += p;
			spacing -= p;
		}
		if (!sconf.suppress_offset_comment) {
			int size_spacing = 5;

			printed += fprintf(fp, "%*s/* %5u",
					   spacing > 0 ? spacing : 0, " ",
					   offset);

			if (self->bit_size != 0) {
				printed += fprintf(fp, ":%2d", self->bit_offset);
				size_spacing -= 3;
			}

			printed += fprintf(fp, " %*u */", size_spacing, size);
		}
	}
	return printed;
}

static size_t union_member__fprintf(struct class_member *self,
				    struct tag *type, const struct cu *cu,
				    const struct conf_fprintf *conf, FILE *fp)
{
	const size_t size = tag__size(type, cu);
	size_t printed = type__fprintf(type, cu, self->name, conf, fp);
	
	if ((tag__is_union(type) || tag__is_struct(type) ||
	     tag__is_enumeration(type)) &&
		/* Look if is a type defined inline */
	    type__name(tag__type(type), cu) == NULL) {
		if (!conf->suppress_offset_comment) {
			/* Check if this is a anonymous union */
			const int slen = self->name != NULL ? (int)strlen(self->name) : -1;
			/*
			 * Add the comment with the union size after padding the
			 * '} member_name;' last line of the type printed in the
			 * above call to type__fprintf.
			 */
			printed += fprintf(fp, ";%*s/* %11zd */",
					   (conf->type_spacing +
					    conf->name_spacing - slen - 3), " ", size);
		}
	} else {
		printed += fprintf(fp, ";");
		
		if (!conf->suppress_offset_comment) {
			const int spacing = conf->type_spacing + conf->name_spacing - printed;
			printed += fprintf(fp, "%*s/* %11zd */",
					   spacing > 0 ? spacing : 0, " ", size);
		}
	}

	return printed;
}

static size_t union__fprintf(struct type *self, const struct cu *cu,
			     const struct conf_fprintf *conf, FILE *fp)
{
	struct class_member *pos;
	size_t printed = 0;
	int indent = conf->indent;
	struct conf_fprintf uconf;

	if (indent >= (int)sizeof(tabs))
		indent = sizeof(tabs) - 1;

	if (conf->prefix != NULL)
		printed += fprintf(fp, "%s ", conf->prefix);
	printed += fprintf(fp, "union%s%s {\n", type__name(self, cu) ? " " : "",
			   type__name(self, cu) ?: "");

	uconf = *conf;
	uconf.indent = indent + 1;
	type__for_each_member(self, pos) {
		struct tag *type = cu__find_tag_by_id(cu, pos->tag.type);

		if (type == NULL) {
			printed += fprintf(fp, "%.*s", uconf.indent, tabs);
			printed += tag__id_not_found_fprintf(fp, pos->tag.type);
			continue;
		}

		printed += fprintf(fp, "%.*s", uconf.indent, tabs);
		printed += union_member__fprintf(pos, type, cu, &uconf, fp);
		fputc('\n', fp);
		++printed;
	}

	return printed + fprintf(fp, "%.*s}%s%s", indent, tabs,
				 conf->suffix ? " " : "", conf->suffix ?: "");
}

void class__delete(struct class *self)
{
	struct class_member *pos, *next;

	type__for_each_member_safe(&self->type, pos, next)
		class_member__delete(pos);

	free(self);
}

void class__add_vtable_entry(struct class *self, struct function *vtable_entry)
{
	++self->nr_vtable_entries;
	list_add_tail(&vtable_entry->vtable_node, &self->vtable);
}

void namespace__add_tag(struct namespace *self, struct tag *tag)
{
	++self->nr_tags;
	list_add_tail(&tag->node, &self->tags);
}

void type__add_member(struct type *self, struct class_member *member)
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
	struct class *self = malloc(sizeof(*self));

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

void enumeration__add(struct type *self, struct enumerator *enumerator)
{
	++self->nr_members;
	namespace__add_tag(&self->namespace, &enumerator->tag);
}

void lexblock__add_lexblock(struct lexblock *self, struct lexblock *child)
{
	++self->nr_lexblocks;
	list_add_tail(&child->tag.node, &self->tags);
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
				tag__id_not_found_fprintf(stderr, self->specification);
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

	ftype__for_each_parameter(self, pos) {
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

void ftype__add_parameter(struct ftype *self, struct parameter *parm)
{
	++self->nr_parms;
	list_add_tail(&parm->tag.node, &self->parms);
}

void lexblock__add_tag(struct lexblock *self, struct tag *tag)
{
	list_add_tail(&tag->node, &self->tags);
}

void lexblock__add_inline_expansion(struct lexblock *self,
				    struct inline_expansion *exp)
{
	++self->nr_inline_expansions;
	self->size_inline_expansions += exp->size;
	lexblock__add_tag(self, &exp->tag);
}

void lexblock__add_variable(struct lexblock *self, struct variable *var)
{
	++self->nr_variables;
	lexblock__add_tag(self, &var->tag);
}

void lexblock__add_label(struct lexblock *self, struct label *label)
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
	uint32_t bitfield_real_offset = 0;

	self->nr_holes = 0;
	self->nr_bit_holes = 0;

	type__for_each_member(ctype, pos) {
		/* XXX for now just skip these */
		if (pos->tag.tag == DW_TAG_inheritance &&
		    pos->virtuality == DW_VIRTUALITY_virtual)
			continue;

		if (last != NULL) {
			/*
			 * We have to cast both offsets to int64_t because
			 * the current offset can be before the last offset
			 * when we are starting a bitfield that combines with
			 * the previous, small size fields.
			 */
			const ssize_t cc_last_size = ((int64_t)pos->offset -
						      (int64_t)last->offset);

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
					if (bitfield_real_offset != 0) {
						last_size = bitfield_real_offset - last->offset;
						bitfield_real_offset = 0;
					}

					last->bit_hole = (last_size * 8) -
							 bit_sum;
					if (last->bit_hole != 0)
						++self->nr_bit_holes;

					last->bitfield_end = 1;
					bit_sum = 0;
				}
			} else if (cc_last_size < 0 && bit_sum == 0)
				bitfield_real_offset = last->offset + last_size;
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
				   const struct cu *cu, int indent,
				   FILE *fp)
{
	struct parameter *pos;
	int first_parm = 1;
	char sbf[128];
	struct tag *type;
	const char *name, *stype;
	size_t printed = fprintf(fp, "(");

	ftype__for_each_parameter(self, pos) {
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
					printed +=
					    tag__id_not_found_fprintf(fp, type->type);
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
		stype = tag__name(type, cu, sbf, sizeof(sbf));
print_it:
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
				    struct function *function,
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
			printed += tag__id_not_found_fprintf(fp, exp->tag.type);
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
		printed = lexblock__fprintf(vtag, cu, function, indent, fp);
		fputc('\n', fp);
		return printed + 1;
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
			 struct function *function, uint16_t indent, FILE *fp)
{
	struct tag *pos;
	size_t printed;

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;
	printed = fprintf(fp, "%.*s{", indent, tabs);
	if (self->low_pc != 0) {
		Dwarf_Off offset = self->low_pc - function->lexblock.low_pc;

		if (offset == 0)
			printed += fprintf(fp, " /* low_pc=%#llx */",
					   (unsigned long long)self->low_pc);
		else
			printed += fprintf(fp, " /* %s+%#llx */",
					   function__name(function, cu),
					   (unsigned long long)offset);
	}
	printed += fprintf(fp, "\n");
	list_for_each_entry(pos, &self->tags, node)
		printed += function__tag_fprintf(pos, cu, function, indent + 1, fp);
	printed += fprintf(fp, "%.*s}", indent, tabs);

	if (function->lexblock.low_pc != self->low_pc) {
		const size_t size = self->high_pc - self->low_pc;
		printed += fprintf(fp, " /* lexblock size=%zd */", size);
	}
	return printed;
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
	size_t printed = 0;

	if (self->virtuality == DW_VIRTUALITY_virtual ||
	    self->virtuality == DW_VIRTUALITY_pure_virtual)
		printed += fprintf(fp, "virtual ");

	printed += ftype__fprintf(&self->proto, cu, function__name(self, cu),
				  function__declared_inline(self), 0, 0, fp);

	if (self->virtuality == DW_VIRTUALITY_pure_virtual)
		printed += fprintf(fp, " = 0");

	return printed;
}

size_t function__fprintf_stats(const struct tag *tag_self,
			       const struct cu *cu, FILE *fp)
{
	struct function *self = tag__function(tag_self);
	size_t printed = lexblock__fprintf(&self->lexblock, cu, self, 0, fp);

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

static size_t class__vtable_fprintf(struct class *self,
				    const struct conf_fprintf *conf, FILE *fp)
{
	struct function *pos;
	size_t printed = 0;

	if (self->nr_vtable_entries == 0)
		goto out;

	printed += fprintf(fp, "%.*s/* vtable has %u entries: {\n",
			   conf->indent, tabs, self->nr_vtable_entries);

	list_for_each_entry(pos, &self->vtable, vtable_node) {
		printed += fprintf(fp, "%.*s   [%d] = %s(%s), \n",
				   conf->indent, tabs, pos->vtable_entry,
				   pos->name, pos->linkage_name);
	}

	printed += fprintf(fp, "%.*s} */", conf->indent, tabs);
out:
	return printed;
}

size_t class__fprintf(struct class *self, const struct cu *cu,
		      const struct conf_fprintf *conf, FILE *fp)
{
	struct type *tself = &self->type;
	size_t last_size = 0, size;
	uint8_t newline = 0;
	uint16_t nr_paddings = 0;
	uint32_t sum = 0;
	uint32_t sum_holes = 0;
	uint32_t sum_paddings = 0;
	uint32_t sum_bit_holes = 0;
	uint32_t last_cacheline = 0;
	uint32_t bitfield_real_offset = 0;
	int first = 1;
	struct class_member *pos, *last = NULL;
	struct tag *tag_pos;
	const char *current_accessibility = NULL;
	struct conf_fprintf cconf = conf ? *conf : conf_fprintf__defaults;
	size_t printed = fprintf(fp, "%s%s%s%s%s",
				 cconf.prefix ?: "", cconf.prefix ? " " : "",
				 tself->namespace.tag.tag == DW_TAG_class_type ? "class" : "struct",
				 type__name(tself, cu) ? " " : "",
				 type__name(tself, cu) ?: "");
	int indent = cconf.indent;

	if (indent >= (int)sizeof(tabs))
		indent = sizeof(tabs) - 1;

	cconf.indent = indent + 1;
	cconf.no_semicolon = 0;

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
		if (type != NULL)
			printed += fprintf(fp, " %s", type__name(tag__type(type), cu));
		else
			printed += tag__id_not_found_fprintf(fp, tag_pos->type);
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
				printed += fprintf(fp, "\n\n");
			}
			continue;
		}
		pos = tag__class_member(tag_pos);

		if (last != NULL &&
		    pos->offset != last->offset &&
		    !cconf.suppress_comments)
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
		if (last != NULL && tag_pos->tag == DW_TAG_member) {
			if (pos->offset < last->offset ||
			    (pos->offset == last->offset &&
			     last->bit_size == 0 &&
			     /*
			      * This is just when transitioning from a non-bitfield to
			      * a bitfield, think about zero sized arrays in the middle
			      * of a struct.
			      */
			     pos->bit_size != 0)) {
				if (!cconf.suppress_comments) {
					if (!newline++) {
						fputc('\n', fp);
						++printed;
					}
					printed += fprintf(fp, "%.*s/* Bitfield combined"
							   " with previous fields */\n",
							   cconf.indent, tabs);
				}
				if (pos->offset != last->offset)
					bitfield_real_offset = last->offset + last_size;
			} else { 
				const ssize_t cc_last_size = ((ssize_t)pos->offset -
							      (ssize_t)last->offset);

				if (cc_last_size > 0 &&
				   (size_t)cc_last_size < last_size) {
					if (!cconf.suppress_comments) {
						if (!newline++) {
							fputc('\n', fp);
							++printed;
						}
						printed += fprintf(fp, "%.*s/* Bitfield combined"
								   " with next fields */\n",
								   cconf.indent, tabs);
					}
					sum -= last_size;
					sum += cc_last_size;
				}
			}
		}

		if (newline) {
			fputc('\n', fp);
			newline = 0;
			++printed;
		}

		type = cu__find_tag_by_id(cu, pos->tag.type);
		if (type == NULL) {
			printed += fprintf(fp, "%.*s", cconf.indent, tabs);
			printed += tag__id_not_found_fprintf(fp, pos->tag.type);
			continue;
		}

		size = tag__size(type, cu);
		printed += fprintf(fp, "%.*s", cconf.indent, tabs);
		printed += struct_member__fprintf(pos, type, cu, &cconf, fp);

		if (tag__is_struct(type) && !cconf.suppress_comments) {
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

		if (pos->bit_hole != 0 && !cconf.suppress_comments) {
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

		if (pos->hole > 0 && !cconf.suppress_comments) {
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
		 * Check if we have to adjust size because bitfields were
		 * combined with previous fields.
		 */
		if (bitfield_real_offset != 0 && last->bitfield_end) {
			size_t real_last_size = pos->offset - bitfield_real_offset;
			sum -= last_size;
			sum += real_last_size;
			bitfield_real_offset = 0;
		}

		if (last == NULL || /* First member */
		    /*
		     * Last member was a zero sized array, typedef, struct, etc
		     */
		    last_size == 0 ||
		    /*
		     * We moved to a new offset
		     */
		    last->offset != pos->offset) {
			sum += size;
			last_size = size;
		} else if (last->bit_size == 0 && pos->bit_size != 0) {
			/*
			 * Transitioned from from a non-bitfield to a
			 * bitfield sharing the same offset
			 */
			/*
			 * Compensate by removing the size of the
			 * last member that is "inside" this new
			 * member at the same offset.
			 *
			 * E.g.:
			 * struct foo {
			 * 	u8	a;   / 0    1 /
			 * 	int	b:1; / 0:23 4 /
			 * }
			 */
			sum += size - last_size;
			last_size = size;
		}

		last = pos;
	}

	/*
	 * Check if we have to adjust size because bitfields were
	 * combined with previous fields and were the last fields
	 * in the struct.
	 */
	if (bitfield_real_offset != 0) {
		size_t real_last_size = tself->size - bitfield_real_offset;
		sum -= last_size;
		sum += real_last_size;
		bitfield_real_offset = 0;
	}

	if (!cconf.suppress_comments)
		printed += class__fprintf_cacheline_boundary(last_cacheline,
							     sum, sum_holes,
							     &newline,
							     &last_cacheline,
							     cconf.indent, fp);
	class__vtable_fprintf(self, &cconf, fp);
	if (!cconf.emit_stats)
		goto out;

	printed += fprintf(fp, "\n%.*s/* size: %zd, cachelines: %zd */",
			   cconf.indent, tabs,
			   tself->size, tag__nr_cachelines(class__tag(self),
			   cu));
	if (sum_holes > 0)
		printed += fprintf(fp, "\n%.*s/* sum members: %u, holes: %d, "
				   "sum holes: %u */",
				   cconf.indent, tabs,
				   sum, self->nr_holes, sum_holes);
	if (sum_bit_holes > 0)
		printed += fprintf(fp, "\n%.*s/* bit holes: %d, sum bit "
				   "holes: %u bits */",
				   cconf.indent, tabs,
				   self->nr_bit_holes, sum_bit_holes);
	if (self->padding > 0)
		printed += fprintf(fp, "\n%.*s/* padding: %u */",
				   cconf.indent,
				   tabs, self->padding);
	if (nr_paddings > 0)
		printed += fprintf(fp, "\n%.*s/* paddings: %u, sum paddings: "
				   "%u */",
				   cconf.indent, tabs,
				   nr_paddings, sum_paddings);
	if (self->bit_padding > 0)
		printed += fprintf(fp, "\n%.*s/* bit_padding: %u bits */",
				   cconf.indent, tabs,
				   self->bit_padding);
	last_cacheline = tself->size % cacheline_size;
	if (last_cacheline != 0)
		printed += fprintf(fp, "\n%.*s/* last cacheline: %u bytes */",
				   cconf.indent, tabs,
				   last_cacheline);
	if (cconf.show_first_biggest_size_base_type_member &&
	    tself->nr_members != 0) {
		struct class_member *m = type__find_first_biggest_size_base_type_member(tself, cu);

		printed += fprintf(fp, "\n%.*s/* first biggest size base type member: %s %u %zd */",
				   cconf.indent, tabs, m->name, m->offset,
				   class_member__size(m, cu));
	}

	if (sum + sum_holes != tself->size - self->padding)
		printed += fprintf(fp, "\n\n%.*s/* BRAIN FART ALERT! %zd != %u "
				   "+ %u(holes), diff = %zd */\n",
				   cconf.indent, tabs,
				   tself->size, sum, sum_holes,
				   tself->size - (sum + sum_holes));
	fputc('\n', fp);
out:
	return printed + fprintf(fp, "%.*s}%s%s", indent, tabs,
				 cconf.suffix ? " ": "", cconf.suffix ?: "");
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
	cconf.no_semicolon = 0;

	namespace__for_each_tag(self, pos) {
		printed += tag__fprintf(pos, cu, &cconf, fp);
		printed += fprintf(fp, "\n\n");
	}

	return printed + fprintf(fp, "}");
}

size_t tag__fprintf(struct tag *self, const struct cu *cu,
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
		else if (tag__is_union(self))
			tconf.name_spacing = 21;
	} else if (conf->name_spacing == 0 || conf->type_spacing == 0) {
		tconf = *conf;
		pconf = &tconf; 

		if (tconf.name_spacing == 0) {
			if (tconf.expand_types)
				tconf.name_spacing = 55;
			else
				tconf.name_spacing =
						tag__is_union(self) ? 21 : 23;
		}
		if (tconf.type_spacing == 0)
			tconf.type_spacing = 26;
	}

	if (pconf->expand_types)
		++self->recursivity_level;

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
		printed += typedef__fprintf(self, cu, pconf, fp);
		break;
	case DW_TAG_class_type:
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

	if (!pconf->no_semicolon) {
		fputc(';', fp);
		++printed;
	}

	if (self->tag == DW_TAG_subprogram &&
	    !pconf->suppress_comments) {
		const struct function *fself = tag__function(self);

		if (fself->linkage_name != NULL)
			printed += fprintf(fp, " /* linkage=%s */", fself->linkage_name);
	}

	if (pconf->expand_types)
		--self->recursivity_level;

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
	int err = dwarf__load_filename(self, filename);
	/* 
	 * See cus__loadfl.
	 */
	return err;
}

int cus__loadfl(struct cus *self, struct argp *argp, int argc, char *argv[])
{
	int err = dwarf__load(self, argp, argc, argv);
	/*
	 * If dwarf__load fails, try ctf__load. Eventually we should just
	 * register all the shared objects at some directory and ask them
	 * for the magic types they support or just pass them the file,
	 * unloading the shared object if it says its not the type they
	 * support.
	 * FIXME: for now we just check if no DWARF info was found
	 * by looking at the list of CUs found:
	 */
	if (list_empty(&self->cus))
		err = ctf__load(self, argp, argc, argv);

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
