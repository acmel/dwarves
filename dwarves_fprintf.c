/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007..2009 Red Hat Inc.
  Copyright (C) 2007..2009 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <dwarf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
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
#ifdef STB_GNU_UNIQUE
	[DW_TAG_type_unit]		  = "type_unit",
	[DW_TAG_rvalue_reference_type]    = "rvalue_reference_type",
#endif
};

static const char *dwarf_gnu_tag_names[] = {
	[DW_TAG_MIPS_loop - DW_TAG_MIPS_loop]			= "MIPS_loop",
	[DW_TAG_format_label - DW_TAG_MIPS_loop]		= "format_label",
	[DW_TAG_function_template - DW_TAG_MIPS_loop]		= "function_template",
	[DW_TAG_class_template - DW_TAG_MIPS_loop]		= "class_template",
#ifdef STB_GNU_UNIQUE
	[DW_TAG_GNU_BINCL - DW_TAG_MIPS_loop]			= "BINCL",
	[DW_TAG_GNU_EINCL - DW_TAG_MIPS_loop]			= "EINCL",
	[DW_TAG_GNU_template_template_param - DW_TAG_MIPS_loop] = "template_template_param",
	[DW_TAG_GNU_template_parameter_pack - DW_TAG_MIPS_loop] = "template_parameter_pack",
	[DW_TAG_GNU_formal_parameter_pack - DW_TAG_MIPS_loop]	= "formal_parameter_pack",
#endif
};

const char *dwarf_tag_name(const uint32_t tag)
{
	if (tag >= DW_TAG_array_type && tag <=
#ifdef STB_GNU_UNIQUE
		DW_TAG_rvalue_reference_type
#else
		DW_TAG_shared_type
#endif
	    )
		return dwarf_tag_names[tag];
	else if (tag >= DW_TAG_MIPS_loop && tag <=
#ifdef STB_GNU_UNIQUE
		 DW_TAG_GNU_formal_parameter_pack
#else
		 DW_TAG_class_template
#endif
		)
		return dwarf_gnu_tag_names[tag - DW_TAG_MIPS_loop];
	return "INVALID";
}

static const struct conf_fprintf conf_fprintf__defaults = {
	.name_spacing = 23,
	.type_spacing = 26,
	.emit_stats   = 1,
};

static const char tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

static size_t cacheline_size;

size_t tag__nr_cachelines(const struct tag *self, const struct cu *cu)
{
	return (tag__size(self, cu) + cacheline_size - 1) / cacheline_size;
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

static size_t __tag__id_not_found_snprintf(char *bf, size_t len, uint16_t id,
					   const char *fn, int line)
{
	return snprintf(bf, len, "<ERROR(%s:%d): %#llx not found!>", fn, line,
			(unsigned long long)id);
}

#define tag__id_not_found_snprintf(bf, len, id) \
	__tag__id_not_found_snprintf(bf, len, id, __func__, __LINE__)

size_t tag__fprintf_decl_info(const struct tag *self,
			      const struct cu *cu, FILE *fp)
{
	return fprintf(fp, "/* <%llx> %s:%u */\n", tag__orig_id(self, cu),
		       tag__decl_file(self, cu), tag__decl_line(self, cu));
	return 0;
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
	struct tag *type = cu__type(cu, tag_self->type);
	size_t printed;
	unsigned long long flat_dimensions = 0;
	int i;

	if (type == NULL)
		return tag__id_not_found_fprintf(fp, tag_self->type);

	printed = type__fprintf(type, cu, name, conf, fp);
	for (i = 0; i < self->dimensions; ++i) {
		if (conf->flat_arrays || self->is_vector) {
			/*
			 * Seen on the Linux kernel on tun_filter:
			 *
			 * __u8   addr[0][ETH_ALEN];
			 */
			if (self->nr_entries[i] == 0 && i == 0)
				break;
			if (!flat_dimensions)
				flat_dimensions = self->nr_entries[i];
			else
				flat_dimensions *= self->nr_entries[i];
		} else
			printed += fprintf(fp, "[%u]", self->nr_entries[i]);
	}

	if (self->is_vector) {
		type = tag__follow_typedef(tag_self, cu);

		if (flat_dimensions == 0)
			flat_dimensions = 1;
		printed += fprintf(fp, " __attribute__ ((__vector_size__ (%llu)))",
				   flat_dimensions * tag__size(type, cu));
	} else if (conf->flat_arrays)
		printed += fprintf(fp, "[%llu]", flat_dimensions);

	return printed;
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

	type = cu__type(cu, tag_self->type);
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
		ptr_type = cu__type(cu, type->type);
		if (ptr_type == NULL) {
			printed = fprintf(fp, "typedef ");
			printed += tag__id_not_found_fprintf(fp, type->type);
			return printed + fprintf(fp, " *%s",
						 type__name(self, cu));
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
						pconf, fp);
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
		       tag__name(type, cu, bf, sizeof(bf), pconf),
				 type__name(self, cu));
}

static size_t imported_declaration__fprintf(const struct tag *self,
					    const struct cu *cu, FILE *fp)
{
	char bf[BUFSIZ];
	size_t printed = fprintf(fp, "using ::");
	const struct tag *decl = cu__function(cu, self->type);

	if (decl == NULL) {
		decl = cu__tag(cu, self->type);
		if (decl == NULL)
			return printed + tag__id_not_found_fprintf(fp, self->type);
	}

	return printed + fprintf(fp, "%s", tag__name(decl, cu, bf, sizeof(bf), NULL));
}

static size_t imported_module__fprintf(const struct tag *self,
				       const struct cu *cu, FILE *fp)
{
	const struct tag *module = cu__tag(cu, self->type);
	const char *name = "<IMPORTED MODULE ERROR!>";

	if (tag__is_namespace(module))
		name = namespace__name(tag__namespace(module), cu);

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
				   enumerator__name(pos, cu), pos->value);

	return printed + fprintf(fp, "%.*s}%s%s", indent, tabs,
				 conf->suffix ? " " : "", conf->suffix ?: "");
}

static const char *tag__prefix(const struct cu *cu, const uint32_t tag,
			       const struct conf_fprintf *conf)
{
	switch (tag) {
	case DW_TAG_enumeration_type:	return "enum ";
	case DW_TAG_structure_type:
		return (!conf->classes_as_structs &&
			cu->language == DW_LANG_C_plus_plus) ? "class " :
							       "struct ";
	case DW_TAG_class_type:
		return conf->classes_as_structs ? "struct " : "class ";
	case DW_TAG_union_type:		return "union ";
	case DW_TAG_pointer_type:	return " *";
	case DW_TAG_reference_type:	return " &";
	}

	return "";
}

static const char *__tag__name(const struct tag *self, const struct cu *cu,
			       char *bf, size_t len,
			       const struct conf_fprintf *conf);

static const char *tag__ptr_name(const struct tag *self, const struct cu *cu,
				 char *bf, size_t len, const char *ptr_suffix)
{
	if (self->type == 0) /* No type == void */
		snprintf(bf, len, "void %s", ptr_suffix);
	else {
		const struct tag *type = cu__type(cu, self->type);

		if (type == NULL) {
			size_t l = tag__id_not_found_snprintf(bf, len,
							      self->type);
			snprintf(bf + l, len - l, " %s", ptr_suffix);
		} else if (!tag__has_type_loop(self, type, bf, len, NULL)) {
			char tmpbf[1024];

			snprintf(bf, len, "%s %s",
				 __tag__name(type, cu,
					     tmpbf, sizeof(tmpbf), NULL),
				 ptr_suffix);
		}
	}

	return bf;
}

static const char *__tag__name(const struct tag *self, const struct cu *cu,
			       char *bf, size_t len,
			       const struct conf_fprintf *conf)
{
	struct tag *type;
	const struct conf_fprintf *pconf = conf ?: &conf_fprintf__defaults;

	if (self == NULL)
		strncpy(bf, "void", len);
	else switch (self->tag) {
	case DW_TAG_base_type: {
		const struct base_type *bt = tag__base_type(self);
		const char *name = "nameless base type!";
		char bf2[64];

		if (bt->name)
			name = base_type__name(tag__base_type(self), cu,
					       bf2, sizeof(bf2));

		strncpy(bf, name, len);
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
		uint16_t id = tag__ptr_to_member_type(self)->containing_type;

		type = cu__type(cu, id);
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
		type = cu__type(cu, self->type);
		if (type == NULL && self->type != 0)
			tag__id_not_found_snprintf(bf, len, self->type);
		else if (!tag__has_type_loop(self, type, bf, len, NULL)) {
			char tmpbf[128];
			const char *prefix = "const",
				   *type_str = __tag__name(type, cu, tmpbf,
							   sizeof(tmpbf),
							   pconf);
			if (self->tag == DW_TAG_volatile_type)
				prefix = "volatile";
			snprintf(bf, len, "%s %s ", prefix, type_str);
		}
		break;
	case DW_TAG_array_type:
		type = cu__type(cu, self->type);
		if (type == NULL)
			tag__id_not_found_snprintf(bf, len, self->type);
		else if (!tag__has_type_loop(self, type, bf, len, NULL))
			return __tag__name(type, cu, bf, len, pconf);
		break;
	case DW_TAG_subroutine_type: {
		FILE *bfp = fmemopen(bf, len, "w");

		if (bfp != NULL) {
			ftype__fprintf(tag__ftype(self), cu, NULL, 0, 0, 0,
				       pconf, bfp);
			fclose(bfp);
		} else
			snprintf(bf, len, "<ERROR(%s): fmemopen failed!>",
				 __func__);
	}
		break;
	case DW_TAG_member:
		snprintf(bf, len, "%s", class_member__name(tag__class_member(self), cu));
		break;
	case DW_TAG_variable:
		snprintf(bf, len, "%s", variable__name(tag__variable(self), cu));
		break;
	default:
		snprintf(bf, len, "%s%s", tag__prefix(cu, self->tag, pconf),
			 type__name(tag__type(self), cu) ?: "");
		break;
	}

	return bf;
}

const char *tag__name(const struct tag *self, const struct cu *cu,
		      char *bf, size_t len, const struct conf_fprintf *conf)
{
	bool starts_with_const = false;

	if (self == NULL) {
		strncpy(bf, "void", len);
		return bf;
	}

	if (self->tag == DW_TAG_const_type) {
		starts_with_const = true;
		self = cu__type(cu, self->type);
	}

	__tag__name(self, cu, bf, len, conf);

	if (starts_with_const)
		strncat(bf, "const", len);

	return bf;
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
			struct tag *ttype = cu__type(cu, type->type);
			if (ttype == NULL)
				goto out_type_not_found;
			else {
				printed = tag__has_type_loop(type, ttype,
							     NULL, 0, fp);
				if (printed)
					return printed;
			}
			type = ttype;
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

		while (tag__is_typedef(type)) {
			struct tag *type_type;
			int n;

			ctype = tag__type(type);
			if (typedef_expanded)
				printed += fprintf(fp, " -> %s",
						   type__name(ctype, cu));
			else {
				printed += fprintf(fp, "/* typedef %s",
						   type__name(ctype, cu));
				typedef_expanded = 1;
			}
			type_type = cu__type(cu, type->type);
			if (type_type == NULL)
				goto out_type_not_found;
			n = tag__has_type_loop(type, type_type, NULL, 0, fp);
			if (n)
				return printed + n;
			type = type_type;
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
			int n;
			struct tag *ptype = cu__type(cu, type->type);
			if (ptype == NULL)
				goto out_type_not_found;
			n = tag__has_type_loop(type, ptype, NULL, 0, fp);
			if (n)
				return printed + n;
			if (ptype->tag == DW_TAG_subroutine_type) {
				printed += ftype__fprintf(tag__ftype(ptype),
							  cu, name, 0, 1,
							  conf->type_spacing,
							  conf, fp);
				break;
			}
		}
		/* Fall Thru */
	default:
		printed += fprintf(fp, "%-*s %s", conf->type_spacing,
				   tag__name(type, cu, tbf, sizeof(tbf), conf),
				   name);
		break;
	case DW_TAG_subroutine_type:
		printed += ftype__fprintf(tag__ftype(type), cu, name, 0, 0,
					  conf->type_spacing, conf, fp);
		break;
	case DW_TAG_array_type:
		printed += array_type__fprintf(type, cu, name, conf, fp);
		break;
	case DW_TAG_class_type:
	case DW_TAG_structure_type:
		ctype = tag__type(type);

		if (type__name(ctype, cu) != NULL && !expand_types)
			printed += fprintf(fp, "%s %-*s %s",
					   (type->tag == DW_TAG_class_type &&
					    !conf->classes_as_structs) ? "class" : "struct",
					   conf->type_spacing - 7,
					   type__name(ctype, cu), name);
		else
			printed += class__fprintf(tag__class(type),
						  cu, &tconf, fp);
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
	const int size = self->byte_size;
	struct conf_fprintf sconf = *conf;
	uint32_t offset = self->byte_offset;
	size_t printed = 0;
	const char *cm_name = class_member__name(self, cu),
		   *name = cm_name;

	if (!sconf.rel_offset) {
		sconf.base_offset += self->byte_offset;
		offset = sconf.base_offset;
	}

	if (self->tag.tag == DW_TAG_inheritance) {
		name = "<ancestor>";
		printed += fprintf(fp, "/* ");
	}

	printed += type__fprintf(type, cu, name, &sconf, fp);

	if (self->bitfield_size != 0)
		printed += fprintf(fp, ":%u;", self->bitfield_size);
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
			const int slen = cm_name ? (int)strlen(cm_name) : -1;
			printed += fprintf(fp, sconf.hex_fmt ?
							"%*s/* %#5x %#5x */" :
							"%*s/* %5u %5u */",
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

			printed += fprintf(fp, sconf.hex_fmt ?
						"%*s/* %#5x" : "%*s/* %5u",
					   spacing > 0 ? spacing : 0, " ",
					   offset);

			if (self->bitfield_size != 0) {
				printed += fprintf(fp, sconf.hex_fmt ?
							":%#2x" : ":%2u",
						   self->bitfield_offset);
				size_spacing -= 3;
			}

			printed += fprintf(fp, sconf.hex_fmt ?
						" %#*x */" : " %*u */",
					   size_spacing, size);
		}
	}
	return printed;
}

static size_t union_member__fprintf(struct class_member *self,
				    struct tag *type, const struct cu *cu,
				    const struct conf_fprintf *conf, FILE *fp)
{
	const size_t size = self->byte_size;
	const char *name = class_member__name(self, cu);
	size_t printed = type__fprintf(type, cu, name, conf, fp);

	if ((tag__is_union(type) || tag__is_struct(type) ||
	     tag__is_enumeration(type)) &&
		/* Look if is a type defined inline */
	    type__name(tag__type(type), cu) == NULL) {
		if (!conf->suppress_offset_comment) {
			/* Check if this is a anonymous union */
			const int slen = name ? (int)strlen(name) : -1;
			/*
			 * Add the comment with the union size after padding the
			 * '} member_name;' last line of the type printed in the
			 * above call to type__fprintf.
			 */
			printed += fprintf(fp, conf->hex_fmt ?
							";%*s/* %#11zx */" :
							";%*s/* %11zd */",
					   (conf->type_spacing +
					    conf->name_spacing - slen - 3), " ", size);
		}
	} else {
		printed += fprintf(fp, ";");

		if (!conf->suppress_offset_comment) {
			const int spacing = conf->type_spacing + conf->name_spacing - printed;
			printed += fprintf(fp, conf->hex_fmt ?
							"%*s/* %#11zx */" :
							"%*s/* %11zd */",
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
		struct tag *type = cu__type(cu, pos->tag.type);

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

const char *function__prototype(const struct function *self,
				const struct cu *cu, char *bf, size_t len)
{
	FILE *bfp = fmemopen(bf, len, "w");

	if (bfp != NULL) {
		ftype__fprintf(&self->proto, cu, NULL, 0, 0, 0,
			       &conf_fprintf__defaults, bfp);
		fclose(bfp);
	} else
		snprintf(bf, len, "<ERROR(%s): fmemopen failed!>", __func__);

	return bf;
}

size_t ftype__fprintf_parms(const struct ftype *self,
			    const struct cu *cu, int indent,
			    const struct conf_fprintf *conf, FILE *fp)
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
		name = conf->no_parm_names ? NULL : parameter__name(pos, cu);
		type = cu__type(cu, pos->tag.type);
		if (type == NULL) {
			snprintf(sbf, sizeof(sbf),
				 "<ERROR: type %d not found>", pos->tag.type);
			stype = sbf;
			goto print_it;
		}
		if (type->tag == DW_TAG_pointer_type) {
			if (type->type != 0) {
				int n;
				struct tag *ptype = cu__type(cu, type->type);
				if (ptype == NULL) {
					printed +=
					    tag__id_not_found_fprintf(fp, type->type);
					continue;
				}
				n = tag__has_type_loop(type, ptype, NULL, 0, fp);
				if (n)
					return printed + n;
				if (ptype->tag == DW_TAG_subroutine_type) {
					printed +=
					     ftype__fprintf(tag__ftype(ptype),
							    cu, name, 0, 1, 0,
							    conf, fp);
					continue;
				}
			}
		} else if (type->tag == DW_TAG_subroutine_type) {
			printed += ftype__fprintf(tag__ftype(type), cu, name,
						  0, 0, 0, conf, fp);
			continue;
		}
		stype = tag__name(type, cu, sbf, sizeof(sbf), conf);
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
				    struct function *function, uint16_t indent,
				    const struct conf_fprintf *conf, FILE *fp)
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
		const struct tag *talias = cu__function(cu, exp->ip.tag.type);
		struct function *alias = tag__function(talias);
		const char *name;

		if (alias == NULL) {
			printed += tag__id_not_found_fprintf(fp, exp->ip.tag.type);
			break;
		}
		printed = fprintf(fp, "%.*s", indent, tabs);
		name = function__name(alias, cu);
		n = fprintf(fp, "%s", name);
		size_t namelen = 0;
		if (name != NULL)
			namelen = strlen(name);
		n += ftype__fprintf_parms(&alias->proto, cu,
					  indent + (namelen + 7) / 8,
					  conf, fp);
		n += fprintf(fp, "; /* size=%zd, low_pc=%#llx */",
			     exp->size, (unsigned long long)exp->ip.addr);
#if 0
		n = fprintf(fp, "%s(); /* size=%zd, low_pc=%#llx */",
			    function__name(alias, cu), exp->size,
			    (unsigned long long)exp->ip.addr);
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
		c = fprintf(fp, "%s:", label__name(label, cu));
		printed += c;
	}
		break;
	case DW_TAG_lexical_block:
		printed = lexblock__fprintf(vtag, cu, function, indent,
					    conf, fp);
		fputc('\n', fp);
		return printed + 1;
	default:
		printed = fprintf(fp, "%.*s", indent, tabs);
		n = fprintf(fp, "%s <%llx>", dwarf_tag_name(tag->tag),
			    tag__orig_id(tag, cu));
		c += n;
		printed += n;
		break;
	}
	return printed + fprintf(fp, "%-*.*s// %5u\n", 70 - c, 70 - c, " ",
				 tag__decl_line(tag, cu));
}

size_t lexblock__fprintf(const struct lexblock *self, const struct cu *cu,
			 struct function *function, uint16_t indent,
			 const struct conf_fprintf *conf, FILE *fp)
{
	struct tag *pos;
	size_t printed;

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;
	printed = fprintf(fp, "%.*s{", indent, tabs);
	if (self->ip.addr != 0) {
		uint64_t offset = self->ip.addr - function->lexblock.ip.addr;

		if (offset == 0)
			printed += fprintf(fp, " /* low_pc=%#llx */",
					   (unsigned long long)self->ip.addr);
		else
			printed += fprintf(fp, " /* %s+%#llx */",
					   function__name(function, cu),
					   (unsigned long long)offset);
	}
	printed += fprintf(fp, "\n");
	list_for_each_entry(pos, &self->tags, node)
		printed += function__tag_fprintf(pos, cu, function, indent + 1,
						 conf, fp);
	printed += fprintf(fp, "%.*s}", indent, tabs);

	if (function->lexblock.ip.addr != self->ip.addr)
		printed += fprintf(fp, " /* lexblock size=%d */", self->size);

	return printed;
}

size_t ftype__fprintf(const struct ftype *self, const struct cu *cu,
		      const char *name, const int inlined,
		      const int is_pointer, int type_spacing,
		      const struct conf_fprintf *conf, FILE *fp)
{
	struct tag *type = cu__type(cu, self->tag.type);
	char sbf[128];
	const char *stype = tag__name(type, cu, sbf, sizeof(sbf), conf);
	size_t printed = fprintf(fp, "%s%-*s %s%s%s%s",
				 inlined ? "inline " : "",
				 type_spacing, stype,
				 self->tag.tag == DW_TAG_subroutine_type ?
					"(" : "",
				 is_pointer ? "*" : "", name ?: "",
				 self->tag.tag == DW_TAG_subroutine_type ?
					")" : "");

	return printed + ftype__fprintf_parms(self, cu, 0, conf, fp);
}

static size_t function__fprintf(const struct tag *tag_self,
				const struct cu *cu,
				const struct conf_fprintf *conf,
				FILE *fp)
{
	struct function *self = tag__function(tag_self);
	size_t printed = 0;

	if (self->virtuality == DW_VIRTUALITY_virtual ||
	    self->virtuality == DW_VIRTUALITY_pure_virtual)
		printed += fprintf(fp, "virtual ");

	printed += ftype__fprintf(&self->proto, cu, function__name(self, cu),
				  function__declared_inline(self), 0, 0,
				  conf, fp);

	if (self->virtuality == DW_VIRTUALITY_pure_virtual)
		printed += fprintf(fp, " = 0");

	return printed;
}

size_t function__fprintf_stats(const struct tag *tag_self,
			       const struct cu *cu,
			       const struct conf_fprintf *conf,
			       FILE *fp)
{
	struct function *self = tag__function(tag_self);
	size_t printed = lexblock__fprintf(&self->lexblock, cu, self, 0, conf, fp);

	printed += fprintf(fp, "/* size: %d", function__size(self));
	if (self->lexblock.nr_variables > 0)
		printed += fprintf(fp, ", variables: %u",
				   self->lexblock.nr_variables);
	if (self->lexblock.nr_labels > 0)
		printed += fprintf(fp, ", goto labels: %u",
				   self->lexblock.nr_labels);
	if (self->lexblock.nr_inline_expansions > 0)
		printed += fprintf(fp, ", inline expansions: %u (%d bytes)",
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

static size_t class__vtable_fprintf(struct class *self, const struct cu *cu,
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
				   function__name(pos, cu),
				   function__linkage_name(pos, cu));
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
	const uint16_t t = tself->namespace.tag.tag;
	size_t printed = fprintf(fp, "%s%s%s%s%s",
				 cconf.prefix ?: "", cconf.prefix ? " " : "",
				 ((cconf.classes_as_structs ||
				   t == DW_TAG_structure_type) ? "struct" :
				  t == DW_TAG_class_type ? "class" :
							"interface"),
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

		type = cu__type(cu, tag_pos->type);
		if (type != NULL)
			printed += fprintf(fp, " %s",
					   type__name(tag__type(type), cu));
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
		    pos->byte_offset != last->byte_offset &&
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
		if (last != NULL && tag_pos->tag == DW_TAG_member &&
		/*
		 * kmemcheck bitfield tricks use zero sized arrays as markers
		 * all over the place.
		 */
		    last_size != 0) {
			if (pos->byte_offset < last->byte_offset ||
			    (pos->byte_offset == last->byte_offset &&
			     last->bitfield_size == 0 &&
			     /*
			      * This is just when transitioning from a non-bitfield to
			      * a bitfield, think about zero sized arrays in the middle
			      * of a struct.
			      */
			     pos->bitfield_size != 0)) {
				if (!cconf.suppress_comments) {
					if (!newline++) {
						fputc('\n', fp);
						++printed;
					}
					printed += fprintf(fp, "%.*s/* Bitfield combined"
							   " with previous fields */\n",
							   cconf.indent, tabs);
				}
				if (pos->byte_offset != last->byte_offset)
					bitfield_real_offset = last->byte_offset + last_size;
			} else {
				const ssize_t cc_last_size = ((ssize_t)pos->byte_offset -
							      (ssize_t)last->byte_offset);

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

		type = cu__type(cu, pos->tag.type);
		if (type == NULL) {
			printed += fprintf(fp, "%.*s", cconf.indent, tabs);
			printed += tag__id_not_found_fprintf(fp, pos->tag.type);
			continue;
		}

		size = pos->byte_size;
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
			size_t real_last_size = pos->byte_offset - bitfield_real_offset;
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
		    last->byte_offset != pos->byte_offset) {
			sum += size;
			last_size = size;
		} else if (last->bitfield_size == 0 && pos->bitfield_size != 0) {
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
	if (!cconf.show_only_data_members)
		class__vtable_fprintf(self, cu, &cconf, fp);

	if (!cconf.emit_stats)
		goto out;

	printed += fprintf(fp, "\n%.*s/* size: %zd, cachelines: %zd, members: %u */",
			   cconf.indent, tabs,
			   tag__size(class__tag(self), cu),
			   tag__nr_cachelines(class__tag(self), cu),
			   tself->nr_members);
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
				   cconf.indent, tabs,
				   class_member__name(m, cu), m->byte_offset,
				   m->byte_size);
	}

	if (sum + sum_holes != tself->size - self->padding &&
	    tself->nr_members != 0)
		printed += fprintf(fp, "\n\n%.*s/* BRAIN FART ALERT! %d != %u "
				   "+ %u(holes), diff = %d */\n",
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
		struct tag *type = cu__type(cu, var->ip.tag.type);
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
	size_t printed = fprintf(fp, "namespace %s {\n",
				 namespace__name(self, cu));
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
		printed += tag__fprintf_decl_info(self, cu, fp);
	}
	printed += fprintf(fp, "%.*s", pconf->indent, tabs);

	switch (self->tag) {
	case DW_TAG_array_type:
		printed += array_type__fprintf(self, cu, "array", pconf, fp);
		break;
	case DW_TAG_enumeration_type:
		printed += enumeration__fprintf(self, cu, pconf, fp);
		break;
	case DW_TAG_typedef:
		printed += typedef__fprintf(self, cu, pconf, fp);
		break;
	case DW_TAG_class_type:
	case DW_TAG_interface_type:
	case DW_TAG_structure_type:
		printed += class__fprintf(tag__class(self), cu, pconf, fp);
		break;
	case DW_TAG_namespace:
		printed += namespace__fprintf(self, cu, pconf, fp);
		break;
	case DW_TAG_subprogram:
		printed += function__fprintf(self, cu, pconf, fp);
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
		printed += fprintf(fp, "/* %s: %s tag not supported! */",
				   __func__, dwarf_tag_name(self->tag));
		break;
	}

	if (!pconf->no_semicolon) {
		fputc(';', fp);
		++printed;
	}

	if (tag__is_function(self) && !pconf->suppress_comments) {
		const struct function *fself = tag__function(self);

		if (fself->linkage_name)
			printed += fprintf(fp, " /* linkage=%s */",
					   function__linkage_name(fself, cu));
	}

	if (pconf->expand_types)
		--self->recursivity_level;

	return printed;
}

void cus__print_error_msg(const char *progname, const struct cus *cus,
			  const char *filename, const int err)
{
	if (err == -EINVAL || (cus != NULL && list_empty(&cus->cus)))
		fprintf(stderr, "%s: couldn't load debugging info from %s\n",
		       progname, filename);
	else
		fprintf(stderr, "%s: %s\n", progname, strerror(err));
}

void dwarves__fprintf_init(uint16_t user_cacheline_size)
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
