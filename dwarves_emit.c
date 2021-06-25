/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Red Hat Inc.
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
*/

#include <string.h>

#include "list.h"
#include "dwarves_emit.h"
#include "dwarves.h"

void type_emissions__init(struct type_emissions *emissions)
{
	INIT_LIST_HEAD(&emissions->definitions);
	INIT_LIST_HEAD(&emissions->fwd_decls);
}

static void type_emissions__add_definition(struct type_emissions *emissions,
					   struct type *type)
{
	type->definition_emitted = 1;
	if (!list_empty(&type->node))
		list_del(&type->node);
	list_add_tail(&type->node, &emissions->definitions);
}

static void type_emissions__add_fwd_decl(struct type_emissions *emissions,
					 struct type *type)
{
	type->fwd_decl_emitted = 1;
	if (list_empty(&type->node))
		list_add_tail(&type->node, &emissions->fwd_decls);
}

struct type *type_emissions__find_definition(const struct type_emissions *emissions,
					     const char *name)
{
	struct type *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, &emissions->definitions, node)
		if (type__name(pos) != NULL &&
		    strcmp(type__name(pos), name) == 0)
			return pos;

	return NULL;
}

static struct type *type_emissions__find_fwd_decl(const struct type_emissions *emissions,
						  const char *name)
{
	struct type *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, &emissions->fwd_decls, node) {
		const char *curr_name = type__name(pos);

		if (curr_name && strcmp(curr_name, name) == 0)
			return pos;
	}

	return NULL;
}

static int enumeration__emit_definitions(struct tag *tag,
					 struct type_emissions *emissions,
					 const struct conf_fprintf *conf,
					 FILE *fp)
{
	struct type *etype = tag__type(tag);

	/* Have we already emitted this in this CU? */
	if (etype->definition_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (type_emissions__find_definition(emissions, type__name(etype)) != NULL) {
		/*
		 * Yes, so lets mark it visited on this CU too,
		 * to speed up the lookup.
		 */
		etype->definition_emitted = 1;
		return 0;
	}

	enumeration__fprintf(tag, conf, fp);
	fputs(";\n", fp);
	type_emissions__add_definition(emissions, etype);
	return 1;
}

static int tag__emit_definitions(struct tag *tag, struct cu *cu,
				 struct type_emissions *emissions, FILE *fp);

static int typedef__emit_definitions(struct tag *tdef, struct cu *cu,
				     struct type_emissions *emissions, FILE *fp)
{
	struct type *def = tag__type(tdef);
	struct tag *type, *ptr_type;

	/* Have we already emitted this in this CU? */
	if (def->definition_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (type_emissions__find_definition(emissions, type__name(def)) != NULL) {
		/*
		 * Yes, so lets mark it visited on this CU too,
		 * to speed up the lookup.
		 */
		def->definition_emitted = 1;
		return 0;
	}

	type = cu__type(cu, tdef->type);
	tag__assert_search_result(type);

	switch (type->tag) {
	case DW_TAG_array_type:
		tag__emit_definitions(type, cu, emissions, fp);
		break;
	case DW_TAG_typedef:
		typedef__emit_definitions(type, cu, emissions, fp);
		break;
	case DW_TAG_pointer_type:
		ptr_type = cu__type(cu, type->type);
		/* void ** can make ptr_type be NULL */
		if (ptr_type == NULL)
			break;
		if (ptr_type->tag == DW_TAG_typedef) {
			typedef__emit_definitions(ptr_type, cu, emissions, fp);
			break;
		} else if (ptr_type->tag != DW_TAG_subroutine_type)
			break;
		type = ptr_type;
		/* Fall thru */
	case DW_TAG_subroutine_type:
		ftype__emit_definitions(tag__ftype(type), cu, emissions, fp);
		break;
	case DW_TAG_enumeration_type: {
		struct type *ctype = tag__type(type);
		struct conf_fprintf conf = {
			.suffix = NULL,
		};

		if (type__name(ctype) == NULL) {
			fputs("typedef ", fp);
			conf.suffix = type__name(def);
			enumeration__emit_definitions(type, emissions, &conf, fp);
			goto out;
		} else
			enumeration__emit_definitions(type, emissions, &conf, fp);
	}
		break;
	case DW_TAG_structure_type:
	case DW_TAG_union_type: {
		struct type *ctype = tag__type(type);

		if (type__name(ctype) == NULL) {
			if (type__emit_definitions(type, cu, emissions, fp))
				type__emit(type, cu, "typedef",
					   type__name(def), fp);
			goto out;
		} else if (type__emit_definitions(type, cu, emissions, fp))
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
		typedef__fprintf(tdef, cu, NULL, fp);
		fputs(";\n", fp);
	}
out:
	type_emissions__add_definition(emissions, def);
	return 1;
}

static int type__emit_fwd_decl(struct type *ctype, struct type_emissions *emissions, FILE *fp)
{
	/* Have we already emitted this in this CU? */
	if (ctype->fwd_decl_emitted)
		return 0;

	const char *name = type__name(ctype);
	if (name == NULL)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (type_emissions__find_fwd_decl(emissions, name) != NULL) {
		/*
		 * Yes, so lets mark it visited on this CU too,
		 * to speed up the lookup.
		 */
		ctype->fwd_decl_emitted = 1;
		return 0;
	}

	fprintf(fp, "%s %s;\n",
		tag__is_union(&ctype->namespace.tag) ? "union" : "struct",
		type__name(ctype));
	type_emissions__add_fwd_decl(emissions, ctype);
	return 1;
}

static int tag__emit_definitions(struct tag *tag, struct cu *cu,
				 struct type_emissions *emissions, FILE *fp)
{
	struct tag *type = cu__type(cu, tag->type);
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
		type = cu__type(cu, type->type);
		if (type == NULL)
			return 0;
		goto next_indirection;
	case DW_TAG_typedef:
		return typedef__emit_definitions(type, cu, emissions, fp);
	case DW_TAG_enumeration_type:
		if (type__name(tag__type(type)) != NULL) {
			struct conf_fprintf conf = {
				.suffix = NULL,
			};
			return enumeration__emit_definitions(type, emissions, &conf, fp);
		}
		break;
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
		if (pointer) {
			/*
			 * Struct defined inline, no name, need to have its
			 * members types emitted.
			 */
			if (type__name(tag__type(type)) == NULL)
				type__emit_definitions(type, cu, emissions, fp);

			return type__emit_fwd_decl(tag__type(type), emissions, fp);
		}
		if (type__emit_definitions(type, cu, emissions, fp))
			type__emit(type, cu, NULL, NULL, fp);
		return 1;
	case DW_TAG_subroutine_type:
		return ftype__emit_definitions(tag__ftype(type), cu,
					       emissions, fp);
	}

	return 0;
}

int ftype__emit_definitions(struct ftype *ftype, struct cu *cu,
			    struct type_emissions *emissions, FILE *fp)
{
	struct parameter *pos;
	/* First check the function return type */
	int printed = tag__emit_definitions(&ftype->tag, cu, emissions, fp);

	/* Then its parameters */
	list_for_each_entry(pos, &ftype->parms, tag.node)
		if (tag__emit_definitions(&pos->tag, cu, emissions, fp))
			printed = 1;

	if (printed)
		fputc('\n', fp);
	return printed;
}

int type__emit_definitions(struct tag *tag, struct cu *cu,
			   struct type_emissions *emissions, FILE *fp)
{
	struct type *ctype = tag__type(tag);
	struct class_member *pos;

	if (ctype->definition_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (type_emissions__find_definition(emissions, type__name(ctype)) != NULL) {
		ctype->definition_emitted = 1;
		return 0;
	}

	if (tag__is_typedef(tag))
		return typedef__emit_definitions(tag, cu, emissions, fp);

	type_emissions__add_definition(emissions, ctype);

	type__check_structs_at_unnatural_alignments(ctype, cu);

	type__for_each_member(ctype, pos)
		if (tag__emit_definitions(&pos->tag, cu, emissions, fp))
			fputc('\n', fp);

	return 1;
}

void type__emit(struct tag *tag, struct cu *cu,
		const char *prefix, const char *suffix, FILE *fp)
{
	struct type *ctype = tag__type(tag);

	if (type__name(ctype) != NULL ||
	    suffix != NULL || prefix != NULL) {
		struct conf_fprintf conf = {
			.prefix	    = prefix,
			.suffix	    = suffix,
			.emit_stats = 1,
		};
		tag__fprintf(tag, cu, &conf, fp);
		fputc('\n', fp);
	}
}
