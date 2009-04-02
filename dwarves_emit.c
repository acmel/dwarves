/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Red Hat Inc.
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <string.h>

#include "list.h"
#include "dwarves_emit.h"
#include "dwarves.h"

void type_emissions__init(struct type_emissions *self)
{
	INIT_LIST_HEAD(&self->definitions);
	INIT_LIST_HEAD(&self->fwd_decls);
}

static void type_emissions__add_definition(struct type_emissions *self,
					   struct type *type)
{
	type->definition_emitted = 1;
	if (!list_empty(&type->node))
		list_del(&type->node);
	list_add_tail(&type->node, &self->definitions);
}

static void type_emissions__add_fwd_decl(struct type_emissions *self,
					 struct type *type)
{
	type->fwd_decl_emitted = 1;
	if (list_empty(&type->node))
		list_add_tail(&type->node, &self->fwd_decls);
}

struct type *type_emissions__find_definition(const struct type_emissions *self,
					     const struct cu *cu,
					     const char *name)
{
	struct type *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, &self->definitions, node)
		if (type__name(pos, cu) != NULL &&
		    strcmp(type__name(pos, cu), name) == 0)
			return pos;

	return NULL;
}

static struct type *type_emissions__find_fwd_decl(const struct type_emissions *self,
						  const struct cu *cu,
						  const char *name)
{
	struct type *pos;

	list_for_each_entry(pos, &self->fwd_decls, node)
		if (strcmp(type__name(pos, cu), name) == 0)
			return pos;

	return NULL;
}

static int enumeration__emit_definitions(struct tag *self, struct cu *cu,
					 struct type_emissions *emissions,
					 const struct conf_fprintf *conf,
					 FILE *fp)
{
	struct type *etype = tag__type(self);

	/* Have we already emitted this in this CU? */
	if (etype->definition_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (type_emissions__find_definition(emissions, cu,
					    type__name(etype, cu)) != NULL) {
		/*
		 * Yes, so lets mark it visited on this CU too,
		 * to speed up the lookup.
		 */
		etype->definition_emitted = 1;
		return 0;
	}

	enumeration__fprintf(self, cu, conf, fp);
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
	int is_pointer = 0;

	/* Have we already emitted this in this CU? */
	if (def->definition_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (type_emissions__find_definition(emissions, cu,
					    type__name(def, cu)) != NULL) {
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
		tag__assert_search_result(ptr_type);
		if (ptr_type->tag != DW_TAG_subroutine_type)
			break;
		type = ptr_type;
		is_pointer = 1;
		/* Fall thru */
	case DW_TAG_subroutine_type:
		ftype__emit_definitions(tag__ftype(type), cu, emissions, fp);
		break;
	case DW_TAG_enumeration_type: {
		struct type *ctype = tag__type(type);
		struct conf_fprintf conf = {
			.suffix = NULL,
		};

		if (type__name(ctype, cu) == NULL) {
			fputs("typedef ", fp);
			conf.suffix = type__name(def, cu);
			enumeration__emit_definitions(type, cu, emissions,
						      &conf, fp);
			goto out;
		} else
			enumeration__emit_definitions(type, cu, emissions,
						      &conf, fp);
	}
		break;
	case DW_TAG_structure_type:
	case DW_TAG_union_type: {
		struct type *ctype = tag__type(type);

		if (type__name(ctype, cu) == NULL) {
			if (type__emit_definitions(type, cu, emissions, fp))
				type__emit(type, cu, "typedef",
					   type__name(def, cu), fp);
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

int type__emit_fwd_decl(struct type *ctype, const struct cu *cu,
			struct type_emissions *emissions, FILE *fp)
{
	/* Have we already emitted this in this CU? */
	if (ctype->fwd_decl_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (type_emissions__find_fwd_decl(emissions, cu,
					  type__name(ctype, cu)) != NULL) {
		/*
		 * Yes, so lets mark it visited on this CU too,
		 * to speed up the lookup.
		 */
		ctype->fwd_decl_emitted = 1;
		return 0;
	}

	fprintf(fp, "%s %s;\n",
		tag__is_union(&ctype->namespace.tag) ? "union" : "struct",
		type__name(ctype, cu));
	type_emissions__add_fwd_decl(emissions, ctype);
	return 1;
}

static int tag__emit_definitions(struct tag *self, struct cu *cu,
				 struct type_emissions *emissions, FILE *fp)
{
	struct tag *type = cu__type(cu, self->type);
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
		if (type__name(tag__type(type), cu) != NULL) {
			struct conf_fprintf conf = {
				.suffix = NULL,
			};
			return enumeration__emit_definitions(type, cu, emissions,
							     &conf, fp);
		}
		break;
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
		if (pointer)
			return type__emit_fwd_decl(tag__type(type), cu,
						   emissions, fp);
		if (type__emit_definitions(type, cu, emissions, fp))
			type__emit(type, cu, NULL, NULL, fp);
		return 1;
	case DW_TAG_subroutine_type:
		return ftype__emit_definitions(tag__ftype(type), cu,
					       emissions, fp);
	}

	return 0;
}

int ftype__emit_definitions(struct ftype *self, struct cu *cu,
			    struct type_emissions *emissions, FILE *fp)
{
	struct parameter *pos;
	/* First check the function return type */
	int printed = tag__emit_definitions(&self->tag, cu, emissions, fp);

	/* Then its parameters */
	list_for_each_entry(pos, &self->parms, tag.node)
		if (tag__emit_definitions(&pos->tag, cu, emissions, fp))
			printed = 1;

	if (printed)
		fputc('\n', fp);
	return printed;
}

int type__emit_definitions(struct tag *self, struct cu *cu,
			   struct type_emissions *emissions, FILE *fp)
{
	struct type *ctype = tag__type(self);
	struct class_member *pos;

	if (ctype->definition_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (type_emissions__find_definition(emissions, cu,
					    type__name(ctype, cu)) != NULL) {
		ctype->definition_emitted = 1;
		return 0;
	}

	type_emissions__add_definition(emissions, ctype);

	type__for_each_member(ctype, pos)
		if (tag__emit_definitions(&pos->tag, cu, emissions, fp))
			fputc('\n', fp);

	return 1;
}

void type__emit(struct tag *tag_self, struct cu *cu,
		const char *prefix, const char *suffix, FILE *fp)
{
	struct type *ctype = tag__type(tag_self);

	if (type__name(ctype, cu) != NULL ||
	    suffix != NULL || prefix != NULL) {
		struct conf_fprintf conf = {
			.prefix	    = prefix,
			.suffix	    = suffix,
			.emit_stats = 1,
		};
		tag__fprintf(tag_self, cu, &conf, fp);
		fputc('\n', fp);
	}
}
