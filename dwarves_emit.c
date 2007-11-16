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

struct type *cus__find_definition(const struct cus *self, const char *name)
{
	struct type *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, self->definitions, node)
		if (type__name(pos, NULL) != NULL &&
		    strcmp(type__name(pos, NULL), name) == 0)
			return pos;

	return NULL;
}

static struct type *cus__find_fwd_decl(const struct cus *self,
				       const char *name)
{
	struct type *pos;

	list_for_each_entry(pos, self->fwd_decls, node)
		if (strcmp(type__name(pos, NULL), name) == 0)
			return pos;

	return NULL;
}

static int cus__emit_enumeration_definitions(struct cus *self, struct tag *tag,
					     const struct cu *cu,
					     const struct conf_fprintf *conf,
					     FILE *fp)
{
	struct type *etype = tag__type(tag);

	/* Have we already emitted this in this CU? */
	if (etype->definition_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (cus__find_definition(self, type__name(etype, cu)) != NULL) {
		/*
		 * Yes, so lets mark it visited on this CU too,
		 * to speed up the lookup.
		 */
		etype->definition_emitted = 1;
		return 0;
	}

	enumeration__fprintf(tag, cu, conf, fp);
	fputs(";\n", fp);
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
	if (cus__find_definition(self, type__name(def, cu)) != NULL) {
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
		struct type *ctype = tag__type(type);
		struct conf_fprintf conf = {
			.suffix = NULL,
		};

		tag__fprintf_decl_info(type, fp);
		if (type__name(ctype, cu) == NULL) {
			fputs("typedef ", fp);
			conf.suffix = type__name(def, cu);
			cus__emit_enumeration_definitions(self, type, cu, &conf, fp);
			goto out;
		} else 
			cus__emit_enumeration_definitions(self, type, cu, &conf, fp);
	}
		break;
	case DW_TAG_structure_type:
	case DW_TAG_union_type: {
		struct type *ctype = tag__type(type);

		if (type__name(ctype, cu) == NULL) {
			if (cus__emit_type_definitions(self, cu, type, fp))
				type__emit(type, cu, "typedef",
					   type__name(def, cu), fp);
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
		typedef__fprintf(tdef, cu, NULL, fp);
		fputs(";\n", fp);
	}
out:
	cus__add_definition(self, def);
	return 1;
}

int cus__emit_fwd_decl(struct cus *self, struct type *ctype,
		       const struct cu *cu, FILE *fp)
{
	/* Have we already emitted this in this CU? */
	if (ctype->fwd_decl_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (cus__find_fwd_decl(self, type__name(ctype, cu)) != NULL) {
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
		if (type__name(tag__type(type), cu) != NULL) {
			struct conf_fprintf conf = {
				.suffix = NULL,
			};
			tag__fprintf_decl_info(type, fp);
			return cus__emit_enumeration_definitions(self, type,
								 cu, &conf, fp);
		}
		break;
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
		if (pointer)
			return cus__emit_fwd_decl(self, tag__type(type),
						  cu, fp);
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

	if (ctype->definition_emitted)
		return 0;

	/* Ok, lets look at the previous CUs: */
	if (cus__find_definition(self, type__name(ctype, cu)) != NULL) {
		ctype->definition_emitted = 1;
		return 0;
	}

	cus__add_definition(self, ctype);

	type__for_each_member(ctype, pos)
		if (cus__emit_tag_definitions(self, cu, &pos->tag, fp))
			fputc('\n', fp);

	return 1;
}

void type__emit(struct tag *tag_self, struct cu *cu,
		const char *prefix, const char *suffix, FILE *fp)
{
	struct type *ctype = tag__type(tag_self);

	if (tag__is_struct(tag_self))
		class__find_holes(tag__class(tag_self), cu);

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
