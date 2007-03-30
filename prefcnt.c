/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <assert.h>
#include <dwarf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dwarves.h"

static void refcnt_tag(struct tag *tag, const struct cu *cu);

static void refcnt_member(struct class_member *member, const struct cu *cu)
{
	if (member->visited)
		return;
	member->visited = 1;
	if (member->tag.type != 0) { /* if not void */
		struct tag *type = cu__find_tag_by_id(cu, member->tag.type);
		if (type != NULL)
			refcnt_tag(type, cu);
	}
}

static void refcnt_parameter(const struct parameter *parameter,
			     const struct cu *cu)
{
	if (parameter->tag.type != 0) { /* if not void */
		struct tag *type = cu__find_tag_by_id(cu, parameter->tag.type);
		if (type != NULL)
			refcnt_tag(type, cu);
	}
}

static void refcnt_variable(const struct variable *variable,
			    const struct cu *cu)
{
	if (variable->tag.type != 0) { /* if not void */
		struct tag *type = cu__find_tag_by_id(cu, variable->tag.type);
		if (type != NULL)
			refcnt_tag(type, cu);
	}
}

static void refcnt_inline_expansion(const struct inline_expansion *exp,
				    const struct cu *cu)
{
	if (exp->tag.type != 0) { /* if not void */
		struct tag *type = cu__find_tag_by_id(cu, exp->tag.type);
		if (type != NULL)
			refcnt_tag(type, cu);
	}
}

static void refcnt_tag(struct tag *tag, const struct cu *cu)
{
	struct class_member *member;

	tag->refcnt++;

	if (tag->tag == DW_TAG_structure_type ||
	    tag->tag == DW_TAG_union_type)
		list_for_each_entry(member, &tag__type(tag)->members, tag.node)
			refcnt_member(member, cu);
}

static void refcnt_function(struct function *function, const struct cu *cu)
{
	struct parameter *parameter;
	struct tag *pos;

	function->proto.tag.refcnt++;

	if (function->proto.tag.type != 0) /* if not void */ {
		struct tag *type =
			cu__find_tag_by_id(cu, function->proto.tag.type);
		if (type != NULL)
			refcnt_tag(type, cu);
	}

	list_for_each_entry(parameter, &function->proto.parms, tag.node)
		refcnt_parameter(parameter, cu);

	list_for_each_entry(pos, &function->lexblock.tags, node)
		switch (pos->tag) {
		case DW_TAG_variable:
			refcnt_variable(tag__variable(pos), cu);
			break;
		case DW_TAG_inlined_subroutine:
			refcnt_inline_expansion(tag__inline_expansion(pos), cu);
			break;
		}
}

static int refcnt_function_iterator(struct function *function,
				    const struct cu *cu,
				    void *cookie __unused)
{
	refcnt_function(function, cu);
	return 0;
}

static int refcnt_tag_iterator(struct tag *tag, struct cu *cu, void *cookie)
{
	if (tag->tag == DW_TAG_structure_type)
		class__find_holes(tag__class(tag), cu);
	else if (tag->tag == DW_TAG_structure_type)
		refcnt_function_iterator(tag__function(tag), cu, cookie);

	return 0;
}

static int cu_refcnt_iterator(struct cu *cu, void *cookie)
{
	cu__for_each_tag(cu, refcnt_tag_iterator, cookie, NULL);
	return 0;
}

static int lost_iterator(struct tag *tag, struct cu *cu,
			 void *cookie __unused)
{
	if (tag->refcnt == 0 && tag->decl_file != NULL) {
		tag__fprintf(tag, cu, NULL, NULL, 0, stdout);
		puts(";\n");
	}
	return 0;
}

static int cu_lost_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_tag(cu, lost_iterator, cookie, NULL);
}

int main(int argc, char *argv[])
{
	int err, remaining;
	struct cus *cus = cus__new(NULL, NULL);

	if (cus == NULL) {
		fputs("prefcnt: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}

	err = cus__loadfl(cus, NULL, argc, argv, &remaining);
	if (err != 0)
		return EXIT_FAILURE;

	dwarves__init(0);
	cus__for_each_cu(cus, cu_refcnt_iterator, NULL, NULL);
	cus__for_each_cu(cus, cu_lost_iterator, NULL, NULL);

	return EXIT_SUCCESS;
}
