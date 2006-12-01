/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <assert.h>
#include <dwarf.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "classes.h"

static struct option long_options[] = {
	{ "help",			no_argument,		NULL, 'h' },
	{ NULL, 0, NULL, 0, }
};

static void usage(void)
{
	fprintf(stderr,
		"usage: prefcnt [options] <file_name>\n"
		" where: \n"
		"   -h, --help   usage options\n");
}

static void refcnt_class(struct class *class);

static void refcnt_member(struct class_member *member)
{
	if (member->visited)
		return;
	member->visited = 1;
	if (member->tag.type != 0) { /* if not void */
		struct class *type = cu__find_class_by_id(member->class->cu,
							  member->tag.type);
		if (type != NULL)
			refcnt_class(type);
	}
}

static void refcnt_parameter(const struct parameter *parameter)
{
	if (parameter->tag.type != 0) { /* if not void */
		struct class *type = cu__find_class_by_id(parameter->function->cu,
							  parameter->tag.type);

		if (type != NULL)
			refcnt_class(type);
	}
}

static void refcnt_variable(const struct variable *variable)
{
	if (variable->tag.type != 0) { /* if not void */
		struct class *type = cu__find_class_by_id(variable->cu,
							  variable->tag.type);
		if (type != NULL)
			refcnt_class(type);
	}
}

static void refcnt_inline_expansion(const struct inline_expansion *exp)
{
	if (exp->tag.type != 0) { /* if not void */
		struct class *type = cu__find_class_by_id(exp->function->cu,
							  exp->tag.type);
		if (type != NULL)
			refcnt_class(type);
	}
}

static void refcnt_class(struct class *class)
{
	struct class_member *member;

	class->refcnt++;

	list_for_each_entry(member, &class->members, tag.node)
		refcnt_member(member);
}

static void refcnt_function(struct function *function)
{
	struct parameter *parameter;
	struct inline_expansion *exp;
	struct variable *variable;

	function->refcnt++;

	if (function->tag.type != 0) /* if not void */ {
		struct class *type = cu__find_class_by_id(function->cu,
							  function->tag.type);
		if (type != NULL)
			refcnt_class(type);
	}

	list_for_each_entry(parameter, &function->parameters, tag.node)
		refcnt_parameter(parameter);

	list_for_each_entry(variable, &function->lexblock.variables, tag.node)
		refcnt_variable(variable);

	list_for_each_entry(exp, &function->lexblock.inline_expansions, tag.node)
		refcnt_inline_expansion(exp);
}

static int refcnt_function_iterator(struct function *function, void *cookie)
{
	refcnt_function(function);
	return 0;
}

static int refcnt_class_iterator(struct class *class, void *cookie)
{
	if (class->tag.tag == DW_TAG_structure_type)
		class__find_holes(class);

	return 0;
}

static int cu_refcnt_iterator(struct cu *cu, void *cookie)
{
	cu__for_each_class(cu, refcnt_class_iterator, cookie, NULL);
	cu__for_each_function(cu, refcnt_function_iterator, cookie);
	return 0;
}

static int lost_iterator(struct class *class, void *cookie)
{
	if (class->refcnt == 0 && class->tag.decl_file != NULL)
		class__print(class);
	return 0;
}

static int cu_lost_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_class(cu, lost_iterator, cookie, NULL);
}

int main(int argc, char *argv[])
{
	int option, option_index;
	struct cus *cus;
	const char *file_name;

	while ((option = getopt_long(argc, argv, "h",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 'h': usage(); return EXIT_SUCCESS;
		default:  usage(); return EXIT_FAILURE;
		}

	if (optind < argc) {
		switch (argc - optind) {
		case 1:	 file_name = argv[optind++];	 break;
		default: usage();			 return EXIT_FAILURE;
		}
	} else {
		usage();
		return EXIT_FAILURE;
	}

	cus = cus__new(file_name);
	if (cus == NULL) {
		fputs("prefcnt: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}

	if (cus__load(cus) != 0) {
		fprintf(stderr, "prefcnt: couldn't load DWARF info from %s\n",
			file_name);
		return EXIT_FAILURE;
	}

	cus__for_each_cu(cus, cu_refcnt_iterator, NULL, NULL);
	cus__for_each_cu(cus, cu_lost_iterator, NULL, NULL);

	return EXIT_SUCCESS;
}
