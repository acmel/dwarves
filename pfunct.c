/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <dwarf.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "classes.h"

static int verbose;

static struct option long_options[] = {
	{ "class",	  required_argument,	NULL, 'c' },
	{ "goto_labels",  no_argument,		NULL, 'g' },
	{ "help",	  no_argument,		NULL, 'h' },
	{ "sizes",	  no_argument,		NULL, 's' },
	{ "variables",	  no_argument,		NULL, 'S' },
	{ "verbose",	  no_argument,		NULL, 'V' },
	{ NULL, 0, NULL, 0, }
};

static void usage(void)
{
	fprintf(stderr,
		"usage: pfunct [options] <file_name> {<function_name>}\n"
		" where: \n"
		"   -c, --class=<class>  functions that have <class> "
					"pointer parameters\n"
		"   -g, --goto_labels    show number of goto labels in functions\n"
		"   -s, --sizes          show size of functions\n"
		"   -S, --variables	 show number of variables in functions\n"
		"   -V, --verbose        be verbose\n");
}

static int class__has_parameter_of_type(struct cu *cu, struct class *self,
					struct class *target)
{
	struct class_member *pos;

	list_for_each_entry(pos, &self->members, node) {
		struct class *class = cu__find_class_by_id(cu, pos->type);

		if (class != NULL && class->tag == DW_TAG_pointer_type) {
			class = cu__find_class_by_id(cu, class->type);
			if (class != NULL &&
			    class->id == target->id)
				return 1;
		}
	}
	return 0;
}

static int class_iterator(struct cu *cu, struct class *class, void *cookie)
{
	if (class->tag != DW_TAG_subprogram || class->inlined)
		return 0;

	if (class__has_parameter_of_type(cu, class, cookie)) {
		if (verbose)
			class__print(class, cu);
		else
			printf("%s\n", class->name);
	}
	return 0;
}

static int cu_class_iterator(struct cu *cu, void *cookie)
{
	struct class *target = cu__find_class_by_name(cu, cookie);

	if (target == NULL)
		return 0;

	return cu__for_each_class(cu, class_iterator, target);
}

static int sizes_iterator(struct cu *cu, struct class *class, void *cookie)
{
	if (class->tag != DW_TAG_subprogram || class->inlined)
		return 0;

	printf("%s: %u\n", class->name, class->high_pc - class->low_pc);
	return 0;
}

static int cu_sizes_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_class(cu, sizes_iterator, cookie);
}

static int variables_iterator(struct cu *cu, struct class *class, void *cookie)
{
	if (class->tag != DW_TAG_subprogram || class->inlined)
		return 0;

	if (class->nr_variables > 0)
		printf("%s: %u\n", class->name, class->nr_variables);
	return 0;
}

static int cu_variables_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_class(cu, variables_iterator, cookie);
}

static int goto_labels_iterator(struct cu *cu, struct class *class, void *cookie)
{
	if (class->tag != DW_TAG_subprogram || class->inlined)
		return 0;

	if (class->nr_labels > 0)
		printf("%s: %u\n", class->name, class->nr_labels);
	return 0;
}

static int cu_goto_labels_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_class(cu, goto_labels_iterator, cookie);
}

static int function_iterator(struct cu *cu, struct class *class, void *cookie)
{
	if (class->tag != DW_TAG_subprogram || class->inlined)
		return 0;

	if (strcmp(class->name, cookie) == 0) {
		class__print(class, cu);
		return 1;
	}
	return 0;
}

static int cu_function_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_class(cu, function_iterator, cookie);
}

int main(int argc, char *argv[])
{
	int option, option_index;
	const char *file_name = NULL;
	char *class_name = NULL;
	char *function_name = NULL;
	int show_sizes = 0;
	int show_variables = 0;
	int show_goto_labels = 0;

	while ((option = getopt_long(argc, argv, "c:gsSV",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 'c': class_name = optarg;	    break;
		case 's': show_sizes = 1;	    break;
		case 'S': show_variables = 1;	    break;
		case 'g': show_goto_labels = 1;	    break;
		case 'V': verbose    = 1;	    break;
		case 'h': usage();		    return EXIT_SUCCESS;
		default:  usage();		    return EXIT_FAILURE;
		}

	if (optind < argc) {
		switch (argc - optind) {
		case 1:	 file_name = argv[optind++];	 break;
		case 2:	 file_name = argv[optind++];
			 function_name = argv[optind++]; break;
		default: usage();			 return EXIT_FAILURE;
		}
	}

	if (classes__load(file_name) != 0) {
		fprintf(stderr, "pfunct: couldn't load DWARF info from %s\n",
			file_name);
		return EXIT_FAILURE;
	}

	if (show_variables)
		cus__for_each_cu(cu_variables_iterator, NULL);
	else if (show_goto_labels)
		cus__for_each_cu(cu_goto_labels_iterator, NULL);
	else if (show_sizes)
		cus__for_each_cu(cu_sizes_iterator, NULL);
	else if (class_name != NULL)
		cus__for_each_cu(cu_class_iterator, class_name);
	else if (function_name == NULL)
		classes__print(DW_TAG_subprogram);
	else
		cus__for_each_cu(cu_function_iterator, function_name);

	return EXIT_SUCCESS;
}
