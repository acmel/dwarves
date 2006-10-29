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
	{ "class",	required_argument,	NULL, 'c' },
	{ "verbose",	no_argument,		NULL, 'V' },
	{ NULL, 0, NULL, 0, }
};

static void usage(void)
{
	fprintf(stderr,
		"usage: pfunct [options] <file_name> {<function_name>}\n"
		" where: \n",
		"   -c, --class=<class>  functions that have <class> "
					"pointer parameters\n"
		"   -V, --verbose        be verbose\n");
}

static int class__has_parameter_of_type(struct class *self,
					struct class *target)
{
	struct class_member *pos;

	list_for_each_entry(pos, &self->members, node) {
		struct class *class = classes__find_by_id(&pos->type);

		if (class != NULL && class->tag == DW_TAG_pointer_type) {
			class = classes__find_by_id(&class->type);
			if (class != NULL &&
			    class->id.offset == target->id.offset)
				return 1;
		}
	}
	return 0;
}

static int iterator(struct class *class, void *cookie)
{
	if (class->tag != DW_TAG_subprogram || class->inlined)
		return 0;

	if (class__has_parameter_of_type(class, cookie)) {
		if (verbose)
			class__print(class);
		else
			printf("%s\n", class->name);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int option, option_index;
	const char *file_name = NULL;
	const char *class_name = NULL;
	const char *function_name = NULL;

	while ((option = getopt_long(argc, argv, "c:V",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 'c': class_name = optarg;	    break;
		case 'V': verbose    = 1;	    break;
		default: usage();		    return EXIT_FAILURE;
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

	if (class_name != NULL) {
		struct class *class = classes__find_by_name(class_name);

		if (class == NULL)
			printf("class %s not found!\n", class_name);
		else
			classes__for_each(iterator, class);
	} else if (function_name == NULL)
		classes__print(DW_TAG_subprogram);
	else {
		struct class *class = classes__find_by_name(function_name);
		if (class != NULL)
			class__print(class);
		else
			printf("function %s not found!\n", function_name);
	}

	return EXIT_SUCCESS;
}
