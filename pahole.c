/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <getopt.h>
#include <stdio.h>
#include <dwarf.h>
#include <stdlib.h>

#include "classes.h"

static struct option long_options[] = {
	{ "class_name_len",	no_argument,		NULL, 'N' },
	{ "help",		no_argument,		NULL, 'h' },
	{ "nr_members",		no_argument,		NULL, 'n' },
	{ "sizes",		no_argument,		NULL, 's' },
	{ NULL, 0, NULL, 0, }
};

static void usage(void)
{
	fprintf(stderr,
		"usage: pfunct [options] <file_name> {<function_name>}\n"
		" where: \n"
		"   -h, --help            show usage info\n"
		"   -N, --class_name_len  show size of classes\n"
		"   -s, --sizes           show size of classes\n"
		"   -m, --nr_members	  show number of members in classes\n");
}

static int nr_members_iterator(struct cu *cu, struct class *class, void *cookie)
{
	if (class->tag != DW_TAG_structure_type)
		return 0;

	if (class->nr_members > 0 && class->name != NULL)
		printf("%s: %u\n", class->name, class->nr_members);
	return 0;
}

static int cu_nr_members_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_class(cu, nr_members_iterator, cookie);
}

static int sizes_iterator(struct cu *cu, struct class *class, void *cookie)
{
	if (class->tag != DW_TAG_structure_type)
		return 0;

	if (class->name != NULL && class->size > 0)
		printf("%s: %u\n", class->name, class->size);
	return 0;
}

static int cu_sizes_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_class(cu, sizes_iterator, cookie);
}

int main(int argc, char *argv[])
{
	int option, option_index;
	char *file_name;
	char *class_name = NULL;
	int show_sizes = 0;
	int show_nr_members = 0;
	int show_class_name_len = 0;

	while ((option = getopt_long(argc, argv, "hnNs",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 's': show_sizes = 1;		break;
		case 'n': show_nr_members = 1;		break;
		case 'N': show_class_name_len = 1;	break;
		case 'h': usage();			return EXIT_SUCCESS;
		default:  usage();			return EXIT_FAILURE;
		}

	if (optind < argc) {
		switch (argc - optind) {
		case 1:	 file_name = argv[optind++];	break;
		case 2:	 file_name = argv[optind++];
			 class_name = argv[optind++];	break;
		default: usage();			return EXIT_FAILURE;
		}
	}

	if (classes__load(file_name) != 0) {
		fprintf(stderr, "pahole: couldn't load DWARF info from %s\n",
		       file_name);
		return EXIT_FAILURE;
	}

	if (show_nr_members)
		cus__for_each_cu(cu_nr_members_iterator, NULL);
	else if (show_sizes)
		cus__for_each_cu(cu_sizes_iterator, NULL);
	else if (class_name != NULL) {
		struct cu *cu;
		struct class *class = cus__find_class_by_name(&cu, class_name);
		if (class != NULL) {
			class__find_holes(class, cu);
			class__print(class, cu);
		} else
			printf("struct %s not found!\n", class_name);
	} else
		classes__print(DW_TAG_structure_type);

	return EXIT_SUCCESS;
}
