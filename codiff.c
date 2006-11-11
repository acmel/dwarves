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
		"usage: codiff [options] <old_file> <new_file>\n"
		" where: \n"
		"   -h, --help   usage options\n");
}

static void diff_function(struct cu *cu, struct cu *new_cu,
			  struct class *function)
{
	struct class *new_function;

	assert(function->tag == DW_TAG_subprogram);

	if (function->inlined)
		return;

	new_function = cu__find_class_by_name(new_cu, function->name);
	if (new_function != NULL) {
		function->diff = (class__function_size(new_function) -
				  class__function_size(function));
		if (function->diff != 0) {
			const size_t len = strlen(function->name);

			if (len > cu->max_len_changed_function)
				cu->max_len_changed_function = len;

			++cu->nr_functions_changed;
			if (function->diff > 0)
				cu->function_bytes_added += function->diff;
			else
				cu->function_bytes_removed += -function->diff;
		}
	}
}

static int diff_iterator(struct cu *cu, struct class *class, void *new_cu)
{
	switch (class->tag) {
	case DW_TAG_subprogram:
		diff_function(cu, new_cu, class);
		break;
	}

	return 0;
}

static int cu_diff_iterator(struct cu *cu, void *new_cus)
{
	struct cu *new_cu = cus__find_cu_by_name(new_cus, cu->name);

	if (new_cu != NULL)
		return cu__for_each_class(cu, diff_iterator, new_cu);
	return 0;
}

static void show_diffs_function(struct class *class, struct cu *cu)
{
	if (class->diff != 0)
		printf(" %-*.*s | %+4d\n",
		       cu->max_len_changed_function,
		       cu->max_len_changed_function,
		       class->name, class->diff);
}

static int show_diffs_iterator(struct cu *cu, struct class *class, void *new_cu)
{
	switch (class->tag) {
	case DW_TAG_subprogram:
		show_diffs_function(class, cu);
		break;
	}

	return 0;
}

static int cu_show_diffs_iterator(struct cu *cu, void *cookie)
{
	static int first_cu_printed;

	if (cu->nr_functions_changed == 0)
		return 0;

	if (first_cu_printed)
		putchar('\n');
	else
		first_cu_printed = 1;
	printf("%s:\n", cu->name);
	cu__for_each_class(cu, show_diffs_iterator, NULL);
	printf("%u function%s changed", cu->nr_functions_changed,
	       cu->nr_functions_changed > 1 ? "s" : "");
	if (cu->function_bytes_added != 0)
		printf(", %u bytes added", cu->function_bytes_added);
	if (cu->function_bytes_removed != 0)
		printf(", %u bytes removed", cu->function_bytes_removed);
	putchar('\n');
	return 0;
}

int main(int argc, char *argv[])
{
	int option, option_index;
	struct cus *old_cus, *new_cus;
	const char *old_filename, *new_filename;

	while ((option = getopt_long(argc, argv, "h",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 'h': usage(); return EXIT_SUCCESS;
		default:  usage(); return EXIT_FAILURE;
		}

	if (optind < argc) {
		switch (argc - optind) {
		case 2:	 old_filename = argv[optind++];
			 new_filename = argv[optind++]; break;
		case 1:
		default: usage();			 return EXIT_FAILURE;
		}
	} else {
		usage();
		return EXIT_FAILURE;
	}

	old_cus = cus__new(old_filename);
	new_cus = cus__new(new_filename);
	if (old_cus == NULL || new_cus == NULL) {
		fputs("codiff: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}

	if (cus__load(old_cus) != 0) {
		fprintf(stderr, "codiff: couldn't load DWARF info from %s\n",
			old_filename);
		return EXIT_FAILURE;
	}

	if (cus__load(new_cus) != 0) {
		fprintf(stderr, "codiff: couldn't load DWARF info from %s\n",
			new_filename);
		return EXIT_FAILURE;
	}

	cus__for_each_cu(old_cus, cu_diff_iterator, new_cus);
	cus__for_each_cu(old_cus, cu_show_diffs_iterator, NULL);

	return EXIT_SUCCESS;
}
