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
	{ "structs",			no_argument,		NULL, 's' },
	{ "functions",			no_argument,		NULL, 'f' },
	{ "verbose",			no_argument,		NULL, 'V' },
	{ NULL, 0, NULL, 0, }
};

static int show_struct_diffs;
static int show_function_diffs;
static int verbose;

static unsigned int total_cus_changed;
static unsigned int total_nr_functions_changed;
static unsigned long total_function_bytes_added;
static unsigned long total_function_bytes_removed;

static void usage(void)
{
	fprintf(stderr,
		"usage: codiff [options] <old_file> <new_file>\n"
		" where: \n"
		"   -h, --help        usage options\n"
		"   -s, --structs     show struct diffs\n"
		"   -f, --functions   show function diffs\n"
		"   -V, --verbose     show diffs details\n"
		" without options all diffs are shown\n");
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

			if (len > cu->max_len_changed_item)
				cu->max_len_changed_item = len;

			++cu->nr_functions_changed;
			if (function->diff > 0)
				cu->function_bytes_added += function->diff;
			else
				cu->function_bytes_removed += -function->diff;
		}
	}
}

static void diff_struct(struct cu *cu, struct cu *new_cu,
			struct class *structure)
{
	struct class *new_structure;
	size_t len;

	assert(structure->tag == DW_TAG_structure_type);

	if (structure->size == 0)
		return;

	new_structure = cu__find_class_by_name(new_cu, structure->name);
	if (new_structure == NULL || new_structure->size == 0)
		return;

	structure->diff = new_structure->size - structure->size;
	if (structure->diff == 0)
		return;
	++cu->nr_structures_changed;
	len = strlen(structure->name) + sizeof("struct");
	if (len > cu->max_len_changed_item)
		cu->max_len_changed_item = len;
	structure->class_to_diff = new_structure;
}

static int diff_iterator(struct cu *cu, struct class *class, void *new_cu)
{
	switch (class->tag) {
	case DW_TAG_subprogram:
		diff_function(cu, new_cu, class);
		break;
	case DW_TAG_structure_type:
		diff_struct(cu, new_cu, class);
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
	printf("  %-*.*s | %+4d\n",
	       cu->max_len_changed_item,
	       cu->max_len_changed_item,
	       class->name, class->diff);
}

static void show_diffs_structure(struct class *structure, struct cu *cu)
{
	int diff;
	const struct class *new_structure;

	printf("  struct %-*.*s | %+4d\n",
	       cu->max_len_changed_item - sizeof("struct"),
	       cu->max_len_changed_item - sizeof("struct"),
	       structure->name, structure->diff);

	if (!verbose)
		return;

	new_structure = structure->class_to_diff;
	diff = new_structure->nr_members - structure->nr_members;
	if (diff != 0)
		printf("   nr_members: %+d\n", diff);
}

static int show_function_diffs_iterator(struct cu *cu, struct class *class, void *new_cu)
{
	if (class->diff != 0 && class->tag == DW_TAG_subprogram)
		show_diffs_function(class, cu);
	return 0;
}

static int show_structure_diffs_iterator(struct cu *cu, struct class *class, void *new_cu)
{
	if (class->diff != 0 && class->tag == DW_TAG_structure_type)
		show_diffs_structure(class, cu);
	return 0;
}

static int cu_show_diffs_iterator(struct cu *cu, void *cookie)
{
	static int first_cu_printed;

	if (cu->nr_functions_changed == 0 &&
	    cu->nr_structures_changed == 0)
		return 0;

	if (first_cu_printed)
		putchar('\n');
	else
		first_cu_printed = 1;

	++total_cus_changed;

	printf("%s:\n", cu->name);

	if (cu->nr_structures_changed != 0 && show_struct_diffs) {
		cu__for_each_class(cu, show_structure_diffs_iterator, NULL);
		printf(" %u struct%s changed\n", cu->nr_structures_changed,
		       cu->nr_structures_changed > 1 ? "s" : "");
	}

	if (cu->nr_functions_changed != 0 && show_function_diffs) {
		total_nr_functions_changed += cu->nr_functions_changed;

		cu__for_each_class(cu, show_function_diffs_iterator, NULL);
		printf(" %u function%s changed", cu->nr_functions_changed,
		       cu->nr_functions_changed > 1 ? "s" : "");
		if (cu->function_bytes_added != 0) {
			total_function_bytes_added += cu->function_bytes_added;
			printf(", %u bytes added", cu->function_bytes_added);
		}
		if (cu->function_bytes_removed != 0) {
			total_function_bytes_removed += cu->function_bytes_removed;
			printf(", %u bytes removed", cu->function_bytes_removed);
		}
		putchar('\n');
	}
	return 0;
}

static void print_total_function_diff(const char *filename)
{
	printf("\n%s:\n", filename);

	printf(" %u function%s changed", total_nr_functions_changed,
	       total_nr_functions_changed > 1 ? "s" : "");

	if (total_function_bytes_added != 0)
		printf(", %lu bytes added", total_function_bytes_added);

	if (total_function_bytes_removed != 0)
		printf(", %lu bytes removed", total_function_bytes_removed);

	putchar('\n');
}

int main(int argc, char *argv[])
{
	int option, option_index;
	struct cus *old_cus, *new_cus;
	const char *old_filename, *new_filename;

	while ((option = getopt_long(argc, argv, "fhsV",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 'f': show_function_diffs = 1; break;
		case 's': show_struct_diffs = 1;   break;
		case 'V': verbose = 1;		   break;
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

	if (show_function_diffs == 0 && show_struct_diffs == 0)
		show_function_diffs = show_struct_diffs = 1;

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

	if (total_cus_changed > 1) {
		if (show_function_diffs)
			print_total_function_diff(new_filename);
	}

	return EXIT_SUCCESS;
}
