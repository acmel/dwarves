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
	{ "terse_type_changes",		no_argument,		NULL, 't' },
	{ "structs",			no_argument,		NULL, 's' },
	{ "functions",			no_argument,		NULL, 'f' },
	{ "verbose",			no_argument,		NULL, 'V' },
	{ NULL, 0, NULL, 0, }
};

static int show_struct_diffs;
static int show_function_diffs;
static int verbose;
static int show_terse_type_changes;

#define TCHANGEF__SIZE		(1 << 0)
#define TCHANGEF__NR_MEMBERS	(1 << 1)
#define TCHANGEF__TYPE		(1 << 2)
#define TCHANGEF__OFFSET	(1 << 3)
#define TCHANGEF__BIT_OFFSET	(1 << 4)
#define TCHANGEF__BIT_SIZE	(1 << 5)

static unsigned int terse_type_changes;

static unsigned int total_cus_changed;
static unsigned int total_nr_functions_changed;
static unsigned long total_function_bytes_added;
static unsigned long total_function_bytes_removed;

static void usage(void)
{
	fprintf(stderr,
		"usage: codiff [options] <old_file> <new_file>\n"
		" where: \n"
		"   -h, --help                usage options\n"
		"   -s, --structs             show struct diffs\n"
		"   -f, --functions           show function diffs\n"
		"   -t, --terse_type_changes  show terse type changes\n"
		"   -V, --verbose             show diffs details\n"
		" without options all diffs are shown\n");
}

static void diff_function(const struct cu *new_cu, struct function *function)
{
	struct function *new_function;

	assert(function->tag.tag == DW_TAG_subprogram);

	if (function->inlined)
		return;

	new_function = cu__find_function_by_name(new_cu, function->name);
	if (new_function != NULL) {
		function->diff = (function__size(new_function) -
				  function__size(function));
		if (function->diff != 0) {
			const size_t len = strlen(function->name);

			if (len > function->cu->max_len_changed_item)
				function->cu->max_len_changed_item = len;

			++function->cu->nr_functions_changed;
			if (function->diff > 0)
				function->cu->function_bytes_added += function->diff;
			else
				function->cu->function_bytes_removed += -function->diff;
		}
	}
}

static int check_print_change(const struct class_member *old,
			      const struct class_member *new, int print)
{
	char old_class_name[128];
	char new_class_name[128];
	char old_member_name[128];
	char new_member_name[128];
	uint64_t old_size;
	uint64_t new_size;
	int changes = 0;

	old_size = class_member__names(old, old_class_name,
				       sizeof(old_class_name),
				       old_member_name,
				       sizeof(old_member_name));
	if (old_size == (uint64_t)-1)
		return 0;
	new_size = class_member__names(new, new_class_name,
				       sizeof(new_class_name),
				       new_member_name,
				       sizeof(new_member_name));
	if (new_size == (uint64_t)-1)
		return 0;

	if (old_size != new_size)
		changes = 1;

	if (old->offset != new->offset) {
		changes = 1;
		terse_type_changes |= TCHANGEF__OFFSET;
	}

	if (old->bit_offset != new->bit_offset) {
		changes = 1;
		terse_type_changes |= TCHANGEF__BIT_OFFSET;
	}

	if (old->bit_size != new->bit_size) {
		changes = 1;
		terse_type_changes |= TCHANGEF__BIT_SIZE;
	}

	if (strcmp(old_class_name, new_class_name) != 0) {
		changes = 1;
		terse_type_changes |= TCHANGEF__TYPE;
	}

	if (changes && print && !show_terse_type_changes)
		printf("    %s\n"
		       "     from: %-21s /* %5llu(%u) %5llu(%u) */\n"
		       "     to:   %-21s /* %5llu(%u) %5llu(%u) */\n",
		       old_member_name,
		       old_class_name, old->offset, old->bit_offset, old_size, old->bit_size,
		       new_class_name, new->offset, new->bit_offset, new_size, new->bit_size);

	return changes;
}

static int check_print_members_changes(const struct class *structure,
				       const struct class *new_structure,
				       int print)
{
	int changes = 0;
	struct class_member *member;

	list_for_each_entry(member, &structure->members, tag.node) {
		struct class_member *twin =
			class__find_member_by_name(new_structure, member->name);
		if (twin != NULL)
			if (check_print_change(member, twin, print))
				changes = 1;
	}
	return changes;
}

static void diff_struct(const struct cu *new_cu, struct class *structure)
{
	struct class *new_structure;
	size_t len;

	assert(structure->tag.tag == DW_TAG_structure_type);

	if (structure->size == 0)
		return;

	new_structure = cu__find_class_by_name(new_cu, structure->name);
	if (new_structure == NULL || new_structure->size == 0)
		return;

	assert(new_structure->tag.tag == DW_TAG_structure_type);

	structure->diff = structure->size != new_structure->size ||
			  structure->nr_members != new_structure->nr_members ||
			  check_print_members_changes(structure,
					  	      new_structure, 0);
	if (!structure->diff)
		return;
	++structure->cu->nr_structures_changed;
	len = strlen(structure->name) + sizeof("struct");
	if (len > structure->cu->max_len_changed_item)
		structure->cu->max_len_changed_item = len;
	structure->class_to_diff = new_structure;
}

static int diff_class_iterator(struct class *class, void *new_cu)
{
	if (class->tag.tag == DW_TAG_structure_type)
		diff_struct(new_cu, class);

	return 0;
}

static int diff_function_iterator(struct function *function, void *new_cu)
{
	diff_function(new_cu, function);
	return 0;
}

static int cu_diff_iterator(struct cu *cu, void *new_cus)
{
	struct cu *new_cu = cus__find_cu_by_name(new_cus, cu->name);

	if (new_cu != NULL) {
		cu__for_each_class(cu, diff_class_iterator, new_cu, NULL);
		cu__for_each_function(cu, diff_function_iterator, new_cu, NULL);
	}

	return 0;
}

static void show_diffs_function(const struct function *function)
{
	printf("  %-*.*s | %+4d\n",
	       function->cu->max_len_changed_item,
	       function->cu->max_len_changed_item,
	       function->name, function->diff);
}

static void show_changed_member(char change, const struct class_member *member)
{
	char class_name[128];
	char member_name[128];
	uint64_t size;

	size = class_member__names(member, class_name, sizeof(class_name),
				   member_name, sizeof(member_name));
	printf("    %c%-26s %-21s /* %5llu %5llu */\n",
	       change, class_name, member_name, member->offset, size);
}

static void show_nr_members_changes(const struct class *structure,
				    const struct class *new_structure)
{
	struct class_member *member;

	/* Find the removed ones */
	list_for_each_entry(member, &structure->members, tag.node) {
		struct class_member *twin =
			class__find_member_by_name(new_structure, member->name);
		if (twin == NULL)
			show_changed_member('-', member);
	}

	/* Find the new ones */
	list_for_each_entry(member, &new_structure->members, tag.node) {
		struct class_member *twin =
			class__find_member_by_name(structure, member->name);
		if (twin == NULL)
			show_changed_member('+', member);
	}
}

static void print_terse_type_changes(const struct class *structure)
{
	const char *sep = "";

	printf("struct %s: ", structure->name);

	if (terse_type_changes & TCHANGEF__SIZE) {
		fputs("size", stdout);
		sep = ", ";
	}
	if (terse_type_changes & TCHANGEF__NR_MEMBERS) {
		printf("%snr_members", sep);
		sep = ", ";
	}
	if (terse_type_changes & TCHANGEF__TYPE) {
		printf("%stype", sep);
		sep = ", ";
	}
	if (terse_type_changes & TCHANGEF__OFFSET) {
		printf("%soffset", sep);
		sep = ", ";
	}
	if (terse_type_changes & TCHANGEF__BIT_OFFSET) {
		printf("%sbit_offset", sep);
		sep = ", ";
	}
	if (terse_type_changes & TCHANGEF__BIT_SIZE)
		printf("%sbit_size", sep);

	putchar('\n');
}

static void show_diffs_structure(const struct class *structure)
{
	const struct class *new_structure = structure->class_to_diff;
	int diff = new_structure->size - structure->size;

	terse_type_changes = 0;

	if (!show_terse_type_changes)
		printf("  struct %-*.*s | %+4d\n",
		       structure->cu->max_len_changed_item - sizeof("struct"),
		       structure->cu->max_len_changed_item - sizeof("struct"),
		       structure->name, diff);

	if (diff != 0)
		terse_type_changes |= TCHANGEF__SIZE;

	if (!verbose && !show_terse_type_changes)
		return;

	diff = new_structure->nr_members - structure->nr_members;
	if (diff != 0) {
		terse_type_changes |= TCHANGEF__NR_MEMBERS;
		if (!show_terse_type_changes) {
			printf("   nr_members: %+d\n", diff);
			show_nr_members_changes(structure, new_structure);
		}
	}
	check_print_members_changes(structure, new_structure, 1);
	if (show_terse_type_changes)
		print_terse_type_changes(structure);
}

static int show_function_diffs_iterator(struct function *function, void *new_cu)
{
	if (function->diff != 0)
		show_diffs_function(function);
	return 0;
}

static int show_structure_diffs_iterator(struct class *class, void *new_cu)
{
	if (class->diff != 0 && class->tag.tag == DW_TAG_structure_type)
		show_diffs_structure(class);
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

	if (show_terse_type_changes) {
		cu__for_each_class(cu, show_structure_diffs_iterator,
				   NULL, NULL);
		return 0;
	}

	if (cu->nr_structures_changed != 0 && show_struct_diffs) {
		cu__for_each_class(cu, show_structure_diffs_iterator,
				   NULL, NULL);
		printf(" %u struct%s changed\n", cu->nr_structures_changed,
		       cu->nr_structures_changed > 1 ? "s" : "");
	}

	if (cu->nr_functions_changed != 0 && show_function_diffs) {
		total_nr_functions_changed += cu->nr_functions_changed;

		cu__for_each_function(cu, show_function_diffs_iterator,
				      NULL, NULL);
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

	while ((option = getopt_long(argc, argv, "fhstV",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 'f': show_function_diffs = 1;	break;
		case 's': show_struct_diffs = 1;	break;
		case 't': show_terse_type_changes = 1;	break;
		case 'V': verbose = 1;			break;
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

	if (show_function_diffs == 0 && show_struct_diffs == 0 &&
	    show_terse_type_changes == 0)
		show_function_diffs = show_struct_diffs = 1;

	old_cus = cus__new();
	new_cus = cus__new();
	if (old_cus == NULL || new_cus == NULL) {
		fputs("codiff: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}

	if (cus__load(old_cus, old_filename) != 0) {
		fprintf(stderr, "codiff: couldn't load DWARF info from %s\n",
			old_filename);
		return EXIT_FAILURE;
	}

	if (cus__load(new_cus, new_filename) != 0) {
		fprintf(stderr, "codiff: couldn't load DWARF info from %s\n",
			new_filename);
		return EXIT_FAILURE;
	}

	cus__for_each_cu(old_cus, cu_diff_iterator, new_cus, NULL);
	cus__for_each_cu(old_cus, cu_show_diffs_iterator, NULL, NULL);

	if (total_cus_changed > 1) {
		if (show_function_diffs)
			print_total_function_diff(new_filename);
	}

	return EXIT_SUCCESS;
}
