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

#include "dwarves.h"

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

static uint32_t terse_type_changes;

static uint32_t total_cus_changed;
static uint32_t total_nr_functions_changed;
static uint32_t total_function_bytes_added;
static uint32_t total_function_bytes_removed;

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

struct diff_info {
	const struct tag *tag;
	const struct cu	 *cu;
	int32_t		 diff;
};

static struct diff_info *diff_info__new(const struct tag *twin,
					const struct cu *cu,
					int32_t diff)
{
	struct diff_info *self = malloc(sizeof(*self));

	if (self == NULL) {
		puts("out of memory!");
		exit(1);
	}
	self->tag  = twin;
	self->cu   = cu;
	self->diff = diff;
	return self;
}

static void diff_function(const struct cu *new_cu, struct function *function,
			  struct cu *cu)
{
	struct tag *new_tag;
	const char *name;

	assert(function->proto.tag.tag == DW_TAG_subprogram);

	if (function->inlined || function->abstract_origin != 0)
		return;

	name = function__name(function, cu);
	new_tag = cu__find_function_by_name(new_cu, name);
	if (new_tag != NULL) {
		struct function *new_function = tag__function(new_tag);
		int32_t diff = (function__size(new_function) -
				function__size(function));
		if (diff != 0) {
			const size_t len = strlen(name);

			function->priv = diff_info__new(&new_function->proto.tag, new_cu,
							diff);
			if (len > cu->max_len_changed_item)
				cu->max_len_changed_item = len;

			++cu->nr_functions_changed;
			if (diff > 0)
				cu->function_bytes_added += diff;
			else
				cu->function_bytes_removed += -diff;
		}
	} else {
		const size_t len = strlen(name);
		const uint32_t diff = -function__size(function);

		if (len > cu->max_len_changed_item)
			cu->max_len_changed_item = len;
		function->priv = diff_info__new(NULL, NULL, diff);
		++cu->nr_functions_changed;
		cu->function_bytes_removed += -diff;
	}
}

static int check_print_change(const struct class_member *old,
			      const struct cu *old_cu,
			      const struct class_member *new,
			      const struct cu *new_cu,
			      int print)
{
	size_t old_size, new_size;
	char old_type_name[128], new_type_name[128];
	const struct tag *old_type = cu__find_tag_by_id(old_cu, old->tag.type);
	const struct tag *new_type = cu__find_tag_by_id(new_cu, new->tag.type);
	int changes = 0;

	if (old_type == NULL || new_type == NULL)
		return 0;

	old_size = tag__size(old_type, old_cu);
	new_size = tag__size(new_type, new_cu);
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

	if (strcmp(tag__name(old_type, old_cu, old_type_name,
			     sizeof(old_type_name)),
		   tag__name(new_type, new_cu, new_type_name,
			     sizeof(new_type_name))) != 0) {
		changes = 1;
		terse_type_changes |= TCHANGEF__TYPE;
	}

	if (changes && print && !show_terse_type_changes)
		printf("    %s\n"
		       "     from: %-21s /* %5u(%u) %5u(%u) */\n"
		       "     to:   %-21s /* %5u(%u) %5u(%u) */\n",
		       old->name,
		       old_type_name, old->offset, old->bit_offset,
		       old_size, old->bit_size,
		       new_type_name, new->offset, new->bit_offset,
		       new_size, new->bit_size);

	return changes;
}

static int check_print_members_changes(const struct class *structure,
				       const struct cu *cu,
				       const struct class *new_structure,
				       const struct cu *new_cu,
				       int print)
{
	int changes = 0;
	struct class_member *member;

	list_for_each_entry(member, &structure->type.members, tag.node) {
		struct class_member *twin =
			class__find_member_by_name(new_structure, member->name);
		if (twin != NULL)
			if (check_print_change(member, cu, twin, new_cu, print))
				changes = 1;
	}
	return changes;
}

static void diff_struct(const struct cu *new_cu, struct class *structure,
			struct cu *cu)
{
	struct tag *new_tag;
	struct class *new_structure;
	size_t len;
	int32_t diff;

	assert(class__tag_type(structure) == DW_TAG_structure_type);

	if (class__size(structure) == 0 || class__name(structure) == NULL)
		return;

	new_tag = cu__find_struct_by_name(new_cu, class__name(structure));
	if (new_tag == NULL) {
		diff = 1;
		goto out;
	}

	new_structure = tag__class(new_tag);
	if (class__size(new_structure) == 0)
		return;

	assert(class__tag_type(new_structure) == DW_TAG_structure_type);

	diff = class__size(structure) != class__size(new_structure) ||
	       class__nr_members(structure) != class__nr_members(new_structure) ||
	       check_print_members_changes(structure, cu,
			       		   new_structure, new_cu, 0);
	if (diff == 0)
		return;
out:
	++cu->nr_structures_changed;
	len = strlen(class__name(structure)) + sizeof("struct");
	if (len > cu->max_len_changed_item)
		cu->max_len_changed_item = len;
	structure->priv = diff_info__new(class__tag(new_structure),
					 new_cu, diff);
}

static int diff_class_iterator(struct tag *tag, struct cu *cu, void *new_cu)
{
	if (tag->tag == DW_TAG_structure_type)
		diff_struct(new_cu, tag__class(tag), cu);

	return 0;
}

static int diff_function_iterator(struct function *function, void *new_cu)
{
	return 0;
}

static int diff_tag_iterator(struct tag *tag, struct cu *cu, void *new_cu)
{
	if (tag->tag == DW_TAG_structure_type)
		diff_struct(new_cu, tag__class(tag), cu);
	else if (tag->tag == DW_TAG_subprogram)
		diff_function(new_cu, tag__function(tag), cu);

	return 0;
}

static int find_new_functions_iterator(struct tag *tfunction, struct cu *cu,
				       void *old_cu)
{
	struct function *function = tag__function(tfunction);
	const char *name;

	assert(function->proto.tag.tag == DW_TAG_subprogram);

	if (function->inlined)
		return 0;

	name = function__name(function, cu);
	if (cu__find_function_by_name(old_cu, name) == NULL) {
		const size_t len = strlen(name);
		const int32_t diff = function__size(function);

		if (len > cu->max_len_changed_item)
			cu->max_len_changed_item = len;
		++cu->nr_functions_changed;
		cu->function_bytes_added += diff;
		function->priv = diff_info__new(NULL, NULL, diff);
	}

	return 0;
}

static int find_new_classes_iterator(struct tag *tag, struct cu *cu, void *old_cu)
{
	struct class *class;
	size_t len;

	if (tag->tag != DW_TAG_structure_type)
		return 0;

	class = tag__class(tag);
	if (class__name(class) == NULL)
		return 0;

	if (class__size(class) == 0)
		return 0;

	if (cu__find_struct_by_name(old_cu, class__name(class)) != NULL)
		return 0;

	class->priv = diff_info__new(NULL, NULL, 1);
	++cu->nr_structures_changed;

	len = strlen(class__name(class)) + sizeof("struct");
	if (len > cu->max_len_changed_item)
		cu->max_len_changed_item = len;
	return 0;
}

static int find_new_tags_iterator(struct tag *tag, struct cu *cu, void *old_cu)
{
	if (tag->tag == DW_TAG_subprogram)
		return find_new_functions_iterator(tag, cu, old_cu);
	return find_new_classes_iterator(tag, cu, old_cu);
}

static int cu_find_new_tags_iterator(struct cu *new_cu, void *old_cus)
{
	struct cu *old_cu = cus__find_cu_by_name(old_cus, new_cu->name);

	if (old_cu != NULL)
		cu__for_each_tag(new_cu, find_new_tags_iterator,
				 old_cu, NULL);

	return 0;
}

static int cu_diff_iterator(struct cu *cu, void *new_cus)
{
	struct cu *new_cu = cus__find_cu_by_name(new_cus, cu->name);

	if (new_cu != NULL)
		cu__for_each_tag(cu, diff_tag_iterator, new_cu, NULL);

	return 0;
}

static void show_diffs_function(struct function *function, const struct cu *cu,
				const void *cookie)
{
	const struct diff_info *di = function->priv;

	printf("  %-*.*s | %+4d",
	       cu->max_len_changed_item, cu->max_len_changed_item,
	       function__name(function, cu), di->diff);

	if (!verbose) {
		putchar('\n');
		return;
	}

	if (di->tag == NULL)
		puts(cookie ? " (added)" : " (removed)");
	else {
		const struct function *twin = tag__function(di->tag);

		if (strcmp(function->name, twin->name) != 0)
			printf("%s: BRAIN FART ALERT: comparing %s to %s, "
			       "should be the same name\n", __FUNCTION__,
			       function->name, twin->name);
		else
			printf(" # %d -> %d\n", function__size(function),
			       function__size(twin));
	}
}

static void show_changed_member(char change, const struct class_member *member,
				const struct cu *cu)
{
	const struct tag *type = cu__find_tag_by_id(cu, member->tag.type);
	char bf[128];

	printf("    %c%-26s %-21s /* %5u %5u */\n",
	       change, tag__name(type, cu, bf, sizeof(bf)), member->name,
	       member->offset, tag__size(type, cu));
}

static void show_nr_members_changes(const struct class *structure,
				    const struct cu *cu,
				    const struct class *new_structure,
				    const struct cu *new_cu)
{
	struct class_member *member;

	/* Find the removed ones */
	list_for_each_entry(member, &structure->type.members, tag.node) {
		struct class_member *twin =
			class__find_member_by_name(new_structure, member->name);
		if (twin == NULL)
			show_changed_member('-', member, cu);
	}

	/* Find the new ones */
	list_for_each_entry(member, &new_structure->type.members, tag.node) {
		struct class_member *twin =
			class__find_member_by_name(structure, member->name);
		if (twin == NULL)
			show_changed_member('+', member, new_cu);
	}
}

static void print_terse_type_changes(const struct class *structure)
{
	const char *sep = "";

	printf("struct %s: ", class__name(structure));

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

static void show_diffs_structure(const struct class *structure,
				 const struct cu *cu)
{
	const struct diff_info *di = structure->priv;
	const struct class *new_structure = tag__class(di->tag);
	int diff = (new_structure != NULL ? class__size(new_structure) : 0) -
		   class__size(structure);

	terse_type_changes = 0;

	if (!show_terse_type_changes)
		printf("  struct %-*.*s | %+4d\n",
		       cu->max_len_changed_item - sizeof("struct"),
		       cu->max_len_changed_item - sizeof("struct"),
		       class__name(structure), diff);

	if (diff != 0)
		terse_type_changes |= TCHANGEF__SIZE;

	if (!verbose && !show_terse_type_changes)
		return;

	if (new_structure == NULL)
		diff = -class__nr_members(structure);
	else
		diff = (class__nr_members(new_structure) -
		        class__nr_members(structure));
	if (diff != 0) {
		terse_type_changes |= TCHANGEF__NR_MEMBERS;
		if (!show_terse_type_changes) {
			printf("   nr_members: %+d\n", diff);
			if (new_structure != NULL)
				show_nr_members_changes(structure, cu,
							new_structure, di->cu);
		}
	}
	if (new_structure != NULL)
		check_print_members_changes(structure, cu,
					    new_structure, di->cu, 1);
	if (show_terse_type_changes)
		print_terse_type_changes(structure);
}

static int show_function_diffs_iterator(struct tag *tag, struct cu *cu,
					void *cookie)
{
	struct function *function = tag__function(tag);

	if (tag->tag == DW_TAG_subprogram && function->priv != NULL)
		show_diffs_function(function, cu, cookie);
	return 0;
}

static int show_structure_diffs_iterator(struct tag *tag, struct cu *cu,
					 void *cookie)
{
	struct class *class;

	if (tag->tag != DW_TAG_structure_type)
		return 0;

	class = tag__class(tag);
	if (class->priv != NULL)
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

	if (show_terse_type_changes) {
		cu__for_each_tag(cu, show_structure_diffs_iterator,
				 NULL, NULL);
		return 0;
	}

	if (cu->nr_structures_changed != 0 && show_struct_diffs) {
		cu__for_each_tag(cu, show_structure_diffs_iterator,
				 NULL, NULL);
		printf(" %u struct%s changed\n", cu->nr_structures_changed,
		       cu->nr_structures_changed > 1 ? "s" : "");
	}

	if (cu->nr_functions_changed != 0 && show_function_diffs) {
		int kind = 0;
		total_nr_functions_changed += cu->nr_functions_changed;

		cu__for_each_tag(cu, show_function_diffs_iterator, cookie, NULL);
		printf(" %u function%s changed", cu->nr_functions_changed,
		       cu->nr_functions_changed > 1 ? "s" : "");
		if (cu->function_bytes_added != 0) {
			++kind;
			total_function_bytes_added += cu->function_bytes_added;
			printf(", %u bytes added", cu->function_bytes_added);
		}
		if (cu->function_bytes_removed != 0) {
			++kind;
			total_function_bytes_removed += cu->function_bytes_removed;
			printf(", %u bytes removed", cu->function_bytes_removed);
		}
		if (kind == 2)
			printf(", diff: %+d",
			       (cu->function_bytes_added -
			        cu->function_bytes_removed));
		putchar('\n');
	}
	return 0;
}

static int cu_show_new_classes_iterator(struct cu *cu, void *cookie)
{
}

static void print_total_function_diff(const char *filename)
{
	int kind = 0;

	printf("\n%s:\n", filename);

	printf(" %u function%s changed", total_nr_functions_changed,
	       total_nr_functions_changed > 1 ? "s" : "");

	if (total_function_bytes_added != 0) {
		++kind;
		printf(", %lu bytes added", total_function_bytes_added);
	}

	if (total_function_bytes_removed != 0) {
		++kind;
		printf(", %lu bytes removed", total_function_bytes_removed);
	}
  
	if (kind == 2)
		printf(", diff: %+ld",
		       (total_function_bytes_added -
		        total_function_bytes_removed));
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

	dwarves__init(0);

	old_cus = cus__new(NULL, NULL);
	new_cus = cus__new(NULL, NULL);
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
	cus__for_each_cu(new_cus, cu_find_new_tags_iterator, old_cus, NULL);
	cus__for_each_cu(old_cus, cu_show_diffs_iterator, NULL, NULL);
	cus__for_each_cu(new_cus, cu_show_diffs_iterator, (void *)1, NULL);

	if (total_cus_changed > 1) {
		if (show_function_diffs)
			print_total_function_diff(new_filename);
	}

	return EXIT_SUCCESS;
}
