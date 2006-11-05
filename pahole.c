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

struct structure {
	struct list_head   node;
	const struct class *class;
	unsigned int	   nr_files;
};

static struct structure *structure__new(const struct class *class)
{
	struct structure *self = malloc(sizeof(*self));

	if (self != NULL) {
		self->class = class;
		self->nr_files = 1;
	}

	return self;
}

static LIST_HEAD(structures__list);

static struct structure *structures__find(const char *name)
{
	struct structure *pos;

	list_for_each_entry(pos, &structures__list, node)
		if (strcmp(pos->class->name, name) == 0)
			return pos;
	return NULL;
}

static void structures__add(const struct class *class)
{
	struct structure *str = structures__find(class->name);

	if (str == NULL) {
		str = structure__new(class);
		if (str != NULL)
			list_add(&str->node, &structures__list);
	} else {
		if (str->class->size != class->size)
			printf("%s size changed! was %llu, now its %llu\n",
			       class->name, str->class->size, class->size);
		str->nr_files++;
	}
}

static void structure__print(struct structure *self)
{
	printf("%-32.32s %5lu\n", self->class->name, self->nr_files);
}

static void print_total_structure_stats(void)
{
	struct structure *pos;

	printf("%-32.32s %5.5s\n", "name", "src#");
	list_for_each_entry(pos, &structures__list, node)
		structure__print(pos);
}

static int total_structure_iterator(struct cu *cu, struct class *class, void *cookie)
{
	if (class->tag == DW_TAG_structure_type && class->name != NULL)
		structures__add(class);
	return 0;
}

static int cu_total_structure_iterator(struct cu *cu, void *cookie)
{
	cu__for_each_class(cu, total_structure_iterator, cookie);
	return 0;
}

static struct option long_options[] = {
	{ "class_name_len",	no_argument,		NULL, 'N' },
	{ "help",		no_argument,		NULL, 'h' },
	{ "nr_members",		no_argument,		NULL, 'n' },
	{ "sizes",		no_argument,		NULL, 's' },
	{ "total_struct_stats",	no_argument,		NULL, 't' },
	{ NULL, 0, NULL, 0, }
};

static void usage(void)
{
	fprintf(stderr,
		"usage: pfunct [options] <file_name> {<function_name>}\n"
		" where: \n"
		"   -h, --help                show usage info\n"
		"   -m, --nr_members	      show number of members\n"
		"   -N, --class_name_len      show size of classes\n"
		"   -s, --sizes               show size of classes\n"
		"   -t, --total_struct_stats  show Multi-CU structure stats\n");
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
	struct class *typedef_alias;

	if (!class__is_struct(class, cu, &typedef_alias))
		return 0;

	class__find_holes(typedef_alias ?: class, cu);
	if (typedef_alias != NULL) {
		if (typedef_alias->size > 0)
			printf("typedef %s:struct(%s): %llu %u\n",
			       class->name ?: "",
			       typedef_alias->name ?: "",
			       typedef_alias->size, typedef_alias->nr_holes);
	} else if (class->size > 0)
		printf("struct %s: %llu %u\n", class->name ?: "<unknown>",
		       class->size, class->nr_holes);
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
	int show_total_structure_stats = 0;

	while ((option = getopt_long(argc, argv, "hnNst",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 's': show_sizes = 1;		  break;
		case 'n': show_nr_members = 1;		  break;
		case 'N': show_class_name_len = 1;	  break;
		case 't': show_total_structure_stats = 1; break;
		case 'h': usage();			  return EXIT_SUCCESS;
		default:  usage();			  return EXIT_FAILURE;
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

	if (show_total_structure_stats) {
		cus__for_each_cu(cu_total_structure_iterator, NULL);
		print_total_structure_stats();
	} else if (show_nr_members)
		cus__for_each_cu(cu_nr_members_iterator, NULL);
	else if (show_sizes)
		cus__for_each_cu(cu_sizes_iterator, NULL);
	else if (class_name != NULL) {
		struct cu *cu;
		struct class *class = cus__find_class_by_name(&cu, class_name);
		struct class *alias;

		if (class__is_struct(class, cu, &alias)) {
			class__find_holes(alias ?: class, cu);
			class__print(alias ?: class, cu);
		} else
			printf("struct %s not found!\n", class_name);
	} else
		classes__print(DW_TAG_structure_type);

	return EXIT_SUCCESS;
}
