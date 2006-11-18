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
#include <string.h>

#include "classes.h"

static int verbose;
static int show_inline_expansions;
static int show_variables;

struct inline_function {
	struct list_head node;
	const char *name;
	unsigned long nr_expansions;
	unsigned long size_expansions;
	unsigned int nr_files;
};

static struct inline_function *
			inline_function__new(const struct function *function)
{
	struct inline_function *self = malloc(sizeof(*self));

	if (self != NULL) {
		self->name = function->name;
		self->nr_files = 1;
		self->nr_expansions = function->cu_total_nr_inline_expansions;
		self->size_expansions = function->cu_total_size_inline_expansions;
	}

	return self;
}

static LIST_HEAD(inlines__list);

static struct inline_function *inlines__find(const char *name)
{
	struct inline_function *pos;

	list_for_each_entry(pos, &inlines__list, node)
		if (strcmp(pos->name, name) == 0)
			return pos;
	return NULL;
}

static void inlines__add(const struct function *function)
{
	struct inline_function *inl = inlines__find(function->name);

	if (inl == NULL) {
		inl = inline_function__new(function);
		if (inl != NULL)
			list_add(&inl->node, &inlines__list);
	} else {
		inl->nr_expansions   += function->cu_total_nr_inline_expansions;
		inl->size_expansions += function->cu_total_size_inline_expansions;
		inl->nr_files++;
	}
}

static void inline_function__print(struct inline_function *self)
{
	printf("%-31.31s %6lu %7lu  %6lu %6u\n", self->name,
	       self->size_expansions, self->nr_expansions,
	       self->size_expansions / self->nr_expansions,
	       self->nr_files);
}

static void print_total_inline_stats(void)
{
	struct inline_function *pos;

	printf("%-32.32s  %5.5s / %5.5s = %5.5s  %s\n", "name", "totsz", "exp#", "avgsz", "src#");
	list_for_each_entry(pos, &inlines__list, node)
		if (pos->nr_expansions > 1)
			inline_function__print(pos);
}

static struct option long_options[] = {
	{ "class",			required_argument,	NULL, 'c' },
	{ "externals",			no_argument,		NULL, 'e' },
	{ "cu_inline_expansions_stats",	no_argument,		NULL, 'C' },
	{ "function_name_len",		no_argument,		NULL, 'N' },
	{ "goto_labels",		no_argument,		NULL, 'g' },
	{ "inline_expansions",		no_argument,		NULL, 'i' },
	{ "inline_expansions_stats",	no_argument,		NULL, 'I' },
	{ "total_inline_stats",		no_argument,		NULL, 't' },
	{ "help",			no_argument,		NULL, 'h' },
	{ "nr_parameters",		no_argument,		NULL, 'p' },
	{ "sizes",			no_argument,		NULL, 's' },
	{ "nr_variables",		no_argument,		NULL, 'S' },
	{ "variables",			no_argument,		NULL, 'T' },
	{ "verbose",			no_argument,		NULL, 'V' },
	{ NULL, 0, NULL, 0, }
};

static void usage(void)
{
	fprintf(stderr,
		"usage: pfunct [options] <file_name> {<function_name>}\n"
		" where: \n"
		"   -c, --class=<class>               functions that have <class> "
					             "pointer parameters\n"
		"   -e, --externals		      show just external functions\n"
		"   -g, --goto_labels                 show number of goto labels\n"
		"   -i, --inline_expansions           show inline expansions\n"
		"   -I, --inline_expansions_stats     show inline expansions stats\n"
		"   -C, --cu_inline_expansions_stats  show CU inline expansions stats\n"
		"   -t, --total_inline_stats	      show Multi-CU total inline "
						     "expansions stats\n"
		"   -s, --sizes                       show size of functions\n"
		"   -N, --function_name_len           show size of functions\n"
		"   -p, --nr_parameters               show number or parameters\n"
		"   -S, --nr_variables                show number of variables\n"
		"   -T, --variables                   show variables\n"
		"   -V, --verbose                     be verbose\n");
}

static int function__has_parameter_of_type(const struct function *self,
					   const struct class *target)
{
	struct class_member *pos;

	list_for_each_entry(pos, &self->parameters, tag.node) {
		struct class *class = cu__find_class_by_id(self->cu,
							   pos->tag.type);

		if (class != NULL && class->tag.tag == DW_TAG_pointer_type) {
			class = cu__find_class_by_id(self->cu, class->tag.type);
			if (class != NULL &&
			    class->tag.id == target->tag.id)
				return 1;
		}
	}
	return 0;
}

static int class_iterator(struct function *function, void *cookie)
{
	if (function->inlined)
		return 0;

	if (function__has_parameter_of_type(function, cookie)) {
		if (verbose)
			function__print(function);
		else
			printf("%s\n", function->name ?: "");
	}
	return 0;
}

static int cu_class_iterator(struct cu *cu, void *cookie)
{
	struct class *target = cu__find_class_by_name(cu, cookie);

	if (target == NULL)
		return 0;

	return cu__for_each_function(cu, class_iterator, target);
}

static int sizes_iterator(struct function *function, void *cookie)
{
	if (function->inlined)
		return 0;

	printf("%s: %u\n", function->name ?: "", function__size(function));
	return 0;
}

static int cu_sizes_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_function(cu, sizes_iterator, cookie);
}

static int externals_iterator(struct function *function, void *cookie)
{
	if (function->external)
		puts(function->name);

	return 0;
}

static int cu_externals_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_function(cu, externals_iterator, cookie);
}

static int variables_iterator(struct function *function, void *cookie)
{
	if (function->nr_variables > 0)
		printf("%s: %u\n", function->name ?: "",
		      function->nr_variables);
	return 0;
}

static int cu_variables_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_function(cu, variables_iterator, cookie);
}

static int goto_labels_iterator(struct function *function, void *cookie)
{
	if (function->inlined)
		return 0;

	if (function->nr_labels > 0)
		printf("%s: %u\n", function->name ?: "", function->nr_labels);
	return 0;
}

static int cu_goto_labels_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_function(cu, goto_labels_iterator, cookie);
}

static int function_iterator(struct function *function, void *cookie)
{
	if (function->inlined)
		return 0;

	if (cookie == NULL) {
		if (function->nr_inline_expansions > 0)
			printf("%s: %u %u\n", function->name ?: "",
			       function->nr_inline_expansions,
			       function->size_inline_expansions);
	} else if (function->name != NULL &&
		   strcmp(function->name, cookie) == 0) {
		function__print(function);
		if (show_inline_expansions)
			function__print_inline_expansions(function);
		if (show_variables)
			function__print_variables(function);
		return 1;
	}
	return 0;
}

static int cu_function_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_function(cu, function_iterator, cookie);
}

static int inlines_iterator(struct function *function, void *cookie)
{
	if (!function->inlined)
		return 0;

	if (function->name != NULL)
		printf("%s: %u %lu\n", function->name,
		       function->cu_total_nr_inline_expansions,
		       function->cu_total_size_inline_expansions);
	return 0;
}

static int cu_inlines_iterator(struct cu *cu, void *cookie)
{
	cu__account_inline_expansions(cu);
	if (cu->nr_inline_expansions > 0) {
		printf("%s: %lu %lu\n", cu->name, cu->nr_inline_expansions,
		       cu->size_inline_expansions);
		cu__for_each_function(cu, inlines_iterator, cookie);
	}
	return 0;
}

static int nr_parameters_iterator(struct function *function, void *cookie)
{
	printf("%s: %u\n", function->name ?: "", function->nr_parameters);
	return 0;
}

static int cu_nr_parameters_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_function(cu, nr_parameters_iterator, cookie);
}

static int function_name_len_iterator(struct function *function, void *cookie)
{
	if (function->name != NULL)
		printf("%s: %u\n", function->name, strlen(function->name));
	return 0;
}

static int cu_function_name_len_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_function(cu, function_name_len_iterator, cookie);
}

static int total_inlines_iterator(struct function *function, void *cookie)
{
	if (function->inlined)
		inlines__add(function);
	return 0;
}

static int cu_total_inlines_iterator(struct cu *cu, void *cookie)
{
	cu__account_inline_expansions(cu);
	if (cu->nr_inline_expansions > 0)
		cu__for_each_function(cu, total_inlines_iterator, cookie);
	return 0;
}

int main(int argc, char *argv[])
{
	int option, option_index;
	const char *file_name;
	struct cus *cus;
	char *class_name = NULL;
	char *function_name = NULL;
	int show_externals = 0;
	int show_sizes = 0;
	int show_nr_variables = 0;
	int show_goto_labels = 0;
	int show_nr_parameters = 0;
	int show_function_name_len = 0;
	int show_inline_expansions_stats = 0;
	int show_inline_stats = 0;
	int show_total_inline_expansion_stats = 0;

	while ((option = getopt_long(argc, argv, "c:CegiINpsStTV",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 'c': class_name = optarg;			break;
		case 'C': show_inline_stats = 1;		break;
		case 'e': show_externals = 1;			break;
		case 's': show_sizes = 1;			break;
		case 'S': show_nr_variables = 1;		break;
		case 'p': show_nr_parameters = 1;		break;
		case 'g': show_goto_labels = 1;			break;
		case 'i': show_inline_expansions = 1;		break;
		case 'I': show_inline_expansions_stats = 1;	break;
		case 't': show_total_inline_expansion_stats = 1;break;
		case 'T': show_variables = 1;			break;
		case 'N': show_function_name_len = 1;		break;
		case 'V': verbose = 1;				break;
		case 'h': usage(); return EXIT_SUCCESS;
		default:  usage(); return EXIT_FAILURE;
		}

	if (optind < argc) {
		switch (argc - optind) {
		case 1:	 file_name = argv[optind++];	 break;
		case 2:	 file_name = argv[optind++];
			 function_name = argv[optind++]; break;
		default: usage();			 return EXIT_FAILURE;
		}
	} else {
		usage();
		return EXIT_FAILURE;
	}

	cus = cus__new(file_name);
	if (cus == NULL) {
		fputs("pfunct: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}

	if (cus__load(cus) != 0) {
		fprintf(stderr, "pfunct: couldn't load DWARF info from %s\n",
			file_name);
		return EXIT_FAILURE;
	}

	if (show_total_inline_expansion_stats) {
		cus__for_each_cu(cus, cu_total_inlines_iterator, NULL);
		print_total_inline_stats();
	} else if (show_inline_stats)
		cus__for_each_cu(cus, cu_inlines_iterator, NULL);
	else if (show_nr_parameters)
		cus__for_each_cu(cus, cu_nr_parameters_iterator, NULL);
	else if (show_nr_variables)
		cus__for_each_cu(cus, cu_variables_iterator, NULL);
	else if (show_goto_labels)
		cus__for_each_cu(cus, cu_goto_labels_iterator, NULL);
	else if (show_sizes)
		cus__for_each_cu(cus, cu_sizes_iterator, NULL);
	else if (show_externals)
		cus__for_each_cu(cus, cu_externals_iterator, NULL);
	else if (show_function_name_len)
		cus__for_each_cu(cus, cu_function_name_len_iterator, NULL);
	else if (class_name != NULL)
		cus__for_each_cu(cus, cu_class_iterator, class_name);
	else if (function_name == NULL && !show_inline_expansions_stats)
		cus__print_functions(cus);
	else
		cus__for_each_cu(cus, cu_function_iterator, function_name);

	return EXIT_SUCCESS;
}
