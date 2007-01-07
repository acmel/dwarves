/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "classes.h"

static int verbose;
static int show_inline_expansions;
static int show_variables;
static int show_externals;
static int show_cc_inlined;
static int show_cc_uninlined;

struct fn_stats {
	struct list_head	node;
	const struct function	*function;
	const struct cu		*cu;
	uint32_t		nr_expansions;
	uint32_t		size_expansions;
	uint32_t		nr_files;
};

static struct fn_stats *fn_stats__new(const struct function *function,
				      const struct cu *cu)
{
	struct fn_stats *self = malloc(sizeof(*self));

	if (self != NULL) {
		self->function = function;
		self->cu = cu;
		self->nr_files = 1;
		self->nr_expansions = function->cu_total_nr_inline_expansions;
		self->size_expansions = function->cu_total_size_inline_expansions;
	}

	return self;
}

static LIST_HEAD(fn_stats__list);

static struct fn_stats *fn_stats__find(const char *name)
{
	struct fn_stats *pos;

	list_for_each_entry(pos, &fn_stats__list, node)
		if (strcmp(pos->function->name, name) == 0)
			return pos;
	return NULL;
}

static void fn_stats__add(const struct function *function, const struct cu *cu)
{
	struct fn_stats *inl = fn_stats__new(function, cu);
	if (inl != NULL)
		list_add(&inl->node, &fn_stats__list);
}

static void fn_stats_inline_exps_fmtr(const struct fn_stats *self)
{
	if (self->function->lexblock.nr_inline_expansions > 0)
		printf("%s: %u %u\n", self->function->name,
		       self->function->lexblock.nr_inline_expansions,
		       self->function->lexblock.size_inline_expansions);
}

static void fn_stats_labels_fmtr(const struct fn_stats *self)
{
	if (self->function->lexblock.nr_labels > 0)
		printf("%s: %u\n", self->function->name,
		       self->function->lexblock.nr_labels);
}

static void fn_stats_variables_fmtr(const struct fn_stats *self)
{
	if (self->function->lexblock.nr_variables > 0)
		printf("%s: %u\n", self->function->name,
		       self->function->lexblock.nr_variables);
}

static void fn_stats_nr_parms_fmtr(const struct fn_stats *self)
{
	printf("%s: %u\n", self->function->name,
	       self->function->proto.nr_parms);
}

static void fn_stats_name_len_fmtr(const struct fn_stats *self)
{
	printf("%s: %u\n", self->function->name, strlen(self->function->name));
}

static void fn_stats_size_fmtr(const struct fn_stats *self)
{
	const size_t size = function__size(self->function);
	if (size != 0)
		printf("%s: %u\n", self->function->name, size);
}

static void fn_stats_fmtr(const struct fn_stats *self)
{
	if (verbose) {
		function__print(self->function, self->cu, 1,
				show_variables, show_inline_expansions);
		printf("/* definitions: %u */\n", self->nr_files);
		putchar('\n');
	} else
		puts(self->function->name);
}

static void print_fn_stats(void (*formatter)(const struct fn_stats *f))
{
	struct fn_stats *pos;

	list_for_each_entry(pos, &fn_stats__list, node)
		formatter(pos);
}

static void fn_stats_inline_stats_fmtr(const struct fn_stats *self)
{
	if (self->nr_expansions > 1)
		printf("%-31.31s %6lu %7lu  %6lu %6u\n", self->function->name,
		       self->size_expansions, self->nr_expansions,
		       self->size_expansions / self->nr_expansions,
		       self->nr_files);
}

static void print_total_inline_stats(void)
{
	printf("%-32.32s  %5.5s / %5.5s = %5.5s  %s\n",
	       "name", "totsz", "exp#", "avgsz", "src#");
	print_fn_stats(fn_stats_inline_stats_fmtr);
}

static void fn_stats__dupmsg(const struct function *self,
			     const struct cu *self_cu,
			     const struct function *dup,
			     const struct cu *dup_cu,
			     char *hdr, const char *fmt, ...)
{
	va_list args;

	if (!*hdr)
		printf("function: %s\nfirst: %s\ncurrent: %s\n",
		       self->name, self_cu->name, dup_cu->name);
	
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	*hdr = 1;
}

static void fn_stats__chkdupdef(const struct function *self,
				const struct cu *self_cu,
				const struct function *dup,
				const struct cu *dup_cu)
{
	char hdr = 0;
	const size_t self_size = function__size(self);
	const size_t dup_size = function__size(dup);

	if (self_size != dup_size)
		fn_stats__dupmsg(self, self_cu, dup, dup_cu,
				 &hdr, "size: %zd != %zd\n",
				 self_size, dup_size);

	if (self->proto.nr_parms != dup->proto.nr_parms)
		fn_stats__dupmsg(self, self_cu, dup, dup_cu,
				 &hdr, "nr_parms: %u != %u\n",
				 self->proto.nr_parms, dup->proto.nr_parms);

	/* XXX put more checks here: member types, member ordering, etc */

	if (hdr)
		putchar('\n');
}

static struct tag *function__filter(struct tag *tag, struct cu *cu,
				    void *cookie)
{
	struct function *function;
	struct fn_stats *fstats;

	if (tag->tag != DW_TAG_subprogram)
		return NULL;

	function = tag__function(tag);
	if (function->name == NULL)
		return NULL;

	if (show_externals && !function->external)
		return NULL;

	if (show_cc_uninlined &&
	    function->inlined != DW_INL_declared_not_inlined)
		return NULL;

	if (show_cc_inlined && function->inlined != DW_INL_inlined)
		return NULL;

	fstats = fn_stats__find(function->name);
	if (fstats != NULL && fstats->function->external) {
		fn_stats__chkdupdef(fstats->function, fstats->cu, function, cu);
		fstats->nr_expansions   += function->cu_total_nr_inline_expansions;
		fstats->size_expansions += function->cu_total_size_inline_expansions;
		fstats->nr_files++;
		return NULL;
	}

	return tag;
}

static int unique_iterator(struct tag *tag, struct cu *cu, void *cookie)
{
	if (tag->tag == DW_TAG_subprogram)
		fn_stats__add(tag__function(tag), cu);
	return 0;
}

static int cu_unique_iterator(struct cu *cu, void *cookie)
{
	cu__account_inline_expansions(cu);
	return cu__for_each_tag(cu, unique_iterator, cookie, function__filter);
}

static int class_iterator(struct tag *tag, struct cu *cu, void *cookie)
{
	struct function *function;

	if (tag->tag != DW_TAG_subprogram)
		return 0;

	function = tag__function(tag);
	if (function->inlined)
		return 0;

	if (ftype__has_parm_of_type(&function->proto, cookie, cu)) {
		if (verbose)
			function__print(function, cu, 1, 0, 0);
		else
			printf("%s\n", function->name ?: "");
	}
	return 0;
}

static int cu_class_iterator(struct cu *cu, void *cookie)
{
	struct tag *target = cu__find_struct_by_name(cu, cookie);

	if (target == NULL)
		return 0;

	return cu__for_each_tag(cu, class_iterator, target, NULL);
}

static int function_iterator(struct tag *tag, struct cu *cu, void *cookie)
{
	struct function *function;

	if (tag->tag != DW_TAG_subprogram)
		return 0;

	function = tag__function(tag);
	if (function->name != NULL &&
	    strcmp(function->name, cookie) == 0) {
		function__print(function, cu, 1, show_variables,
				show_inline_expansions);
		return 1;
	}
	return 0;
}

static int cu_function_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_tag(cu, function_iterator, cookie, NULL);
}

static struct option long_options[] = {
	{ "class",			required_argument,	NULL, 'c' },
	{ "externals",			no_argument,		NULL, 'e' },
	{ "cc_inlined",			no_argument,		NULL, 'H' },
	{ "cc_uninlined",		no_argument,		NULL, 'G' },
	{ "function_name_len",		no_argument,		NULL, 'N' },
	{ "goto_labels",		no_argument,		NULL, 'g' },
	{ "inline_expansions",		no_argument,		NULL, 'i' },
	{ "inline_expansions_stats",	no_argument,		NULL, 'I' },
	{ "total_inline_stats",		no_argument,		NULL, 't' },
	{ "help",			no_argument,		NULL, 'h' },
	{ "nr_parms",			no_argument,		NULL, 'p' },
	{ "sizes",			no_argument,		NULL, 's' },
	{ "nr_variables",		no_argument,		NULL, 'S' },
	{ "variables",			no_argument,		NULL, 'T' },
	{ "verbose",			no_argument,		NULL, 'V' },
	{ NULL, 0, NULL, 0, }
};

static void usage(void)
{
	fprintf(stdout,
		"usage: pfunct [options] <file_name> {<function_name>}\n"
		" where: \n"
		"   -c, --class=<class>               functions that have "
						     "<class> pointer "
						     "parameters\n"
		"   -e, --externals		      show just external "
						     "functions\n"
		"   -g, --goto_labels                 show number of goto "
						     "labels\n"
		"   -G, --cc_uninlined		      declared inline, "
						     "uninlined by compiler\n"
		"   -H, --cc_inlined		      not declared inline, "
						     "inlined by compiler\n"
		"   -i, --inline_expansions           show inline expansions\n"
		"   -I, --inline_expansions_stats     show inline expansions "
						     "stats\n"
		"   -t, --total_inline_stats	      show Multi-CU total "
						     "inline expansions "
						     "stats\n"
		"   -s, --sizes                       show size of functions\n"
		"   -N, --function_name_len           show size of functions\n"
		"   -p, --nr_parms 	              show number of "
						     "parameters\n"
		"   -S, --nr_variables                show number of "
						     "variables\n"
		"   -T, --variables                   show variables\n"
		"   -V, --verbose                     be verbose\n");
}

int main(int argc, char *argv[])
{
	int option, option_index;
	const char *file_name;
	struct cus *cus;
	char *class_name = NULL;
	char *function_name = NULL;
	int show_total_inline_expansion_stats = 0;
	void (*formatter)(const struct fn_stats *f) = fn_stats_fmtr;

	while ((option = getopt_long(argc, argv, "c:egGHiINpsStTV",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 'c': class_name = optarg;			break;
		case 'e': show_externals = 1;			break;
		case 's': formatter = fn_stats_size_fmtr;	break;
		case 'S': formatter = fn_stats_variables_fmtr;	break;
		case 'p': formatter = fn_stats_nr_parms_fmtr;	break;
		case 'g': formatter = fn_stats_labels_fmtr;	break;
		case 'G': show_cc_uninlined = 1;		break;
		case 'H': show_cc_inlined = 1;			break;
		case 'i': show_inline_expansions = verbose = 1;	break;
		case 'I': formatter = fn_stats_inline_exps_fmtr; break;
		case 't': show_total_inline_expansion_stats = 1; break;
		case 'T': show_variables = 1;			break;
		case 'N': formatter = fn_stats_name_len_fmtr;	break;
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

	cus = cus__new(NULL, NULL);
	if (cus == NULL) {
		fputs("pfunct: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}

	if (cus__load(cus, file_name) != 0) {
		fprintf(stderr, "pfunct: couldn't load DWARF info from %s\n",
			file_name);
		return EXIT_FAILURE;
	}

	cus__for_each_cu(cus, cu_unique_iterator, NULL, NULL);

	if (show_total_inline_expansion_stats)
		print_total_inline_stats();
	else if (class_name != NULL)
		cus__for_each_cu(cus, cu_class_iterator, class_name, NULL);
	else if (function_name != NULL)
		cus__for_each_cu(cus, cu_function_iterator,
				 function_name, NULL);
	else 
		print_fn_stats(formatter);

	return EXIT_SUCCESS;
}
