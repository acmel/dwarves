/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <argp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dwarves.h"
#include "dwarves_emit.h"
#include "dutil.h"

static int verbose;
static int show_inline_expansions;
static int show_variables;
static int show_externals;
static int show_cc_inlined;
static int show_cc_uninlined;
static bool expand_types;
static struct type_emissions emissions;

static struct conf_fprintf conf;

static struct conf_load conf_load;

struct fn_stats {
	struct list_head node;
	struct tag	 *tag;
	const struct cu	 *cu;
	uint32_t	 nr_expansions;
	uint32_t	 size_expansions;
	uint32_t	 nr_files;
};

static struct fn_stats *fn_stats__new(struct tag *tag, const struct cu *cu)
{
	struct fn_stats *self = malloc(sizeof(*self));

	if (self != NULL) {
		const struct function *fn = tag__function(tag);

		self->tag = tag;
		self->cu = cu;
		self->nr_files = 1;
		self->nr_expansions = fn->cu_total_nr_inline_expansions;
		self->size_expansions = fn->cu_total_size_inline_expansions;
	}

	return self;
}

static void fn_stats__delete(struct fn_stats *self)
{
	free(self);
}

static LIST_HEAD(fn_stats__list);

static struct fn_stats *fn_stats__find(const char *name)
{
	struct fn_stats *pos;

	list_for_each_entry(pos, &fn_stats__list, node)
		if (strcmp(function__name(tag__function(pos->tag), pos->cu),
			   name) == 0)
			return pos;
	return NULL;
}

static void fn_stats__delete_list(void)
{
	struct fn_stats *pos, *n;

	list_for_each_entry_safe(pos, n, &fn_stats__list, node) {
		list_del_init(&pos->node);
		fn_stats__delete(pos);
	}
}

static void fn_stats__add(struct tag *tag, const struct cu *cu)
{
	struct fn_stats *fns = fn_stats__new(tag, cu);
	if (fns != NULL)
		list_add(&fns->node, &fn_stats__list);
}

static void fn_stats_inline_exps_fmtr(const struct fn_stats *self)
{
	struct function *fn = tag__function(self->tag);
	if (fn->lexblock.nr_inline_expansions > 0)
		printf("%s: %u %d\n", function__name(fn, self->cu),
		       fn->lexblock.nr_inline_expansions,
		       fn->lexblock.size_inline_expansions);
}

static void fn_stats_labels_fmtr(const struct fn_stats *self)
{
	struct function *fn = tag__function(self->tag);
	if (fn->lexblock.nr_labels > 0)
		printf("%s: %u\n", function__name(fn, self->cu),
		       fn->lexblock.nr_labels);
}

static void fn_stats_variables_fmtr(const struct fn_stats *self)
{
	struct function *fn = tag__function(self->tag);
	if (fn->lexblock.nr_variables > 0)
		printf("%s: %u\n", function__name(fn, self->cu),
		       fn->lexblock.nr_variables);
}

static void fn_stats_nr_parms_fmtr(const struct fn_stats *self)
{
	struct function *fn = tag__function(self->tag);
	printf("%s: %u\n", function__name(fn, self->cu),
	       fn->proto.nr_parms);
}

static void fn_stats_name_len_fmtr(const struct fn_stats *self)
{
	struct function *fn = tag__function(self->tag);
	const char *name = function__name(fn, self->cu);
	printf("%s: %zd\n", name, strlen(name));
}

static void fn_stats_size_fmtr(const struct fn_stats *self)
{
	struct function *fn = tag__function(self->tag);
	const size_t size = function__size(fn);

	if (size != 0)
		printf("%s: %zd\n", function__name(fn, self->cu), size);
}

static void fn_stats_fmtr(const struct fn_stats *self)
{
	if (verbose) {
		tag__fprintf(self->tag, self->cu, &conf, stdout);
		putchar('\n');
		if (show_variables || show_inline_expansions)
			function__fprintf_stats(self->tag, self->cu, stdout);
		printf("/* definitions: %u */\n", self->nr_files);
		putchar('\n');
	} else {
		struct function *fn = tag__function(self->tag);
		puts(function__name(fn, self->cu));
	}
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
		printf("%-31.31s %6u %7u  %6u %6u\n",
		       function__name(tag__function(self->tag), self->cu),
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

static void fn_stats__dupmsg(struct function *self,
			     const struct cu *self_cu,
			     struct function *dup __unused,
			     const struct cu *dup_cu,
			     char *hdr, const char *fmt, ...)
{
	va_list args;

	if (!*hdr)
		printf("function: %s\nfirst: %s\ncurrent: %s\n",
		       function__name(self, self_cu),
		       self_cu->name,
		       dup_cu->name);
	
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	*hdr = 1;
}

static void fn_stats__chkdupdef(struct function *self,
				const struct cu *self_cu,
				struct function *dup,
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
				    void *cookie __unused)
{
	struct function *function;
	struct fn_stats *fstats;
	const char *name;

	if (!tag__is_function(tag))
		return NULL;

	if (!tag->top_level)
		return NULL;

	function = tag__function(tag);
	/*
	 * FIXME: remove this check and try to fix the parameter abstract
	 * origin code someday...
	 */
	if (!function->name)
		return NULL;

	name = function__name(function, cu);
	if (show_externals && !function->external)
		return NULL;

	if (show_cc_uninlined &&
	    function->inlined != DW_INL_declared_not_inlined)
		return NULL;

	if (show_cc_inlined && function->inlined != DW_INL_inlined)
		return NULL;

	fstats = fn_stats__find(name);
	if (fstats != NULL) {
		struct function *fn = tag__function(fstats->tag);

		if (!fn->external)
			return tag;

		if (verbose)
			fn_stats__chkdupdef(fn, fstats->cu, function, cu);
		fstats->nr_expansions   += function->cu_total_nr_inline_expansions;
		fstats->size_expansions += function->cu_total_size_inline_expansions;
		fstats->nr_files++;
		return NULL;
	}

	return tag;
}

static int unique_iterator(struct tag *tag, struct cu *cu,
			   void *cookie __unused)
{
	if (tag__is_function(tag))
		fn_stats__add(tag, cu);
	return 0;
}

static int cu_unique_iterator(struct cu *cu, void *cookie)
{
	cu__account_inline_expansions(cu);
	return cu__for_each_tag(cu, unique_iterator, cookie, function__filter);
}

static int class_iterator(struct tag *tag, struct cu *cu, void *cookie)
{
	uint16_t *target_id = cookie;
	struct function *function;

	if (!tag__is_function(tag))
		return 0;

	function = tag__function(tag);
	if (function->inlined)
		return 0;

	if (ftype__has_parm_of_type(&function->proto, *target_id, cu)) {
		if (verbose)
			tag__fprintf(tag, cu, &conf, stdout);
		else
			fputs(function__name(function, cu), stdout);
		putchar('\n');
	}
	return 0;
}

static int cu_class_iterator(struct cu *cu, void *cookie)
{
	uint16_t target_id;
	struct tag *target = cu__find_struct_by_name(cu, cookie, 0, &target_id);

	if (target == NULL)
		return 0;

	return cu__for_each_tag(cu, class_iterator, &target_id, NULL);
}

static int function__emit_type_definitions(struct function *self,
					   struct cu *cu, FILE *fp)
{
	struct parameter *pos;

	function__for_each_parameter(self, pos) {
		struct tag *type = cu__find_type_by_id(cu, pos->tag.type);
	try_again:
		if (type == NULL)
			continue;

		if (type->tag == DW_TAG_pointer_type) {
			type = cu__find_type_by_id(cu, type->type);
			goto try_again;
		}

		if (tag__is_type(type)) {
			type__emit_definitions(type, cu, &emissions, fp);
			type__emit(type, cu, NULL, NULL, fp);
			putchar('\n');
		}
	}

	return 0;
}

static int function_iterator(struct tag *tag, struct cu *cu, void *cookie)
{
	struct function *function;

	if (!tag__is_function(tag))
		return 0;

	function = tag__function(tag);
	if (strcmp(function__name(function, cu), cookie) == 0) {
		if (expand_types)
			function__emit_type_definitions(function, cu, stdout);
		tag__fprintf(tag, cu, &conf, stdout);
		putchar('\n');
		if (show_variables || show_inline_expansions)
			function__fprintf_stats(tag, cu, stdout);
		return 1;
	}
	return 0;
}

static int cu_function_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_tag(cu, function_iterator, cookie, NULL);
}

/* Name and version of program.  */
ARGP_PROGRAM_VERSION_HOOK_DEF = dwarves_print_version;

static const struct argp_option pfunct__options[] = {
	{
		.key  = 'b',
		.name = "expand_types",
		.doc  = "Expand types needed by the prototype",
	},
	{
		.key  = 'c',
		.name = "class",
		.arg  = "CLASS",
		.doc  = "functions that have CLASS pointer parameters",
	},
	{
		.key  = 'E',
		.name = "externals",
		.doc  = "show just external functions",
	},
	{
		.key  = 'f',
		.name = "function",
		.arg  = "FUNCTION",
		.doc  = "show just FUNCTION",
	},
	{
		.key  = 'g',
		.name = "goto_labels",
		.doc  = "show number of goto labels",
	},
	{
		.key  = 'G',
		.name = "cc_uninlined",
		.doc  = "declared inline, uninlined by compiler",
	},
	{
		.key  = 'H',
		.name = "cc_inlined",
		.doc  = "not declared inline, inlined by compiler",
	},
	{
		.key  = 'i',
		.name = "inline_expansions",
		.doc  = "show inline expansions",
	},
	{
		.key  = 'I',
		.name = "inline_expansions_stats",
		.doc  = "show inline expansions stats",
	},
	{
		.key  = 'l',
		.name = "decl_info",
		.doc  = "show source code info",
	},
	{
		.key  = 't',
		.name = "total_inline_stats",
		.doc  = "show Multi-CU total inline expansions stats",
	},
	{
		.key  = 's',
		.name = "sizes",
		.doc  = "show size of functions",
	},
	{
		.key  = 'N',
		.name = "function_name_len",
		.doc  = "show size of functions names",
	},
	{
		.key  = 'p',
		.name = "nr_parms",
		.doc  = "show number of parameters",
	},
	{
		.key  = 'S',
		.name = "nr_variables",
		.doc  = "show number of variables",
	},
	{
		.key  = 'T',
		.name = "variables",
		.doc  = "show variables",
	},
	{
		.key  = 'V',
		.name = "verbose",
		.doc  = "be verbose",
	},
	{
		.name = NULL,
	}
};

static void (*formatter)(const struct fn_stats *f) = fn_stats_fmtr;
static char *class_name;
static char *function_name;
static int show_total_inline_expansion_stats;

static error_t pfunct__options_parser(int key, char *arg,
				      struct argp_state *state)
{
	switch (key) {
	case ARGP_KEY_INIT:
		if (state->child_inputs != NULL)
			state->child_inputs[0] = state->input;
		break;
	case 'b': expand_types = true;
		  type_emissions__init(&emissions);	 break;
	case 'c': class_name = arg;			 break;
	case 'f': function_name = arg;			 break;
	case 'E': show_externals = 1;			 break;
	case 's': formatter = fn_stats_size_fmtr;	 break;
	case 'S': formatter = fn_stats_variables_fmtr;	 break;
	case 'p': formatter = fn_stats_nr_parms_fmtr;	 break;
	case 'g': formatter = fn_stats_labels_fmtr;	 break;
	case 'G': show_cc_uninlined = 1;		 break;
	case 'H': show_cc_inlined = 1;			 break;
	case 'i': show_inline_expansions = verbose = 1;
		  conf_load.extra_dbg_info = 1;		 break;
	case 'I': formatter = fn_stats_inline_exps_fmtr; break;
	case 'l': conf.show_decl_info = 1;
		  conf_load.extra_dbg_info = 1;		 break;
	case 't': show_total_inline_expansion_stats = 1; break;
	case 'T': show_variables = 1;			 break;
	case 'N': formatter = fn_stats_name_len_fmtr;	 break;
	case 'V': verbose = 1;
		  conf_load.extra_dbg_info = 1;		 break;
	default:  return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static const char pfunct__args_doc[] = "FILE";

static struct argp pfunct__argp = {
	.options  = pfunct__options,
	.parser	  = pfunct__options_parser,
	.args_doc = pfunct__args_doc,
};

int main(int argc, char *argv[])
{
	int err, remaining, rc = EXIT_FAILURE;
	struct cus *cus;

	if (argp_parse(&pfunct__argp, argc, argv, 0, &remaining, NULL) ||
	    remaining == argc) {
                argp_help(&pfunct__argp, stderr, ARGP_HELP_SEE, argv[0]);
                goto out;
	}

	cus = cus__new();
	if (dwarves__init(0) || cus == NULL) {
		fputs("pfunct: insufficient memory\n", stderr);
		goto out;
	}

	err = cus__load_files(cus, &conf_load, argv + remaining);
	if (err != 0)
		goto out;

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

	rc = EXIT_SUCCESS;
out:
	cus__delete(cus);
	fn_stats__delete_list();
	dwarves__exit();
	return rc;
}
