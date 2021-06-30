/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2007-2016 Arnaldo Carvalho de Melo <acme@kernel.org>
*/

#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include "dwarves.h"
#include "dutil.h"

static struct conf_fprintf conf = {
	.emit_stats	= 1,
};

static void emit_tag(struct tag *tag, uint32_t tag_id, struct cu *cu)
{
	printf("/* %d */\n", tag_id);

	if (tag__is_struct(tag))
		class__find_holes(tag__class(tag));

	if (tag->tag == DW_TAG_base_type) {
		char bf[64];
		const char *name = base_type__name(tag__base_type(tag), bf, sizeof(bf));

		if (name == NULL)
			printf("anonymous base_type\n");
		else
			puts(name);
	} else if (tag__is_pointer(tag))
		printf(" /* pointer to %lld */\n", (unsigned long long)tag->type);
	else
		tag__fprintf(tag, cu, &conf, stdout);

	printf(" /* size: %zd */\n\n", tag__size(tag, cu));
}

static int cu__emit_tags(struct cu *cu)
{
	uint32_t i;
	struct tag *tag;

	puts("/* Types: */\n");
	cu__for_each_type(cu, i, tag)
		emit_tag(tag, i, cu);

	puts("/* Functions: */\n");
	conf.no_semicolon = true;
	struct function *function;
	cu__for_each_function(cu, i, function) {
		tag__fprintf(function__tag(function), cu, &conf, stdout);
		putchar('\n');
		lexblock__fprintf(&function->lexblock, cu, function, 0,
				  &conf, stdout);
		printf(" /* size: %zd */\n\n",
		       tag__size(function__tag(function), cu));
	}
	conf.no_semicolon = false;

	puts("\n\n/* Variables: */\n");
	cu__for_each_variable(cu, i, tag) {
		tag__fprintf(tag, cu, NULL, stdout);
		printf(" /* size: %zd */\n\n", tag__size(tag, cu));
	}


	return 0;
}

static enum load_steal_kind pdwtags_stealer(struct cu *cu,
					    struct conf_load *conf_load __maybe_unused)
{
	cu__emit_tags(cu);
	return LSK__DELETE;
}

static struct conf_load pdwtags_conf_load = {
	.steal = pdwtags_stealer,
	.conf_fprintf = &conf,
};

/* Name and version of program.  */
ARGP_PROGRAM_VERSION_HOOK_DEF = dwarves_print_version;

static const struct argp_option pdwtags__options[] = {
	{
		.name = "format_path",
		.key  = 'F',
		.arg  = "FORMAT_LIST",
		.doc  = "List of debugging formats to try"
	},
	{
		.key  = 'V',
		.name = "verbose",
		.doc  = "show details",
	},
	{
		.name = NULL,
	}
};

static error_t pdwtags__options_parser(int key, char *arg __maybe_unused,
				      struct argp_state *state)
{
	switch (key) {
	case ARGP_KEY_INIT:
		if (state->child_inputs != NULL)
			state->child_inputs[0] = state->input;
		break;
	case 'F': pdwtags_conf_load.format_path = arg;	break;
	case 'V': conf.show_decl_info = 1;		break;
	default:  return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char pdwtags__args_doc[] = "FILE";

static struct argp pdwtags__argp = {
	.options  = pdwtags__options,
	.parser	  = pdwtags__options_parser,
	.args_doc = pdwtags__args_doc,
};

int main(int argc, char *argv[])
{
	int remaining, rc = EXIT_FAILURE, err;
	struct cus *cus = cus__new();

	if (dwarves__init(0) || cus == NULL) {
		fputs("pwdtags: insufficient memory\n", stderr);
		goto out;
	}

	if (argp_parse(&pdwtags__argp, argc, argv, 0, &remaining, NULL) ||
	    remaining == argc) {
                argp_help(&pdwtags__argp, stderr, ARGP_HELP_SEE, argv[0]);
                goto out;
	}

	err = cus__load_files(cus, &pdwtags_conf_load, argv + remaining);
	if (err == 0) {
		rc = EXIT_SUCCESS;
		goto out;
	}

	cus__fprintf_load_files_err(cus, "pdwtags", argv + remaining, err, stderr);
out:
	cus__delete(cus);
	dwarves__exit();
	return rc;
}
