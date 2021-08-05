/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2007-2016 Arnaldo Carvalho de Melo <acme@kernel.org>

  System call sign extender
*/

#include <argp.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dwarves.h"
#include "dutil.h"

static const char *prefix = "sys_";
static size_t prefix_len = 4;

static bool filter(struct function *f)
{
	if (f->proto.nr_parms != 0) {
		const char *name = function__name(f);

		if (strlen(name) > prefix_len &&
		    memcmp(name, prefix, prefix_len) == 0)
			return false;
	}
	return true;
}

static void zero_extend(const int regparm, const struct base_type *bt, const char *parm)
{
	const char *instr = "INVALID";

	switch (bt->bit_size) {
	case 32:
		instr = "sll";
		break;
	case 16:
		instr = "slw";
		break;
	case 8:
		instr = "slb";
		break;
	}

	char bf[64];
	printf("\t%s\t$a%d, $a%d, 0"
	       "\t/* zero extend $a%d(%s %s) from %d to 64-bit */\n",
	       instr, regparm, regparm, regparm,
	       base_type__name(bt, bf, sizeof(bf)),
	       parm, bt->bit_size);
}

static void emit_wrapper(struct function *f, struct cu *cu)
{
	struct parameter *parm;
	const char *name = function__name(f);
	int regparm = 0, needs_wrapper = 0;

	function__for_each_parameter(f, cu, parm) {
		const type_id_t type_id = parm->tag.type;
		struct tag *type = cu__type(cu, type_id);

		tag__assert_search_result(type);
		if (type->tag == DW_TAG_base_type) {
			struct base_type *bt = tag__base_type(type);
			char bf[64];

			if (bt->bit_size < 64 &&
			    strncmp(base_type__name(bt, bf, sizeof(bf)), "unsigned", 8) == 0) {
				if (!needs_wrapper) {
					printf("wrap_%s:\n", name);
					needs_wrapper = 1;
				}
				zero_extend(regparm, bt, parameter__name(parm));
			}
		}
		++regparm;
	}

	if (needs_wrapper)
		printf("\tj\t%s\n\n", name);
}

static int cu__emit_wrapper(struct cu *cu, void *cookie __maybe_unused)
{
	struct function *pos;
	uint32_t id;

	cu__for_each_function(cu, id, pos)
		if (!filter(pos))
			emit_wrapper(pos, cu);
	return 0;
}

static void cus__emit_wrapper(struct cus *cu)
{
	cus__for_each_cu(cu, cu__emit_wrapper, NULL, NULL);
}

/* Name and version of program.  */
ARGP_PROGRAM_VERSION_HOOK_DEF = dwarves_print_version;

static const struct argp_option options[] = {
	{
		.key  = 'p',
		.name = "prefix",
		.arg  = "PREFIX",
		.doc  = "function prefix",
	},
	{
		.name = NULL,
	}
};

static error_t options_parser(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARGP_KEY_INIT:
		if (state->child_inputs != NULL)
			state->child_inputs[0] = state->input;
		break;
	case 'p':
		prefix = arg;
		prefix_len = strlen(prefix);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char args_doc[] = "FILE";

static struct argp argp = {
	.options  = options,
	.parser	  = options_parser,
	.args_doc = args_doc,
};

int main(int argc, char *argv[])
{
	int err, remaining;
	struct cus *cus = cus__new();

	if (cus == NULL) {
		fprintf(stderr, "%s: insufficient memory\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (argp_parse(&argp, argc, argv, 0, &remaining, NULL) ||
	    remaining == argc) {
                argp_help(&argp, stderr, ARGP_HELP_SEE, argv[0]);
                return EXIT_FAILURE;
	}
	err = cus__load_files(cus, NULL, argv + remaining);
	if (err != 0) {
		cus__fprintf_load_files_err(cus, "syscse", argv + remaining, err, stderr);
		return EXIT_FAILURE;
	}

	cus__emit_wrapper(cus);
	return EXIT_SUCCESS;
}
