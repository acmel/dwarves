/* 
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
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

static void emit_tag(struct tag *self, uint32_t tag_id, struct cu *cu)
{
	conf.no_semicolon = tag__is_function(self);

	printf("%d ", tag_id);

	if (self->tag == DW_TAG_base_type) {
		const char *name = base_type__name(tag__base_type(self));

		if (name == NULL)
			printf("anonymous base_type\n");
		else
			puts(name);
	} else if (self->tag == DW_TAG_pointer_type)
		printf("pointer to %lld\n", (unsigned long long)self->type);
	else
		tag__fprintf(self, cu, &conf, stdout);

	if (tag__is_function(self)) {
		struct function *fn = tag__function(self);
		putchar('\n');
		lexblock__fprintf(&fn->lexblock, cu, fn, 0, stdout);
	}
	puts("\n");
}

static int cu__emit_tags(struct cu *self, void *cookie __unused)
{
	uint16_t i;

	for (i = 1; i < self->types_table.nr_entries; ++i) {
		struct tag *tag = self->types_table.entries[i];
		emit_tag(tag, i, self);
	}
	return 0;
}

static void cus__emit_tags(struct cus *self)
{
	cus__for_each_cu(self, cu__emit_tags, NULL, NULL);
}

/* Name and version of program.  */
ARGP_PROGRAM_VERSION_HOOK_DEF = dwarves_print_version;

static const struct argp_option pdwtags__options[] = {
	{
		.key  = 'V',
		.name = "verbose",
		.doc  = "show details",
	},
	{
		.name = NULL,
	}
};

static error_t pdwtags__options_parser(int key, char *arg __unused,
				      struct argp_state *state)
{
	switch (key) {
	case ARGP_KEY_INIT:
		if (state->child_inputs != NULL)
			state->child_inputs[0] = state->input;
		break;
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
	int err, remaining;
	struct cus *cus = cus__new();

	if (dwarves__init(0) || cus == NULL) {
		fputs("pwdtags: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}

	if (argp_parse(&pdwtags__argp, argc, argv, 0, &remaining, NULL) ||
	    remaining == argc) {
                argp_help(&pdwtags__argp, stderr, ARGP_HELP_SEE, argv[0]);
                return EXIT_FAILURE;
	}

	err = cus__loadfl(cus, argv + remaining);
	if (err != 0)
		return EXIT_FAILURE;

	cus__emit_tags(cus);
	return EXIT_SUCCESS;
}
