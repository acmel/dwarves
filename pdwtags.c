/* 
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include "dwarves.h"

static int emit_tag(struct tag *self, struct cu *cu, void *cookie __unused)
{
	if (self->tag != DW_TAG_array_type &&
	    self->tag != DW_TAG_base_type &&
	    self->tag != DW_TAG_const_type &&
	    self->tag != DW_TAG_formal_parameter &&
	    self->tag != DW_TAG_pointer_type &&
	    self->tag != DW_TAG_reference_type &&
	    self->tag != DW_TAG_subroutine_type &&
	    self->tag != DW_TAG_volatile_type) {
		if (self->tag == DW_TAG_structure_type)
			class__find_holes(tag__class(self), cu);

		tag__fprintf(self, cu, NULL, NULL, 0, stdout);

		if (self->tag == DW_TAG_subprogram) {
			const struct function *fn = tag__function(self);
			putchar('\n');
			lexblock__fprintf(&fn->lexblock, cu, 0, stdout);
		} else if (self->tag != DW_TAG_structure_type)
			puts(";");
		putchar('\n');
	}
	return 0;
}

static int cu__emit_tags(struct cu *self, void *cookie __unused)
{
	cu__for_each_tag(self, emit_tag, NULL, NULL);
	return 0;
}

static void cus__emit_tags(struct cus *self)
{
	cus__for_each_cu(self, cu__emit_tags, NULL, NULL);
}

static void usage(void)
{
	printf("usage: pdwtags <filename>\n");
}

int main(int argc, char *argv[])
{
	int err;
	struct cus *cus;
	char *filename = argv[1];

	if (argc != 2) {
		usage();
		return EXIT_FAILURE;
	}

	dwarves__init(0);

	cus = cus__new(NULL, NULL);
	if (cus == NULL) {
		fputs("pwdtags: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}

	err = cus__load(cus, filename);
	if (err != 0) {
		cus__print_error_msg("pdwtags", filename, err);
		return EXIT_FAILURE;
	}

	cus__emit_tags(cus);
	return EXIT_SUCCESS;
}
