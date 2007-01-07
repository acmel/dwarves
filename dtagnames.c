/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include "classes.h"

static void print_malloc_stats(void)
{
	struct mallinfo m = mallinfo();

	fprintf(stderr, "size: %u\n", m.uordblks);
}

static int class__tag_name(struct tag *self, struct cu *cu, void *cookie)
{
	puts(dwarf_tag_name(self->tag));
	return 0;
}

static int cu__dump_class_tag_names(struct cu *self, void *cookie)
{
	cu__for_each_tag(self, class__tag_name, NULL, NULL);
	return 0;
}

static void cus__dump_class_tag_names(struct cus *self)
{
	cus__for_each_cu(self, cu__dump_class_tag_names, NULL, NULL);
}

static void usage(void)
{
	fprintf(stderr, "usage: dtagnames <filename>\n");
}

int main(int argc, char *argv[])
{
	struct cus *cus;
	char *filename = argv[1];

	if (argc != 2) {
		usage();
		return EXIT_FAILURE;
	}

	cus = cus__new(NULL, NULL);
	if (cus == NULL) {
		fputs("dtagnames: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}

	if (cus__load(cus, filename) != 0) {
		fprintf(stderr, "dtagnames: couldn't load DWARF info from %s\n",
		       filename);
		return EXIT_FAILURE;
	}

	cus__dump_class_tag_names(cus);
	print_malloc_stats();
	return EXIT_SUCCESS;
}
