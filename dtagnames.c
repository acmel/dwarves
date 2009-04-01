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

#include "dwarves.h"
#include "dutil.h"

static void print_malloc_stats(void)
{
	struct mallinfo m = mallinfo();

	fprintf(stderr, "size: %u\n", m.uordblks);
}

static int class__tag_name(struct tag *self, struct cu *cu __unused,
			   void *cookie __unused)
{
	puts(dwarf_tag_name(self->tag));
	return 0;
}

static int cu__dump_class_tag_names(struct cu *self, void *cookie __unused)
{
	cu__for_all_tags(self, class__tag_name, NULL);
	return 0;
}

static void cus__dump_class_tag_names(struct cus *self)
{
	cus__for_each_cu(self, cu__dump_class_tag_names, NULL, NULL);
}

int main(int argc __unused, char *argv[])
{
	int err, rc = EXIT_FAILURE;
	struct cus *cus = cus__new();

	if (dwarves__init(0) || cus == NULL) {
		fputs("dtagnames: insufficient memory\n", stderr);
		goto out;
	}

	err = cus__load_files(cus, NULL, argv + 1);
	if (err != 0)
		goto out;

	cus__dump_class_tag_names(cus);
	print_malloc_stats();
	rc = EXIT_SUCCESS;
out:
	cus__delete(cus);
	dwarves__exit();
	return rc;
}
