/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
*/

#include <stdio.h>
#include <stdlib.h>

#include "dwarves.h"
#include "dutil.h"

static int class__tag_name(struct tag *tag, struct cu *cu __maybe_unused,
			   void *cookie __maybe_unused)
{
	puts(dwarf_tag_name(tag->tag));
	return 0;
}

static int cu__dump_class_tag_names(struct cu *cu, void *cookie __maybe_unused)
{
	cu__for_all_tags(cu, class__tag_name, NULL);
	return 0;
}

static void cus__dump_class_tag_names(struct cus *cus)
{
	cus__for_each_cu(cus, cu__dump_class_tag_names, NULL, NULL);
}

int main(int argc __maybe_unused, char *argv[])
{
	int err, rc = EXIT_FAILURE;
	struct cus *cus = cus__new();

	if (dwarves__init(0) || cus == NULL) {
		fputs("dtagnames: insufficient memory\n", stderr);
		goto out;
	}

	err = cus__load_files(cus, NULL, argv + 1);
	if (err != 0) {
		cus__fprintf_load_files_err(cus, "dtagnames", argv + 1, err, stderr);
		goto out;
	}

	cus__dump_class_tag_names(cus);
	rc = EXIT_SUCCESS;
out:
	cus__delete(cus);
	dwarves__exit();
	return rc;
}
