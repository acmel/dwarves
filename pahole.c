/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <stdio.h>
#include <dwarf.h>
#include <stdlib.h>

#include "classes.h"

int main(int argc, char *argv[])
{
	if (argc == 0) {
		puts("usage: "
		     "pahole <elf_file_with_debug_info> {<struct_name>}");
		return EXIT_FAILURE;
	}

	if (classes__load(argv[1]) != 0) {
		fprintf(stderr, "pahole: couldn't load DWARF info from %s\n",
		       argv[1]);
		return EXIT_FAILURE;
	}

	if (argc == 2)
		classes__print(DW_TAG_structure_type);
	else {
		struct cu *cu = cus__find_by_id(0);

		if (cu != NULL) {
			struct class *class = cu__find_by_name(argv[2]);
			if (class != NULL) {
				class__find_holes(class, cu);
				class__print(class, cu);
			} else
				printf("struct %s not found!\n", argv[2]);
		} else
			printf("cu 0 not found!\n");
	}

	return EXIT_SUCCESS;
}
