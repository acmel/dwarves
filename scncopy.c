/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright 2009 Red Hat, Inc.
 *
 * Author: Peter Jones <pjones@redhat.com>
 */
#include <gelf.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "elfcreator.h"
#include "dutil.h"

static int should_copy_scn(Elf *elf, GElf_Shdr *shdr, struct strlist *scns)
{
	char *name;
	size_t shstrndx;

	if (elf_getshdrstrndx(elf, &shstrndx) < 0)
		return 0;
	name = elf_strptr(elf, shstrndx, shdr->sh_name);
	if (name == NULL)
		return 0;

	if (strlist__has_entry(scns, name))
		return 1;
	return 0;
}

int main(int argc, char *argv[])
{
	int n;
	struct strlist *sections;
	char *infile = NULL, *outfile = NULL;
	int fd;
	Elf *elf;
	Elf_Scn *scn;
	int copy_all_sections = 0;
	ElfCreator *ctor;

	sections = strlist__new(false);
	for (n = 1; n < argc; n++) {
		if (!strcmp(argv[n], "-a")) {
			copy_all_sections = 1;
		} else if (!strcmp(argv[n], "-s")) {
			if (n == argc-1) {
				fprintf(stderr, "Missing argument to -s\n");
				return -1;
			}
			n++;
			strlist__add(sections, argv[n]);
			continue;
		} else if (!strcmp(argv[n], "-o")) {
			if (n == argc-1) {
				fprintf(stderr, "Missing argument to -o\n");
				return -1;
			}
			n++;
			outfile = argv[n];
			continue;
		} else if (!strcmp(argv[n], "-?") ||
				!strcmp(argv[n], "--help") ||
				!strcmp(argv[n], "--usage")) {
			printf("usage: scncopy [-s section0 [[-s section1] ... -s sectionN] | -a ] -o outfile infile\n");
			return 0;
		} else if (n == argc-1) {
			infile = argv[n];
		} else {
			fprintf(stderr, "usage: pjoc -s section 0 [[-s section1] ... -s sectionN] -o outfile infile\n");
			return 1;
		}
	}
	if (!infile || !outfile) {
		fprintf(stderr, "usage: pjoc -s section 0 [[-s section1] ... -s sectionN] -o outfile infile\n");
		return 1;
	}

	if (!(fd = open(infile, O_RDONLY))) {
		fprintf(stderr, "Could not open \"%s\" for reading: %m\n", infile);
		return 1;
	}

	elf_version(EV_CURRENT);

	if ((elf = elf_begin(fd, ELF_C_READ_MMAP_PRIVATE, NULL)) == NULL) {
		fprintf(stderr, "cannot get elf descriptor for \"%s\": %s\n",
				infile, elf_errmsg(-1));
		close(fd);
		return 1;
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		fprintf(stderr, "\"%s\" is not an ELF file\n", infile);
err:
		elf_end(elf);
		close(fd);
		return 1;
	}

	if ((ctor = elfcreator_begin(outfile, elf)) == NULL) {
		fprintf(stderr, "could not initialize ELF creator\n");
		goto err;
	}

	scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr shdr_mem, *shdr;

		shdr = gelf_getshdr(scn, &shdr_mem);
		if (shdr == NULL)
			continue;

		if (!should_copy_scn(elf, shdr, sections) && !copy_all_sections)
			continue;

		elfcreator_copy_scn(ctor, scn);
	}
	elfcreator_end(ctor);
	return 0;
}
