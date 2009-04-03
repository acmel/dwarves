/*
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/


#include "dutil.h"

#include <ctype.h>
#include <errno.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *zalloc(const size_t size)
{
	void *s = malloc(size);
	if (s != NULL)
		memset(s, 0, size);
	return s;
}

static int str_compare(const void *a, const void *b)
{
	return strcmp(a, b);
}

int strlist__add(struct strlist *self, const char *str)
{
	const char **s = tsearch(str, &self->entries, str_compare);

	if (s != NULL) {
		if (*s == str) {
			const char *dup = self->dupstr ? strdup(str) : str;

			if (dup != NULL)
				*s = dup;
			else {
				tdelete(str, &self->entries, str_compare);
				return -ENOMEM;
			}
		} else
			return -EEXIST;
	} else
		return -ENOMEM;

	return 0;
}

int strlist__load(struct strlist *self, const char *filename)
{
	char entry[1024];
	int err = -1;
	FILE *fp = fopen(filename, "r");

	if (fp == NULL)
		return -1;

	while (fgets(entry, sizeof(entry), fp) != NULL) {
		const size_t len = strlen(entry);

		if (len == 0)
			continue;
		entry[len - 1] = '\0';

		if (strlist__add(self, entry) != 0)
			goto out;
	}

	err = 0;
out:
	fclose(fp);
	return err;
}

struct strlist *strlist__new(bool dupstr)
{
	struct strlist *self = malloc(sizeof(*self));

	if (self != NULL) {
		self->entries = NULL;
		self->dupstr = dupstr;
	}

	return self;
}

static void do_nothing(void *ptr __unused)
{
}

void strlist__delete(struct strlist *self)
{
	if (self != NULL) {
		if (self->dupstr)
			tdestroy(self->entries, free);
		else
			tdestroy(self->entries, do_nothing);
		self->entries = NULL;
		free(self);
	}
}

int strlist__has_entry(const struct strlist *self, const char *entry)
{
	return tfind(entry, &self->entries, str_compare) != NULL;
}

Elf_Scn *elf_section_by_name(Elf *elf, GElf_Ehdr *ep,
			     GElf_Shdr *shp, const char *name)
{
	Elf_Scn *sec = NULL;

	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *str;

		gelf_getshdr(sec, shp);
		str = elf_strptr(elf, ep->e_shstrndx, shp->sh_name);
		if (!strcmp(name, str))
			break;
	}

	return sec;
}
