/* 
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/


#include "dutil.h"

#include <ctype.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int str_compare(const void *a, const void *b)
{
	return strcmp(a, b);
}

static int fstrlist__add(struct fstrlist *self, const char *str)
{
	char **s = tsearch(str, &self->entries, str_compare);

	if (s != NULL) {
		if (*s == str) {
			char *dup = strdup(str);
			if (dup != NULL)
				*s = dup;
			else {
				tdelete(str, &self->entries, str_compare);
				return -1;
			}
		} else
			return -1;
	} else
		return -1;

	return 0;
}

static int fstrlist__load(struct fstrlist *self, const char *filename)
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
		
		if (fstrlist__add(self, entry) != 0)
			goto out;
	}
		
	err = 0;
out:
	fclose(fp);
	return err;
}

struct fstrlist *fstrlist__new(const char *filename)
{
	struct fstrlist *self = malloc(sizeof(*self));

	if (self != NULL) {
		self->entries = NULL;
		if (fstrlist__load(self, filename) != 0) {
			fstrlist__delete(self);
			self = NULL;
		}
	}

	return self;
}

void fstrlist__delete(struct fstrlist *self)
{
	if (self != NULL) {
		tdestroy(self->entries, free);
		self->entries = NULL;
		free(self);
	}
}

int fstrlist__has_entry(const struct fstrlist *self, const char *entry)
{
	return tfind(entry, &self->entries, str_compare) != NULL;
}
