/*
  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include "strings.h"
#include "gobuffer.h"

#include <search.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>

#include "dutil.h"

struct strings *strings__new(void)
{
	struct strings *self = malloc(sizeof(*self));

	if (self != NULL) {
		self->tree = NULL;
		gobuffer__init(&self->gb);
	}

	return self;

}

static void do_nothing(void *ptr __unused)
{
}

void strings__delete(struct strings *self)
{
	if (self == NULL)
		return;
	tdestroy(self->tree, do_nothing);
	__gobuffer__delete(&self->gb);
	free(self);
}

static strings_t strings__insert(struct strings *self, const char *s)
{
	return gobuffer__add(&self->gb, s, strlen(s) + 1);
}

struct search_key {
	struct strings *self;
	const char *str;
};

static int strings__compare(const void *a, const void *b)
{
	const struct search_key *key = a;

	return strcmp(key->str, key->self->gb.entries + (unsigned long)b);
}

strings_t strings__add(struct strings *self, const char *str)
{
	unsigned long *s;
	strings_t index;
	struct search_key key = {
		.self = self,
		.str = str,
	};

	if (str == NULL)
		return 0;

	s = tsearch(&key, &self->tree, strings__compare);
	if (s != NULL) {
		if (*(struct search_key **)s == (void *)&key) { /* Not found, replace with the right key */
			index = strings__insert(self, str);
			if (index != 0)
				*s = (unsigned long)index;
			else {
				tdelete(&key, &self->tree, strings__compare);
				return 0;
			}
		} else /* Found! */
			index = *s;
	} else
		return 0;

	return index;
}

strings_t strings__find(struct strings *self, const char *str)
{
	strings_t *s;
	struct search_key key = {
		.self = self,
		.str = str,
	};

	if (str == NULL)
		return 0;

	s = tfind(&key, &self->tree, strings__compare);
	return s ? *s : 0;
}

int strings__cmp(const struct strings *self, strings_t a, strings_t b)
{
	return a == b ? 0 : strcmp(strings__ptr(self, a),
				   strings__ptr(self, b));
}
