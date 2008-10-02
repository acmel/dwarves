/*
  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include "strings.h"

#include <search.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>

#include "dutil.h"

#define STRINGS__ZCHUNK (128 * 1024)
#define STRINGS__SCHUNK (8 * 1024)

struct strings {
	void		*tree;
	char		*entries;
	unsigned int	nr_entries;
	strings_t	index;
	strings_t	allocated_size;
};

struct strings *strings__new(void)
{
	struct strings *self = malloc(sizeof(*self));

	if (self != NULL) {
		memset(self, 0, sizeof(*self));
		/* 0 == NULL */
		self->index = 1;
	}

	return self;

}

const char *strings__entries(const struct strings *self)
{
	return self->entries;
}

unsigned int strings__nr_entries(const struct strings *self)
{
	return self->nr_entries;
}

strings_t strings__size(const struct strings *self)
{
	return self->index;
}

static void do_nothing(void *ptr __unused)
{
}

void strings__delete(struct strings *self)
{
	tdestroy(self->tree, do_nothing);
	free(self->entries);
	free(self);
}

const char *strings__ptr(const struct strings *self, strings_t s)
{
	return s ? self->entries + s : NULL;
}

static strings_t strings__insert(struct strings *self, const char *s)
{
	const size_t len = strlen(s);
	const strings_t rc = self->index;
	const strings_t index = self->index + len + 1;
	char *copy;

	if (index >= self->allocated_size) {
		const strings_t allocated_size = (self->allocated_size +
						  STRINGS__SCHUNK);
		char *entries = realloc(self->entries, allocated_size);

		if (entries == NULL)
			return 0;

		self->allocated_size = allocated_size;
		self->entries = entries;
	}

	++self->nr_entries;
	copy = self->entries + rc;
	memcpy(copy, s, len + 1);
	self->index = index;
	return rc;
}

struct search_key {
	struct strings *self;
	const char *str;
};

static int strings__compare(const void *a, const void *b)
{
	const struct search_key *key = a;

	return strcmp(key->str, key->self->entries + *(strings_t *)&b);
}

strings_t strings__add(struct strings *self, const char *str)
{
	strings_t *s;
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
				*s = index;
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

const char *strings__compress(struct strings *self, unsigned int *size)
{
	z_stream z = {
		.zalloc	  = Z_NULL,
		.zfree	  = Z_NULL,
		.opaque	  = Z_NULL,
		.avail_in = strings__size(self),
		.next_in  = (Bytef *)strings__entries(self),
	};
	char *bf = NULL;
	unsigned int bf_size = 0;

	if (deflateInit(&z, Z_BEST_COMPRESSION) != Z_OK)
		goto out_free;

	do {
		const unsigned int new_bf_size = bf_size + STRINGS__ZCHUNK;
		char *nbf = realloc(bf, new_bf_size);

		if (nbf == NULL)
			goto out_close_and_free;

		bf = nbf;
		z.avail_out = STRINGS__ZCHUNK;
		z.next_out  = (Bytef *)bf + bf_size;
		bf_size	    = new_bf_size;
		if (deflate(&z, Z_FINISH) == Z_STREAM_ERROR)
			goto out_close_and_free;
	} while (z.avail_out == 0);

	deflateEnd(&z);
	*size = bf_size - z.avail_out;
out:
	return bf;

out_close_and_free:
	deflateEnd(&z);
out_free:
	free(bf);
	bf = NULL;
	goto out;
}
