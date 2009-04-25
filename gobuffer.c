/*
  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  Grow only buffer, add entries but never delete

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include "gobuffer.h"

#include <search.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>
#include <errno.h>

#include "dutil.h"

#define GOBUFFER__BCHUNK (8 * 1024)
#define GOBUFFER__ZCHUNK (8 * 1024)

void gobuffer__init(struct gobuffer *self)
{
	self->entries = NULL;
	self->nr_entries = self->allocated_size = 0;
	/* 0 == NULL */
	self->index = 1;
}

struct gobuffer *gobuffer__new(void)
{
	struct gobuffer *self = malloc(sizeof(*self));

	if (self != NULL)
		gobuffer__init(self);

	return self;
}

void __gobuffer__delete(struct gobuffer *self)
{
	free(self->entries);
}

void gobuffer__delete(struct gobuffer *self)
{
	__gobuffer__delete(self);
	free(self);
}

void *gobuffer__ptr(const struct gobuffer *self, unsigned int s)
{
	return s ? self->entries + s : NULL;
}

int gobuffer__allocate(struct gobuffer *self, unsigned int len)
{
	const unsigned int rc = self->index;
	const unsigned int index = self->index + len;

	if (index >= self->allocated_size) {
		unsigned int allocated_size = (self->allocated_size +
					       GOBUFFER__BCHUNK);
		if (allocated_size < index)
			allocated_size = index + GOBUFFER__BCHUNK;
		char *entries = realloc(self->entries, allocated_size);

		if (entries == NULL)
			return -ENOMEM;

		self->allocated_size = allocated_size;
		self->entries = entries;
	}

	self->index = index;
	return rc;
}

int gobuffer__add(struct gobuffer *self, const void *s, unsigned int len)
{
	const int rc = gobuffer__allocate(self, len);

	if (rc >= 0) {
		++self->nr_entries;
		memcpy(self->entries + rc, s, len);
	}
	return rc;
}

void gobuffer__copy(const struct gobuffer *self, void *dest)
{
	memcpy(dest, self->entries, gobuffer__size(self));
}

const void *gobuffer__compress(struct gobuffer *self, unsigned int *size)
{
	z_stream z = {
		.zalloc	  = Z_NULL,
		.zfree	  = Z_NULL,
		.opaque	  = Z_NULL,
		.avail_in = gobuffer__size(self),
		.next_in  = (Bytef *)gobuffer__entries(self),
	};
	void *bf = NULL;
	unsigned int bf_size = 0;

	if (deflateInit(&z, Z_BEST_COMPRESSION) != Z_OK)
		goto out_free;

	do {
		const unsigned int new_bf_size = bf_size + GOBUFFER__ZCHUNK;
		void *nbf = realloc(bf, new_bf_size);

		if (nbf == NULL)
			goto out_close_and_free;

		bf = nbf;
		z.avail_out = GOBUFFER__ZCHUNK;
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
