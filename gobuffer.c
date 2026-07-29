/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  Grow only buffer, add entries but never delete
*/

#include "gobuffer.h"

#include <search.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "dutil.h"

#define GOBUFFER__BCHUNK (8 * 1024)

void __gobuffer__delete(struct gobuffer *gb)
{
	if (gb == NULL)
		return;

	zfree(&gb->entries);
}

void *gobuffer__ptr(const struct gobuffer *gb, unsigned int s)
{
	return s ? gb->entries + s : NULL;
}

int gobuffer__allocate(struct gobuffer *gb, unsigned int len)
{
	const unsigned int rc = gb->index;
	const unsigned int index = gb->index + len;

	if (index >= gb->allocated_size) {
		unsigned int allocated_size = (gb->allocated_size +
					       GOBUFFER__BCHUNK);
		if (allocated_size < index)
			allocated_size = index + GOBUFFER__BCHUNK;
		char *entries = realloc(gb->entries, allocated_size);

		if (entries == NULL)
			return -ENOMEM;

		gb->allocated_size = allocated_size;
		gb->entries = entries;
	}

	gb->index = index;
	return rc;
}

int gobuffer__add(struct gobuffer *gb, const void *s, unsigned int len)
{
	const int rc = gobuffer__allocate(gb, len);

	if (rc >= 0) {
		++gb->nr_entries;
		memcpy(gb->entries + rc, s, len);
	}
	return rc;
}

void gobuffer__copy(const struct gobuffer *gb, void *dest)
{
        if (gb->entries) {
		memcpy(dest, gb->entries, gobuffer__size(gb));
	} else {
		/* gobuffer__size will be 0 or 1. */
		memcpy(dest, "", gobuffer__size(gb));
	}
}

