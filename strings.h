#ifndef _STRINGS_H_
#define _STRINGS_H_ 1
/*
  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include "gobuffer.h"

typedef unsigned int strings_t;

struct strings {
	void		*tree;
	struct gobuffer	gb;
};

struct strings *strings__new(void);

void strings__delete(struct strings *self);

strings_t strings__add(struct strings *self, const char *str);
strings_t strings__find(struct strings *self, const char *str);

int strings__cmp(const struct strings *self, strings_t a, strings_t b);

static inline const char *strings__ptr(const struct strings *self, strings_t s)
{
	return gobuffer__ptr(&self->gb, s);
}

static inline const char *strings__entries(const struct strings *self)
{
	return gobuffer__entries(&self->gb);
}

static inline unsigned int strings__nr_entries(const struct strings *self)
{
	return gobuffer__nr_entries(&self->gb);
}

static inline strings_t strings__size(const struct strings *self)
{
	return gobuffer__size(&self->gb);
}

static inline const char *strings__compress(struct strings *self,
					    unsigned int *size)
{
	return gobuffer__compress(&self->gb, size);
}

#endif /* _STRINGS_H_ */
