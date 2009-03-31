#ifndef _GOBUFFER_H_
#define _GOBUFFER_H_ 1
/*
  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

struct gobuffer {
	char		*entries;
	unsigned int	nr_entries;
	unsigned int	index;
	unsigned int	allocated_size;
};

struct gobuffer *gobuffer__new(void);

void gobuffer__init(struct gobuffer *self);
void gobuffer__delete(struct gobuffer *self);
void __gobuffer__delete(struct gobuffer *self);

void gobuffer__copy(const struct gobuffer *self, void *dest);

int gobuffer__add(struct gobuffer *self, const void *s, unsigned int len);
int gobuffer__allocate(struct gobuffer *self, unsigned int len);

static inline const void *gobuffer__entries(const struct gobuffer *self)
{
	return self->entries;
}

static inline unsigned int gobuffer__nr_entries(const struct gobuffer *self)
{
	return self->nr_entries;
}

static inline unsigned int gobuffer__size(const struct gobuffer *self)
{
	return self->index;
}

void *gobuffer__ptr(const struct gobuffer *self, unsigned int s);

const void *gobuffer__compress(struct gobuffer *self, unsigned int *size);

#endif /* _GOBUFFER_H_ */
