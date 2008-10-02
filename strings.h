#ifndef _STRINGS_H_
#define _STRINGS_H_ 1
/* 
  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

typedef unsigned int strings_t;

struct strings;

struct strings *strings__new(void);

void strings__delete(struct strings *self);

strings_t strings__add(struct strings *self, const char *str);

const char *strings__ptr(const struct strings *self, strings_t s);

const char *strings__entries(const struct strings *self);

unsigned int strings__nr_entries(const struct strings *self);

strings_t strings__size(const struct strings *self);

const char *strings__compress(struct strings *self, unsigned int *size);

#endif /* _STRINGS_H_ */
