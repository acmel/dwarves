#ifndef _DUTIL_H_
#define _DUTIL_H_ 1
/* 
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <stdbool.h>

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

struct strlist {
	void *entries;
	bool dupstr;
};

struct strlist *strlist__new(bool dupstr);
void strlist__delete(struct strlist *self);

int strlist__load(struct strlist *self, const char *filename);
int strlist__add(struct strlist *self, const char *str);

int strlist__has_entry(const struct strlist *self, const char *entry);

#endif /* _DUTIL_H_ */
