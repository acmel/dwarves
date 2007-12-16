#ifndef _DUTIL_H_
#define _DUTIL_H_ 1
/* 
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

struct fstrlist {
	void *entries;
};

struct fstrlist *fstrlist__new(const char *filename);
void fstrlist__delete(struct fstrlist *self);

int fstrlist__has_entry(const struct fstrlist *self, const char *entry);

#endif /* _DUTIL_H_ */
