#ifndef _DWARF_LOADER_H_
#define _DWARF_LOADER_H_ 1
/* 
  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

struct cus;
struct argp;

int dwarf__load_filename(struct cus *self, const char *filename);
int dwarf__load(struct cus *self, struct argp *argp, int argc, char *argv[]);

#endif /* _DWARF_LOADER_H_ */
