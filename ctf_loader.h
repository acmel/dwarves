#ifndef _CTF_LOADER_H_
#define _CTF_LOADER_H_ 1
/* 
  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

struct cus;
struct conf_load;

int ctf__load(struct cus *self, struct conf_load *conf, char *filenames[]);

#endif /* _CTF_LOADER_H_ */
