#ifndef _CTF_ENCODER_H_
#define _CTF_ENCODER_H_ 1
/*
  Copyright (C) 2009 Red Hat Inc.
  Copyright (C) 2009 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

struct cu;

int cu__encode_ctf(struct cu *self, int verbose);

#endif /* _CTF_ENCODER_H_ */
