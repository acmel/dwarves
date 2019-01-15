#ifndef _CTF_ENCODER_H_
#define _CTF_ENCODER_H_ 1
/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2009 Red Hat Inc.
  Copyright (C) 2009 Arnaldo Carvalho de Melo <acme@redhat.com>
*/

struct cu;

int cu__encode_ctf(struct cu *cu, int verbose);

#endif /* _CTF_ENCODER_H_ */
