#ifndef _DWARVES_REORGANIZE_H_
#define _DWARVES_REORGANIZE_H_ 1
/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>
*/


#include <stdint.h>
#include <stdio.h>

struct class;
struct cu;
struct class_member;

void class__subtract_offsets_from(struct class *cls, struct class_member *from,
				  const uint16_t size);

void class__add_offsets_from(struct class *cls, struct class_member *from,
			     const uint16_t size);

void class__fixup_alignment(struct class *cls, const struct cu *cu);

void class__reorganize(struct class *cls, const struct cu *cu,
		       const int verbose, FILE *fp);

#endif /* _DWARVES_REORGANIZE_H_ */
