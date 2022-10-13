#ifndef _DWARVES_EMIT_H_
#define _DWARVES_EMIT_H_ 1
/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>
*/

#include <stdio.h>
#include <stdint.h>
#include "list.h"

struct cu;
struct ftype;
struct tag;
struct type;
struct conf_fprintf;

struct type_emissions {
	struct list_head definitions; /* struct type entries */
	struct list_head base_type_definitions; /* struct base_type entries */
	struct list_head fwd_decls;   /* struct class entries */
	struct conf_fprintf *conf_fprintf;
};

void type_emissions__init(struct type_emissions *temissions, struct conf_fprintf *conf_fprintf);

int ftype__emit_definitions(struct ftype *ftype, struct cu *cu,
			    struct type_emissions *emissions, FILE *fp);
int type__emit_definitions(struct tag *tag, struct cu *cu,
			   struct type_emissions *emissions, FILE *fp);
void type__emit(struct tag *tag_type, struct cu *cu,
		const char *prefix, const char *suffix, FILE *fp);
struct type *type_emissions__find_definition(const struct type_emissions *temissions,
					     uint16_t tag, const char *name);

#endif /* _DWARVES_EMIT_H_ */
