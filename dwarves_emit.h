#ifndef _DWARVES_EMIT_H_
#define _DWARVES_EMIT_H_ 1
/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <stdio.h>
#include "list.h"

struct cu;
struct ftype;
struct tag;
struct type;

struct type_emissions {
	struct list_head definitions; /* struct type entries */
	struct list_head fwd_decls;   /* struct class entries */
};

void type_emissions__init(struct type_emissions *self);

int ftype__emit_definitions(struct ftype *self, struct cu *cu,
			    struct type_emissions *emissions, FILE *fp);
int type__emit_definitions(struct tag *self, struct cu *cu,
			   struct type_emissions *emissions, FILE *fp);
int type__emit_fwd_decl(struct type *ctype, const struct cu *cu,
			struct type_emissions *emissions, FILE *fp);
void type__emit(struct tag *tag_self, struct cu *cu,
		const char *prefix, const char *suffix, FILE *fp);
struct type *type_emissions__find_definition(const struct type_emissions *self,
					     const struct cu *cu,
					     const char *name);

#endif /* _DWARVES_EMIT_H_ */
