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

struct cus;
struct cu;
struct ftype;
struct tag;
struct type;

extern int cus__emit_ftype_definitions(struct cus *self, struct cu *cu,
				       struct ftype *ftype, FILE *fp);
extern int cus__emit_type_definitions(struct cus *self, struct cu *cu,
				      struct tag *tag, FILE *fp);
extern int cus__emit_fwd_decl(struct cus *self, struct type *ctype,
			      const struct cu *cu, FILE *fp);
extern void type__emit(struct tag *tag_self, struct cu *cu,
		       const char *prefix, const char *suffix, FILE *fp);

#endif /* _DWARVES_EMIT_H_ */
