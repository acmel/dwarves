#ifndef _STRINGS_H_
#define _STRINGS_H_ 1
/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>
*/

#include "lib/bpf/src/btf.h"

typedef unsigned int strings_t;

struct strings {
	struct btf *btf;
};

struct strings *strings__new(void);

void strings__delete(struct strings *strings);

strings_t strings__add(struct strings *strings, const char *str);
strings_t strings__find(struct strings *strings, const char *str);
strings_t strings__size(const struct strings *strings);
int strings__copy(const struct strings *strings, void *dst);

static inline const char *strings__ptr(const struct strings *strings, strings_t s)
{
	return btf__str_by_offset(strings->btf, s);
}

#endif /* _STRINGS_H_ */
