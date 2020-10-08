/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>
*/

#include "pahole_strings.h"
#include "gobuffer.h"

#include <search.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>

#include "dutil.h"
#include "lib/bpf/src/libbpf.h"

struct strings *strings__new(void)
{
	struct strings *strs = malloc(sizeof(*strs));

	if (!strs)
		return NULL;

	strs->btf = btf__new_empty();
	if (libbpf_get_error(strs->btf)) {
		free(strs);
		return NULL;
	}

	return strs;
}

void strings__delete(struct strings *strs)
{
	if (strs == NULL)
		return;
	btf__free(strs->btf);
	free(strs);
}

strings_t strings__add(struct strings *strs, const char *str)
{
	strings_t index;

	if (str == NULL)
		return 0;

	index = btf__add_str(strs->btf, str);
	if (index < 0)
		return 0;

	return index;
}

strings_t strings__find(struct strings *strs, const char *str)
{
	return btf__find_str(strs->btf, str);
}

/* a horrible and inefficient hack to get string section size out of BTF */
strings_t strings__size(const struct strings *strs)
{
	const struct btf_header *p;
	uint32_t sz;

	p = btf__get_raw_data(strs->btf, &sz);
	if (!p)
		return -1;

	return p->str_len;
}

/* similarly horrible hack to copy out string section out of BTF */
int strings__copy(const struct strings *strs, void *dst)
{
	const struct btf_header *p;
	uint32_t sz;

	p = btf__get_raw_data(strs->btf, &sz);
	if (!p)
		return -1;

	memcpy(dst, (void *)p + p->str_off, p->str_len);
	return 0;
}
