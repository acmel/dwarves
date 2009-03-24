/*
  Copyright (C) 2009 Red Hat Inc.
  Copyright (C) 2009 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <malloc.h>
#include <stdio.h>
#include <string.h>

#include "dutil.h"
#include "elf_symtab.h"

#define HASHSYMS__BITS 8
#define HASHSYMS__SIZE (1UL << HASHSYMS__BITS)

struct elf_symtab {
	uint32_t  nr_syms;
	Elf_Data  *syms;
	Elf_Data  *symstrs;
};

struct elf_symtab *elf_symtab__new(Elf *elf, GElf_Ehdr *ehdr)
{
	GElf_Shdr shdr;
	Elf_Scn *sec = elf_section_by_name(elf, ehdr, &shdr, ".symtab");

	if (sec == NULL)
		return NULL;

	if (gelf_getshdr(sec, &shdr) == NULL)
		return NULL;

	struct elf_symtab *self = malloc(sizeof(*self));
	if (self == NULL)
		return NULL;

	self->syms = elf_getdata(sec, NULL);
	if (self->syms == NULL)
		goto out_delete;

	sec = elf_getscn(elf, shdr.sh_link);
	if (sec == NULL)
		goto out_delete;

	self->symstrs = elf_getdata(sec, NULL);
	if (self->symstrs == NULL)
		goto out_delete;

	self->nr_syms = shdr.sh_size / shdr.sh_entsize;

	return self;
out_delete:
	free(self);
	return NULL;
}

void elf_symtab__delete(struct elf_symtab *self)
{
	free(self);
}

int elf_symtab__iterate(struct elf_symtab *self,
			struct elf_symtab_iter_state *ep,
			bool (*filter)(GElf_Sym *sym, char *name, int type))
{
	uint32_t i, index = 0;

	for (i = 0; i < self->nr_syms; i++) {
		GElf_Sym sym;
		char *name;
		int type;

		if (gelf_getsym(self->syms, i, &sym) == NULL) {
			fprintf(stderr,
				"%s: could not get ELF symbol %d.\n",
				__func__, i);
			return -1;
		}
		type = GELF_ST_TYPE(sym.st_info);
		name = self->symstrs->d_buf + sym.st_name;

		if ((ep->st_type == -1 || ep->st_type == type) &&
		    (filter && !filter(&sym, name, type))) {
			if (index >= ep->limit) {
				fprintf(stderr, "%s: symbol limit reached "
					"([%u], %d vs %d).\n", __func__,
					ep->limit, i, self->nr_syms);
				return -1;
			}

			if (ep->func(ep->priv, name, i, index++, ep->data) < 0)
				return 0;
		}
	}

	return 0;
}
