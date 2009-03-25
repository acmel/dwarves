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

bool elf_symtab__is_local_function(struct elf_symtab *self,
				   GElf_Sym *sym)
{
	if (elf_sym__type(sym) != STT_OBJECT)
		return false;
	if (sym->st_shndx == SHN_ABS &&
	    sym->st_value == 0)
                return false;
        if (sym->st_name == 0)
                return false;
        if (sym->st_shndx == SHN_UNDEF)
                return false;

	const char *name = elf_sym__name(sym, self);
        if (!strcmp(name, "_START_") || !strcmp(name, "_END_"))
                return false;
	return true;
}
