#ifndef _ELF_SYMTAB_H_
#define _ELF_SYMTAB_H_ 1
/*
  Copyright (C) 2009 Red Hat Inc.
  Copyright (C) 2009 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <stdbool.h>
#include <stdint.h>
#include <gelf.h>
#include <elf.h>

struct elf_symtab;

struct elf_symtab *elf_symtab__new(Elf *elf, GElf_Ehdr *ehdr);
void elf_symtab__delete(struct elf_symtab *self);

struct elf_symtab_iter_state {
	int	 (*func)(void *priv, const char *sym_name,
			 int sym_index, int call_index, void *data);
	void	 *data;
	void	 *priv;
	int	 st_type;
	uint32_t limit;
};

int elf_symtab__iterate(struct elf_symtab *self,
			struct elf_symtab_iter_state *ep,
			bool (*filter)(GElf_Sym *sym, char *name, int type));

#endif /* _ELF_SYMTAB_H_ */
