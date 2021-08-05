/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2009 Red Hat Inc.
  Copyright (C) 2009 Arnaldo Carvalho de Melo <acme@redhat.com>
*/

#include <malloc.h>
#include <stdio.h>
#include <string.h>

#include "dutil.h"
#include "elf_symtab.h"

#define HASHSYMS__BITS 8
#define HASHSYMS__SIZE (1UL << HASHSYMS__BITS)

struct elf_symtab *elf_symtab__new(const char *name, Elf *elf)
{
	size_t symtab_index;

	if (name == NULL)
		name = ".symtab";

	GElf_Shdr shdr;
	Elf_Scn *sec = elf_section_by_name(elf, &shdr, name, &symtab_index);

	if (sec == NULL)
		return NULL;

	if (gelf_getshdr(sec, &shdr) == NULL)
		return NULL;

	struct elf_symtab *symtab = zalloc(sizeof(*symtab));
	if (symtab == NULL)
		return NULL;

	symtab->name = strdup(name);
	if (symtab->name == NULL)
		goto out_delete;

	symtab->syms = elf_getdata(sec, NULL);
	if (symtab->syms == NULL)
		goto out_free_name;

	/*
	 * This returns extended section index table's
	 * section index, if it exists.
	 */
	int symtab_xindex = elf_scnshndx(sec);

	sec = elf_getscn(elf, shdr.sh_link);
	if (sec == NULL)
		goto out_free_name;

	symtab->symstrs = elf_getdata(sec, NULL);
	if (symtab->symstrs == NULL)
		goto out_free_name;

	/*
	 * The .symtab section has optional extended section index
	 * table, load its data so it can be used to resolve symbol's
	 * section index.
	 **/
	if (symtab_xindex > 0) {
		GElf_Shdr shdr_xindex;
		Elf_Scn *sec_xindex;

		sec_xindex = elf_getscn(elf, symtab_xindex);
		if (sec_xindex == NULL)
			goto out_free_name;

		if (gelf_getshdr(sec_xindex, &shdr_xindex) == NULL)
			goto out_free_name;

		/* Extra check to verify it's correct type */
		if (shdr_xindex.sh_type != SHT_SYMTAB_SHNDX)
			goto out_free_name;

		/* Extra check to verify it belongs to the .symtab */
		if (symtab_index != shdr_xindex.sh_link)
			goto out_free_name;

		symtab->syms_sec_idx_table = elf_getdata(elf_getscn(elf, symtab_xindex), NULL);
		if (symtab->syms_sec_idx_table == NULL)
			goto out_free_name;
	}

	symtab->nr_syms = shdr.sh_size / shdr.sh_entsize;

	return symtab;
out_free_name:
	zfree(&symtab->name);
out_delete:
	free(symtab);
	return NULL;
}

void elf_symtab__delete(struct elf_symtab *symtab)
{
	if (symtab == NULL)
		return;
	zfree(&symtab->name);
	free(symtab);
}
