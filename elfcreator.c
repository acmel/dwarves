/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright 2009 Red Hat, Inc.
 *
 * Author: Peter Jones <pjones@redhat.com>
 */
#include <dlfcn.h>
#include <gelf.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "elfcreator.h"

struct elf_creator {
	const char *path;
	int fd;

	Elf *elf;
	GElf_Ehdr *ehdr, ehdr_mem;

	Elf *oldelf;
	/* just because we have to look this up /so/ often... */
	Elf_Scn *dynscn;
	GElf_Shdr *dynshdr, dynshdr_mem;
	Elf_Data *dyndata;
};

static void clear(ElfCreator *ctor, int do_unlink)
{
	if (do_unlink) {
		if (ctor->elf)
			elf_end(ctor->elf);
		if (ctor->fd >= 0)
			close(ctor->fd);
		if (ctor->path)
			unlink(ctor->path);
	} else {
		if (ctor->elf) {
			elf_update(ctor->elf, ELF_C_WRITE_MMAP);
			elf_end(ctor->elf);
		}
		if (ctor->fd >= 0)
			close(ctor->fd);
	}
	memset(ctor, '\0', sizeof(*ctor));
}

ElfCreator *elfcreator_begin(char *path, Elf *elf) {
	ElfCreator *ctor = NULL;
	GElf_Ehdr ehdr_mem, *ehdr;

	if (!(ctor = calloc(1, sizeof(*ctor))))
		return NULL;

	clear(ctor, 0);

	ctor->path = path;
	ctor->oldelf = elf;

	ehdr = gelf_getehdr(elf, &ehdr_mem);

	if ((ctor->fd = open(path, O_RDWR|O_CREAT|O_TRUNC, 0755)) < 0) {
err:
		clear(ctor, 1);
		free(ctor);
		return NULL;
	}

	if (!(ctor->elf = elf_begin(ctor->fd, ELF_C_WRITE_MMAP, elf)))
		goto err;

	gelf_newehdr(ctor->elf, gelf_getclass(elf));
	gelf_update_ehdr(ctor->elf, ehdr);

	if (!(ctor->ehdr = gelf_getehdr(ctor->elf, &ctor->ehdr_mem)))
		goto err;

	return ctor;
}

static Elf_Scn *get_scn_by_type(ElfCreator *ctor, Elf64_Word sh_type)
{
	Elf_Scn *scn = NULL;

	while ((scn = elf_nextscn(ctor->elf, scn)) != NULL) {
		GElf_Shdr *shdr, shdr_mem;

		shdr = gelf_getshdr(scn, &shdr_mem);
		if (shdr->sh_type == sh_type)
			return scn;
	}
	return NULL;
}

static void update_dyn_cache(ElfCreator *ctor)
{
	ctor->dynscn = get_scn_by_type(ctor, SHT_DYNAMIC);
	if (ctor->dynscn == NULL)
		return;

	ctor->dynshdr = gelf_getshdr(ctor->dynscn, &ctor->dynshdr_mem);
	ctor->dyndata = elf_getdata(ctor->dynscn, NULL);
}

void elfcreator_copy_scn(ElfCreator *ctor, Elf_Scn *scn)
{
	Elf_Scn *newscn;
	Elf_Data *indata, *outdata;
	GElf_Shdr *oldshdr, oldshdr_mem;
	GElf_Shdr *newshdr, newshdr_mem;

	newscn = elf_newscn(ctor->elf);
	newshdr = gelf_getshdr(newscn, &newshdr_mem);

	oldshdr = gelf_getshdr(scn, &oldshdr_mem);

	memmove(newshdr, oldshdr, sizeof(*newshdr));
	gelf_update_shdr(newscn, newshdr);

	indata = NULL;
	while ((indata = elf_getdata(scn, indata)) != NULL) {
		outdata = elf_newdata(newscn);
		*outdata = *indata;
	}
	if (newshdr->sh_type == SHT_DYNAMIC)
		update_dyn_cache(ctor);
}

static GElf_Dyn *get_dyn_by_tag(ElfCreator *ctor, Elf64_Sxword d_tag,
				GElf_Dyn *mem, size_t *idx)
{
	size_t cnt;

	if (!ctor->dyndata)
		return NULL;

	for (cnt = 1; cnt < ctor->dynshdr->sh_size / ctor->dynshdr->sh_entsize;
			cnt++) {
		GElf_Dyn *dyn;

		if ((dyn = gelf_getdyn(ctor->dyndata, cnt, mem)) == NULL)
			break;

		if (dyn->d_tag == d_tag) {
			*idx = cnt;
			return dyn;
		}
	}
	return NULL;
}

static void remove_dyn(ElfCreator *ctor, size_t idx)
{
	size_t cnt;

	for (cnt = idx; cnt < ctor->dynshdr->sh_size/ctor->dynshdr->sh_entsize;
			cnt++) {
		GElf_Dyn *dyn, dyn_mem;

		if (cnt+1 == ctor->dynshdr->sh_size/ctor->dynshdr->sh_entsize) {
			memset(&dyn_mem, '\0', sizeof(dyn_mem));
			gelf_update_dyn(ctor->dyndata, cnt, &dyn_mem);
			break;
		}

		dyn = gelf_getdyn(ctor->dyndata, cnt+1, &dyn_mem);
		gelf_update_dyn(ctor->dyndata, cnt, dyn);
	}
	ctor->dynshdr->sh_size--;
	gelf_update_shdr(ctor->dynscn, ctor->dynshdr);
	update_dyn_cache(ctor);
}

typedef void (*dyn_fixup_fn)(ElfCreator *ctor, Elf64_Sxword d_tag, Elf_Scn *scn);

static void generic_dyn_fixup_fn(ElfCreator *ctor, Elf64_Sxword d_tag, Elf_Scn *scn)
{
	GElf_Shdr *shdr, shdr_mem;
	GElf_Dyn *dyn, dyn_mem;
	size_t idx = 0;

	dyn = get_dyn_by_tag(ctor, d_tag, &dyn_mem, &idx);
	shdr = gelf_getshdr(scn, &shdr_mem);
	if (shdr) {
		dyn->d_un.d_ptr = shdr->sh_addr;
		gelf_update_dyn(ctor->dyndata, idx, dyn);
	} else {
		remove_dyn(ctor, idx);
	}
}

static void rela_dyn_fixup_fn(ElfCreator *ctor, Elf64_Sxword d_tag, Elf_Scn *scn)
{
	GElf_Shdr *shdr, shdr_mem;
	GElf_Dyn *dyn, dyn_mem;
	size_t idx = 0;

	dyn = get_dyn_by_tag(ctor, d_tag, &dyn_mem, &idx);
	shdr = gelf_getshdr(scn, &shdr_mem);
	if (shdr) {
		dyn->d_un.d_ptr = shdr->sh_addr;
		gelf_update_dyn(ctor->dyndata, idx, dyn);
	} else {
		remove_dyn(ctor, idx);
		dyn = get_dyn_by_tag(ctor, DT_RELASZ, &dyn_mem, &idx);
		if (dyn) {
			dyn->d_un.d_val = 0;
			gelf_update_dyn(ctor->dyndata, idx, dyn);
		}
	}
}

static void rel_dyn_fixup_fn(ElfCreator *ctor, Elf64_Sxword d_tag, Elf_Scn *scn)
{
	GElf_Shdr *shdr, shdr_mem;
	GElf_Dyn *dyn, dyn_mem;
	size_t idx = 0;

	dyn = get_dyn_by_tag(ctor, d_tag, &dyn_mem, &idx);
	shdr = gelf_getshdr(scn, &shdr_mem);
	if (shdr) {
		dyn->d_un.d_ptr = shdr->sh_addr;
		gelf_update_dyn(ctor->dyndata, idx, dyn);
	} else {
		remove_dyn(ctor, idx);
		dyn = get_dyn_by_tag(ctor, DT_RELSZ, &dyn_mem, &idx);
		if (dyn) {
			dyn->d_un.d_val = 0;
			gelf_update_dyn(ctor->dyndata, idx, dyn);
		}
	}
}

static void fixup_dynamic(ElfCreator *ctor)
{
	struct {
		Elf64_Sxword d_tag;
		Elf64_Word sh_type;
		dyn_fixup_fn fn;
	} fixups[] = {
		{ DT_HASH, SHT_HASH, NULL },
		{ DT_STRTAB, SHT_STRTAB, NULL },
		{ DT_SYMTAB, SHT_SYMTAB, NULL },
		{ DT_RELA, SHT_RELA, rela_dyn_fixup_fn},
		{ DT_REL, SHT_REL, rel_dyn_fixup_fn},
		{ DT_GNU_HASH, SHT_GNU_HASH, NULL },
		{ DT_NULL, SHT_NULL, NULL }
	};
	int i;

	for (i = 0; fixups[i].d_tag != DT_NULL; i++) {
		Elf_Scn *scn;

		scn = get_scn_by_type(ctor, fixups[i].sh_type);
		if (fixups[i].fn)
			fixups[i].fn(ctor, fixups[i].d_tag, scn);
		else
			generic_dyn_fixup_fn(ctor, fixups[i].d_tag, scn);
	}
}

void elfcreator_end(ElfCreator *ctor)
{
	GElf_Phdr phdr_mem, *phdr;
	int m,n;

	for (m = 0; (phdr = gelf_getphdr(ctor->oldelf, m, &phdr_mem)) != NULL; m++)
		/* XXX this should check if an entry is needed */;

	gelf_newphdr(ctor->elf, m);
	elf_update(ctor->elf, ELF_C_NULL);
	update_dyn_cache(ctor);

	for (n = 0; n < m; n++) {
		/* XXX this should check if an entry is needed */
		phdr = gelf_getphdr(ctor->oldelf, n, &phdr_mem);
		if (ctor->dynshdr && phdr->p_type == PT_DYNAMIC)
			phdr->p_offset = ctor->dynshdr->sh_offset;

		gelf_update_phdr(ctor->elf, n, phdr);
	}

	fixup_dynamic(ctor);

	clear(ctor, 0);
	free(ctor);
}
