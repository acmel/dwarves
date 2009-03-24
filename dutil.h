#ifndef _DUTIL_H_
#define _DUTIL_H_ 1
/*
 * Copyright (C) 2007..2009 Arnaldo Carvalho de Melo <acme@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * Some functions came from the Linux Kernel sources, copyrighted by a
 * cast of dozens, please see the Linux Kernel git history for details.
 */

#include <stdbool.h>
#include <stddef.h>
#include <elf.h>
#include <gelf.h>

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

#ifndef __pure
#define __pure __attribute__ ((pure))
#endif

#define roundup(x,y) ((((x) + ((y) - 1)) / (y)) * (y))

static inline __attribute__((const)) bool is_power_of_2(unsigned long n)
{
        return (n != 0 && ((n & (n - 1)) == 0));
}

/* We need define two variables, argp_program_version_hook and
   argp_program_bug_address, in all programs.  argp.h declares these
   variables as non-const (which is correct in general).  But we can
   do better, it is not going to change.  So we want to move them into
   the .rodata section.  Define macros to do the trick.  */
#define ARGP_PROGRAM_VERSION_HOOK_DEF \
	void (*const apvh) (FILE *, struct argp_state *) \
	__asm ("argp_program_version_hook")
#define ARGP_PROGRAM_BUG_ADDRESS_DEF \
	const char *const apba__ __asm ("argp_program_bug_address")

struct strlist {
	void *entries;
	bool dupstr;
};

struct strlist *strlist__new(bool dupstr);
void strlist__delete(struct strlist *self);

int strlist__load(struct strlist *self, const char *filename);
int strlist__add(struct strlist *self, const char *str);

int strlist__has_entry(const struct strlist *self, const char *entry);

void *zalloc(const size_t size);

Elf_Scn *elf_section_by_name(Elf *elf, GElf_Ehdr *ep,
			     GElf_Shdr *shp, const char *name);

#endif /* _DUTIL_H_ */
