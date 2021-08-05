/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright 2009 Red Hat, Inc.
 *
 * Author: Peter Jones <pjones@redhat.com>
 */
#ifndef ELFCREATOR_H
#define ELFCREATOR_H 1

#include <gelf.h>

typedef struct elf_creator ElfCreator;
extern ElfCreator *elfcreator_begin(char *path, Elf *elf);
extern void elfcreator_copy_scn(ElfCreator *ctor, Elf_Scn *scn);
extern void elfcreator_end(ElfCreator *ctor);

#endif /* ELFCREATOR_H */
