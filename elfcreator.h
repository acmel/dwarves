/*
 * Copyright 2009 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * Author: Peter Jones <pjones@redhat.com>
 */
#ifndef ELFCREATOR_H
#define ELFCREATOR_H 1

#include <gelf.h>

typedef struct elf_creator ElfCreator;
extern ElfCreator *elfcreator_begin(char *path, Elf *elf);
extern void elfcreator_copy_scn(ElfCreator *ctor, Elf *src, Elf_Scn *scn);
extern void elfcreator_end(ElfCreator *ctor);

#endif /* ELFCREATOR_H */
