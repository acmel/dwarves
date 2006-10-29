#ifndef _PAHOLE_CLASSES_H_
#define _PAHOLE_CLASSES_H_ 1
/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/


#include <stdint.h>

#include "list.h"

struct cu_info {
	unsigned int	 cu;
	uintmax_t	 offset;
};

struct class {
	struct list_head node;
	struct list_head members;
	char		 name[32];
	unsigned long	 size;
	struct cu_info	 id;
	struct cu_info	 type;
	unsigned int	 tag;		/* struct, union, base type, etc */
	uintmax_t	 nr_entries;	/* For arrays */
	const char	 *decl_file;
	unsigned int	 decl_line;
	unsigned short	 nr_holes;
	unsigned short	 padding;
	unsigned short	 inlined;
};

struct class_member {
	struct list_head node;
	char		 name[32];
	struct cu_info	 type;
	unsigned int	 offset;
	unsigned int	 bit_size;
	unsigned int	 bit_offset;
	unsigned short	 hole;		/* If there is a hole before the next
					   one (or the end of the struct) */
};

extern void class__find_holes(struct class *self);
extern void class__print(struct class *self);

extern int	    classes__load(const char *filename);
extern struct class *classes__find_by_name(const char *name);
extern struct class *classes__find_by_id(const struct cu_info *type);
extern void	    classes__print(const unsigned int tag);
extern void	    classes__for_each(int (*iterator)(struct class *class,
						      void *cookie),
				      void *cookie);

#endif /* _PAHOLE_CLASSES_H_ */
