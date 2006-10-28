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
};

struct class_member {
	struct list_head node;
	char		 name[32];
	struct cu_info	 type;
	unsigned int	 offset;
	unsigned int	 bit_size;
	unsigned int	 bit_offset;
};

#endif /* _PAHOLE_CLASSES_H_ */
