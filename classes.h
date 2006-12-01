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
#include <dwarf.h>

#include "list.h"

struct cus {
	struct list_head cus;
	const char	 *filename;
};

struct cu {
	struct list_head node;
	struct list_head classes;
	struct list_head functions;
	struct list_head variables;
	const char	 *name;
	unsigned int	 id;
	unsigned long	 nr_inline_expansions;
	unsigned long	 size_inline_expansions;
	unsigned int	 nr_functions_changed;
	unsigned int	 nr_structures_changed;
	size_t		 max_len_changed_item;
	size_t		 function_bytes_added;
	size_t		 function_bytes_removed;
};

struct tag {
	struct list_head node;
	uint64_t	 type;
	uint64_t	 id;
	uint16_t	 tag;
	uint16_t	 decl_line;
	const char	 *decl_file;
};

struct class {
	struct tag	 tag;
	struct cu	 *cu;
	struct list_head members;
	const char	 *name;
	uint64_t	 size;
	uint64_t	 nr_entries;	/* For arrays */
	unsigned short	 nr_members;
	unsigned short	 nr_holes;
	unsigned short	 padding;
	unsigned int	 refcnt;
	signed int	 diff;
	struct class	 *class_to_diff;
};

struct class_member {
	struct tag	 tag;
	char		 *name;
	struct class	 *class;
	uint64_t	 offset;
	unsigned int	 bit_size;
	unsigned int	 bit_offset;
	unsigned char	 visited:1;
	unsigned short	 hole;		/* If there is a hole before the next
					   one (or the end of the struct) */
};

struct lexblock {
	struct list_head inline_expansions;
	struct list_head labels;
	struct list_head variables;
	unsigned short	 nr_inline_expansions;
	unsigned short	 nr_labels;
	unsigned short	 nr_variables;
	uint32_t	 size_inline_expansions;
};

struct function {
	struct tag	 tag;
	struct cu	 *cu;
	struct lexblock	 lexblock;
	struct list_head parameters;
	const char	 *name;
	uint64_t	 low_pc;
	uint64_t	 high_pc;
	unsigned short	 nr_parameters;
	unsigned short	 inlined;
	unsigned char	 external:1;
	unsigned char	 unspecified_parameters;
	unsigned int	 refcnt;
	signed int	 diff;
	unsigned int	 cu_total_nr_inline_expansions;
	unsigned long	 cu_total_size_inline_expansions;
	struct class	 *class_to_diff;
};

struct parameter {
	struct tag	 tag;
	char		 *name;
	struct function	 *function;
};

struct variable {
	struct tag	 tag;
	struct cu	 *cu;
	struct list_head cu_node;
	char		 *name;
	uint64_t	 abstract_origin;
};

struct inline_expansion {
	struct tag	 tag;
	struct function	 *function;
	uint32_t	 size;
};

struct label {
	struct tag	 tag;
	char		 *name;
	uint64_t	 low_pc;
};

#define DEFAULT_CACHELINE_SIZE 32

extern void class__find_holes(struct class *self);
extern void class__print(struct class *self);
extern void function__print(const struct function *self, int show_stats,
			    const int show_variables,
			    const int show_inline_expansions);

extern struct cus   *cus__new(const char *filename);
extern int	    cus__load(struct cus *self);
extern struct cu    *cus__find_cu_by_name(const struct cus *self,
					  const char *name);
extern struct class *cu__find_class_by_id(const struct cu *cu,
					  const uint64_t type);
extern struct class *cu__find_class_by_name(const struct cu *cu,
					    const char *name);
extern int	    class__is_struct(const struct class *self,
				     struct class **typedef_alias);
extern void	    cus__print_classes(struct cus *cus,
				       const unsigned int tag);
extern void	    cus__print_functions(struct cus *cus);
extern struct class *cus__find_class_by_name(const struct cus *self,
					     const char *name);
extern void	    cu__account_inline_expansions(struct cu *self);
extern int	    cu__for_each_class(struct cu *cu,
				       int (*iterator)(struct class *class,
						       void *cookie),
				       void *cookie);
extern int	    cu__for_each_function(struct cu *cu,
					  int (*iterator)(struct function *func,
							  void *cookie),
					  void *cookie);
extern void	    cus__for_each_cu(struct cus *self,
				     int (*iterator)(struct cu *cu,
						     void *cookie),
				     void *cookie,
				     struct cu *(*filter)(struct cu *cu));

extern struct function *cu__find_function_by_id(const struct cu *self,
						const uint64_t id);
extern struct function *cu__find_function_by_name(const struct cu *cu,
						  const char *name);

static inline uint32_t function__size(const struct function *self)
{
	return self->high_pc - self->low_pc;
}

static inline int function__declared_inline(const struct function *self)
{
	return (self->inlined == DW_INL_declared_inlined ||
	        self->inlined == DW_INL_declared_not_inlined);
}

static inline int function__inlined(const struct function *self)
{
	return (self->inlined == DW_INL_inlined ||
	        self->inlined == DW_INL_declared_inlined);
}

extern struct class_member *class__find_member_by_name(const struct class *self,
						       const char *name);

extern uint64_t class_member__names(const struct class_member *self,
				    char *class_name,
				    size_t class_name_size,
				    char *member_name,
				    size_t member_name_size);
extern unsigned int cacheline_size;

extern const char *variable__name(const struct variable *self);
extern const char *variable__type_name(const struct variable *self,
				       char *bf, size_t len);

extern const char *dwarf_tag_name(const unsigned int tag);

#endif /* _PAHOLE_CLASSES_H_ */
