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
	struct list_head definitions;
	struct list_head fwd_decls;
};

struct cu {
	struct list_head node;
	struct list_head classes;
	struct list_head functions;
	struct list_head variables;
	struct list_head tool_list;	/* To be used by tools such as ctracer */
	const char	 *name;
	unsigned short	 language;
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
	struct list_head node;
	const char	 *name;
	uint64_t	 size;
	struct {
		uint8_t	 dimensions;
		uint32_t *nr_entries;
	}		 array;
	unsigned short	 nr_members;
	unsigned short	 nr_holes;
	unsigned short	 nr_bit_holes;
	unsigned short	 padding;
	unsigned short	 bit_padding;
	unsigned int	 refcnt;
	signed int	 diff;
	struct class	 *class_to_diff;
	uint8_t		 declaration:1;
	uint8_t		 visited:1;
	uint8_t		 fwd_decl_emitted:1;
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
	unsigned short	 bit_hole;	/* If there is a bit hole before the next
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
	struct list_head tool_node;	/* Node to be used by tools */
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

struct enumerator {
	struct tag	 tag;
	const char	 *name;
	uint32_t	 value;
};

#define DEFAULT_CACHELINE_SIZE 32

extern void class__find_holes(struct class *self);
extern void class__print(const struct class *self,
			 const char *prefix, const char *suffix);
extern void function__print(const struct function *self, int show_stats,
			    const int show_variables,
			    const int show_inline_expansions);

extern struct cus   *cus__new(void);
extern int	    cus__load(struct cus *self, const char *filename);
extern struct cu    *cus__find_cu_by_name(const struct cus *self,
					  const char *name);
extern struct function *cus__find_function_by_name(const struct cus *self,
						   const char *name);
extern int cus__emit_function_definitions(struct cus *self,
					  struct function *function);
extern int cus__emit_struct_definitions(struct cus *self, struct class *class,
					const char *prefix,
					const char *suffix);
extern int cus__emit_fwd_decl(struct cus *self, struct class *class);

extern struct class *cu__find_class_by_id(const struct cu *cu,
					  const uint64_t type);
extern struct class *cu__find_class_by_name(const struct cu *cu,
					    const char *name);
extern int	    class__is_struct(const struct class *self,
				     struct class **typedef_alias);
extern struct class *cus__find_class_by_name(const struct cus *self,
					     const char *name);
extern void	    cu__account_inline_expansions(struct cu *self);
extern int	    cu__for_each_class(struct cu *self,
				       int (*iterator)(struct class *class,
						       void *cookie),
				       void *cookie,
				 struct class *(*filter)(struct class *class));
extern int	    cu__for_each_function(struct cu *cu,
					  int (*iterator)(struct function *func,
							  void *cookie),
					  void *cookie,
			struct function *(*filter)(struct function *function,
						   void *cookie));
extern void	    cus__for_each_cu(struct cus *self,
				     int (*iterator)(struct cu *cu,
						     void *cookie),
				     void *cookie,
				     struct cu *(*filter)(struct cu *cu));

extern const struct class_member *
		class__find_bit_hole(const struct class *self,
				     const struct class_member *trailer,
				     const size_t bit_hole_size);

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

extern int function__has_parameter_of_type(const struct function *self,
					   const struct class *target);

extern const char *class__name(const struct class *self, char *bf, size_t len);

extern struct class_member *class__find_member_by_name(const struct class *self,
						       const char *name);

extern uint64_t class_member__names(const struct class *type,
				    const struct class_member *self,
				    char *class_name,
				    size_t class_name_size,
				    char *member_name,
				    size_t member_name_size);
extern unsigned int cacheline_size;

extern const char *variable__name(const struct variable *self);
extern const char *variable__type_name(const struct variable *self,
				       char *bf, size_t len);

extern const char *dwarf_tag_name(const unsigned int tag);

extern int tag__fwd_decl(const struct cu *cu, const struct tag *tag);

extern size_t parameter__names(const struct parameter *self,
			       char *class_name, size_t class_name_size,
			       char *parameter_name,
			       size_t parameter_name_size);

#endif /* _PAHOLE_CLASSES_H_ */
