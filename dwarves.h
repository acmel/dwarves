#ifndef _DWARVES_H_
#define _DWARVES_H_ 1
/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006..2009 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/


#include <stdint.h>
#include <stdio.h>
#include <obstack.h>
#include <dwarf.h>
#include <elfutils/libdwfl.h>

#include "dutil.h"
#include "list.h"
#include "rbtree.h"
#include "strings.h"

struct cu;

enum load_steal_kind {
	LSK__KEEPIT,
	LSK__DELETE,
	LSK__STOP_LOADING,
};

/** struct conf_load - load configuration
 * @extra_dbg_info - keep original debugging format extra info
 *		     (e.g. DWARF's decl_{line,file}, id, etc)
 * @fixup_silly_bitfields - Fixup silly things such as "int foo:32;"
 * @get_addr_info - wheter to load DW_AT_location and other addr info
 */
struct conf_load {
	enum load_steal_kind	(*steal)(struct cu *self,
					 struct conf_load *conf);
	void			*cookie;
	char			*format_path;
	bool			extra_dbg_info;
	bool			fixup_silly_bitfields;
	bool			get_addr_info;
};

/** struct conf_fprintf - hints to the __fprintf routines
 *
 * @flat_arrays - a->foo[10][2] becomes a->foo[20]
 * @classes_as_structs - class f becomes struct f, CTF doesn't have a "class"
 */
struct conf_fprintf {
	const char *prefix;
	const char *suffix;
	int32_t	   type_spacing;
	int32_t	   name_spacing;
	uint32_t   base_offset;
	uint8_t	   indent;
	uint8_t	   expand_types:1;
	uint8_t	   expand_pointers:1;
	uint8_t    rel_offset:1;
	uint8_t	   emit_stats:1;
	uint8_t	   suppress_comments:1;
	uint8_t	   suppress_offset_comment:1;
	uint8_t	   show_decl_info:1;
	uint8_t	   show_only_data_members:1;
	uint8_t	   no_semicolon:1;
	uint8_t	   show_first_biggest_size_base_type_member:1;
	uint8_t	   flat_arrays:1;
	uint8_t	   no_parm_names:1;
	uint8_t	   classes_as_structs:1;
	uint8_t	   hex_fmt:1;
};

struct cus {
	struct list_head      cus;
};

struct cus *cus__new(void);
void cus__delete(struct cus *self);

int cus__load_file(struct cus *self, struct conf_load *conf,
		   const char *filename);
int cus__load_files(struct cus *self, struct conf_load *conf,
		    char *filenames[]);
int cus__load_dir(struct cus *self, struct conf_load *conf,
		  const char *dirname, const char *filename_mask,
		  const int recursive);
void cus__add(struct cus *self, struct cu *cu);
void cus__print_error_msg(const char *progname, const struct cus *cus,
			  const char *filename, const int err);
struct cu *cus__find_cu_by_name(const struct cus *self, const char *name);
struct tag *cus__find_struct_by_name(const struct cus *self, struct cu **cu,
				     const char *name, const int include_decls,
				     uint16_t *id);
struct function *cus__find_function_at_addr(const struct cus *self,
					    uint64_t addr, struct cu **cu);
void cus__for_each_cu(struct cus *self, int (*iterator)(struct cu *cu,
							void *cookie),
		      void *cookie,
		      struct cu *(*filter)(struct cu *cu));

struct ptr_table {
	void	 **entries;
	uint32_t nr_entries;
	uint32_t allocated_entries;
};

struct function;
struct tag;
struct cu;
struct variable;

/* Same as DW_LANG, so that we don't have to include dwarf.h in CTF */
enum dwarf_languages {
    LANG_C89		= 0x01,	/* ISO C:1989 */
    LANG_C		= 0x02,	/* C */
    LANG_Ada83		= 0x03,	/* ISO Ada:1983 */
    LANG_C_plus_plus	= 0x04,	/* ISO C++:1998 */
    LANG_Cobol74	= 0x05,	/* ISO Cobol:1974 */
    LANG_Cobol85	= 0x06,	/* ISO Cobol:1985 */
    LANG_Fortran77	= 0x07,	/* ISO FORTRAN 77 */
    LANG_Fortran90	= 0x08,	/* ISO Fortran 90 */
    LANG_Pascal83	= 0x09,	/* ISO Pascal:1983 */
    LANG_Modula2	= 0x0a,	/* ISO Modula-2:1996 */
    LANG_Java		= 0x0b,	/* Java */
    LANG_C99		= 0x0c,	/* ISO C:1999 */
    LANG_Ada95		= 0x0d,	/* ISO Ada:1995 */
    LANG_Fortran95	= 0x0e,	/* ISO Fortran 95 */
    LANG_PL1		= 0x0f,	/* ISO PL/1:1976 */
    LANG_Objc		= 0x10,	/* Objective-C */
    LANG_ObjC_plus_plus	= 0x11,	/* Objective-C++ */
    LANG_UPC		= 0x12,	/* Unified Parallel C */
    LANG_D		= 0x13,	/* D */
};

/** struct debug_fmt_ops - specific to the underlying debug file format
 *
 * @function__name - will be called by function__name(), giving a chance to
 *		     formats such as CTF to get this from some other place
 *		     than the global strings table. CTF does this by storing
 * 		     GElf_Sym->st_name in function->name, and by using
 *		     function->name as an index into the .strtab ELF section.
 * @variable__name - will be called by variable__name(), see @function_name
 * cu__delete - called at cu__delete(), to give a chance to formats such as
 *		CTF to keep the .strstab ELF section available till the cu is
 *		deleted. See @function__name
 */
struct debug_fmt_ops {
	const char	   *name;
	int		   (*init)(void);
	void		   (*exit)(void);
	int		   (*load_file)(struct cus *self,
				       struct conf_load *conf,
				       const char *filename);
	const char	   *(*tag__decl_file)(const struct tag *self,
					      const struct cu *cu);
	uint32_t	   (*tag__decl_line)(const struct tag *self,
					     const struct cu *cu);
	unsigned long long (*tag__orig_id)(const struct tag *self,
					   const struct cu *cu);
	void		   (*tag__free_orig_info)(struct tag *self,
						  struct cu *cu);
	const char	   *(*function__name)(struct function *self,
					      const struct cu *cu);
	const char	   *(*variable__name)(const struct variable *self,
					      const struct cu *cu);
	const char	   *(*strings__ptr)(const struct cu *self, strings_t s);
	void		   (*cu__delete)(struct cu *self);
};

struct cu {
	struct list_head node;
	struct list_head tags;
	struct list_head tool_list;	/* To be used by tools such as ctracer */
	struct ptr_table types_table;
	struct ptr_table functions_table;
	struct ptr_table tags_table;
	struct rb_root	 functions;
	char		 *name;
	char		 *filename;
	void 		 *priv;
	struct obstack	 obstack;
	struct debug_fmt_ops *dfops;
	Elf		 *elf;
	Dwfl_Module	 *dwfl;
	uint32_t	 cached_symtab_nr_entries;
	uint8_t		 addr_size;
	uint8_t		 extra_dbg_info:1;
	uint8_t		 has_addr_info:1;
	uint8_t		 uses_global_strings:1;
	uint16_t	 language;
	unsigned long	 nr_inline_expansions;
	size_t		 size_inline_expansions;
	uint32_t	 nr_functions_changed;
	uint32_t	 nr_structures_changed;
	size_t		 max_len_changed_item;
	size_t		 function_bytes_added;
	size_t		 function_bytes_removed;
	int		 build_id_len;
	unsigned char	 build_id[0];
};

struct cu *cu__new(const char *name, uint8_t addr_size,
		   const unsigned char *build_id, int build_id_len,
		   const char *filename);
void cu__delete(struct cu *self);

const char *cu__string(const struct cu *self, strings_t s);

static inline int cu__cache_symtab(struct cu *self)
{
	int err = dwfl_module_getsymtab(self->dwfl);
	if (err > 0)
		self->cached_symtab_nr_entries = dwfl_module_getsymtab(self->dwfl);
	return err;
}

static inline __pure bool cu__is_c_plus_plus(const struct cu *self)
{
	return self->language == LANG_C_plus_plus;
}

/**
 * cu__for_each_cached_symtab_entry - iterate thru the cached symtab entries
 * @cu: struct cu instance
 * @id: uint32_t tag id
 * @pos: struct GElf_Sym iterator
 * @name: char pointer where the symbol_name will be stored
 */
#define cu__for_each_cached_symtab_entry(cu, id, pos, name)	  \
	for (id = 1,						  \
	     name = dwfl_module_getsym(cu->dwfl, id, &sym, NULL); \
	     id < cu->cached_symtab_nr_entries;						  \
	     ++id, name = dwfl_module_getsym(cu->dwfl, id, &sym, NULL))

/**
 * cu__for_each_type - iterate thru all the type tags
 * @cu: struct cu instance to iterate
 * @id: uint16_t tag id
 * @pos: struct tag iterator
 *
 * See cu__table_nullify_type_entry and users for the reason for
 * the NULL test (hint: CTF Unknown types)
 */
#define cu__for_each_type(cu, id, pos)				\
	for (id = 1; id < cu->types_table.nr_entries; ++id)	\
		if (!(pos = cu->types_table.entries[id]))	\
			continue;				\
		else

/**
 * cu__for_each_struct - iterate thru all the struct tags
 * @cu: struct cu instance to iterate
 * @pos: struct class iterator
 * @id: uint16_t tag id
 */
#define cu__for_each_struct(cu, id, pos)				\
	for (id = 1; id < cu->types_table.nr_entries; ++id)		\
		if (!(pos = tag__class(cu->types_table.entries[id])) || \
		    !tag__is_struct(class__tag(pos)))			\
			continue;					\
		else

/**
 * cu__for_each_function - iterate thru all the function tags
 * @cu: struct cu instance to iterate
 * @pos: struct function iterator
 * @id: uint32_t tag id
 */
#define cu__for_each_function(cu, id, pos)				     \
	for (id = 0; id < cu->functions_table.nr_entries; ++id)		     \
		if (!(pos = tag__function(cu->functions_table.entries[id]))) \
			continue;					     \
		else

/**
 * cu__for_each_variable - iterate thru all the global variable tags
 * @cu: struct cu instance to iterate
 * @pos: struct tag iterator
 * @id: uint32_t tag id
 */
#define cu__for_each_variable(cu, id, pos)		\
	for (id = 0; id < cu->tags_table.nr_entries; ++id) \
		if (!(pos = cu->tags_table.entries[id]) || \
		    !tag__is_variable(pos))		\
			continue;			\
		else

int cu__add_tag(struct cu *self, struct tag *tag, long *id);
int cu__table_add_tag(struct cu *self, struct tag *tag, long *id);
int cu__table_nullify_type_entry(struct cu *self, uint32_t id);
struct tag *cu__find_base_type_by_name(const struct cu *self, const char *name,
				       uint16_t *id);
struct tag *cu__find_base_type_by_sname_and_size(const struct cu *self,
						 strings_t name,
						 uint16_t bit_size,
						 uint16_t *idp);
struct tag *cu__find_enumeration_by_sname_and_size(const struct cu *self,
						   strings_t sname,
						   uint16_t bit_size,
						   uint16_t *idp);
struct tag *cu__find_first_typedef_of_type(const struct cu *self,
					   const uint16_t type);
struct tag *cu__find_function_by_name(const struct cu *cu, const char *name);
struct tag *cu__find_struct_by_sname(const struct cu *self, strings_t sname,
				     const int include_decls, uint16_t *idp);
struct function *cu__find_function_at_addr(const struct cu *self,
					   uint64_t addr);
struct tag *cu__function(const struct cu *self, const uint32_t id);
struct tag *cu__tag(const struct cu *self, const uint32_t id);
struct tag *cu__type(const struct cu *self, const uint16_t id);
struct tag *cu__find_struct_by_name(const struct cu *cu, const char *name,
				    const int include_decls, uint16_t *id);
bool cu__same_build_id(const struct cu *self, const struct cu *other);
void cu__account_inline_expansions(struct cu *self);
int cu__for_all_tags(struct cu *self,
		     int (*iterator)(struct tag *tag,
				     struct cu *cu, void *cookie),
		     void *cookie);

/** struct tag - basic representation of a debug info element
 * @priv - extra data, for instance, DWARF offset, id, decl_{file,line}
 * @top_level -
 */
struct tag {
	struct list_head node;
	uint16_t	 type;
	uint16_t	 tag;
	bool		 visited;
	bool		 top_level;
	uint16_t	 recursivity_level;
	void		 *priv;
};

void tag__delete(struct tag *self, struct cu *cu);

static inline int tag__is_enumeration(const struct tag *self)
{
	return self->tag == DW_TAG_enumeration_type;
}

static inline int tag__is_namespace(const struct tag *self)
{
	return self->tag == DW_TAG_namespace;
}

static inline int tag__is_struct(const struct tag *self)
{
	return self->tag == DW_TAG_structure_type ||
	       self->tag == DW_TAG_interface_type ||
	       self->tag == DW_TAG_class_type;
}

static inline int tag__is_typedef(const struct tag *self)
{
	return self->tag == DW_TAG_typedef;
}

static inline int tag__is_union(const struct tag *self)
{
	return self->tag == DW_TAG_union_type;
}

static inline int tag__is_const(const struct tag *self)
{
	return self->tag == DW_TAG_const_type;
}

static inline bool tag__is_variable(const struct tag *self)
{
	return self->tag == DW_TAG_variable;
}

static inline bool tag__is_volatile(const struct tag *self)
{
	return self->tag == DW_TAG_volatile_type;
}

static inline bool tag__has_namespace(const struct tag *self)
{
	return tag__is_struct(self) ||
	       tag__is_union(self) ||
	       tag__is_namespace(self) ||
	       tag__is_enumeration(self);
}

/**
 * tag__is_tag_type - is this tag derived from the 'type' class?
 * @tag - tag queried
 */
static inline int tag__is_type(const struct tag *self)
{
	return tag__is_union(self)   ||
	       tag__is_struct(self)  ||
	       tag__is_typedef(self) ||
	       tag__is_enumeration(self);
}

/**
 * tag__is_tag_type - is this one of the possible types for a tag?
 * @tag - tag queried
 */
static inline int tag__is_tag_type(const struct tag *self)
{
	return tag__is_type(self) ||
	       self->tag == DW_TAG_array_type ||
	       self->tag == DW_TAG_base_type ||
	       self->tag == DW_TAG_const_type ||
	       self->tag == DW_TAG_pointer_type ||
	       self->tag == DW_TAG_ptr_to_member_type ||
	       self->tag == DW_TAG_reference_type ||
	       self->tag == DW_TAG_subroutine_type ||
	       self->tag == DW_TAG_volatile_type;
}

static inline const char *tag__decl_file(const struct tag *self,
					 const struct cu *cu)
{
	if (cu->dfops && cu->dfops->tag__decl_file)
		return cu->dfops->tag__decl_file(self, cu);
	return NULL;
}

static inline uint32_t tag__decl_line(const struct tag *self,
				      const struct cu *cu)
{
	if (cu->dfops && cu->dfops->tag__decl_line)
		return cu->dfops->tag__decl_line(self, cu);
	return 0;
}

static inline unsigned long long tag__orig_id(const struct tag *self,
					      const struct cu *cu)
{
	if (cu->dfops && cu->dfops->tag__orig_id)
		return cu->dfops->tag__orig_id(self, cu);
	return 0;
}

static inline void tag__free_orig_info(struct tag *self, struct cu *cu)
{
	if (cu->dfops && cu->dfops->tag__free_orig_info)
		cu->dfops->tag__free_orig_info(self, cu);
}

size_t tag__fprintf_decl_info(const struct tag *self,
			      const struct cu *cu, FILE *fp);
size_t tag__fprintf(struct tag *self, const struct cu *cu,
		    const struct conf_fprintf *conf, FILE *fp);

const char *tag__name(const struct tag *self, const struct cu *cu,
		      char *bf, size_t len, const struct conf_fprintf *conf);
void tag__not_found_die(const char *file, int line, const char *func);

#define tag__assert_search_result(tag) \
	do { if (!tag) tag__not_found_die(__FILE__,\
					  __LINE__, __func__); } while (0)

size_t tag__size(const struct tag *self, const struct cu *cu);
size_t tag__nr_cachelines(const struct tag *self, const struct cu *cu);
struct tag *tag__follow_typedef(const struct tag *tag, const struct cu *cu);

size_t __tag__id_not_found_fprintf(FILE *fp, uint16_t id,
				   const char *fn, int line);
#define tag__id_not_found_fprintf(fp, id) \
	__tag__id_not_found_fprintf(fp, id, __func__, __LINE__)

int __tag__has_type_loop(const struct tag *self, const struct tag *type,
			 char *bf, size_t len, FILE *fp,
			 const char *fn, int line);
#define tag__has_type_loop(self, type, bf, len, fp) \
	__tag__has_type_loop(self, type, bf, len, fp, __func__, __LINE__)

struct ptr_to_member_type {
	struct tag tag;
	uint16_t   containing_type;
};

static inline struct ptr_to_member_type *
		tag__ptr_to_member_type(const struct tag *self)
{
	return (struct ptr_to_member_type *)self;
}

/** struct namespace - base class for enums, structs, unions, typedefs, etc
 *
 * @sname - for clones, for instance, where we can't always add a new string
 * @tags - class_member, enumerators, etc
 * @shared_tags: if this bit is set, don't free the entries in @tags
 */
struct namespace {
	struct tag	 tag;
	strings_t	 name;
	uint16_t	 nr_tags;
	uint8_t		 shared_tags;
	char *		 sname;
	struct list_head tags;
};

static inline struct namespace *tag__namespace(const struct tag *self)
{
	return (struct namespace *)self;
}

void namespace__delete(struct namespace *self, struct cu *cu);

/**
 * namespace__for_each_tag - iterate thru all the tags
 * @self: struct namespace instance to iterate
 * @pos: struct tag iterator
 */
#define namespace__for_each_tag(self, pos) \
	list_for_each_entry(pos, &(self)->tags, node)

/**
 * namespace__for_each_tag_safe_reverse - safely iterate thru all the tags, in reverse order
 * @self: struct namespace instance to iterate
 * @pos: struct tag iterator
 * @n: struct class_member temp iterator
 */
#define namespace__for_each_tag_safe_reverse(self, pos, n) \
	list_for_each_entry_safe_reverse(pos, n, &(self)->tags, node)

void namespace__add_tag(struct namespace *self, struct tag *tag);

struct ip_tag {
	struct tag tag;
	uint64_t   addr;
};

struct inline_expansion {
	struct ip_tag	 ip;
	size_t		 size;
	uint64_t	 high_pc;
};

static inline struct inline_expansion *
				tag__inline_expansion(const struct tag *self)
{
	return (struct inline_expansion *)self;
}

struct label {
	struct ip_tag	 ip;
	strings_t	 name;
};

static inline struct label *tag__label(const struct tag *self)
{
	return (struct label *)self;
}

static inline const char *label__name(const struct label *self,
				      const struct cu *cu)
{
	return cu__string(cu, self->name);
}

enum vlocation {
	LOCATION_UNKNOWN,
	LOCATION_LOCAL,
	LOCATION_GLOBAL,
	LOCATION_REGISTER,
	LOCATION_OPTIMIZED
} __attribute__((packed));

struct variable {
	struct ip_tag	 ip;
	strings_t	 name;
	uint8_t		 external:1;
	uint8_t		 declaration:1;
	enum vlocation	 location;
	struct hlist_node tool_hnode;
};

static inline struct variable *tag__variable(const struct tag *self)
{
	return (struct variable *)self;
}

const char *variable__name(const struct variable *self, const struct cu *cu);

const char *variable__type_name(const struct variable *self,
				const struct cu *cu, char *bf, size_t len);

struct lexblock {
	struct ip_tag	 ip;
	struct list_head tags;
	uint32_t	 size;
	uint16_t	 nr_inline_expansions;
	uint16_t	 nr_labels;
	uint16_t	 nr_variables;
	uint16_t	 nr_lexblocks;
	uint32_t	 size_inline_expansions;
};

static inline struct lexblock *tag__lexblock(const struct tag *self)
{
	return (struct lexblock *)self;
}

void lexblock__delete(struct lexblock *self, struct cu *cu);

struct function;

void lexblock__add_inline_expansion(struct lexblock *self,
				    struct inline_expansion *exp);
void lexblock__add_label(struct lexblock *self, struct label *label);
void lexblock__add_lexblock(struct lexblock *self, struct lexblock *child);
void lexblock__add_tag(struct lexblock *self, struct tag *tag);
void lexblock__add_variable(struct lexblock *self, struct variable *var);
size_t lexblock__fprintf(const struct lexblock *self, const struct cu *cu,
			 struct function *function, uint16_t indent,
			 const struct conf_fprintf *conf, FILE *fp);

struct parameter {
	struct tag	 tag;
	strings_t	 name;
};

static inline struct parameter *tag__parameter(const struct tag *self)
{
	return (struct parameter *)self;
}

static inline const char *parameter__name(const struct parameter *self,
					  const struct cu *cu)
{
	return cu__string(cu, self->name);
}

/*
 * tag.tag can be DW_TAG_subprogram_type or DW_TAG_subroutine_type.
 */
struct ftype {
	struct tag	 tag;
	struct list_head parms;
	uint16_t	 nr_parms;
	uint8_t		 unspec_parms; /* just one bit is needed */
};

static inline struct ftype *tag__ftype(const struct tag *self)
{
	return (struct ftype *)self;
}

void ftype__delete(struct ftype *self, struct cu *cu);

/**
 * ftype__for_each_parameter - iterate thru all the parameters
 * @self: struct ftype instance to iterate
 * @pos: struct parameter iterator
 */
#define ftype__for_each_parameter(self, pos) \
	list_for_each_entry(pos, &(self)->parms, tag.node)

/**
 * ftype__for_each_parameter_safe - safely iterate thru all the parameters
 * @self: struct ftype instance to iterate
 * @pos: struct parameter iterator
 * @n: struct parameter temp iterator
 */
#define ftype__for_each_parameter_safe(self, pos, n) \
	list_for_each_entry_safe(pos, n, &(self)->parms, tag.node)

/**
 * ftype__for_each_parameter_safe_reverse - safely iterate thru all the parameters, in reverse order
 * @self: struct ftype instance to iterate
 * @pos: struct parameter iterator
 * @n: struct parameter temp iterator
 */
#define ftype__for_each_parameter_safe_reverse(self, pos, n) \
	list_for_each_entry_safe_reverse(pos, n, &(self)->parms, tag.node)

void ftype__add_parameter(struct ftype *self, struct parameter *parm);
size_t ftype__fprintf(const struct ftype *self, const struct cu *cu,
		      const char *name, const int inlined,
		      const int is_pointer, const int type_spacing,
		      const struct conf_fprintf *conf, FILE *fp);
size_t ftype__fprintf_parms(const struct ftype *self,
			    const struct cu *cu, int indent,
			    const struct conf_fprintf *conf, FILE *fp);
int ftype__has_parm_of_type(const struct ftype *self, const uint16_t target,
			    const struct cu *cu);

struct function {
	struct ftype	 proto;
	struct lexblock	 lexblock;
	struct rb_node	 rb_node;
	strings_t	 name;
	strings_t	 linkage_name;
	uint32_t	 cu_total_size_inline_expansions;
	uint16_t	 cu_total_nr_inline_expansions;
	uint8_t		 inlined:2;
	uint8_t		 abstract_origin:1;
	uint8_t		 external:1;
	uint8_t		 accessibility:2; /* DW_ACCESS_{public,protected,private} */
	uint8_t		 virtuality:2; /* DW_VIRTUALITY_{none,virtual,pure_virtual} */
	int32_t		 vtable_entry;
	struct list_head vtable_node;
	/* fields used by tools */
	union {
		struct list_head  tool_node;
		struct hlist_node tool_hnode;
	};
	void		 *priv;
};

static inline struct function *tag__function(const struct tag *self)
{
	return (struct function *)self;
}

static inline struct tag *function__tag(const struct function *self)
{
	return (struct tag *)self;
}

void function__delete(struct function *self, struct cu *cu);

static __pure inline int tag__is_function(const struct tag *self)
{
	return self->tag == DW_TAG_subprogram;
}

/**
 * function__for_each_parameter - iterate thru all the parameters
 * @self: struct function instance to iterate
 * @pos: struct parameter iterator
 */
#define function__for_each_parameter(self, pos) \
	ftype__for_each_parameter(&self->proto, pos)

const char *function__name(struct function *self, const struct cu *cu);

static inline const char *function__linkage_name(const struct function *self,
						 const struct cu *cu)
{
	return cu__string(cu, self->linkage_name);
}

size_t function__fprintf_stats(const struct tag *tag_self,
			       const struct cu *cu,
			       const struct conf_fprintf *conf,
			       FILE *fp);
const char *function__prototype(const struct function *self,
				const struct cu *cu, char *bf, size_t len);

static __pure inline uint64_t function__addr(const struct function *self)
{
	return self->lexblock.ip.addr;
}

static __pure inline uint32_t function__size(const struct function *self)
{
	return self->lexblock.size;
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

/* struct class_member - struct, union, class member
 *
 * @bit_offset - offset in bits from the start of the struct
 * @bit_size - cached bit size, can be smaller than the integral type if in a bitfield
 * @byte_offset - offset in bytes from the start of the struct
 * @byte_size - cached byte size, integral type byte size for bitfields
 * @bitfield_offset - offset in the current bitfield
 * @bitfield_offset - size in the current bitfield
 * @bit_hole - If there is a bit hole before the next one (or the end of the struct)
 * @bitfield_end - Is this the last entry in a bitfield?
 * @accessibility - DW_ACCESS_{public,protected,private}
 * @virtuality - DW_VIRTUALITY_{none,virtual,pure_virtual}
 * @hole - If there is a hole before the next one (or the end of the struct)
 */
struct class_member {
	struct tag	 tag;
	strings_t	 name;
	uint32_t	 bit_offset;
	uint32_t	 bit_size;
	uint32_t	 byte_offset;
	size_t		 byte_size;
	uint8_t		 bitfield_offset;
	uint8_t		 bitfield_size;
	uint8_t		 bit_hole;
	uint8_t		 bitfield_end:1;
	uint8_t		 visited:1;
	uint8_t		 accessibility:2;
	uint8_t		 virtuality:2;
	uint16_t	 hole;
};

void class_member__delete(struct class_member *self, struct cu *cu);

static inline struct class_member *tag__class_member(const struct tag *self)
{
	return (struct class_member *)self;
}

static inline const char *class_member__name(const struct class_member *self,
					     const struct cu *cu)
{
	return cu__string(cu, self->name);
}

static __pure inline int tag__is_class_member(const struct tag *self)
{
	return self->tag == DW_TAG_member;
}

/**
 * struct type - base type for enumerations, structs and unions
 *
 * @nr_members: number of DW_TAG_member entries
 * @nr_tags: number of tags
 */
struct type {
	struct namespace namespace;
	struct list_head node;
	uint32_t	 size;
	int32_t		 size_diff;
	uint16_t	 nr_members;
	uint8_t		 declaration; /* only one bit used */
	uint8_t		 definition_emitted:1;
	uint8_t		 fwd_decl_emitted:1;
	uint8_t		 resized:1;
};

static inline struct class *type__class(const struct type *self)
{
	return (struct class *)self;
}

void type__delete(struct type *self, struct cu *cu);

/**
 * type__for_each_tag - iterate thru all the tags
 * @self: struct type instance to iterate
 * @pos: struct tag iterator
 */
#define type__for_each_tag(self, pos) \
	list_for_each_entry(pos, &(self)->namespace.tags, node)

/**
 * type__for_each_enumerator - iterate thru the enumerator entries
 * @self: struct type instance to iterate
 * @pos: struct enumerator iterator
 */
#define type__for_each_enumerator(self, pos) \
	struct list_head *__type__for_each_enumerator_head = \
		(self)->namespace.shared_tags ? \
			(self)->namespace.tags.next : \
			&(self)->namespace.tags; \
	list_for_each_entry(pos, __type__for_each_enumerator_head, tag.node)

/**
 * type__for_each_enumerator_safe_reverse - safely iterate thru the enumerator entries, in reverse order
 * @self: struct type instance to iterate
 * @pos: struct enumerator iterator
 * @n: struct enumerator temp iterator
 */
#define type__for_each_enumerator_safe_reverse(self, pos, n)		   \
	if ((self)->namespace.shared_tags) /* Do nothing */ ; else \
	list_for_each_entry_safe_reverse(pos, n, &(self)->namespace.tags, tag.node)

/**
 * type__for_each_member - iterate thru the entries that use space
 *                         (data members and inheritance entries)
 * @self: struct type instance to iterate
 * @pos: struct class_member iterator
 */
#define type__for_each_member(self, pos) \
	list_for_each_entry(pos, &(self)->namespace.tags, tag.node) \
		if (!(pos->tag.tag == DW_TAG_member || \
		      pos->tag.tag == DW_TAG_inheritance)) \
			continue; \
		else

/**
 * type__for_each_data_member - iterate thru the data member entries
 * @self: struct type instance to iterate
 * @pos: struct class_member iterator
 */
#define type__for_each_data_member(self, pos) \
	list_for_each_entry(pos, &(self)->namespace.tags, tag.node) \
		if (pos->tag.tag != DW_TAG_member) \
			continue; \
		else

/**
 * type__for_each_member_safe - safely iterate thru the entries that use space
 *                              (data members and inheritance entries)
 * @self: struct type instance to iterate
 * @pos: struct class_member iterator
 * @n: struct class_member temp iterator
 */
#define type__for_each_member_safe(self, pos, n) \
	list_for_each_entry_safe(pos, n, &(self)->namespace.tags, tag.node) \
		if (pos->tag.tag != DW_TAG_member) \
			continue; \
		else

/**
 * type__for_each_data_member_safe - safely iterate thru the data member entries
 * @self: struct type instance to iterate
 * @pos: struct class_member iterator
 * @n: struct class_member temp iterator
 */
#define type__for_each_data_member_safe(self, pos, n) \
	list_for_each_entry_safe(pos, n, &(self)->namespace.tags, tag.node) \
		if (pos->tag.tag != DW_TAG_member) \
			continue; \
		else

/**
 * type__for_each_tag_safe_reverse - safely iterate thru all tags in a type, in reverse order
 * @self: struct type instance to iterate
 * @pos: struct class_member iterator
 * @n: struct class_member temp iterator
 */
#define type__for_each_tag_safe_reverse(self, pos, n) \
	list_for_each_entry_safe_reverse(pos, n, &(self)->namespace.tags, tag.node)

void type__add_member(struct type *self, struct class_member *member);
struct class_member *
	type__find_first_biggest_size_base_type_member(struct type *self,
						       const struct cu *cu);

struct class_member *type__find_member_by_name(const struct type *self,
					       const struct cu *cu,
					       const char *name);
uint32_t type__nr_members_of_type(const struct type *self, const uint16_t type);
struct class_member *type__last_member(struct type *self);

size_t typedef__fprintf(const struct tag *tag_self, const struct cu *cu,
			const struct conf_fprintf *conf, FILE *fp);

static inline struct type *tag__type(const struct tag *self)
{
	return (struct type *)self;
}

struct class {
	struct type	 type;
	struct list_head vtable;
	uint16_t	 nr_vtable_entries;
	uint8_t		 nr_holes;
	uint8_t		 nr_bit_holes;
	uint16_t	 padding;
	uint8_t		 bit_padding;
	void		 *priv;
};

static inline struct class *tag__class(const struct tag *self)
{
	return (struct class *)self;
}

static inline struct tag *class__tag(const struct class *self)
{
	return (struct tag *)self;
}

struct class *class__clone(const struct class *from,
			   const char *new_class_name, struct cu *cu);
void class__delete(struct class *self, struct cu *cu);

static inline struct list_head *class__tags(struct class *self)
{
	return &self->type.namespace.tags;
}

static __pure inline const char *namespace__name(const struct namespace *self,
						 const struct cu *cu)
{
	return self->sname ?: cu__string(cu, self->name);
}

static __pure inline const char *type__name(const struct type *self,
					    const struct cu *cu)
{
	return namespace__name(&self->namespace, cu);
}

static __pure inline const char *class__name(struct class *self,
					     const struct cu *cu)
{
	return type__name(&self->type, cu);
}

static inline int class__is_struct(const struct class *self)
{
	return tag__is_struct(&self->type.namespace.tag);
}

void class__find_holes(struct class *self);
int class__has_hole_ge(const struct class *self, const uint16_t size);
size_t class__fprintf(struct class *self, const struct cu *cu,
		      const struct conf_fprintf *conf, FILE *fp);

void class__add_vtable_entry(struct class *self, struct function *vtable_entry);
static inline struct class_member *
	class__find_member_by_name(const struct class *self,
				   const struct cu *cu, const char *name)
{
	return type__find_member_by_name(&self->type, cu, name);
}

static inline uint16_t class__nr_members(const struct class *self)
{
	return self->type.nr_members;
}

static inline uint32_t class__size(const struct class *self)
{
	return self->type.size;
}

static inline int class__is_declaration(const struct class *self)
{
	return self->type.declaration;
}

const struct class_member *class__find_bit_hole(const struct class *self,
					   const struct class_member *trailer,
						const uint16_t bit_hole_size);

enum base_type_float_type {
	BT_FP_SINGLE = 1,
	BT_FP_DOUBLE,
	BT_FP_CMPLX,
	BT_FP_CMPLX_DBL,
	BT_FP_CMPLX_LDBL,
	BT_FP_LDBL,
	BT_FP_INTVL,
	BT_FP_INTVL_DBL,
	BT_FP_INTVL_LDBL,
	BT_FP_IMGRY,
	BT_FP_IMGRY_DBL,
	BT_FP_IMGRY_LDBL
};

struct base_type {
	struct tag	tag;
	strings_t	name;
	uint16_t	bit_size;
	uint8_t		name_has_encoding:1;
	uint8_t		is_signed:1;
	uint8_t		is_bool:1;
	uint8_t		is_varargs:1;
	uint8_t		float_type:4;
};

static inline struct base_type *tag__base_type(const struct tag *self)
{
	return (struct base_type *)self;
}

static inline uint16_t base_type__size(const struct tag *self)
{
	return tag__base_type(self)->bit_size / 8;
}

const char *base_type__name(const struct base_type *self, const struct cu *cu,
			    char *bf, size_t len);

void base_type_name_to_size_table__init(struct strings *strings);
size_t base_type__name_to_size(struct base_type *self, struct cu *cu);

struct array_type {
	struct tag	tag;
	uint32_t	*nr_entries;
	uint8_t		dimensions;
	bool		is_vector;
};

static inline struct array_type *tag__array_type(const struct tag *self)
{
	return (struct array_type *)self;
}

struct enumerator {
	struct tag	 tag;
	strings_t	 name;
	uint32_t	 value;
};

static inline const char *enumerator__name(const struct enumerator *self,
					   const struct cu *cu)
{
	return cu__string(cu, self->name);
}

void enumeration__delete(struct type *self, struct cu *cu);
void enumeration__add(struct type *self, struct enumerator *enumerator);
size_t enumeration__fprintf(const struct tag *tag_self, const struct cu *cu,
			    const struct conf_fprintf *conf, FILE *fp);

int dwarves__init(uint16_t user_cacheline_size);
void dwarves__exit(void);

const char *dwarf_tag_name(const uint32_t tag);

struct argp_state;

void dwarves_print_version(FILE *fp, struct argp_state *state);

#endif /* _DWARVES_H_ */
