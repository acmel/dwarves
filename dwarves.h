#ifndef _DWARVES_H_
#define _DWARVES_H_ 1
/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006..2019 Arnaldo Carvalho de Melo <acme@redhat.com>
*/


#include <stdint.h>
#include <stdio.h>
#include <obstack.h>
#include <dwarf.h>
#include <elfutils/libdwfl.h>
#include <sys/types.h>

#include "dutil.h"
#include "list.h"
#include "rbtree.h"

struct cu;

enum load_steal_kind {
	LSK__KEEPIT,
	LSK__DELETE,
	LSK__STOP_LOADING,
};

/*
 * BTF combines all the types into one big CU using btf_dedup(), so for something
 * like a allyesconfig vmlinux kernel we can get over 65535 types.
 */
typedef uint32_t type_id_t;

struct btf;
struct conf_fprintf;

/** struct conf_load - load configuration
 * @thread_exit - called at the end of a thread, 1st user: BTF encoder dedup
 * @extra_dbg_info - keep original debugging format extra info
 *		     (e.g. DWARF's decl_{line,file}, id, etc)
 * @fixup_silly_bitfields - Fixup silly things such as "int foo:32;"
 * @get_addr_info - wheter to load DW_AT_location and other addr info
 * @nr_jobs - -j argument, number of threads to use
 * @ptr_table_stats - print developer oriented ptr_table statistics.
 * @skip_missing - skip missing types rather than bailing out.
 */
struct conf_load {
	enum load_steal_kind	(*steal)(struct cu *cu,
					 struct conf_load *conf,
					 void *thr_data);
	int			(*thread_exit)(struct conf_load *conf, void *thr_data);
	void			*cookie;
	char			*format_path;
	int			nr_jobs;
	bool			extra_dbg_info;
	bool			use_obstack;
	bool			fixup_silly_bitfields;
	bool			get_addr_info;
	bool			ignore_alignment_attr;
	bool			ignore_inline_expansions;
	bool			ignore_labels;
	bool			ptr_table_stats;
	bool			skip_encoding_btf_decl_tag;
	bool			skip_missing;
	bool			skip_encoding_btf_type_tag;
	uint8_t			hashtable_bits;
	uint8_t			max_hashtable_bits;
	uint16_t		kabi_prefix_len;
	const char		*kabi_prefix;
	struct btf		*base_btf;
	struct conf_fprintf	*conf_fprintf;
	int			(*threads_prepare)(struct conf_load *conf, int nr_threads, void **thr_data);
	int			(*threads_collect)(struct conf_load *conf, int nr_threads, void **thr_data, int error);
};

/** struct conf_fprintf - hints to the __fprintf routines
 *
 * @count - Just like 'dd', stop pretty printing input after 'count' records
 * @skip - Just like 'dd', skip 'count' records when pretty printing input
 * @seek_bytes - Number of bytes to seek, if stdin only from start, when we have --pretty FILE, then from the end as well with negative numbers,
 * 		 may be of the form $header.MEMBER_NAME when using with --header.
 * @size_bytes - Number of bytes to read, similar to seek_bytes, and when both are in place, first seek seek_bytes then read size_bytes
 * @range - data structure field in --header to determine --seek_bytes and --size_bytes, must have 'offset' and 'size' fields
 * @flat_arrays - a->foo[10][2] becomes a->foo[20]
 * @classes_as_structs - class f becomes struct f, CTF doesn't have a "class"
 * @cachelinep - pointer to current cacheline, so that when expanding types we keep track of it,
 * 		 needs to be "global", i.e. not set at each recursion.
 * @suppress_force_paddings: This makes sense only if the debugging format has struct alignment information,
 *                           So allow for it to be disabled and disable it automatically for things like BTF,
 *                           that don't have such info.
 */
struct conf_fprintf {
	const char *prefix;
	const char *suffix;
	int32_t	   type_spacing;
	int32_t	   name_spacing;
	uint32_t   base_offset;
	uint32_t   count;
	uint32_t   *cachelinep;
	const char *seek_bytes;
	const char *size_bytes;
	const char *header_type;
	const char *range;
	uint32_t   skip;
	uint16_t   cacheline_size;
	uint8_t	   indent;
	uint8_t	   expand_types:1;
	uint8_t	   expand_pointers:1;
	uint8_t    rel_offset:1;
	uint8_t	   emit_stats:1;
	uint8_t	   suppress_comments:1;
	uint8_t	   has_alignment_info:1;
	uint8_t	   suppress_aligned_attribute:1;
	uint8_t	   suppress_offset_comment:1;
	uint8_t	   suppress_force_paddings:1;
	uint8_t	   suppress_packed:1;
	uint8_t	   show_decl_info:1;
	uint8_t	   show_only_data_members:1;
	uint8_t	   no_semicolon:1;
	uint8_t	   show_first_biggest_size_base_type_member:1;
	uint8_t	   flat_arrays:1;
	uint8_t	   first_member:1;
	uint8_t	   last_member:1;
	uint8_t	   union_member:1;
	uint8_t	   no_parm_names:1;
	uint8_t	   classes_as_structs:1;
	uint8_t	   hex_fmt:1;
	uint8_t	   strip_inline:1;
};

struct cus;

struct cus *cus__new(void);
void cus__delete(struct cus *cus);

int cus__load_file(struct cus *cus, struct conf_load *conf,
		   const char *filename);
int cus__load_files(struct cus *cus, struct conf_load *conf,
		    char *filenames[]);
int cus__fprintf_load_files_err(struct cus *cus, const char *tool,
				char *argv[], int err, FILE *output);
int cus__load_dir(struct cus *cus, struct conf_load *conf,
		  const char *dirname, const char *filename_mask,
		  const int recursive);
void cus__add(struct cus *cus, struct cu *cu);
void cus__print_error_msg(const char *progname, const struct cus *cus,
			  const char *filename, const int err);
struct cu *cus__find_pair(struct cus *cus, const char *name);
struct cu *cus__find_cu_by_name(struct cus *cus, const char *name);
struct tag *cus__find_struct_by_name(struct cus *cus, struct cu **cu,
				     const char *name, const int include_decls,
				     type_id_t *id);
struct tag *cus__find_struct_or_union_by_name(struct cus *cus, struct cu **cu,
					      const char *name, const int include_decls, type_id_t *id);
struct tag *cu__find_type_by_name(const struct cu *cu, const char *name, const int include_decls, type_id_t *idp);
struct tag *cus__find_type_by_name(struct cus *cus, struct cu **cu, const char *name,
				   const int include_decls, type_id_t *id);
struct function *cus__find_function_at_addr(struct cus *cus, uint64_t addr, struct cu **cu);
void cus__for_each_cu(struct cus *cus, int (*iterator)(struct cu *cu, void *cookie),
		      void *cookie,
		      struct cu *(*filter)(struct cu *cu));
bool cus__empty(const struct cus *cus);
uint32_t cus__nr_entries(const struct cus *cus);

void cus__lock(struct cus *cus);
void cus__unlock(struct cus *cus);

void *cus__priv(struct cus *cus);
void cus__set_priv(struct cus *cus, void *priv);

void cus__set_loader_exit(struct cus *cus, void (*loader_exit)(struct cus *cus));

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
 * cu__delete - called at cu__delete(), to give a chance to formats such as
 *		CTF to keep the .strstab ELF section available till the cu is
 *		deleted.
 */
struct debug_fmt_ops {
	const char	   *name;
	int		   (*init)(void);
	void		   (*exit)(void);
	int		   (*load_file)(struct cus *cus,
				       struct conf_load *conf,
				       const char *filename);
	const char	   *(*tag__decl_file)(const struct tag *tag,
					      const struct cu *cu);
	uint32_t	   (*tag__decl_line)(const struct tag *tag,
					     const struct cu *cu);
	unsigned long long (*tag__orig_id)(const struct tag *tag,
					   const struct cu *cu);
	void		   (*cu__delete)(struct cu *cu);
	bool		   has_alignment_info;
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
	struct debug_fmt_ops *dfops;
	Elf		 *elf;
	Dwfl_Module	 *dwfl;
	struct obstack	 obstack;
	uint32_t	 cached_symtab_nr_entries;
	bool		 use_obstack;
	uint8_t		 addr_size;
	uint8_t		 extra_dbg_info:1;
	uint8_t		 has_addr_info:1;
	uint8_t		 uses_global_strings:1;
	uint8_t		 little_endian:1;
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
		   const char *filename, bool use_obstack);
void cu__delete(struct cu *cu);

void *cu__malloc(struct cu *cu, size_t size);
void *cu__zalloc(struct cu *cu, size_t size);
void cu__free(struct cu *cu, void *ptr);

int cu__fprintf_ptr_table_stats_csv(struct cu *cu, FILE *fp);

int cus__fprintf_ptr_table_stats_csv_header(FILE *fp);

static inline int cu__cache_symtab(struct cu *cu)
{
	int err = dwfl_module_getsymtab(cu->dwfl);
	if (err > 0)
		cu->cached_symtab_nr_entries = dwfl_module_getsymtab(cu->dwfl);
	return err;
}

static inline __pure bool cu__is_c_plus_plus(const struct cu *cu)
{
	return cu->language == LANG_C_plus_plus;
}

static inline __pure bool cu__is_c(const struct cu *cu)
{
	return cu->language == LANG_C;
}

int lang__str2int(const char *lang);

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
 * @id: type_id_t id
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
 * @id: type_id_t id
 */
#define cu__for_each_struct(cu, id, pos)				\
	for (id = 1; id < cu->types_table.nr_entries; ++id)		\
		if (!(pos = tag__class(cu->types_table.entries[id])) || \
		    !tag__is_struct(class__tag(pos)))			\
			continue;					\
		else

/**
 * cu__for_each_struct_or_union - iterate thru all the struct and union tags
 * @cu: struct cu instance to iterate
 * @pos: struct class iterator
 * @id: type_id_t tag id
 */
#define cu__for_each_struct_or_union(cu, id, pos)			\
	for (id = 1; id < cu->types_table.nr_entries; ++id)		\
		if (!(pos = tag__class(cu->types_table.entries[id])) || \
		    !(tag__is_struct(class__tag(pos)) || 		\
		      tag__is_union(class__tag(pos))))			\
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

int cu__add_tag(struct cu *cu, struct tag *tag, uint32_t *id);
int cu__add_tag_with_id(struct cu *cu, struct tag *tag, uint32_t id);
int cu__table_add_tag(struct cu *cu, struct tag *tag, uint32_t *id);
int cu__table_add_tag_with_id(struct cu *cu, struct tag *tag, uint32_t id);
int cu__table_nullify_type_entry(struct cu *cu, uint32_t id);
struct tag *cu__find_base_type_by_name(const struct cu *cu, const char *name,
				       type_id_t *id);
struct tag *cu__find_base_type_by_name_and_size(const struct cu *cu, const char* name,
						uint16_t bit_size, type_id_t *idp);
struct tag *cu__find_enumeration_by_name(const struct cu *cu, const char *name, type_id_t *idp);
struct tag *cu__find_enumeration_by_name_and_size(const struct cu *cu, const char* name,
						  uint16_t bit_size, type_id_t *idp);
struct tag *cu__find_first_typedef_of_type(const struct cu *cu,
					   const type_id_t type);
struct tag *cu__find_function_by_name(const struct cu *cu, const char *name);
struct function *cu__find_function_at_addr(const struct cu *cu,
					   uint64_t addr);
struct tag *cu__function(const struct cu *cu, const uint32_t id);
struct tag *cu__tag(const struct cu *cu, const uint32_t id);
struct tag *cu__type(const struct cu *cu, const type_id_t id);
struct tag *cu__find_struct_by_name(const struct cu *cu, const char *name,
				    const int include_decls, type_id_t *id);
struct tag *cu__find_struct_or_union_by_name(const struct cu *cu, const char *name,
					     const int include_decls, type_id_t *id);
bool cu__same_build_id(const struct cu *cu, const struct cu *other);
void cu__account_inline_expansions(struct cu *cu);
int cu__for_all_tags(struct cu *cu,
		     int (*iterator)(struct tag *tag,
				     struct cu *cu, void *cookie),
		     void *cookie);

/** struct tag - basic representation of a debug info element
 * @priv - extra data, for instance, DWARF offset, id, decl_{file,line}
 * @top_level -
 */
struct tag {
	struct list_head node;
	type_id_t	 type;
	uint16_t	 tag;
	bool		 visited;
	bool		 top_level;
	bool		 has_btf_type_tag;
	uint16_t	 recursivity_level;
	void		 *priv;
};

// To use with things like type->type_enum == perf_event_type+perf_user_event_type
struct tag_cu {
	struct tag	 *tag;
	struct cu	 *cu;
};

void tag__delete(struct tag *tag);

static inline int tag__is_enumeration(const struct tag *tag)
{
	return tag->tag == DW_TAG_enumeration_type;
}

static inline int tag__is_namespace(const struct tag *tag)
{
	return tag->tag == DW_TAG_namespace;
}

static inline int tag__is_struct(const struct tag *tag)
{
	return tag->tag == DW_TAG_structure_type ||
	       tag->tag == DW_TAG_interface_type ||
	       tag->tag == DW_TAG_class_type;
}

static inline int tag__is_typedef(const struct tag *tag)
{
	return tag->tag == DW_TAG_typedef;
}

static inline int tag__is_rvalue_reference_type(const struct tag *tag)
{
	return tag->tag == DW_TAG_rvalue_reference_type;
}

static inline int tag__is_union(const struct tag *tag)
{
	return tag->tag == DW_TAG_union_type;
}

static inline int tag__is_const(const struct tag *tag)
{
	return tag->tag == DW_TAG_const_type;
}

static inline int tag__is_pointer(const struct tag *tag)
{
	return tag->tag == DW_TAG_pointer_type;
}

static inline int tag__is_pointer_to(const struct tag *tag, type_id_t type)
{
	return tag__is_pointer(tag) && tag->type == type;
}

static inline bool tag__is_variable(const struct tag *tag)
{
	return tag->tag == DW_TAG_variable;
}

static inline bool tag__is_volatile(const struct tag *tag)
{
	return tag->tag == DW_TAG_volatile_type;
}

static inline bool tag__is_atomic(const struct tag *tag)
{
	return tag->tag == DW_TAG_atomic_type;
}

static inline bool tag__is_restrict(const struct tag *tag)
{
	return tag->tag == DW_TAG_restrict_type;
}

static inline int tag__is_modifier(const struct tag *tag)
{
	return tag__is_const(tag) ||
	       tag__is_volatile(tag) ||
	       tag__is_restrict(tag) ||
	       tag__is_atomic(tag);
}

static inline bool tag__has_namespace(const struct tag *tag)
{
	return tag__is_struct(tag) ||
	       tag__is_union(tag) ||
	       tag__is_namespace(tag) ||
	       tag__is_enumeration(tag);
}

/**
 * tag__is_tag_type - is this tag derived from the 'type' class?
 * @tag - tag queried
 */
static inline int tag__is_type(const struct tag *tag)
{
	return tag__is_union(tag)   ||
	       tag__is_struct(tag)  ||
	       tag__is_typedef(tag) ||
	       tag__is_rvalue_reference_type(tag) ||
	       tag__is_enumeration(tag);
}

/**
 * tag__is_tag_type - is this one of the possible types for a tag?
 * @tag - tag queried
 */
static inline int tag__is_tag_type(const struct tag *tag)
{
	return tag__is_type(tag) ||
	       tag->tag == DW_TAG_array_type ||
	       tag->tag == DW_TAG_string_type ||
	       tag->tag == DW_TAG_base_type ||
	       tag->tag == DW_TAG_const_type ||
	       tag->tag == DW_TAG_pointer_type ||
	       tag->tag == DW_TAG_rvalue_reference_type ||
	       tag->tag == DW_TAG_ptr_to_member_type ||
	       tag->tag == DW_TAG_reference_type ||
	       tag->tag == DW_TAG_restrict_type ||
	       tag->tag == DW_TAG_subroutine_type ||
	       tag->tag == DW_TAG_unspecified_type ||
	       tag->tag == DW_TAG_volatile_type ||
	       tag->tag == DW_TAG_atomic_type ||
	       tag->tag == DW_TAG_LLVM_annotation;
}

static inline const char *tag__decl_file(const struct tag *tag,
					 const struct cu *cu)
{
	if (cu->dfops && cu->dfops->tag__decl_file)
		return cu->dfops->tag__decl_file(tag, cu);
	return NULL;
}

static inline uint32_t tag__decl_line(const struct tag *tag,
				      const struct cu *cu)
{
	if (cu->dfops && cu->dfops->tag__decl_line)
		return cu->dfops->tag__decl_line(tag, cu);
	return 0;
}

static inline unsigned long long tag__orig_id(const struct tag *tag,
					      const struct cu *cu)
{
	if (cu->dfops && cu->dfops->tag__orig_id)
		return cu->dfops->tag__orig_id(tag, cu);
	return 0;
}

size_t tag__fprintf_decl_info(const struct tag *tag,
			      const struct cu *cu, FILE *fp);
size_t tag__fprintf(struct tag *tag, const struct cu *cu,
		    const struct conf_fprintf *conf, FILE *fp);

const char *tag__name(const struct tag *tag, const struct cu *cu,
		      char *bf, size_t len, const struct conf_fprintf *conf);
void tag__not_found_die(const char *file, int line, const char *func);

#define tag__assert_search_result(tag) \
	do { if (!tag) tag__not_found_die(__FILE__,\
					  __LINE__, __func__); } while (0)

size_t tag__size(const struct tag *tag, const struct cu *cu);
size_t tag__nr_cachelines(const struct conf_fprintf *conf, const struct tag *tag, const struct cu *cu);
struct tag *tag__follow_typedef(const struct tag *tag, const struct cu *cu);
struct tag *tag__strip_typedefs_and_modifiers(const struct tag *tag, const struct cu *cu);

size_t __tag__id_not_found_fprintf(FILE *fp, type_id_t id,
				   const char *fn, int line);
#define tag__id_not_found_fprintf(fp, id) \
	__tag__id_not_found_fprintf(fp, id, __func__, __LINE__)

int __tag__has_type_loop(const struct tag *tag, const struct tag *type,
			 char *bf, size_t len, FILE *fp,
			 const char *fn, int line);
#define tag__has_type_loop(tag, type, bf, len, fp) \
	__tag__has_type_loop(tag, type, bf, len, fp, __func__, __LINE__)

struct ptr_to_member_type {
	struct tag tag;
	type_id_t  containing_type;
};

static inline struct ptr_to_member_type *
		tag__ptr_to_member_type(const struct tag *tag)
{
	return (struct ptr_to_member_type *)tag;
}

struct llvm_annotation {
	const char		*value;
	int16_t			component_idx;
	struct list_head	node;
};

/** struct btf_type_tag_type - representing a btf_type_tag annotation
 *
 * @tag   - DW_TAG_LLVM_annotation tag
 * @value - btf_type_tag value string
 * @node  - list_head node
 */
struct btf_type_tag_type {
	struct tag		tag;
	const char		*value;
	struct list_head	node;
};

/** The struct btf_type_tag_ptr_type - type containing both pointer type and
 *  its btf_type_tag annotations
 *
 * @tag  - pointer type tag
 * @tags - btf_type_tag annotations for the pointer type
 */
struct btf_type_tag_ptr_type {
	struct tag		tag;
	struct list_head 	tags;
};

static inline struct btf_type_tag_ptr_type *tag__btf_type_tag_ptr(struct tag *tag)
{
	return (struct btf_type_tag_ptr_type *)tag;
}

static inline struct btf_type_tag_type *tag__btf_type_tag(struct tag *tag)
{
	return (struct btf_type_tag_type *)tag;
}

/** struct namespace - base class for enums, structs, unions, typedefs, etc
 *
 * @tags - class_member, enumerators, etc
 * @shared_tags: if this bit is set, don't free the entries in @tags
 */
struct namespace {
	struct tag	 tag;
	const char	 *name;
	uint16_t	 nr_tags;
	uint8_t		 shared_tags;
	struct list_head tags;
	struct list_head annots;
};

static inline struct namespace *tag__namespace(const struct tag *tag)
{
	return (struct namespace *)tag;
}

void namespace__delete(struct namespace *nspace);

/**
 * namespace__for_each_tag - iterate thru all the tags
 * @nspace: struct namespace instance to iterate
 * @pos: struct tag iterator
 */
#define namespace__for_each_tag(nspace, pos) \
	list_for_each_entry(pos, &(nspace)->tags, node)

/**
 * namespace__for_each_tag_safe_reverse - safely iterate thru all the tags, in reverse order
 * @nspace: struct namespace instance to iterate
 * @pos: struct tag iterator
 * @n: struct class_member temp iterator
 */
#define namespace__for_each_tag_safe_reverse(nspace, pos, n) \
	list_for_each_entry_safe_reverse(pos, n, &(nspace)->tags, node)

void namespace__add_tag(struct namespace *nspace, struct tag *tag);

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
				tag__inline_expansion(const struct tag *tag)
{
	return (struct inline_expansion *)tag;
}

struct label {
	struct ip_tag	 ip;
	const char	 *name;
};

static inline struct label *tag__label(const struct tag *tag)
{
	return (struct label *)tag;
}

static inline const char *label__name(const struct label *label)
{
	return label->name;
}

enum vscope {
	VSCOPE_UNKNOWN,
	VSCOPE_LOCAL,
	VSCOPE_GLOBAL,
	VSCOPE_REGISTER,
	VSCOPE_OPTIMIZED
} __attribute__((packed));

struct location {
	Dwarf_Op *expr;
	size_t	  exprlen;
};

struct variable {
	struct ip_tag	 ip;
	const char	 *name;
	uint8_t		 external:1;
	uint8_t		 declaration:1;
	uint8_t		 has_specification:1;
	enum vscope	 scope;
	struct location	 location;
	struct hlist_node tool_hnode;
	struct list_head annots;
	struct variable  *spec;
};

static inline struct variable *tag__variable(const struct tag *tag)
{
	return (struct variable *)tag;
}

enum vscope variable__scope(const struct variable *var);
const char *variable__scope_str(const struct variable *var);

const char *variable__name(const struct variable *var);

const char *variable__type_name(const struct variable *var,
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

static inline struct lexblock *tag__lexblock(const struct tag *tag)
{
	return (struct lexblock *)tag;
}

void lexblock__delete(struct lexblock *lexblock);

struct function;

void lexblock__add_inline_expansion(struct lexblock *lexblock,
				    struct inline_expansion *exp);
void lexblock__add_label(struct lexblock *lexblock, struct label *label);
void lexblock__add_lexblock(struct lexblock *lexblock, struct lexblock *child);
void lexblock__add_tag(struct lexblock *lexblock, struct tag *tag);
void lexblock__add_variable(struct lexblock *lexblock, struct variable *var);
size_t lexblock__fprintf(const struct lexblock *lexblock, const struct cu *cu,
			 struct function *function, uint16_t indent,
			 const struct conf_fprintf *conf, FILE *fp);

struct parameter {
	struct tag tag;
	const char *name;
};

static inline struct parameter *tag__parameter(const struct tag *tag)
{
	return (struct parameter *)tag;
}

static inline const char *parameter__name(const struct parameter *parm)
{
	return parm->name;
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

static inline struct ftype *tag__ftype(const struct tag *tag)
{
	return (struct ftype *)tag;
}

void ftype__delete(struct ftype *ftype);

/**
 * ftype__for_each_parameter - iterate thru all the parameters
 * @ftype: struct ftype instance to iterate
 * @pos: struct parameter iterator
 */
#define ftype__for_each_parameter(ftype, pos) \
	list_for_each_entry(pos, &(ftype)->parms, tag.node)

/**
 * ftype__for_each_parameter_safe - safely iterate thru all the parameters
 * @ftype: struct ftype instance to iterate
 * @pos: struct parameter iterator
 * @n: struct parameter temp iterator
 */
#define ftype__for_each_parameter_safe(ftype, pos, n) \
	list_for_each_entry_safe(pos, n, &(ftype)->parms, tag.node)

/**
 * ftype__for_each_parameter_safe_reverse - safely iterate thru all the parameters, in reverse order
 * @ftype: struct ftype instance to iterate
 * @pos: struct parameter iterator
 * @n: struct parameter temp iterator
 */
#define ftype__for_each_parameter_safe_reverse(ftype, pos, n) \
	list_for_each_entry_safe_reverse(pos, n, &(ftype)->parms, tag.node)

void ftype__add_parameter(struct ftype *ftype, struct parameter *parm);
size_t ftype__fprintf(const struct ftype *ftype, const struct cu *cu,
		      const char *name, const int inlined,
		      const int is_pointer, const int type_spacing, bool is_prototype,
		      const struct conf_fprintf *conf, FILE *fp);
size_t ftype__fprintf_parms(const struct ftype *ftype,
			    const struct cu *cu, int indent,
			    const struct conf_fprintf *conf, FILE *fp);
int ftype__has_parm_of_type(const struct ftype *ftype, const type_id_t target,
			    const struct cu *cu);

struct function {
	struct ftype	 proto;
	struct lexblock	 lexblock;
	struct rb_node	 rb_node;
	const char	 *name;
	const char	 *linkage_name;
	uint32_t	 cu_total_size_inline_expansions;
	uint16_t	 cu_total_nr_inline_expansions;
	uint8_t		 inlined:2;
	uint8_t		 abstract_origin:1;
	uint8_t		 external:1;
	uint8_t		 accessibility:2; /* DW_ACCESS_{public,protected,private} */
	uint8_t		 virtuality:2; /* DW_VIRTUALITY_{none,virtual,pure_virtual} */
	uint8_t		 declaration:1;
	uint8_t		 btf:1;
	int32_t		 vtable_entry;
	struct list_head vtable_node;
	struct list_head annots;
	/* fields used by tools */
	union {
		struct list_head  tool_node;
		struct hlist_node tool_hnode;
	};
	void		 *priv;
};

static inline struct function *tag__function(const struct tag *tag)
{
	return (struct function *)tag;
}

static inline struct tag *function__tag(const struct function *func)
{
	return (struct tag *)func;
}

void function__delete(struct function *func);

static __pure inline int tag__is_function(const struct tag *tag)
{
	return tag->tag == DW_TAG_subprogram;
}

/**
 * function__for_each_parameter - iterate thru all the parameters
 * @func: struct function instance to iterate
 * @pos: struct parameter iterator
 */
#define function__for_each_parameter(func, cu, pos) \
	ftype__for_each_parameter(func->btf ? tag__ftype(cu__type(cu, func->proto.tag.type)) : &func->proto, pos)

const char *function__name(struct function *func);

static inline const char *function__linkage_name(const struct function *func)
{
	return func->linkage_name;
}

size_t function__fprintf_stats(const struct tag *tag_func,
			       const struct cu *cu,
			       const struct conf_fprintf *conf,
			       FILE *fp);
const char *function__prototype(const struct function *func,
				const struct cu *cu, char *bf, size_t len);

static __pure inline uint64_t function__addr(const struct function *func)
{
	return func->lexblock.ip.addr;
}

static __pure inline uint32_t function__size(const struct function *func)
{
	return func->lexblock.size;
}

static inline int function__declared_inline(const struct function *func)
{
	return (func->inlined == DW_INL_declared_inlined ||
	        func->inlined == DW_INL_declared_not_inlined);
}

static inline int function__inlined(const struct function *func)
{
	return (func->inlined == DW_INL_inlined ||
	        func->inlined == DW_INL_declared_inlined);
}

/* struct class_member - struct, union, class member
 *
 * @bit_offset - offset in bits from the start of the struct
 * @bit_size - cached bit size, can be smaller than the integral type if in a bitfield
 * @byte_offset - offset in bytes from the start of the struct
 * @byte_size - cached byte size, integral type byte size for bitfields
 * @bitfield_offset - offset in the current bitfield
 * @bitfield_size - size in the current bitfield
 * @bit_hole - If there is a bit hole before the next one (or the end of the struct)
 * @bitfield_end - Is this the last entry in a bitfield?
 * @alignment - DW_AT_alignement, zero if not present, gcc emits since circa 7.3.1
 * @accessibility - DW_ACCESS_{public,protected,private}
 * @virtuality - DW_VIRTUALITY_{none,virtual,pure_virtual}
 * @hole - If there is a hole before the next one (or the end of the struct)
 * @has_bit_offset: Don't recalcule this, it came from the debug info (DWARF5's DW_AT_data_bit_offset)
 */
struct class_member {
	struct tag	 tag;
	const char	 *name;
	uint32_t	 bit_offset;
	uint32_t	 bit_size;
	uint32_t	 byte_offset;
	size_t		 byte_size;
	int8_t		 bitfield_offset;
	uint8_t		 bitfield_size;
	uint8_t		 bit_hole;
	uint8_t		 bitfield_end:1;
	uint64_t	 const_value;
	uint32_t	 alignment;
	uint8_t		 visited:1;
	uint8_t		 is_static:1;
	uint8_t		 has_bit_offset:1;
	uint8_t		 accessibility:2;
	uint8_t		 virtuality:2;
	uint16_t	 hole;
};

void class_member__delete(struct class_member *member);

static inline struct class_member *tag__class_member(const struct tag *tag)
{
	return (struct class_member *)tag;
}

static inline const char *class_member__name(const struct class_member *member)
{
	return member->name;
}

static __pure inline int tag__is_class_member(const struct tag *tag)
{
	return tag->tag == DW_TAG_member;
}

int tag__is_base_type(const struct tag *tag, const struct cu *cu);
bool tag__is_array(const struct tag *tag, const struct cu *cu);

struct class_member_filter;

struct tag_cu_node {
	struct list_head node;
	struct tag_cu	 tc;
};

/**
 * struct type - base type for enumerations, structs and unions
 *
 * @node: Used in emissions->fwd_decls, i.e. only on the 'dwarves_emit.c' file
 * @nr_members: number of non static DW_TAG_member entries
 * @nr_static_members: number of static DW_TAG_member entries
 * @nr_tags: number of tags
 * @alignment: DW_AT_alignement, zero if not present, gcc emits since circa 7.3.1
 * @natural_alignment: For inferring __packed__, normally the widest scalar in it, recursively
 * @suffix_disambiguation: if we have both 'union foo' and 'struct foo' then we must disambiguate,
 *                         useful to generate a vmlinux.h with all Linux types out of BTF data, for instance.
 * @sizeof_member: Use this to find the size of the record
 * @type_member: Use this to select a member from where to get an id on an enum to find a type
 * 		 to cast for, needs to be used with the upcoming type_enum.
 * @type_enum: enumeration(s) to use together with type_member to find a type to cast
 * @member_prefix: the common prefix for all members, say in an enum, this should be calculated on demand
 * @member_prefix_len: the lenght of the common prefix for all members
 */
struct type {
	struct namespace namespace;
	struct list_head node;
	uint32_t	 size;
	int32_t		 size_diff;
	uint16_t	 nr_static_members;
	uint16_t	 nr_members;
	uint32_t	 alignment;
	struct class_member *sizeof_member;
	struct class_member *type_member;
	struct class_member_filter *filter;
	struct list_head type_enum;
	char 		 *member_prefix;
	uint16_t	 member_prefix_len;
	uint16_t	 max_tag_name_len;
	uint16_t	 natural_alignment;
	uint8_t		 suffix_disambiguation;
	uint8_t		 packed_attributes_inferred:1;
	uint8_t		 declaration:1;
	uint8_t		 definition_emitted:1;
	uint8_t		 fwd_decl_emitted:1;
	uint8_t		 resized:1;
};

void __type__init(struct type *type);

size_t tag__natural_alignment(struct tag *tag, const struct cu *cu);

static inline struct class *type__class(const struct type *type)
{
	return (struct class *)type;
}

static inline struct tag *type__tag(const struct type *type)
{
	return (struct tag *)type;
}

void type__delete(struct type *type);

static inline struct class_member *type__first_member(struct type *type)
{
	return list_first_entry(&type->namespace.tags, struct class_member, tag.node);
}

static inline struct class_member *class_member__next(struct class_member *member)
{
	return list_entry(member->tag.node.next, struct class_member, tag.node);
}

/**
 * type__for_each_tag - iterate thru all the tags
 * @type: struct type instance to iterate
 * @pos: struct tag iterator
 */
#define type__for_each_tag(type, pos) \
	list_for_each_entry(pos, &(type)->namespace.tags, node)

/**
 * type__for_each_enumerator - iterate thru the enumerator entries
 * @type: struct type instance to iterate
 * @pos: struct enumerator iterator
 */
#define type__for_each_enumerator(type, pos) \
	struct list_head *__type__for_each_enumerator_head = \
		(type)->namespace.shared_tags ? \
			(type)->namespace.tags.next : \
			&(type)->namespace.tags; \
	list_for_each_entry(pos, __type__for_each_enumerator_head, tag.node)

/**
 * type__for_each_enumerator_safe_reverse - safely iterate thru the enumerator entries, in reverse order
 * @type: struct type instance to iterate
 * @pos: struct enumerator iterator
 * @n: struct enumerator temp iterator
 */
#define type__for_each_enumerator_safe_reverse(type, pos, n)		   \
	if ((type)->namespace.shared_tags) /* Do nothing */ ; else \
	list_for_each_entry_safe_reverse(pos, n, &(type)->namespace.tags, tag.node)

/**
 * type__for_each_member - iterate thru the entries that use space
 *                         (data members and inheritance entries)
 * @type: struct type instance to iterate
 * @pos: struct class_member iterator
 */
#define type__for_each_member(type, pos) \
	list_for_each_entry(pos, &(type)->namespace.tags, tag.node) \
		if (!(pos->tag.tag == DW_TAG_member || \
		      pos->tag.tag == DW_TAG_inheritance)) \
			continue; \
		else

/**
 * type__for_each_data_member - iterate thru the data member entries
 * @type: struct type instance to iterate
 * @pos: struct class_member iterator
 */
#define type__for_each_data_member(type, pos) \
	list_for_each_entry(pos, &(type)->namespace.tags, tag.node) \
		if (pos->tag.tag != DW_TAG_member) \
			continue; \
		else

/**
 * type__for_each_member_safe - safely iterate thru the entries that use space
 *                              (data members and inheritance entries)
 * @type: struct type instance to iterate
 * @pos: struct class_member iterator
 * @n: struct class_member temp iterator
 */
#define type__for_each_member_safe(type, pos, n) \
	list_for_each_entry_safe(pos, n, &(type)->namespace.tags, tag.node) \
		if (pos->tag.tag != DW_TAG_member) \
			continue; \
		else

/**
 * type__for_each_data_member_safe - safely iterate thru the data member entries
 * @type: struct type instance to iterate
 * @pos: struct class_member iterator
 * @n: struct class_member temp iterator
 */
#define type__for_each_data_member_safe(type, pos, n) \
	list_for_each_entry_safe(pos, n, &(type)->namespace.tags, tag.node) \
		if (pos->tag.tag != DW_TAG_member) \
			continue; \
		else

/**
 * type__for_each_tag_safe_reverse - safely iterate thru all tags in a type, in reverse order
 * @type: struct type instance to iterate
 * @pos: struct class_member iterator
 * @n: struct class_member temp iterator
 */
#define type__for_each_tag_safe_reverse(type, pos, n) \
	list_for_each_entry_safe_reverse(pos, n, &(type)->namespace.tags, tag.node)

void type__add_member(struct type *type, struct class_member *member);
struct class_member *
	type__find_first_biggest_size_base_type_member(struct type *type,
						       const struct cu *cu);

struct class_member *type__find_member_by_name(const struct type *type, const char *name);
uint32_t type__nr_members_of_type(const struct type *type, const type_id_t oftype);
struct class_member *type__last_member(struct type *type);

void enumerations__calc_prefix(struct list_head *enumerations);

size_t typedef__fprintf(const struct tag *tag_type, const struct cu *cu,
			const struct conf_fprintf *conf, FILE *fp);

static inline struct type *tag__type(const struct tag *tag)
{
	return (struct type *)tag;
}

struct class {
	struct type	 type;
	struct list_head vtable;
	uint16_t	 nr_vtable_entries;
	uint8_t		 nr_holes;
	uint8_t		 nr_bit_holes;
	uint16_t	 pre_hole;
	uint16_t	 padding;
	uint8_t		 pre_bit_hole;
	uint8_t		 bit_padding;
	bool		 holes_searched;
	bool		 is_packed;
	void		 *priv;
};

static inline struct class *tag__class(const struct tag *tag)
{
	return (struct class *)tag;
}

static inline struct tag *class__tag(const struct class *cls)
{
	return (struct tag *)cls;
}

struct class *class__clone(const struct class *from, const char *new_class_name);
void class__delete(struct class *cls);

static inline struct list_head *class__tags(struct class *cls)
{
	return &cls->type.namespace.tags;
}

static __pure inline const char *namespace__name(const struct namespace *nspace)
{
	return nspace->name;
}

static __pure inline const char *type__name(const struct type *type)
{
	return namespace__name(&type->namespace);
}

static __pure inline const char *class__name(struct class *cls)
{
	return type__name(&cls->type);
}

static inline int class__is_struct(const struct class *cls)
{
	return tag__is_struct(&cls->type.namespace.tag);
}

void class__find_holes(struct class *cls);
int class__has_hole_ge(const struct class *cls, const uint16_t size);

bool class__infer_packed_attributes(struct class *cls, const struct cu *cu);

void union__infer_packed_attributes(struct type *type, const struct cu *cu);

void type__check_structs_at_unnatural_alignments(struct type *type, const struct cu *cu);

size_t class__fprintf(struct class *cls, const struct cu *cu, FILE *fp);

void class__add_vtable_entry(struct class *cls, struct function *vtable_entry);
static inline struct class_member *
	class__find_member_by_name(const struct class *cls, const char *name)
{
	return type__find_member_by_name(&cls->type, name);
}

static inline uint16_t class__nr_members(const struct class *cls)
{
	return cls->type.nr_members;
}

static inline uint32_t class__size(const struct class *cls)
{
	return cls->type.size;
}

static inline int class__is_declaration(const struct class *cls)
{
	return cls->type.declaration;
}

const struct class_member *class__find_bit_hole(const struct class *cls,
					   const struct class_member *trailer,
						const uint16_t bit_hole_size);

#define class__for_each_member_from(cls, from, pos)			\
	pos = list_prepare_entry(from, class__tags(cls), tag.node);	\
	list_for_each_entry_from(pos, class__tags(cls), tag.node)	\
		if (!tag__is_class_member(&pos->tag))			\
			continue;					\
		else

#define class__for_each_member_safe_from(cls, from, pos, tmp)			\
	pos = list_prepare_entry(from, class__tags(cls), tag.node);		\
	list_for_each_entry_safe_from(pos, tmp, class__tags(cls), tag.node)	\
		if (!tag__is_class_member(&pos->tag))				\
			continue;						\
		else

#define class__for_each_member_continue(cls, from, pos)			\
	pos = list_prepare_entry(from, class__tags(cls), tag.node);	\
	list_for_each_entry_continue(pos, class__tags(cls), tag.node)	\
		if (!tag__is_class_member(&pos->tag))			\
			continue;					\
		else

#define class__for_each_member_reverse(cls, member)			\
	list_for_each_entry_reverse(member, class__tags(cls), tag.node)	\
		if (member->tag.tag != DW_TAG_member)			\
			continue;					\
		else

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
	const char	*name;
	uint16_t	bit_size;
	uint8_t		name_has_encoding:1;
	uint8_t		is_signed:1;
	uint8_t		is_bool:1;
	uint8_t		is_varargs:1;
	uint8_t		float_type:4;
};

static inline struct base_type *tag__base_type(const struct tag *tag)
{
	return (struct base_type *)tag;
}

static inline uint16_t base_type__size(const struct tag *tag)
{
	return tag__base_type(tag)->bit_size / 8;
}

const char *__base_type__name(const struct base_type *bt);

const char *base_type__name(const struct base_type *btype, char *bf, size_t len);

size_t base_type__name_to_size(struct base_type *btype, struct cu *cu);

struct array_type {
	struct tag	tag;
	uint32_t	*nr_entries;
	uint8_t		dimensions;
	bool		is_vector;
};

static inline struct array_type *tag__array_type(const struct tag *tag)
{
	return (struct array_type *)tag;
}

struct string_type {
	struct tag      tag;
	uint32_t        nr_entries;
};

static inline struct string_type *tag__string_type(const struct tag *tag)
{
	return (struct string_type *)tag;
}

struct enumerator {
	struct tag	 tag;
	const char	 *name;
	uint32_t	 value;
	struct tag_cu	 type_enum; // To cache the type_enum searches
};

static inline const char *enumerator__name(const struct enumerator *enumerator)
{
	return enumerator->name;
}

void enumeration__delete(struct type *type);
void enumeration__add(struct type *type, struct enumerator *enumerator);
size_t enumeration__fprintf(const struct tag *tag_enum,
			    const struct conf_fprintf *conf, FILE *fp);

int dwarves__init(void);
void dwarves__exit(void);
void dwarves__resolve_cacheline_size(const struct conf_load *conf, uint16_t user_cacheline_size);

const char *dwarf_tag_name(const uint32_t tag);

struct argp_state;

void dwarves_print_version(FILE *fp, struct argp_state *state);
void dwarves_print_numeric_version(FILE *fp);

extern bool print_numeric_version;

extern bool no_bitfield_type_recode;

extern const char tabs[];

#ifndef DW_TAG_skeleton_unit
#define DW_TAG_skeleton_unit 0x4a
#endif

#endif /* _DWARVES_H_ */
