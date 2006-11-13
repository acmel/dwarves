/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <dwarf.h>
#include <fcntl.h>
#include <libdw.h>
#include <libelf.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "list.h"
#include "classes.h"

unsigned int cacheline_size = DEFAULT_CACHELINE_SIZE;

static void *zalloc(const size_t size)
{
	void *s = malloc(size);
	if (s != NULL)
		memset(s, 0, size);
	return s;
}

static void *strings;

static int strings__compare(const void *a, const void *b)
{
	return strcmp(a, b);
}

static char *strings__add(const char *str)
{
	char **s;

	if (str == NULL)
		return NULL;

	s = tsearch(str, &strings, strings__compare);
	if (s != NULL) {
		if (*s == str) {
			char *dup = strdup(str);
			if (dup != NULL)
				*s = dup;
			else {
				tdelete(str, &strings, strings__compare);
				return NULL;
			}
		}
	} else
		return NULL;

	return *s;
}

static struct variable *variable__new(const char *name, uint64_t id,
				      uint64_t type, uint64_t abstract_origin)
{
	struct variable *self = malloc(sizeof(*self));

	if (self != NULL) {
		self->name	      = strings__add(name);
		self->cu	      = NULL;
		self->id	      = id;
		self->type	      = type;
		self->abstract_origin = abstract_origin;
	}

	return self;
}

static void cus__add(struct cus *self, struct cu *cu)
{
	list_add_tail(&cu->node, &self->cus);
}

static struct cu *cu__new(unsigned int cu, const char *name)
{
	struct cu *self = malloc(sizeof(*self));

	if (self != NULL) {
		INIT_LIST_HEAD(&self->classes);
		INIT_LIST_HEAD(&self->variables);
		self->name = strings__add(name);
		self->nr_inline_expansions   = 0;
		self->size_inline_expansions = 0;
		self->nr_structures_changed    = 0;
		self->nr_functions_changed     = 0;
		self->max_len_changed_item     = 0;
		self->function_bytes_added     = 0;
		self->function_bytes_removed   = 0;
	}

	return self;
}

static void cu__add_class(struct cu *self, struct class *class)
{
	class->cu = self;
	list_add_tail(&class->node, &self->classes);
}

static void cu__add_variable(struct cu *self, struct variable *variable)
{
	variable->cu = self;
	list_add_tail(&variable->cu_node, &self->variables);
}

static const char *tag_name(const unsigned int tag)
{
	switch (tag) {
	case DW_TAG_enumeration_type:	return "enum ";
	case DW_TAG_structure_type:	return "struct ";
	case DW_TAG_union_type:		return "union ";
	case DW_TAG_pointer_type:	return " *";
	}

	return "";
}

struct class *cu__find_class_by_name(const struct cu *self, const char *name)
{
	struct class *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, &self->classes, node)
		if (pos->name != NULL && strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

struct class *cus__find_class_by_name(const struct cus *self, const char *name)
{
	struct cu *pos;

	list_for_each_entry(pos, &self->cus, node) {
		struct class *class = cu__find_class_by_name(pos, name);

		if (class != NULL)
			return class;
	}

	return NULL;
}

struct cu *cus__find_cu_by_name(const struct cus *self, const char *name)
{
	struct cu *pos;

	list_for_each_entry(pos, &self->cus, node)
		if (strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

struct class *cu__find_class_by_id(const struct cu *self, const uint64_t id)
{
	struct class *pos;

	list_for_each_entry(pos, &self->classes, node)
		if (pos->id == id)
			return pos;

	return NULL;
}

struct variable *cu__find_variable_by_id(const struct cu *self, const uint64_t id)
{
	struct variable *pos;

	list_for_each_entry(pos, &self->variables, cu_node)
		if (pos->id == id)
			return pos;

	return NULL;
}

int class__is_struct(const struct class *self,
		     struct class **typedef_alias)
{
	*typedef_alias = NULL;
	if (self->tag == DW_TAG_typedef) {
		*typedef_alias = cu__find_class_by_id(self->cu, self->type);
		if (*typedef_alias == NULL)
			return 0;
		
		return (*typedef_alias)->tag == DW_TAG_structure_type;
	}

	return self->tag == DW_TAG_structure_type;
}

static uint64_t class__size(const struct class *self)
{
	uint64_t size = self->size;

	if (self->tag != DW_TAG_pointer_type && self->type != 0) {
		struct class *class = cu__find_class_by_id(self->cu,
							   self->type);
		if (class != NULL)
			size = class__size(class);
	}

	if (self->tag == DW_TAG_array_type)
		size *= self->nr_entries;

	return size;
}

static const char *class__name(struct class *self, char *bf, size_t len)
{
	if (self->tag == DW_TAG_pointer_type) {
		if (self->type == 0) /* No type == void */
			strncpy(bf, "void *", len);
		else {
			struct class *ptr_class =
					cu__find_class_by_id(self->cu, self->type);

			if (ptr_class != NULL) {
				char ptr_class_name[128];
				snprintf(bf, len, "%s *",
					 class__name(ptr_class, ptr_class_name,
						     sizeof(ptr_class_name)));
			}
		}
	} else if (self->tag == DW_TAG_volatile_type ||
		   self->tag == DW_TAG_const_type) {
		struct class *vol_class = cu__find_class_by_id(self->cu,
							       self->type);
		if (vol_class != NULL) {
			char vol_class_name[128];
			snprintf(bf, len, "%s %s ",
				 self->tag == DW_TAG_volatile_type ?
				 	"volatile" : "const",
				 class__name(vol_class, vol_class_name,
					     sizeof(vol_class_name)));
		}
	} else if (self->tag == DW_TAG_array_type) {
		struct class *ptr_class = cu__find_class_by_id(self->cu,
							       self->type);
		if (ptr_class != NULL)
			return class__name(ptr_class, bf, len);
	} else
		snprintf(bf, len, "%s%s", tag_name(self->tag),
			 self->name ?: "");
	return bf;
}

static const char *variable__type_name(struct variable *self,
				       char *bf, size_t len)
{
	if (self->type != 0) {
		struct class *class = cu__find_class_by_id(self->cu,
							   self->type);
		if (class == NULL)
			return NULL;
		return class__name(class, bf, len);
	} else if (self->abstract_origin != 0) {
		struct variable *var;

		var = cu__find_variable_by_id(self->cu, self->abstract_origin);
		if (var != NULL)
		       return variable__type_name(var, bf, len);
	}
	
	return NULL;
}

static const char *variable__name(struct variable *self)
{
	if (self->name == NULL) {
		if (self->abstract_origin == 0)
			return NULL;
		else {
			struct variable *var;

			var = cu__find_variable_by_id(self->cu, self->abstract_origin);
			return var == NULL ? NULL : var->name;
		}
	}
	
	return self->name;
}

static struct class_member *class_member__new(uint64_t type,
					      const char *name,
					      uint64_t offset,
					      unsigned int bit_size,
					      unsigned int bit_offset)
{
	struct class_member *self = zalloc(sizeof(*self));

	if (self != NULL) {
		self->type	  = type;
		self->offset	  = offset;
		self->bit_size	  = bit_size;
		self->bit_offset  = bit_offset;
		self->name	  = strings__add(name);
	}

	return self;
}

static int class_member__size(const struct class_member *self)
{
	struct class *class = cu__find_class_by_id(self->class->cu, self->type);
	return class != NULL ? class__size(class) : -1;
}

uint64_t class_member__names(const struct class_member *self,
			     char *class_name, size_t class_name_size,
			     char *member_name, size_t member_name_size)
{
	struct class *class = cu__find_class_by_id(self->class->cu, self->type);
	uint64_t size = -1;

	snprintf(member_name, member_name_size, "%s;", self->name ?: "");

	if (class == NULL)
		snprintf(class_name, class_name_size, "<%llx>",
			 self->type);
	else {
		size = class__size(class);

		/* Is it a function pointer? */
		if (class->tag == DW_TAG_pointer_type) {
			struct class *ptr_class =
					cu__find_class_by_id(self->class->cu, class->type);

			if (ptr_class != NULL &&
			    ptr_class->tag == DW_TAG_subroutine_type) {
				/* function has no return value (void) */
				if (ptr_class->type == 0)
					snprintf(class_name,
						 class_name_size, "void");
				else {
					struct class *ret_class =
					  cu__find_class_by_id(self->class->cu,
							       ptr_class->type);

					if (ret_class != NULL)
						class__name(ret_class,
							    class_name,
							    class_name_size);
				}
				snprintf(member_name, member_name_size,
					 "(*%s)();", self->name ?: "");
				goto out;
			}
		}

		class__name(class, class_name, class_name_size);
		if (class->tag == DW_TAG_array_type)
			snprintf(member_name, member_name_size,
				 "%s[%llu];", self->name ?: "",
				 class->nr_entries);
		else if (self->bit_size != 0)
			snprintf(member_name, member_name_size,
				 "%s:%d;", self->name ?: "",
				 self->bit_size);
	}
out:
	return size;
}

static uint64_t class_member__print(struct class_member *self)
{
	uint64_t size;
	char class_name[128];
	char member_name[128];

	size = class_member__names(self, class_name, sizeof(class_name),
				   member_name, sizeof(member_name));

	printf("        %-26s %-21s /* %5llu %5llu */\n",
	       class_name, member_name, self->offset, size);
	return size;
}

static struct inline_expansion *inline_expansion__new(uint64_t type,
						      uint64_t size)
{
	struct inline_expansion *self = zalloc(sizeof(*self));

	if (self != NULL) {
		self->type = type;
		self->size = size;
	}

	return self;
}

static struct class *class__new(const unsigned int tag,
				uint64_t cu_offset, uint64_t type,
				const char *name, uint64_t size,
				const char *decl_file, unsigned int decl_line,
				unsigned short inlined,
				uint64_t low_pc, uint64_t high_pc)
{
	struct class *self = malloc(sizeof(*self));

	if (self != NULL) {
		INIT_LIST_HEAD(&self->members);
		INIT_LIST_HEAD(&self->variables);
		INIT_LIST_HEAD(&self->inline_expansions);
		self->tag	  = tag;
		self->cu	  = NULL;
		self->id	  = cu_offset;
		self->type	  = type;
		self->size	  = size;
		self->name	  = strings__add(name);
		self->decl_file	  = strings__add(decl_file);
		self->decl_line	  = decl_line;
		self->nr_holes	  = 0;
		self->nr_labels	  = 0;
		self->nr_members  = 0;
		self->nr_variables = 0;
		self->refcnt	  = 0;
		self->padding	  = 0;
		self->nr_inline_expansions = 0;
		self->size_inline_expansions = 0;
		self->inlined	  = inlined;
		self->low_pc	  = low_pc;
		self->high_pc	  = high_pc;
		self->cu_total_nr_inline_expansions = 0;
		self->cu_total_size_inline_expansions = 0;
		self->diff	  = 0;
		self->class_to_diff = NULL;
	}

	return self;
}

static void class__add_member(struct class *self, struct class_member *member)
{
	++self->nr_members;
	member->class = self;
	list_add_tail(&member->node, &self->members);
}

static void class__add_inline_expansion(struct class *self,
					struct inline_expansion *exp)
{
	++self->nr_inline_expansions;
	exp->class = self;
	self->size_inline_expansions += exp->size;
	list_add_tail(&exp->node, &self->inline_expansions);
}

static void class__add_variable(struct class *self, struct variable *var)
{
	++self->nr_variables;
	list_add_tail(&var->class_node, &self->variables);
}

void class__find_holes(struct class *self)
{
	struct class_member *pos, *last = NULL;
	uint64_t last_size = 0, size;

	self->nr_holes = 0;

	list_for_each_entry(pos, &self->members, node) {
		 if (last != NULL) {
			 const int cc_last_size = pos->offset - last->offset;

			 /*
			  * If the offset is the same this better
			  * be a bitfield or an empty struct (see
			  * rwlock_t in the Linux kernel sources when
			  * compiled for UP) or...
			  */
			 if (cc_last_size > 0) {
				 last->hole = cc_last_size - last_size;
				 if (last->hole > 0)
					 ++self->nr_holes;
			 }
		 }

		 size = class_member__size(pos);
		 /*
		  * check for bitfields, accounting for only the biggest
		  * of the byte_size in the fields in each bitfield set.
		  */
		 if (last == NULL || last->offset != pos->offset ||
		     pos->bit_size == 0 || last->bit_size == 0) {
			 last_size = size;
		 } else if (size > last_size)
			last_size = size;

		 last = pos;
	}

	if (last != NULL && last->offset + last_size != self->size)
		self->padding = self->size - (last->offset + last_size);
}

struct class_member *class__find_member_by_name(const struct class *self,
						const char *name)
{
	struct class_member *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, &self->members, node)
		if (pos->name != NULL && strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

static void class__account_inline_expansions(struct class *self)
{
	struct class *class_type;
	struct inline_expansion *pos;

	if (self->nr_inline_expansions == 0)
		return;

	list_for_each_entry(pos, &self->inline_expansions, node) {
		class_type = cu__find_class_by_id(self->cu, pos->type);
		if (class_type != NULL) {
			class_type->cu_total_nr_inline_expansions++;
			class_type->cu_total_size_inline_expansions += pos->size;
		}

	}
}

void cu__account_inline_expansions(struct cu *self)
{
	struct class *pos;

	list_for_each_entry(pos, &self->classes, node) {
		class__account_inline_expansions(pos);
		self->nr_inline_expansions   += pos->nr_inline_expansions;
		self->size_inline_expansions += pos->size_inline_expansions;
	}
}

void class__print_inline_expansions(struct class *self)
{
	char bf[256];
	struct class *class_type;
	const char *type = "<ERROR>";
	struct inline_expansion *pos;

	if (self->nr_inline_expansions == 0)
		return;

	printf("/* inline expansions in %s:\n", self->name);
	list_for_each_entry(pos, &self->inline_expansions, node) {
		type = "<ERROR>";
		class_type = cu__find_class_by_id(self->cu, pos->type);
		if (class_type != NULL)
			type = class__name(class_type, bf, sizeof(bf));
		printf("%s: %llu\n", type, pos->size);
	}
	fputs("*/\n", stdout);
}

void class__print_variables(struct class *self)
{
	struct variable *pos;

	if (self->nr_variables == 0)
		return;

	printf("{\n        /* variables in %s: */\n", self->name);
	list_for_each_entry(pos, &self->variables, class_node) {
		char bf[256];
		printf("        %s %s;\n", 
		       variable__type_name(pos, bf, sizeof(bf)),
		       variable__name(pos));
	}
	fputs("}\n", stdout);
}

static void class__print_function(struct class *self)
{
	char bf[256];
	struct class *class_type;
	const char *type = "<ERROR>";
	struct class_member *pos;
	int first_parameter = 1;

	if (self->type == 0)
		type = "void";
	else {
		class_type = cu__find_class_by_id(self->cu, self->type);
		if (class_type != NULL)
			type = class__name(class_type, bf, sizeof(bf));
	}

	printf("%s%s %s(", self->inlined ? "inline " : "",
	       type, self->name ?: "");
	list_for_each_entry(pos, &self->members, node) {
		if (!first_parameter)
			fputs(", ", stdout);
		else
			first_parameter = 0;
		type = "<ERROR>";
		class_type = cu__find_class_by_id(self->cu, pos->type);
		if (class_type != NULL)
			type = class__name(class_type, bf, sizeof(bf));
		printf("%s %s", type, pos->name ?: "");
	}

	/* No parameters? */
	if (first_parameter)
		fputs("void", stdout);
	fputs(");\n", stdout);
	if (self->size == 0)
		return;
	printf("/* size: %llu", self->high_pc - self->low_pc);
	if (self->nr_variables > 0)
		printf(", variables: %u", self->nr_variables);
	if (self->nr_labels > 0)
		printf(", goto labels: %u", self->nr_labels);
	if (self->nr_inline_expansions > 0)
		printf(", inline expansions: %u (%u bytes)",
		       self->nr_inline_expansions, self->size_inline_expansions);
	fputs(" */\n", stdout);
}

static void class__print_struct(struct class *self)
{
	unsigned long sum = 0;
	unsigned long sum_holes = 0;
	struct class_member *pos;
	char name[128];
	uint64_t last_size = 0, size;
	int last_bit_size = 0;
	int last_offset = -1;

	printf("%s {\n", class__name(self, name, sizeof(name)));
	list_for_each_entry(pos, &self->members, node) {
		if (sum > 0 && last_size > 0 && sum % cacheline_size == 0)
			printf("        /* ---------- cacheline "
			       "%lu boundary ---------- */\n",
			       sum / cacheline_size);
		 size = class_member__print(pos);
		 if (pos->hole > 0) {
			printf("\n        /* XXX %d bytes hole, "
			       "try to pack */\n\n", pos->hole);
			sum_holes += pos->hole;
		 }
		 /*
		  * check for bitfields, accounting for only the biggest
		  * of the byte_size in the fields in each bitfield set.
		  */
		 if (last_offset != pos->offset ||
		     pos->bit_size == 0 || last_bit_size == 0) {
			 last_size = size;
			 sum += last_size;
		 } else if (size > last_size) {
			sum += size - last_size;
			last_size = size;
		 }

		 last_offset = pos->offset;
		 last_bit_size = pos->bit_size;
	}

	printf("}; /* size: %llu", self->size);
	if (sum_holes > 0)
		printf(", sum members: %lu, holes: %d, sum holes: %lu",
		       sum, self->nr_holes, sum_holes);
	if (self->padding > 0)
		printf(", padding: %u", self->padding);
	puts(" */");

	if (sum + sum_holes != self->size - self->padding)
		printf("\n/* BRAIN FART ALERT! %llu != "
		       "%lu + %lu(holes), diff = %llu */\n\n",
		       self->size, sum, sum_holes,
		       self->size - (sum + sum_holes));
	putchar('\n');
}

void class__print(struct class *self)
{
	printf("/* %s:%u */\n", self->decl_file, self->decl_line);

	switch (self->tag) {
	case DW_TAG_structure_type:
		class__print_struct(self);
		break;
	case DW_TAG_subprogram:
		class__print_function(self);
		break;
	default:
		printf("%s%s;\n", tag_name(self->tag), self->name ?: "");
		break;
	}
	putchar('\n');
}

int cu__for_each_class(struct cu *cu,
			int (*iterator)(struct class *class, void *cookie),
			void *cookie)
{

	struct class *pos;

	list_for_each_entry(pos, &cu->classes, node)
		if (iterator(pos, cookie))
			return 1;
	return 0;
}

void cus__for_each_cu(struct cus *self,
		      int (*iterator)(struct cu *cu, void *cookie),
		      void *cookie)
{
	struct cu *pos;

	list_for_each_entry(pos, &self->cus, node)
		if (iterator(pos, cookie))
			break;
}

void cus__print_classes(struct cus *self, const unsigned int tag)
{
	struct cu *cu_pos;

	list_for_each_entry(cu_pos, &self->cus, node) {
		struct class *class_pos;

		list_for_each_entry(class_pos, &cu_pos->classes, node)
			if (class_pos->tag == tag && class_pos->name != NULL) {
				if (tag == DW_TAG_structure_type)
					class__find_holes(class_pos);
				class__print(class_pos);
			}
	}
}

static struct class *cu__current_class;
static struct cu *current_cu;
static unsigned int current_cu_id;

static void oom(const char *msg)
{
	fprintf(stderr, "pahole: out of memory(%s)\n", msg);
	exit(EXIT_FAILURE);
}

static const char *attr_string(Dwarf_Die *die, unsigned int name,
			       Dwarf_Attribute *attr)
{
	if (dwarf_attr(die, name, attr) != NULL)
		return dwarf_formstring(attr);
	return NULL;
}

/* Number decoding macros.  See 7.6 Variable Length Data.  */

#define get_uleb128_step(var, addr, nth, break)			\
	__b = *(addr)++;					\
	var |= (uintmax_t) (__b & 0x7f) << (nth * 7);		\
	if ((__b & 0x80) == 0)					\
		break

#define get_uleb128_rest_return(var, i, addrp)			\
	do {							\
		for (; i < 10; ++i) {				\
			get_uleb128_step(var, *addrp, i,	\
					  return var);		\
	}							\
	/* Other implementations set VALUE to UINT_MAX in this	\
	  case. So we better do this as well.  */		\
	return UINT64_MAX;					\
  } while (0)

static uint64_t __libdw_get_uleb128(uint64_t acc, unsigned int i,
				    const unsigned char **addrp)
{
	unsigned char __b;
	get_uleb128_rest_return (acc, i, addrp);
}

#define get_uleb128(var, addr)					\
	do {							\
		unsigned char __b;				\
		var = 0;					\
		get_uleb128_step(var, addr, 0, break);		\
		var = __libdw_get_uleb128 (var, 1, &(addr));	\
	} while (0)


static uint64_t attr_offset(Dwarf_Die *die)
{
	Dwarf_Attribute attr;

	if (dwarf_attr(die, DW_AT_data_member_location, &attr) != NULL) {
      		Dwarf_Block block;

		if (dwarf_formblock(&attr, &block) == 0) {
			uint64_t uleb;
			const unsigned char *data = block.data + 1;
			get_uleb128(uleb, data);
			return uleb;
		}
	}

	return 0;
}

static uint64_t attr_upper_bound(Dwarf_Die *die)
{
	Dwarf_Attribute attr;

	if (dwarf_attr(die, DW_AT_upper_bound, &attr) != NULL) {
      		Dwarf_Word num;

		if (dwarf_formudata(&attr, &num) == 0) {
			return (uintmax_t)num + 1;
		}
	}

	return 0;
}

static uint64_t attr_numeric(Dwarf_Die *die, unsigned int name)
{
	Dwarf_Attribute attr;
	unsigned int form;

	if (dwarf_attr(die, name, &attr) == NULL)
		return 0;

	form = dwarf_whatform(&attr);

	switch (form) {
	case DW_FORM_addr: {
		Dwarf_Addr addr;
		if (dwarf_formaddr(&attr, &addr) == 0)
			return addr;
	}
		break;
	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
	case DW_FORM_sdata:
	case DW_FORM_udata: {
		Dwarf_Word value;
		if (dwarf_formudata(&attr, &value) == 0)
			return value;
	}
		break;
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	case DW_FORM_ref_addr:
	case DW_FORM_ref_udata: {
		Dwarf_Off ref;
		if (dwarf_formref(&attr, &ref) == 0)
			return (uintmax_t)ref;
	}
	default:
		printf("DW_AT_<0x%x>=0x%x\n", name, form);
		break;
	}

	return 0;
}

static void cu__process_die(Dwarf *dwarf, Dwarf_Die *die)
{
	Dwarf_Die child;
	Dwarf_Off cu_offset;
	Dwarf_Attribute attr_name;
	const char *name;
	uint64_t type;
	unsigned int tag = dwarf_tag(die);

	if (tag == DW_TAG_invalid)
		return;

	/* Tags we trow away */
	if (tag == DW_TAG_compile_unit)
		goto children;

	cu_offset = dwarf_cuoffset(die);
	name	  = attr_string(die, DW_AT_name, &attr_name);
	type	  = attr_numeric(die, DW_AT_type);

	if (tag == DW_TAG_member || tag == DW_TAG_formal_parameter) {
		struct class_member *member;
		
		member = class_member__new(type, name, attr_offset(die),
					   attr_numeric(die, DW_AT_bit_size),
					   attr_numeric(die, DW_AT_bit_offset));
		if (member == NULL)
			oom("class_member__new");

		class__add_member(cu__current_class, member);
	} else if (tag == DW_TAG_subrange_type)
		cu__current_class->nr_entries = attr_upper_bound(die);
	else if (tag == DW_TAG_variable) {
		uint64_t abstract_origin = attr_numeric(die,
							DW_AT_abstract_origin);
		struct variable *variable;

		variable = variable__new(name, cu_offset,
					 type, abstract_origin);
		if (variable == NULL)
			oom("variable__new");

		class__add_variable(cu__current_class, variable);
		cu__add_variable(current_cu, variable);
	} else if (tag == DW_TAG_label)
		++cu__current_class->nr_labels;
	else if (tag == DW_TAG_inlined_subroutine) {
		Dwarf_Addr high_pc, low_pc;
		if (dwarf_highpc(die, &high_pc)) high_pc = 0;
		if (dwarf_lowpc(die, &low_pc)) low_pc = 0;
		const uintmax_t	type  = attr_numeric(die, DW_AT_abstract_origin);
		uint64_t size = high_pc - low_pc;
		struct inline_expansion *exp;

		if (size == 0) {
			Dwarf_Addr base, start, end;
			ptrdiff_t offset = 0;

			while (1) {
				offset = dwarf_ranges(die, offset, &base, &start, &end);
				if (offset <= 0)
					break;
				size += end - start;
			}
		}

		exp = inline_expansion__new(type, size);
		if (exp == NULL)
			oom("inline_expansion__new");

		class__add_inline_expansion(cu__current_class, exp);
		goto next_sibling;
	} else if (tag == DW_TAG_lexical_block) {
		/*
		 * Not handled right now,
		 * will be used for stack size calculation
		 */
	} else {
		uint64_t size = attr_numeric(die, DW_AT_byte_size);
		const unsigned short inlined = attr_numeric(die, DW_AT_inline);
		Dwarf_Addr high_pc, low_pc;
		if (dwarf_highpc(die, &high_pc)) high_pc = 0;
		if (dwarf_lowpc(die, &low_pc)) low_pc = 0;
		const char *decl_file  = dwarf_decl_file(die);
		int decl_line = 0;

		dwarf_decl_line(die, &decl_line);

		if (cu__current_class != NULL)
			cu__add_class(current_cu, cu__current_class);
	    
		cu__current_class = class__new(tag, cu_offset,
						    type, name, size,
						    decl_file, decl_line,
						    inlined, low_pc, high_pc);
		if (cu__current_class == NULL)
			oom("class__new");
	}

children:
	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		cu__process_die(dwarf, &child);
next_sibling:
	if (dwarf_siblingof (die, die) == 0)
		cu__process_die(dwarf, die);
}

int cus__load(struct cus *self)
{
	Dwarf_Off offset, last_offset, abbrev_offset;
	uint8_t addr_size, offset_size;
	size_t hdr_size;
	Dwarf *dwarf;
	int err = -1;
	int fd = open(self->filename, O_RDONLY);	

	if (fd < 0)
		goto out;

	dwarf = dwarf_begin(fd, DWARF_C_READ);
	if (dwarf == NULL)
		goto out_close;

	offset = last_offset = 0;
	while (dwarf_nextcu(dwarf, offset, &offset, &hdr_size,
			    &abbrev_offset, &addr_size, &offset_size) == 0) {
		Dwarf_Die die;

		if (dwarf_offdie(dwarf, last_offset + hdr_size, &die) != NULL) {
			Dwarf_Attribute name;
			current_cu = cu__new(current_cu_id,
					     attr_string(&die, DW_AT_name,
						     	 &name));
			if (current_cu == NULL)
				oom("cu__new");
			++current_cu_id;
			cu__process_die(dwarf, &die);
			cus__add(self, current_cu);
		}

		last_offset = offset;
	}

	dwarf_end(dwarf);
	err = 0;
out_close:
	close(fd);
out:
	return err;
}

struct cus *cus__new(const char *filename)
{
	struct cus *self = malloc(sizeof(*self));

	if (self != NULL) {
		INIT_LIST_HEAD(&self->cus);
		self->filename = strings__add(filename);
	}

	return self;
}
