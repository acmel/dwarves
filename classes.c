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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "list.h"
#include "classes.h"

static void *zalloc(const size_t size)
{
	void *s = malloc(size);
	if (s != NULL)
		memset(s, 0, size);
	return s;
}

static LIST_HEAD(cus__list);

static void cus__add(struct cu *cu)
{
	list_add_tail(&cu->node, &cus__list);
}

static struct cu *cu__new(unsigned int cu)
{
	struct cu *self = malloc(sizeof(*self));

	if (self != NULL)
		INIT_LIST_HEAD(&self->classes);

	return self;
}

static void cu__add(struct cu *self, struct class *class)
{
	list_add_tail(&class->node, &self->classes);
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

struct class *cu__find_class_by_name(struct cu *self, const char *name)
{
	struct class *pos;

	list_for_each_entry(pos, &self->classes, node)
		if (pos->name != NULL && strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

struct class *cus__find_class_by_name(struct cu **cu, const char *name)
{
	struct cu *cu_pos;

	list_for_each_entry(cu_pos, &cus__list, node) {
		struct class *class = cu__find_class_by_name(cu_pos, name);

		if (class != NULL) {
			*cu = cu_pos;
			return class;
		}
	}

	return NULL;
}

struct class *cu__find_class_by_id(const struct cu *self, const unsigned int id)
{
	struct class *pos;

	list_for_each_entry(pos, &self->classes, node)
		if (pos->id == id)
			return pos;

	return NULL;
}

static const unsigned long class__size(const struct class *self,
				       const struct cu *cu)
{
	unsigned long size = self->size;

	if (self->tag != DW_TAG_pointer_type && self->type != 0) {
		struct class *class = cu__find_class_by_id(cu, self->type);
		
		if (class != NULL)
			size = class__size(class, cu);
	}

	if (self->tag == DW_TAG_array_type)
		size *= self->nr_entries;

	return size;
}

static const char *class__name(struct class *self, const struct cu *cu,
			       char *bf, size_t len)
{
	if (self->tag == DW_TAG_pointer_type) {
		if (self->type == 0) /* No type == void */
			strncpy(bf, "void *", len);
		else {
			struct class *ptr_class =
					cu__find_class_by_id(cu, self->type);

			if (ptr_class != NULL) {
				char ptr_class_name[128];
				snprintf(bf, len, "%s *",
					 class__name(ptr_class, cu,
						     ptr_class_name,
						     sizeof(ptr_class_name)));
			}
		}
	} else if (self->tag == DW_TAG_volatile_type ||
		   self->tag == DW_TAG_const_type) {
		struct class *vol_class = cu__find_class_by_id(cu, self->type);

		if (vol_class != NULL) {
			char vol_class_name[128];
			snprintf(bf, len, "%s %s ",
				 self->tag == DW_TAG_volatile_type ?
				 	"volatile" : "const",
				 class__name(vol_class, cu,
					     vol_class_name,
					     sizeof(vol_class_name)));
		}
	} else if (self->tag == DW_TAG_array_type) {
		struct class *ptr_class = cu__find_class_by_id(cu, self->type);

		if (ptr_class != NULL)
			return class__name(ptr_class, cu, bf, len);
	} else
		snprintf(bf, len, "%s%s", tag_name(self->tag),
			 self->name ?: "");
	return bf;
}

static struct class_member *class_member__new(uintmax_t type,
					      const char *name,
					      unsigned int offset,
					      unsigned int bit_size,
					      unsigned int bit_offset)
{
	struct class_member *self = zalloc(sizeof(*self));

	if (self != NULL) {
		self->type	  = type;
		self->offset	  = offset;
		self->bit_size	  = bit_size;
		self->bit_offset  = bit_offset;

		if (name != NULL)
			self->name = strdup(name);
	}

	return self;
}

static int class_member__size(const struct class_member *self,
			      const struct cu *cu)
{
	struct class *class = cu__find_class_by_id(cu, self->type);
	return class != NULL ? class__size(class, cu) : -1;
}

static unsigned long class_member__print(struct class_member *self,
					 const struct cu *cu)
{
	struct class *class = cu__find_class_by_id(cu, self->type);
	char class_name_bf[128];
	char member_name_bf[128];
	char bf[512];
	const char *class_name = bf;
	unsigned long size = -1;

	snprintf(member_name_bf, sizeof(member_name_bf),
		 "%s;", self->name ?: "");

	if (class == NULL)
		snprintf(bf, sizeof(bf), "<%x>", self->type);
	else {
		size = class__size(class, cu);

		/* Is it a function pointer? */
		if (class->tag == DW_TAG_pointer_type) {
			struct class *ptr_class =
					cu__find_class_by_id(cu, class->type);

			if (ptr_class != NULL &&
			    ptr_class->tag == DW_TAG_subroutine_type) {
				/* function has no return value (void) */
				if (ptr_class->type == 0)
					strcpy(bf, "void");
				else {
					struct class *ret_class =
					  cu__find_class_by_id(cu,
							       ptr_class->type);

					if (ret_class != NULL)
						class_name = class__name(ret_class, cu,
									 class_name_bf,
									 sizeof(class_name_bf));
				}
				snprintf(member_name_bf, sizeof(member_name_bf),
					 "(*%s)();", self->name ?: "");
				goto out;
			}
		}

		class_name = class__name(class, cu, class_name_bf, sizeof(class_name_bf));
		if (class->tag == DW_TAG_array_type)
			snprintf(member_name_bf, sizeof(member_name_bf),
				 "%s[%lu];", self->name ?: "",
				 class->nr_entries);
		else if (self->bit_size != 0)
			snprintf(member_name_bf, sizeof(member_name_bf),
				 "%s:%d;", self->name ?: "",
				 self->bit_size);
	}
out:
	printf("        %-26s %-21s /* %5d %5lu */\n",
	       class_name, member_name_bf, self->offset, size);
	return size;
}

static struct class *class__new(const unsigned int tag,
				uintmax_t cu_offset, uintmax_t type,
				const char *name, unsigned int size,
				const char *decl_file, unsigned int decl_line,
				unsigned short inlined,
				uintmax_t low_pc, uintmax_t high_pc)
{
	struct class *self = malloc(sizeof(*self));

	if (self != NULL) {
		INIT_LIST_HEAD(&self->members);
		self->tag	  = tag;
		self->id	  = cu_offset;
		self->type	  = type;
		self->size	  = size;
		self->name	  = NULL;
		if (name != NULL)
			self->name = strdup(name);
		self->decl_file	  = decl_file;
		self->decl_line	  = decl_line;
		self->nr_holes	  = 0;
		self->nr_labels	  = 0;
		self->nr_members  = 0;
		self->nr_variables = 0;
		self->padding	  = 0;
		self->inlined	  = inlined;
		self->low_pc	  = low_pc;
		self->high_pc	  = high_pc;
	}

	return self;
}

static void class__add_member(struct class *self, struct class_member *member)
{
	++self->nr_members;
	list_add_tail(&member->node, &self->members);
}

void class__find_holes(struct class *self, const struct cu *cu)
{
	struct class_member *pos, *last = NULL;
	int last_size = 0, size;

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

		 size = class_member__size(pos, cu);
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

static void class__print_function(struct class *self, const struct cu *cu)
{
	char bf[256];
	struct class *class_type;
	const char *type = "<ERROR>";
	struct class_member *pos;
	int first_parameter = 1;

	if (self->type == 0)
		type = "void";
	else {
		class_type = cu__find_class_by_id(cu, self->type);
		if (class_type != NULL)
			type = class__name(class_type, cu, bf, sizeof(bf));
	}

	printf("%s%s %s(", self->inlined ? "inline " : "",
	       type, self->name ?: "");
	list_for_each_entry(pos, &self->members, node) {
		if (!first_parameter)
			fputs(", ", stdout);
		else
			first_parameter = 0;
		type = "<ERROR>";
		class_type = cu__find_class_by_id(cu, pos->type);
		if (class_type != NULL)
			type = class__name(class_type, cu, bf, sizeof(bf));
		printf("%s %s", type, pos->name ?: "");
	}

	/* No parameters? */
	if (first_parameter)
		fputs("void", stdout);
	fputs(");\n", stdout);
	printf("/* size: %u", self->high_pc - self->low_pc);
	if (self->nr_variables > 0)
		printf(", variables: %u", self->nr_variables);
	if (self->nr_labels > 0)
		printf(", goto labels: %u", self->nr_labels);
	fputs(" */\n", stdout);
}

static void class__print_struct(struct class *self, const struct cu *cu)
{
	unsigned long sum = 0;
	unsigned long sum_holes = 0;
	struct class_member *pos;
	char name[128];
	size_t last_size = 0, size;
	int last_bit_size = 0;
	int last_offset = -1;

	printf("%s {\n", class__name(self, cu, name, sizeof(name)));
	list_for_each_entry(pos, &self->members, node) {
		 size = class_member__print(pos, cu);
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

	printf("}; /* size: %d", self->size);
	if (sum_holes > 0)
		printf(", sum members: %lu, holes: %d, sum holes: %lu",
		       sum, self->nr_holes, sum_holes);
	if (self->padding > 0)
		printf(", padding: %u", self->padding);
	puts(" */");

	if (sum + sum_holes != self->size - self->padding)
		printf("\n/* BRAIN FART ALERT! %d != %d + %d(holes), diff = %d */\n\n",
		       self->size, sum, sum_holes,
		       self->size - (sum + sum_holes));
	putchar('\n');
}

void class__print(struct class *self, const struct cu *cu)
{
	printf("/* %s:%u */\n", self->decl_file, self->decl_line);

	switch (self->tag) {
	case DW_TAG_structure_type:
		class__print_struct(self, cu);
		break;
	case DW_TAG_subprogram:
		class__print_function(self, cu);
		break;
	default:
		printf("%s%s;\n", tag_name(self->tag), self->name ?: "");
		break;
	}
	putchar('\n');
}

int cu__for_each_class(struct cu *cu,
			int (*iterator)(struct cu *cu,
					struct class *class,
					void *cookie),
			void *cookie)
{

	struct class *pos;

	list_for_each_entry(pos, &cu->classes, node)
		if (iterator(cu, pos, cookie))
			return 1;
	return 0;
}

void cus__for_each_cu(int (*iterator)(struct cu *cu, void *cookie),
		      void *cookie)
{
	struct cu *pos;

	list_for_each_entry(pos, &cus__list, node)
		if (iterator(pos, cookie))
			break;
}

void classes__print(const unsigned int tag)
{
	struct cu *cu_pos;

	list_for_each_entry(cu_pos, &cus__list, node) {
		struct class *class_pos;

		list_for_each_entry(class_pos, &cu_pos->classes, node)
			if (class_pos->tag == tag && class_pos->name != NULL) {
				if (tag == DW_TAG_structure_type) {
					class__find_holes(class_pos, cu_pos);
					if (class_pos->nr_holes == 0)
						continue;
				}
				class__print(class_pos, cu_pos);
			}
	}
}

static struct class *classes__current_class;
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


static unsigned int attr_offset(Dwarf_Die *die)
{
	Dwarf_Attribute attr;

	if (dwarf_attr(die, DW_AT_data_member_location, &attr) != NULL) {
      		Dwarf_Block block;

		if (dwarf_formblock(&attr, &block) == 0) {
			unsigned int uleb;
			const unsigned char *data = block.data + 1;
			get_uleb128(uleb, data);
			return uleb;
		}
	}

	return 0;
}

static uintmax_t attr_upper_bound(Dwarf_Die *die)
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

static uintmax_t attr_numeric(Dwarf_Die *die, unsigned int name)
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

static void classes__process_die(Dwarf *dwarf, Dwarf_Die *die)
{
	Dwarf_Die child;
	Dwarf_Off cu_offset;
	Dwarf_Attribute attr_name;
	const char *name;
	uintmax_t type;
	unsigned int tag = dwarf_tag(die);

	if (tag == DW_TAG_invalid)
		return;

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

		class__add_member(classes__current_class, member);
	} else if (tag == DW_TAG_subrange_type)
		classes__current_class->nr_entries = attr_upper_bound(die);
	else if (tag == DW_TAG_variable)
		++classes__current_class->nr_variables;
	else if (tag == DW_TAG_label)
		++classes__current_class->nr_labels;
	else {
		const unsigned long size = attr_numeric(die, DW_AT_byte_size);
		const unsigned short inlined = attr_numeric(die, DW_AT_inline);
		const uintmax_t	low_pc = attr_numeric(die, DW_AT_low_pc);
		const uintmax_t	high_pc = attr_numeric(die, DW_AT_high_pc);
		const char *decl_file  = dwarf_decl_file(die);
		unsigned int decl_line = 0;

		dwarf_decl_line(die, &decl_line);

		if (classes__current_class != NULL)
			cu__add(current_cu, classes__current_class);
	    
		classes__current_class = class__new(tag, cu_offset,
						    type, name, size,
						    decl_file, decl_line,
						    inlined, low_pc, high_pc);
		if (classes__current_class == NULL)
			oom("class__new");
	}

	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		classes__process_die(dwarf, &child);
	if (dwarf_siblingof (die, die) == 0)
		classes__process_die(dwarf, die);
}

int classes__load(const char *filename)
{
	Dwarf_Off offset, last_offset, abbrev_offset;
	uint8_t addr_size, offset_size;
	size_t hdr_size;
	Dwarf *dwarf;
	int err = -1;
	int fd = open(filename, O_RDONLY);	

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
			current_cu = cu__new(current_cu_id);
			if (current_cu == NULL)
				oom("cu__new");
			++current_cu_id;
			classes__process_die(dwarf, &die);
			cus__add(current_cu);
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
