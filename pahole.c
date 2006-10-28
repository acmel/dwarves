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

static LIST_HEAD(classes);

const char *tag_name(const unsigned int tag)
{
	switch (tag) {
	case DW_TAG_enumeration_type:	return "enum ";
	case DW_TAG_structure_type:	return "struct ";
	case DW_TAG_union_type:		return "union ";
	case DW_TAG_pointer_type:	return " *";
	}

	return "";
}

struct class *find_class_by_name(const char *name)
{
	struct class *pos;

	list_for_each_entry(pos, &classes, node)
		if (strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

struct class *find_class_by_type(const struct cu_info *type)
{
	struct class *pos;

	list_for_each_entry(pos, &classes, node)
		if (pos->id.cu	   == type->cu &&
		    pos->id.offset == type->offset)
			return pos;

	return NULL;
}

const unsigned long class__size(struct class *self)
{
	unsigned long size = self->size;

	if (self->tag != DW_TAG_pointer_type && self->type.offset != 0) {
		struct class *class = find_class_by_type(&self->type);
		
		if (class != NULL)
			size = class__size(class);
	}

	if (self->tag == DW_TAG_array_type)
		size *= self->nr_entries;

	return size;
}

const char *class__name(struct class *self, char *bf, size_t len)
{
	if (self->tag == DW_TAG_pointer_type) {
		if (self->type.offset == 0) /* No type == void */
			strncpy(bf, "void *", len);
		else {
			struct class *ptr_class = find_class_by_type(&self->type);

			if (ptr_class != NULL) {
				char ptr_class_name[128];
				snprintf(bf, len, "%s *",
					 class__name(ptr_class,
						     ptr_class_name,
						     sizeof(ptr_class_name)));
			}
		}
	} else if (self->tag == DW_TAG_volatile_type ||
		   self->tag == DW_TAG_const_type) {
		struct class *vol_class = find_class_by_type(&self->type);

		if (vol_class != NULL) {
			char vol_class_name[128];
			snprintf(bf, len, "%s %s ",
				 self->tag == DW_TAG_volatile_type ?
				 	"volatile" : "const",
				 class__name(vol_class,
					     vol_class_name,
					     sizeof(vol_class_name)));
		}
	} else if (self->tag == DW_TAG_array_type) {
		struct class *ptr_class = find_class_by_type(&self->type);

		if (ptr_class != NULL)
			return class__name(ptr_class, bf, len);
	} else
		snprintf(bf, len, "%s%s", tag_name(self->tag), self->name);
	return bf;
}

struct class_member *class_member__new(unsigned int cu,
				       uintmax_t type,
				       const char *name,
				       unsigned int offset,
				       unsigned int bit_size,
				       unsigned int bit_offset)
{
	struct class_member *self = zalloc(sizeof(*self));

	if (self != NULL) {
		self->type.cu	  = cu;
		self->type.offset = type;
		self->offset	  = offset;
		self->bit_size	  = bit_size;
		self->bit_offset  = bit_offset;

		if (name != NULL)
			strncpy(self->name, name, sizeof(self->name));
	}

	return self;
}

unsigned long class_member__print(struct class_member *self)
{
	struct class *class = find_class_by_type(&self->type);
	char class_name_bf[128];
	char member_name_bf[128];
	char bf[512];
	const char *class_name = bf;
	unsigned long size = -1;

	snprintf(member_name_bf, sizeof(member_name_bf),
		 "%s;", self->name);

	if (class == NULL)
		snprintf(bf, sizeof(bf), "<%x>", self->type.offset);
	else {
		size = class__size(class);

		/* Is it a function pointer? */
		if (class->tag == DW_TAG_pointer_type) {
			struct class *ptr_class = find_class_by_type(&class->type);

			if (ptr_class != NULL &&
			    ptr_class->tag == DW_TAG_subroutine_type) {
				/* function has no return value (void) */
				if (ptr_class->type.offset == 0)
					strcpy(bf, "void");
				else {
					struct class *ret_class =
					find_class_by_type(&ptr_class->type);

					if (ret_class != NULL)
						class_name = class__name(ret_class,
									 class_name_bf,
									 sizeof(class_name_bf));
				}
				snprintf(member_name_bf, sizeof(member_name_bf),
					 "(*%s)();", self->name);
				goto out;
			}
		}

		class_name = class__name(class, class_name_bf, sizeof(class_name_bf));
		if (class->tag == DW_TAG_array_type)
			snprintf(member_name_bf, sizeof(member_name_bf),
				 "%s[%lu];", self->name, class->nr_entries);
		else if (self->bit_size != 0)
			snprintf(member_name_bf, sizeof(member_name_bf),
				 "%s:%d;", self->name, self->bit_size);
	}
out:
	printf("        %-26s %-21s /* %5d %5lu */\n",
	       class_name, member_name_bf, self->offset, size);
	return size;
}

struct class *class__new(const unsigned int tag,
			 unsigned int cu,
			 uintmax_t cu_offset,
			 uintmax_t type,
			 const char *name,
			 unsigned int size,
			 const char *decl_file,
			 unsigned int decl_line)
{
	struct class *self = malloc(sizeof(*self));

	if (self != NULL) {
		INIT_LIST_HEAD(&self->members);
		self->tag	  = tag;
		self->id.cu	  = cu;
		self->id.offset   = cu_offset;
		self->type.cu	  = cu;
		self->type.offset = type;
		self->size	  = size;
		self->name[0]	  = '\0';
		if (name != NULL)
			strncpy(self->name, name, sizeof(self->name));
		self->decl_file	  = decl_file;
		self->decl_line	  = decl_line;
	}

	return self;
}

void class__add_member(struct class *self, struct class_member *member)
{
	list_add_tail(&member->node, &self->members);
}

void class__print_struct(struct class *self)
{
	unsigned long sum = 0;
	unsigned long sum_holes = 0;
	unsigned int nr_holes = 0;
	struct class_member *pos;
	char name[128];
	size_t last_size = 0, size;
	int last_bit_size = 0;
	int last_offset = -1;

	printf("/* %s %u */\n", self->decl_file, self->decl_line);
	printf("%s {\n", class__name(self, name, sizeof(name)));
	list_for_each_entry(pos, &self->members, node) {
		 if (sum > 0) {
			 const size_t cc_last_size = pos->offset - last_offset;

			 /*
			  * If the offset is the same this better
			  * be a bitfield or an empty struct (see
			  * rwlock_t in the Linux kernel sources when
			  * compiled for UP) or...
			  */
			 if (cc_last_size > 0) {
				 const size_t hole = cc_last_size - last_size;

				 if (hole > 0) {
					 printf("\n        /* XXX %d bytes hole, "
						"try to pack */\n\n", hole);
					 sum_holes += hole;
					 ++nr_holes;
				}
			 } else if (pos->bit_size == 0 && last_size != 0)
				printf("\n/* BRAIN FART ALERT! not a bitfield "
					" and the offset hasn't changed. */\n\n",
				       self->size, sum, sum_holes);
		 }

		 size = class_member__print(pos);
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

	if (last_offset != -1 && last_offset + last_size != self->size) {
		const size_t hole = self->size - (last_offset + last_size);

		printf("  /* %d bytes hole, try to pack */\n", hole);
		sum_holes += hole;
		++nr_holes;
	}

	printf("}; /* sizeof(struct %s): %d", self->name, self->size);
	if (sum_holes > 0)
		printf(", sum sizeof members: %lu, \n      "
		       "holes: %d, sum holes: %lu",
		       sum, nr_holes, sum_holes);
	puts(" */");

	if (sum + sum_holes != self->size)
		printf("\n/* BRAIN FART ALERT! %d != %d + %d(holes), diff = %d */\n\n",
		       self->size, sum, sum_holes,
		       self->size - (sum + sum_holes));
	putchar('\n');
	putchar('\n');
}

void class__print(struct class *self)
{
	switch (self->tag) {
	case DW_TAG_structure_type:
		class__print_struct(self);
		break;
	default:
		printf("%s%s;\n", tag_name(self->tag), self->name);
		break;
	}
}

void add_class(struct class *class)
{
	list_add_tail(&class->node, &classes);
}

void print_classes(const unsigned int tag)
{
	struct class *pos;

	list_for_each_entry(pos, &classes, node)
		if (pos->tag == tag && pos->name[0] != '\0')
			class__print(pos);
}

static struct class *current_class;
static unsigned int current_cu;

void oom(const char *msg)
{
	fprintf(stderr, "pahole: out of memory(%s)\n", msg);
	exit(EXIT_FAILURE);
}

const char *attr_string(Dwarf_Die *die, unsigned int name,
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

uint64_t __libdw_get_uleb128(uint64_t acc, unsigned int i,
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


unsigned int attr_offset(Dwarf_Die *die)
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

uintmax_t attr_upper_bound(Dwarf_Die *die)
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

uintmax_t attr_numeric(Dwarf_Die *die, unsigned int name)
{
	Dwarf_Attribute attr;
	unsigned int form;

	if (dwarf_attr(die, name, &attr) == NULL)
		return 0;

	form = dwarf_whatform(&attr);

	switch (form) {
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

void process_die(Dwarf *dwarf, Dwarf_Die *die)
{
	Dwarf_Die child;
	Dwarf_Off cu_offset;
	Dwarf_Attribute attr_name;
	const char *name, *decl_file;
	uintmax_t type, nr_entries;
	unsigned int size, bit_size, bit_offset, offset, decl_line = 0;
	unsigned int tag = dwarf_tag(die);

	if (tag == DW_TAG_invalid)
		return;

	cu_offset  = dwarf_cuoffset(die);
	name	   = attr_string(die, DW_AT_name, &attr_name);
	type	   = attr_numeric(die, DW_AT_type);
	size	   = attr_numeric(die, DW_AT_byte_size);
	bit_size   = attr_numeric(die, DW_AT_bit_size);
	bit_offset = attr_numeric(die, DW_AT_bit_offset);
	decl_file  = dwarf_decl_file(die);
	dwarf_decl_line(die, &decl_line);
	nr_entries = attr_upper_bound(die);
	offset	   = attr_offset(die);

	if (tag == DW_TAG_member) {
		struct class_member *member;
		
		member = class_member__new(current_cu, type, name, offset,
					   bit_size, bit_offset);
		if (member == NULL)
			oom("class_member__new");

		class__add_member(current_class, member);
	} else if (tag == DW_TAG_subrange_type)
		current_class->nr_entries = nr_entries;
	else {
		if (current_class != NULL)
			add_class(current_class);
	    
		current_class = class__new(tag, current_cu, cu_offset,
					   type, name, size,
					   decl_file, decl_line);
		if (current_class == NULL)
			oom("class__new");
	}

	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		process_die(dwarf, &child);
	if (dwarf_siblingof (die, die) == 0)
		process_die(dwarf, die);
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
			++current_cu;
			process_die(dwarf, &die);
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

int main(int argc, char *argv[])
{
	if (argc == 0) {
		puts("usage: "
		     "pahole <elf_file_with_debug_info> {<struct_name>}");
		return EXIT_FAILURE;
	}

	if (classes__load(argv[1]) != 0) {
		fprintf(stderr, "pahole: couldn't load DWARF info from %s\n",
		       argv[1]);
		return EXIT_FAILURE;
	}

	if (argc == 2)
		print_classes(DW_TAG_structure_type);
	else {
		struct class *class = find_class_by_name(argv[2]);
		if (class != NULL)
			class__print(class);
		else
			printf("struct %s not found!\n", argv[2]);
	}

	return EXIT_SUCCESS;
}
