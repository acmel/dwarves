/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/


#include <dwarf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libdw.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "list.h"

static char bf[4096];

static void *zalloc(const size_t size)
{
	void *s = malloc(size);
	if (s != NULL)
		memset(s, 0, size);
	return s;
}

static LIST_HEAD(classes);

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
};

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

struct class_member {
	struct list_head node;
	char		 name[32];
	struct cu_info	 type;
	unsigned int	 offset;
	unsigned int	 bit_size;
	unsigned int	 bit_offset;
};

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
	const char *class_name = bf;
	char class_name_bf[128];
	char member_name_bf[128];
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
			 unsigned int size)
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
		if (name != NULL)
			strncpy(self->name, name, sizeof(self->name));
	}

	return self;
}

void class__add_member(struct class *self, struct class_member *member)
{
	list_add_tail(&member->node, &self->members);
}

void class__print(struct class *self)
{
	unsigned long sum = 0;
	unsigned long sum_holes = 0;
	struct class_member *pos;
	char name[128];
	size_t last_size = 0, size;
	int last_bit_size = 0;
	int last_offset = -1;

	printf("%56.56s /* offset size */\n", "");
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
	}

	printf("}; /* sizeof struct(%s): %d", self->name, self->size);
	if (sum_holes > 0)
		printf(", sum sizeof members: %lu, sum holes: %lu", sum, sum_holes);
	puts(" */");

	if (sum + sum_holes != self->size)
		printf("\n/* BRAIN FART ALERT! %d != %d + %d(holes), diff = %d */\n\n",
		       self->size, sum, sum_holes,
		       self->size - (sum + sum_holes));
	putchar('\n');
}

void add_class(struct class *class)
{
	list_add_tail(&class->node, &classes);
}

void print_classes(void)
{
	struct class *pos;

	list_for_each_entry(pos, &classes, node)
		if (pos->tag == DW_TAG_structure_type && pos->name[0] != '\0')
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

unsigned int attr_unsigned(Dwarf_Die *die, unsigned int name,
			   Dwarf_Attribute *attr)
{
	Dwarf_Word value = 0;

	if (dwarf_attr(die, name, attr) != NULL)
		dwarf_formudata(attr, &value);

	return value;
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

uintmax_t attr_type(Dwarf_Die *die)
{
	Dwarf_Attribute attr;

	if (dwarf_attr(die, DW_AT_type, &attr) != NULL) {
      		Dwarf_Off ref;

		if (dwarf_formref(&attr, &ref) == 0)
			return (uintmax_t)ref;
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

void process_die(Dwarf *dwarf, Dwarf_Die *die)
{
	Dwarf_Die child;
	Dwarf_Off cu_offset;
	Dwarf_Attribute attr_name, attr_size, attr_bit_size, attr_bit_offset;
	const char *name;
	uintmax_t type, nr_entries;
	unsigned int size, bit_size, bit_offset, offset;
	unsigned int tag = dwarf_tag(die);

	if (tag == DW_TAG_invalid)
		return;

	cu_offset  = dwarf_cuoffset(die);
	name	   = attr_string(die, DW_AT_name, &attr_name);
	type	   = attr_type(die);
	size	   = attr_unsigned(die, DW_AT_byte_size, &attr_size);
	bit_size   = attr_unsigned(die, DW_AT_bit_size, &attr_bit_size);
	bit_offset = attr_unsigned(die, DW_AT_bit_offset, &attr_bit_offset);
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
					   type, name, size);
		if (current_class == NULL)
			oom("class__new");
	}

	if (dwarf_haschildren(die) != 0 && dwarf_child(die, &child) == 0)
		process_die(dwarf, &child);
	if (dwarf_siblingof (die, die) == 0)
		process_die(dwarf, die);
}

int main(int argc, char *argv[])
{
	Dwarf_Off offset, last_offset, abbrev_offset;
	uint8_t addr_size, offset_size;
	size_t hdr_size;
	Dwarf *dwarf;
	int fd;

	if (argc == 0) {
		puts("usage: "
		     "pahole <elf_file_with_debug_info> {<struct_name>}");
		return EXIT_FAILURE;
	}

	fd = open(argv[1], O_RDONLY);	
	if (fd < 0) {
		fprintf(stderr, "pahole: can't open %s\n", argv[1]);
		return EXIT_FAILURE;
	}

	dwarf = dwarf_begin(fd, DWARF_C_READ);
	if (dwarf == NULL) {
		fprintf(stderr, "pahole: %s doesn't seems to have DWARF info\n",
		       argv[1]);
		return EXIT_FAILURE;
	}

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
	close(fd);

	if (argc == 2)
		print_classes();
	else {
		struct class *class = find_class_by_name(argv[2]);
		if (class != NULL)
			class__print(class);
		else
			printf("struct %s not found!\n", argv[2]);
	}

	return 0;
}
