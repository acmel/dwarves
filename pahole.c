/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <getopt.h>
#include <stdio.h>
#include <dwarf.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "dwarves.h"

static uint8_t class__include_anonymous;
static uint8_t class__include_nested_anonymous;

static char *class__exclude_prefix;
static size_t class__exclude_prefix_len;

static char *cu__exclude_prefix;
static size_t cu__exclude_prefix_len;

static char *decl_exclude_prefix;
static size_t decl_exclude_prefix_len;

static uint16_t nr_holes;
static uint16_t nr_bit_holes;
static uint8_t show_packable;
static uint8_t verbose;
static uint8_t expand_types;

struct structure {
	struct list_head   node;
	const struct class *class;
	const struct cu	   *cu;
	uint32_t	   nr_files;
	uint32_t	   nr_methods;
};

static struct structure *structure__new(const struct class *class,
					const struct cu *cu)
{
	struct structure *self = malloc(sizeof(*self));

	if (self != NULL) {
		self->class      = class;
		self->cu         = cu;
		self->nr_files   = 1;
		self->nr_methods = 0;
	}

	return self;
}

static LIST_HEAD(structures__list);

static struct structure *structures__find(const char *name)
{
	struct structure *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, &structures__list, node) {
		const char *class_name = class__name(pos->class);

		if (class_name != NULL &&
		    strcmp(class__name(pos->class), name) == 0)
			return pos;
	}

	return NULL;
}

static void structures__add(const struct class *class, const struct cu *cu)
{
	struct structure *str = structure__new(class, cu);

	if (str != NULL)
		list_add(&str->node, &structures__list);
}

static void nr_definitions_formatter(const struct structure *self)
{
	printf("%s: %u\n", class__name(self->class), self->nr_files);
}

static void nr_members_formatter(const struct structure *self)
{
	printf("%s: %u\n", class__name(self->class),
	       class__nr_members(self->class));
}

static void nr_methods_formatter(const struct structure *self)
{
	printf("%s: %u\n", class__name(self->class), self->nr_methods);
}

static void size_formatter(const struct structure *self)
{
	printf("%s: %u %u\n", class__name(self->class),
	       class__size(self->class), self->class->nr_holes);
}

static void class_name_len_formatter(const struct structure *self)
{
	const char *name = class__name(self->class);
	printf("%s: %u\n", name, strlen(name));
}

static void class_formatter(const struct structure *self)
{
	struct tag *typedef_alias = NULL;
	struct tag *tag = class__tag(self->class);
	const char *name = class__name(self->class);

	if (name == NULL) {
		/*
		 * Find the first typedef for this struct, this is enough
		 * as if we optimize the struct all the typedefs will be
		 * affected.
		 */
		typedef_alias = cu__find_first_typedef_of_type(self->cu,
							       tag->id);
		/*
		 * If there is no typedefs for this anonymous struct it is
		 * found just inside another struct, and in this case it'll
		 * be printed when the type it is in is printed, but if
		 * the user still wants to see its statistics, just use
		 * --nested_anon_include.
		 */
		if (typedef_alias == NULL && !class__include_nested_anonymous)
			return;
	}

	if (typedef_alias != NULL) {
		const struct type *tdef = tag__type(typedef_alias);
		tag__print(tag, self->cu, "typedef", tdef->name, expand_types);
	} else
		tag__print(tag, self->cu, NULL, NULL, expand_types);

	printf("   /* definitions: %u */\n", self->nr_files);
	putchar('\n');
}

static void print_classes(void (*formatter)(const struct structure *s))
{
	struct structure *pos;

	list_for_each_entry(pos, &structures__list, node)
		formatter(pos);
}

static struct cu *cu__filter(struct cu *cu)
{
	if (cu__exclude_prefix != NULL &&
	    (cu->name == NULL ||
	     strncmp(cu__exclude_prefix, cu->name,
		     cu__exclude_prefix_len) == 0))
		return NULL;

	return cu;
}

static int class__packable(const struct class *self)
{
	struct class_member *pos;

	if (self->nr_holes == 0 && self->nr_bit_holes == 0)
		return 0;

	list_for_each_entry(pos, &self->type.members, tag.node)
		if (pos->hole != 0 &&
		    class__find_bit_hole(self, pos, pos->hole * 8) != NULL)
			return 1;
		else if (pos->bit_hole != 0 &&
			 class__find_bit_hole(self, pos, pos->bit_hole) != NULL)
			return 1;

	return 0;
}

static void class__dupmsg(const struct class *self, const struct cu *cu,
			  const struct class *dup __unused,
			  const struct cu *dup_cu,
			  char *hdr, const char *fmt, ...)
{
	va_list args;

	if (!*hdr)
		printf("class: %s\nfirst: %s\ncurrent: %s\n",
		       class__name(self), cu->name, dup_cu->name);

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	*hdr = 1;
}

static void class__chkdupdef(const struct class *self, const struct cu *cu,
			     struct class *dup, const struct cu *dup_cu)
{
	char hdr = 0;

	if (class__size(self) != class__size(dup))
		class__dupmsg(self, cu, dup, dup_cu,
			      &hdr, "size: %u != %u\n",
			      class__size(self), class__size(dup));

	if (class__nr_members(self) != class__nr_members(dup))
		class__dupmsg(self, cu, dup, dup_cu,
			      &hdr, "nr_members: %u != %u\n",
			      class__nr_members(self), class__nr_members(dup));

	if (self->nr_holes != dup->nr_holes)
		class__dupmsg(self, cu, dup, dup_cu,
			      &hdr, "nr_holes: %u != %u\n",
			      self->nr_holes, dup->nr_holes);

	if (self->nr_bit_holes != dup->nr_bit_holes)
		class__dupmsg(self, cu, dup, dup_cu,
			      &hdr, "nr_bit_holes: %u != %u\n",
			      self->nr_bit_holes, dup->nr_bit_holes);

	if (self->padding != dup->padding)
		class__dupmsg(self, cu, dup, dup_cu,
			      &hdr, "padding: %u != %u\n",
			      self->padding, dup->padding);

	/* XXX put more checks here: member types, member ordering, etc */

	if (hdr)
		putchar('\n');
}

static struct tag *tag__filter(struct tag *tag, struct cu *cu,
			       void *cookie __unused)
{
	struct structure *str;
	struct class *class;
	const char *name;

	if (tag->tag != DW_TAG_structure_type)
		return NULL;

	class = tag__class(tag);
	name = class__name(class);

	if (class__is_declaration(class))
		return NULL;

	if (!class__include_anonymous && name == NULL)
		return NULL;

	if (class__exclude_prefix != NULL && name &&
	    strncmp(class__exclude_prefix, name,
		    class__exclude_prefix_len) == 0)
		return NULL;

	if (decl_exclude_prefix != NULL &&
	    (tag->decl_file == NULL ||
	     strncmp(decl_exclude_prefix, tag->decl_file,
		     decl_exclude_prefix_len) == 0))
		return NULL;

	class__find_holes(class, cu);

	if (class->nr_holes < nr_holes ||
	    class->nr_bit_holes < nr_bit_holes)
		return NULL;

	str = structures__find(name);
	if (str != NULL) {
		if (verbose)
			class__chkdupdef(str->class, str->cu, class, cu);
		str->nr_files++;
		return NULL;
	}

	if (show_packable && !class__packable(class))
		return NULL;

	return tag;
}

static int unique_iterator(struct tag *tag, struct cu *cu,
			   void *cookie __unused)
{
	structures__add(tag__class(tag), cu);
	return 0;
}

static int cu_unique_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_tag(cu, unique_iterator, cookie, tag__filter);
}

static struct tag *nr_methods__filter(struct tag *tag, struct cu *cu __unused,
				      void *cookie __unused)
{
	if (tag->tag != DW_TAG_subprogram)
		return NULL;

	if (function__declared_inline(tag__function(tag)))
		return NULL;

	return tag;
}

static int nr_methods_iterator(struct tag *tag, struct cu *cu,
			       void *cookie __unused)
{
	struct parameter *pos;
	struct structure *str;
	struct type *ctype;

	list_for_each_entry(pos, &tag__ftype(tag)->parms, tag.node) {
		struct tag *type =
			cu__find_tag_by_id(cu, parameter__type(pos, cu));

		if (type == NULL || type->tag != DW_TAG_pointer_type)
			continue;

		type = cu__find_tag_by_id(cu, type->type);
		if (type == NULL || type->tag != DW_TAG_structure_type)
			continue;

		ctype = tag__type(type);
		if (ctype->name == NULL)
			continue;

		str = structures__find(ctype->name);
		if (str != NULL)
			++str->nr_methods;
	}

	return 0;
}

static int cu_nr_methods_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_tag(cu, nr_methods_iterator, cookie,
				nr_methods__filter);
}

static struct class_member *
	class__find_next_hole_of_size(struct class *class,
				      struct class_member *from,
				      const struct cu *cu, size_t size)
{
	struct class_member *member =
		list_prepare_entry(from, &class->type.members, tag.node);

	list_for_each_entry_continue(member, &class->type.members, tag.node) {
		/*
		 * For now refrain from returning the head of a bitfield,
		 * we would have to move all the bitfield members.
		 */
		if (member->bit_size == 0 &&
		    member->hole != 0 &&
		    class_member__size(member, cu) <= size)
		    return member;
	}

	return NULL;
}

static struct class_member *
	class__find_next_bit_hole_of_size(const struct class *class,
					  struct class_member *from,
					  size_t size)
{
	struct class_member *member =
		list_prepare_entry(from, &class->type.members, tag.node);

	list_for_each_entry_continue(member, &class->type.members, tag.node)
		if (member->bit_hole != 0 &&
		    member->bit_size <= size)
		    return member;

	return NULL;
}

static void class__subtract_offsets_from(struct class *class,
					 struct class_member *from,
					 const size_t size)
{
	struct class_member *member =
		list_prepare_entry(from, &class->type.members, tag.node);

	list_for_each_entry_continue(member, &class->type.members, tag.node)
		member->offset -= size;
}

static void class__move_member(struct class *class, struct class_member *dest,
			       struct class_member *from, const struct cu *cu,
			       int from_padding)
{
	const size_t from_size = class_member__size(from, cu);
	const size_t dest_size = class_member__size(dest, cu);
	size_t offset;
	struct class_member *from_prev = list_entry(from->tag.node.prev,
						    struct class_member,
						    tag.node);

	if (verbose)
		printf("/* moving %s(size=%zd) to after "
		       "%s(offset=%zd, size=%zd, hole=%zd) */\n",
		       from->name, from_size,
		       dest->name, dest->offset, dest_size, dest->hole);
	/*
	 *  Remove from from the list
	 */
	list_del(&from->tag.node);
	/*
	 * Add from after dest:
	 */
	__list_add(&from->tag.node,
		   &dest->tag.node,
		   dest->tag.node.next);

	if (from_padding) {
		/*
		 * Check if we're eliminating the need for padding:
		 */
		if (from->offset % cu->addr_size == 0) {
			/*
			 * Good, no need for padding anymore:
			 */
			class->type.size -= from_size + class->padding;
			class->padding = 0;
		} else {
			/*
			 * No, so just add from_size to the padding:
			 */
			class->padding += from_size;
			printf("adding %zd bytes from %s to the padding\n",
			       from_size, from->name);
		}
	} else {
		/*
		 * See if we are adding a new hole that is bigger than
		 * sizeof(long), this may have problems with explicit alignment
		 * made by the programmer, perhaps we need A switch that allows
		 * us to avoid realignment, just using existing holes but
		 * keeping the existing alignment, anyway the programmer has to
		 * check the resulting rerganization before using it, and for
		 * automatic stuff such as the one that will be used for struct
		 * "views" in tools such as ctracer we are more interested in
		 * packing the subset as tightly as possible.
		 */
		if (from->hole + from_size >= cu->addr_size) {
			class__subtract_offsets_from(class, from_prev,
						     cu->addr_size);
			class->type.size -= cu->addr_size;
		} else {
			/*
			 * Add add the hole after from + its size to the member
			 * before it:
			 */
			from_prev->hole += from->hole + from_size;
		}
		/*
		 * Check if we have eliminated a hole
		 */
		if (dest->hole == from_size)
			class->nr_holes--;
	}
	/*
	 * Align from after dest:
	 */
	offset = dest->hole % from_size;
	from->offset = dest->offset + dest_size + offset;
	if (offset != 0) {
		from->hole = dest->hole - (from_size + offset);
		dest->hole = offset;
	} else {
		from->hole = dest->hole - from_size;
		dest->hole = 0;
	}
}

static void class__move_bit_member(struct class *class, const struct cu *cu,
				   struct class_member *dest,
				   struct class_member *from)
{
	struct class_member *from_prev = list_entry(from->tag.node.prev,
						    struct class_member,
						    tag.node);

	if (verbose)
		printf("/* moving %s(bit size=%u) to after "
		       "%s(bit offset=%zd, bit size=%zd, bit hole=%zd) */\n",
		       from->name, from->bit_size,
		       dest->name, dest->bit_offset, dest->bit_size,
		       dest->bit_hole);
	/*
	 *  Remove from from the list
	 */
	list_del(&from->tag.node);
	/*
	 * Add from after dest:
	 */
	__list_add(&from->tag.node,
		   &dest->tag.node,
		   dest->tag.node.next);

	/* Check if this was the last entry in the bitfield */
	if (from_prev->bit_size == 0) {
		const size_t from_size = class_member__size(from, cu);
		/*
		 * Are we shrinking the struct?
		 */
		if (from_size >= cu->addr_size) {
			class__subtract_offsets_from(class, from_prev,
						     from_size);
			class->type.size -= cu->addr_size;
		}
		class->nr_bit_holes--;
	} else {
		/*
		 * Add add the hole after from + its size to the member
		 * before it:
		 */
		from_prev->bit_hole += from->bit_hole + from->bit_size;
	}
	from->bit_hole = dest->bit_hole - from->bit_size;
	/*
	 * Tricky, what are the rules for bitfield layouts on this arch?
	 * Assume its IA32
	 */
	from->bit_offset = dest->bit_offset + dest->bit_size;
	/*
	 * Now both have the some offset:
	 */
	from->offset = dest->offset;
	dest->bit_hole = 0;
}

static void class__demote_bitfield_members(struct class *class,
					   struct class_member *from,
					   struct class_member *to,
					   const struct base_type *old_type,
					   const struct base_type *new_type)
{
	const size_t bit_diff = new_type->size - old_type->size;
	struct class_member *member =
		list_prepare_entry(from, &class->type.members, tag.node);

	list_for_each_entry_from(member, &class->type.members, tag.node) {
		member->bit_hole   = 0;
		/*
		 * Assume IA32 bitfield layout
		 */
		member->bit_offset -= bit_diff;
		member->tag.type = new_type->tag.id;
		if (member == to)
			break;
	}
}

static void class__demote_bitfields(struct class *class, const struct cu *cu)
{
	struct class_member *member;
	struct class_member *bitfield_member_head;
	size_t current_bitfield_size, size;

	list_for_each_entry(member, &class->type.members, tag.node) {
		/*
		 * Check if we are moving away from a bitfield
		 */
		if (member->bit_size == 0) {
			current_bitfield_size = 0;
			bitfield_member_head = NULL;
		} else {
			if (bitfield_member_head == NULL)
				bitfield_member_head = member;
			current_bitfield_size += member->bit_size;
		}

		/*
		 * Have we got to the end of a bitfield with holes?
		 */
		if (member->bit_hole == 0)
			continue;

		size = class_member__size(member, cu);
	{
	    	const struct tag *old_type_tag =
					cu__find_tag_by_id(cu, member->tag.type);
		struct tag *new_type_tag;
		const char *old_type = tag__base_type(old_type_tag)->name;
		const char *new_type;
	    	const size_t bytes_needed = (current_bitfield_size + 7) / 8;
		size_t new_size;

		switch (bytes_needed) {
		case sizeof(unsigned char):
			new_type = "unsigned char"; break;
		case sizeof(unsigned short int):
			new_type = "short unsigned int"; break;
		case sizeof(unsigned int):
			new_type = "unsigned int"; break;
		}
		if (verbose)
			printf("/* demoting bitfield starting at %s "
			       "from %s to %s */\n",
			       bitfield_member_head->name, old_type, new_type);
		new_type_tag = cu__find_base_type_by_name(cu, new_type);

		class__demote_bitfield_members(class,
					       bitfield_member_head, member,	
					       tag__base_type(old_type_tag),
					       tag__base_type(new_type_tag));
		new_size = class_member__size(member, cu);
		member->hole = size - new_size;
		if (member->hole != 0)
			++class->nr_holes;
		member->bit_hole = new_size * 8 - current_bitfield_size;
		if (member->bit_hole != 0)
			++class->nr_bit_holes;
	}
	}
}

static void class__reorganize_bitfields(struct class *class,
					const struct cu *cu)
{
	struct class_member *member, *brother;
restart:
	list_for_each_entry(member, &class->type.members, tag.node) {
		/* See if we have a hole after this member */
		if (member->bit_hole != 0) {
			/*
			 * OK, try to find a member that has a bit hole after
			 * it and that has a size that fits the current hole:
			*/
			brother =
			   class__find_next_bit_hole_of_size(class, member,
							     member->bit_hole);
			if (brother != NULL) {
				class__move_bit_member(class, cu,
						       member, brother);
				goto restart;
			}
		}
	}
}

static struct class *class__reorganize(const struct class *class,
				       const struct cu *cu)
{
	struct class_member *member, *brother, *last_member;
	size_t last_member_size;
	struct class *clone = class__clone(class);

	if (clone == NULL)
		return NULL;

	class__reorganize_bitfields(clone, cu);
	class__demote_bitfields(clone, cu);
restart:
	last_member = list_entry(clone->type.members.prev,
				 struct class_member, tag.node);
	last_member_size = class_member__size(last_member, cu);

	list_for_each_entry(member, &clone->type.members, tag.node) {
		/* See if we have a hole after this member */
		if (member->hole != 0) {
			/*
			 * OK, try to find a member that has a hole after it
			 * and that has a size that fits the current hole:
			*/
			brother = class__find_next_hole_of_size(clone, member,
								cu,
								member->hole);
			if (brother != NULL) {
				class__move_member(clone, member, brother,
						   cu, 0);
				goto restart;
			}
			/*
			 * OK, but is there padding? If so the last member
			 * has a hole, if we are not at the last member and
			 * it has a size that is smaller than the current hole
			 * we can move it after the current member, reducing
			 * the padding or eliminating it altogether.
			 */
			if (clone->padding > 0 &&
			    member != last_member &&
			    last_member_size <= member->hole) {
				class__move_member(clone, member, last_member,
						   cu, 1);
				goto restart;
			}
		}
	}

	return clone;
}

static struct option long_options[] = {
	{ "cacheline_size",	required_argument,	NULL, 'c' },
	{ "class_name_len",	no_argument,		NULL, 'N' },
	{ "help",		no_argument,		NULL, 'h' },
	{ "bit_holes",		required_argument,	NULL, 'B' },
	{ "holes",		required_argument,	NULL, 'H' },
	{ "nr_members",		no_argument,		NULL, 'n' },
	{ "sizes",		no_argument,		NULL, 's' },
	{ "nr_definitions",	no_argument,		NULL, 't' },
	{ "nr_methods",		no_argument,		NULL, 'm' },
	{ "exclude",		required_argument,	NULL, 'x' },
	{ "expand_types",	no_argument,		NULL, 'e' },
	{ "cu_exclude",		required_argument,	NULL, 'X' },
	{ "decl_exclude",	required_argument,	NULL, 'D' },
	{ "anon_include",	no_argument,		NULL, 'a' },
	{ "nested_anon_include",no_argument,		NULL, 'A' },
	{ "packable",		no_argument,		NULL, 'p' },
	{ "reorganize",		no_argument,		NULL, 'k' },
	{ "verbose",		no_argument,		NULL, 'V' },
	{ NULL, 0, NULL, 0, }
};

static void usage(void)
{
	fprintf(stderr,
		"usage: pahole [options] <file_name> {<class_name>}\n"
		" where: \n"
		"   -h, --help                   show usage info\n"
		"   -B, --bit_holes <nr_holes>   show only structs at least "
						"<nr_holes> bit holes\n"
		"   -H, --holes <nr_holes>       show only structs at least "
						"<nr_holes> holes\n"
		"   -p, --packable               show only structs that has "
						"holes that can be packed\n"
		"   -c, --cacheline_size <size>  set cacheline size\n"
		"   -e, --expand_types           expand class members\n"
		"   -n, --nr_members             show number of members\n"
		"   -k, --reorganize             reorg struct trying to "
						"kill holes\n"
		"   -N, --class_name_len         show size of classes\n"
		"   -m, --nr_methods             show number of methods\n"
		"   -s, --sizes                  show size of classes\n"
		"   -t, --nr_definitions         show how many times struct "
						"was defined\n"
		"   -D, --decl_exclude <prefix>  exclude classes declared in "
						"files with prefix\n"
		"   -x, --exclude <prefix>       exclude prefixed classes\n"
		"   -X, --cu_exclude <prefix>    exclude prefixed compilation "
						"units\n"
		"   -a, --anon_include           include anonymous classes\n"
		"   -A, --nested_anon_include    include nested (inside "
						"other structs)\n"
		"                                anonymous classes\n"
		"   -V, --verbose                be verbose\n");
}

int main(int argc, char *argv[])
{
	int option, option_index, reorganize = 0;
	struct cus *cus;
	char *file_name;
	char *class_name = NULL;
	size_t cacheline_size = 0;
	void (*formatter)(const struct structure *s) = class_formatter;

	while ((option = getopt_long(argc, argv, "AaB:c:D:ehH:kmnNpstVx:X:",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 'c': cacheline_size = atoi(optarg);  break;
		case 'H': nr_holes = atoi(optarg);	  break;
		case 'B': nr_bit_holes = atoi(optarg);	  break;
		case 'e': expand_types = 1;			break;
		case 'k': reorganize = 1;			break;
		case 's': formatter = size_formatter;		break;
		case 'n': formatter = nr_members_formatter;	break;
		case 'N': formatter = class_name_len_formatter;	break;
		case 'm': formatter = nr_methods_formatter;	break;
		case 'p': show_packable	= 1;			break;
		case 't': formatter = nr_definitions_formatter;	break;
		case 'a': class__include_anonymous = 1;		break;
		case 'A': class__include_nested_anonymous = 1;	break;
		case 'D': decl_exclude_prefix = optarg;
			  decl_exclude_prefix_len = strlen(decl_exclude_prefix);
							  break;
		case 'x': class__exclude_prefix = optarg;
			  class__exclude_prefix_len = strlen(class__exclude_prefix);
							  break;
		case 'X': cu__exclude_prefix = optarg;
			  cu__exclude_prefix_len = strlen(cu__exclude_prefix);
							  break;
		case 'V': verbose = 1;			  break;
		case 'h': usage();			  return EXIT_SUCCESS;
		default:  usage();			  return EXIT_FAILURE;
		}

	if (optind < argc) {
		switch (argc - optind) {
		case 1:	file_name = argv[optind++];
			if (reorganize) {
				usage();
				return EXIT_FAILURE;
			}
			break;
		case 2:	file_name = argv[optind++];
			class_name = argv[optind++];	break;
		default: usage();			return EXIT_FAILURE;
		}
	} else {
		usage();
		return EXIT_FAILURE;
	}

	dwarves__init(cacheline_size);

	cus = cus__new(NULL, NULL);
	if (cus == NULL) {
		fputs("pahole: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}

	if (cus__load(cus, file_name) != 0) {
		fprintf(stderr, "pahole: couldn't load DWARF info from %s\n",
		       file_name);
		return EXIT_FAILURE;
	}

	cus__for_each_cu(cus, cu_unique_iterator, NULL, cu__filter);
	if (formatter == nr_methods_formatter)
		cus__for_each_cu(cus, cu_nr_methods_iterator, NULL, cu__filter);

	if (class_name != NULL) {
		struct structure *s = structures__find(class_name);

		if (s == NULL) {
			printf("struct %s not found!\n", class_name);
			return EXIT_FAILURE;
		}
 		if (reorganize) {
			size_t savings;
 			struct class *clone = class__reorganize(s->class,
								s->cu);
 			if (clone == NULL) {
 				printf("pahole: out of memory!\n");
 				return EXIT_FAILURE;
 			}
			savings = class__size(s->class) - class__size(clone);
			if (savings != 0)
				putchar('\n');
 			tag__print(class__tag(clone), s->cu,
				   NULL, NULL, 0);
			if (savings != 0) {
				const size_t cacheline_savings =
				      (tag__nr_cachelines(class__tag(s->class),
					 		  s->cu) -
				       tag__nr_cachelines(class__tag(clone),
							  s->cu));

				printf("   /* saved %u byte%s", savings,
				       savings != 1 ? "s" : "");
				if (cacheline_savings != 0)
					printf(" and %zu cacheline%s",
					       cacheline_savings,
					       cacheline_savings != 1 ?
					       		"s" : "");
				puts("! */");
			}
 		} else
 			tag__print(class__tag(s->class), s->cu,
				   NULL, NULL, 0);
	} else
		print_classes(formatter);

	return EXIT_SUCCESS;
}
