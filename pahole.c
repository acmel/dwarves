/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007-2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <argp.h>
#include <assert.h>
#include <stdio.h>
#include <dwarf.h>
#include <search.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "dwarves_reorganize.h"
#include "dwarves.h"
#include "dutil.h"
#include "ctf_encoder.h"

static bool ctf_encode;
static bool first_obj_only;

static uint8_t class__include_anonymous;
static uint8_t class__include_nested_anonymous;
static uint8_t word_size, original_word_size;

static char *class__exclude_prefix;
static size_t class__exclude_prefix_len;

static char *class__include_prefix;
static size_t class__include_prefix_len;

static char *cu__exclude_prefix;
static size_t cu__exclude_prefix_len;

static char *decl_exclude_prefix;
static size_t decl_exclude_prefix_len;

static uint16_t nr_holes;
static uint16_t nr_bit_holes;
static uint16_t hole_size_ge;
static uint8_t show_packable;
static uint8_t global_verbose;
static uint8_t recursive;
static size_t cacheline_size;
static uint8_t find_containers;
static uint8_t find_pointers_in_structs;
static int reorganize;
static bool show_private_classes;
static bool defined_in;
static int show_reorg_steps;
static char *class_name;
static struct strlist *class_names;
static char separator = '\t';

static struct conf_fprintf conf = {
	.emit_stats = 1,
};

static struct conf_load conf_load;

struct structure {
	struct list_head  node;
	struct rb_node	  rb_node;
	char		  *name;
	uint32_t	  nr_files;
	uint32_t	  nr_methods;
};

static struct structure *structure__new(const char *name)
{
	struct structure *self = malloc(sizeof(*self));

	if (self != NULL) {
		self->name = strdup(name);
		if (self->name == NULL) {
			free(self);
			return NULL;
		}
		self->nr_files   = 1;
		self->nr_methods = 0;
	}

	return self;
}

static void structure__delete(struct structure *self)
{
	free(self->name);
	free(self);
}

static struct rb_root structures__tree = RB_ROOT;
static LIST_HEAD(structures__list);

static struct structure *structures__add(struct class *class,
					 const struct cu *cu,
					 bool *existing_entry)
{
        struct rb_node **p = &structures__tree.rb_node;
        struct rb_node *parent = NULL;
	struct structure *str;
	const char *new_class_name = class__name(class, cu);

        while (*p != NULL) {
		int rc;

                parent = *p;
                str = rb_entry(parent, struct structure, rb_node);
		rc = strcmp(str->name, new_class_name);

		if (rc > 0)
                        p = &(*p)->rb_left;
                else if (rc < 0)
                        p = &(*p)->rb_right;
		else {
			*existing_entry = true;
			return str;
		}
        }

	str = structure__new(new_class_name);
	if (str == NULL)
		return NULL;

	*existing_entry = false;
        rb_link_node(&str->rb_node, parent, p);
        rb_insert_color(&str->rb_node, &structures__tree);

	/* For linear traversals */
	list_add_tail(&str->node, &structures__list);

	return str;
}

void structures__delete(void)
{
	struct rb_node *next = rb_first(&structures__tree);

	while (next) {
		struct structure *pos = rb_entry(next, struct structure, rb_node);
		next = rb_next(&pos->rb_node);
		rb_erase(&pos->rb_node, &structures__tree);
		structure__delete(pos);
	}
}

static void nr_definitions_formatter(struct structure *self)
{
	printf("%s%c%u\n", self->name, separator, self->nr_files);
}

static void nr_members_formatter(struct class *self,
				 struct cu *cu, uint16_t id __unused)
{
	printf("%s%c%u\n", class__name(self, cu), separator,
	       class__nr_members(self));
}

static void nr_methods_formatter(struct structure *self)
{
	printf("%s%c%u\n", self->name, separator, self->nr_methods);
}

static void size_formatter(struct class *self,
			   struct cu *cu, uint16_t id __unused)
{
	printf("%s%c%d%c%u\n", class__name(self, cu), separator,
	       class__size(self), separator, self->nr_holes);
}

static void class_name_len_formatter(struct class *self, struct cu *cu,
				     uint16_t id __unused)
{
	const char *name = class__name(self, cu);
	printf("%s%c%zd\n", name, separator, strlen(name));
}

static void class_name_formatter(struct class *self,
				 struct cu *cu, uint16_t id __unused)
{
	puts(class__name(self, cu));
}

static void class_formatter(struct class *self, struct cu *cu, uint16_t id)
{
	struct tag *typedef_alias = NULL;
	struct tag *tag = class__tag(self);
	const char *name = class__name(self, cu);

	if (name == NULL) {
		/*
		 * Find the first typedef for this struct, this is enough
		 * as if we optimize the struct all the typedefs will be
		 * affected.
		 */
		typedef_alias = cu__find_first_typedef_of_type(cu, id);
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
		struct type *tdef = tag__type(typedef_alias);

		conf.prefix = "typedef";
		conf.suffix = type__name(tdef, cu);
	} else
		conf.prefix = conf.suffix = NULL;

	tag__fprintf(tag, cu, &conf, stdout);

	putchar('\n');
}

static void print_packable_info(struct class *c, struct cu *cu, uint16_t id)
{
	const struct tag *t = class__tag(c);
	const size_t orig_size = class__size(c);
	const size_t new_size = class__size(c->priv);
	const size_t savings = orig_size - new_size;
	const char *name = class__name(c, cu);

	/* Anonymous struct? Try finding a typedef */
	if (name == NULL) {
		const struct tag *tdef =
		      cu__find_first_typedef_of_type(cu, id);

		if (tdef != NULL)
			name = class__name(tag__class(tdef), cu);
	}
	if (name != NULL)
		printf("%s%c%zd%c%zd%c%zd\n",
		       name, separator,
		       orig_size, separator,
		       new_size, separator,
		       savings);
	else
		printf("%s(%d)%c%zd%c%zd%c%zd\n",
		       tag__decl_file(t, cu),
		       tag__decl_line(t, cu),
		       separator,
		       orig_size, separator,
		       new_size, separator,
		       savings);
}

static void (*stats_formatter)(struct structure *self) = NULL;

static void print_stats(void)
{
	struct structure *pos;

	list_for_each_entry(pos, &structures__list, node)
		stats_formatter(pos);
}

static struct class *class__filter(struct class *class, struct cu *cu,
				   uint16_t tag_id);

static void (*formatter)(struct class *self,
			 struct cu *cu, uint16_t id) = class_formatter;

static void print_classes(struct cu *cu)
{
	uint16_t id;
	struct class *pos;

	cu__for_each_struct(cu, id, pos) {
		bool existing_entry;
		struct structure *str;

		if (pos->type.namespace.name == 0 &&
		    !(class__include_anonymous ||
		      class__include_nested_anonymous))
			continue;

		if (!class__filter(pos, cu, id))
			continue;
		/*
		 * FIXME: No sense in adding an anonymous struct to the list of
		 * structs already printed, as we look for the name... The
		 * right fix probably will be to call class__fprintf on a
		 * in-memory FILE, do a hash, and look it by full contents, not
		 * by name. And this is needed for CTF as well, but its late now
		 * and I'm sleepy, will leave for later...
		 */
		if (pos->type.namespace.name != 0) {
			str = structures__add(pos, cu, &existing_entry);
			if (str == NULL) {
				fprintf(stderr, "pahole: insufficient memory for "
					"processing %s, skipping it...\n", cu->name);
				return;
			}

			/* Already printed... */
			if (existing_entry) {
				str->nr_files++;
				continue;
			}
		}

		if (show_packable && !global_verbose)
			print_packable_info(pos, cu, id);
		else if (formatter != NULL)
			formatter(pos, cu, id);
	}
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

static int class__packable(struct class *self, struct cu *cu)
{
	struct class *clone;

	if (self->nr_holes == 0 && self->nr_bit_holes == 0)
		return 0;

	clone = class__clone(self, NULL, cu);
	if (clone == NULL)
		return 0;
	class__reorganize(clone, cu, 0, stdout);
	if (class__size(self) > class__size(clone)) {
		self->priv = clone;
		return 1;
	}
	/* FIXME: we need to free in the right order,
	 *	  cu->obstack is being corrupted...
	class__delete(clone, cu);
	*/
	return 0;
}

static struct class *class__filter(struct class *class, struct cu *cu,
				   uint16_t tag_id)
{
	struct tag *tag = class__tag(class);
	const char *name;

	if (!tag->top_level) {
		class__find_holes(class);

		if (!show_private_classes)
			return NULL;
	}

	name = class__name(class, cu);

	if (class__is_declaration(class))
		return NULL;

	if (!class__include_anonymous && name == NULL)
		return NULL;

	if (class__exclude_prefix != NULL) {
		if (name == NULL) {
			const struct tag *tdef =
				cu__find_first_typedef_of_type(cu, tag_id);
			if (tdef != NULL) {
				struct class *c = tag__class(tdef);

				name = class__name(c, cu);
			}
		}
		if (name != NULL && strncmp(class__exclude_prefix, name,
					    class__exclude_prefix_len) == 0)
			return NULL;
	}

	if (class__include_prefix != NULL) {
		if (name == NULL) {
			const struct tag *tdef =
				cu__find_first_typedef_of_type(cu, tag_id);
			if (tdef != NULL) {
				struct class *c = tag__class(tdef);

				name = class__name(c, cu);
			}
		}
		if (name != NULL && strncmp(class__include_prefix, name,
					    class__include_prefix_len) != 0)
			return NULL;
	}

	if (decl_exclude_prefix != NULL &&
	    (!tag__decl_file(tag, cu) ||
	     strncmp(decl_exclude_prefix, tag__decl_file(tag, cu),
		     decl_exclude_prefix_len) == 0))
		return NULL;

	if (tag->top_level)
		class__find_holes(class);

	if (class->nr_holes < nr_holes ||
	    class->nr_bit_holes < nr_bit_holes ||
	    (hole_size_ge != 0 && !class__has_hole_ge(class, hole_size_ge)))
		return NULL;

	if (show_packable && !class__packable(class, cu))
		return NULL;

	return class;
}

static void union__find_new_size(struct tag *tag, struct cu *cu);

static void class__resize_LP(struct tag *tag, struct cu *cu)
{
	struct tag *tag_pos;
	struct class *self = tag__class(tag);
	size_t word_size_diff;
	size_t orig_size = self->type.size;

	if (tag__type(tag)->resized)
		return;

	tag__type(tag)->resized = 1;

	if (original_word_size > word_size)
		word_size_diff = original_word_size - word_size;
	else
		word_size_diff = word_size - original_word_size;

	type__for_each_tag(tag__type(tag), tag_pos) {
		struct tag *type;
		size_t diff = 0;
		size_t array_multiplier = 1;

		/* we want only data members, i.e. with byte_offset attr */
		if (tag_pos->tag != DW_TAG_member &&
		    tag_pos->tag != DW_TAG_inheritance)
		    	continue;

		type = cu__type(cu, tag_pos->type);
		tag__assert_search_result(type);
		if (type->tag == DW_TAG_array_type) {
			int i;
			for (i = 0; i < tag__array_type(type)->dimensions; ++i)
				array_multiplier *= tag__array_type(type)->nr_entries[i];

			type = cu__type(cu, type->type);
			tag__assert_search_result(type);
		}

		if (tag__is_typedef(type)) {
			type = tag__follow_typedef(type, cu);
			tag__assert_search_result(type);
		}

		switch (type->tag) {
		case DW_TAG_base_type: {
			struct base_type *bt = tag__base_type(type);
			char bf[64];
			const char *name = base_type__name(bt, cu, bf,
							   sizeof(bf));
			if (strcmp(name, "long int") != 0 &&
			    strcmp(name, "long unsigned int") != 0)
				break;
			/* fallthru */
		}
		case DW_TAG_pointer_type:
			diff = word_size_diff;
			break;
		case DW_TAG_structure_type:
		case DW_TAG_union_type:
			if (tag__is_union(type))
				union__find_new_size(type, cu);
			else
				class__resize_LP(type, cu);
			diff = tag__type(type)->size_diff;
			break;
		}

		diff *= array_multiplier;

		if (diff != 0) {
			struct class_member *m = tag__class_member(tag_pos);
			if (original_word_size > word_size) {
				self->type.size -= diff;
				class__subtract_offsets_from(self, m, diff);
			} else {
				self->type.size += diff;
				class__add_offsets_from(self, m, diff);
			}
		}
	}

	if (original_word_size > word_size)
		tag__type(tag)->size_diff = orig_size - self->type.size;
	else
		tag__type(tag)->size_diff = self->type.size - orig_size;

	class__find_holes(self);
	class__fixup_alignment(self, cu);
}

static void union__find_new_size(struct tag *tag, struct cu *cu)
{
	struct tag *tag_pos;
	struct type *self = tag__type(tag);
	size_t max_size = 0;

	if (self->resized)
		return;

	self->resized = 1;

	type__for_each_tag(self, tag_pos) {
		struct tag *type;
		size_t size;

		/* we want only data members, i.e. with byte_offset attr */
		if (tag_pos->tag != DW_TAG_member &&
		    tag_pos->tag != DW_TAG_inheritance)
		    	continue;

		type = cu__type(cu, tag_pos->type);
		tag__assert_search_result(type);
		if (tag__is_typedef(type))
			type = tag__follow_typedef(type, cu);

		if (tag__is_union(type))
			union__find_new_size(type, cu);
		else if (tag__is_struct(type))
			class__resize_LP(type, cu);

		size = tag__size(type, cu);
		if (size > max_size)
			max_size = size;
	}

	if (max_size > self->size)
		self->size_diff = max_size - self->size;
	else
		self->size_diff = self->size - max_size;

	self->size = max_size;
}

static void tag__fixup_word_size(struct tag *tag, struct cu *cu)
{
	if (tag__is_struct(tag) || tag__is_union(tag)) {
		struct tag *pos;

		namespace__for_each_tag(tag__namespace(tag), pos)
			tag__fixup_word_size(pos, cu);
	}

	switch (tag->tag) {
	case DW_TAG_base_type: {
		struct base_type *bt = tag__base_type(tag);

		/*
		 * This shouldn't happen, but at least on a tcp_ipv6.c
		 * built with GNU C 4.3.0 20080130 (Red Hat 4.3.0-0.7),
		 * one was found, so just bail out.
		 */
		if (!bt->name)
			return;
		char bf[64];
		const char *name = base_type__name(bt, cu, bf, sizeof(bf));

		if (strcmp(name, "long int") == 0 ||
		    strcmp(name, "long unsigned int") == 0)
			bt->bit_size = word_size * 8;
	}
		break;
	case DW_TAG_structure_type:
		class__resize_LP(tag, cu);
		break;
	case DW_TAG_union_type:
		union__find_new_size(tag, cu);
		break;
	}

	return;
}

static void cu_fixup_word_size_iterator(struct cu *cu)
{
	original_word_size = cu->addr_size;
	cu->addr_size = word_size;

	uint16_t id;
	struct tag *pos;
	cu__for_each_type(cu, id, pos)
		tag__fixup_word_size(pos, cu);
}

static void cu__account_nr_methods(struct cu *self)
{
	struct function *pos_function;
	struct structure *str;
	uint32_t id;

	cu__for_each_function(self, id, pos_function) {
		struct class_member *pos;
		list_for_each_entry(pos, &pos_function->proto.parms, tag.node) {
			struct tag *type = cu__type(self, pos->tag.type);

			if (type == NULL || type->tag != DW_TAG_pointer_type)
				continue;

			type = cu__type(self, type->type);
			if (type == NULL || !tag__is_struct(type))
				continue;

			struct type *ctype = tag__type(type);
			if (ctype->namespace.name == 0)
				continue;

			struct class *class = tag__class(type);

			if (!class__filter(class, self, 0))
				continue;

			bool existing_entry;
			str = structures__add(class, self, &existing_entry);
			if (str == NULL) {
				fprintf(stderr, "pahole: insufficient memory "
					"for processing %s, skipping it...\n",
					self->name);
				return;
			}

			if (!existing_entry)
				class__find_holes(class);
			++str->nr_methods;
		}
	}
}

static char tab[128];

static void print_structs_with_pointer_to(const struct cu *cu, uint16_t type)
{
	struct class *pos;
	struct class_member *pos_member;
	uint16_t id;

	cu__for_each_struct(cu, id, pos) {
		bool looked = false;
		struct structure *str;

		if (pos->type.namespace.name == 0)
			continue;

		type__for_each_member(&pos->type, pos_member) {
			struct tag *ctype = cu__type(cu, pos_member->tag.type);

			tag__assert_search_result(ctype);
			if (ctype->tag != DW_TAG_pointer_type || ctype->type != type)
				continue;

			if (!looked) {
				bool existing_entry;

				str = structures__add(pos, cu, &existing_entry);
				if (str == NULL) {
					fprintf(stderr, "pahole: insufficient memory for "
						"processing %s, skipping it...\n",
						cu->name);
					return;
				}
				/*
				 * We already printed this struct in another CU
				 */
				if (existing_entry)
					break;
				looked = true;
			}
			printf("%s: %s\n", str->name,
			       class_member__name(pos_member, cu));
		}
	}
}

static void print_containers(const struct cu *cu, uint16_t type, int ident)
{
	struct class *pos;
	uint16_t id;

	cu__for_each_struct(cu, id, pos) {
		if (pos->type.namespace.name == 0)
			continue;

		const uint32_t n = type__nr_members_of_type(&pos->type, type);
		if (n == 0)
			continue;

		if (ident == 0) {
			bool existing_entry;
			struct structure *str = structures__add(pos, cu, &existing_entry);
			if (str == NULL) {
				fprintf(stderr, "pahole: insufficient memory for "
					"processing %s, skipping it...\n",
					cu->name);
				return;
			}
			/*
			 * We already printed this struct in another CU
			 */
			if (existing_entry)
				break;
		}

		printf("%.*s%s", ident * 2, tab, class__name(pos, cu));
		if (global_verbose)
			printf(": %u", n);
		putchar('\n');
		if (recursive)
			print_containers(cu, id, ident + 1);
	}
}

/* Name and version of program.  */
ARGP_PROGRAM_VERSION_HOOK_DEF = dwarves_print_version;

#define ARGP_flat_arrays	   300
#define ARGP_show_private_classes  301
#define ARGP_fixup_silly_bitfields 302
#define ARGP_first_obj_only	   303
#define ARGP_classes_as_structs	   304
#define ARGP_hex_fmt		   305

static const struct argp_option pahole__options[] = {
	{
		.name = "bit_holes",
		.key  = 'B',
		.arg  = "NR_HOLES",
		.doc  = "Show only structs at least NR_HOLES bit holes"
	},
	{
		.name = "cacheline_size",
		.key  = 'c',
		.arg  = "SIZE",
		.doc  = "set cacheline size to SIZE"
	},
	{
		.name = "class_name",
		.key  = 'C',
		.arg  = "CLASS_NAME",
		.doc  = "Show just this class"
	},
	{
		.name = "find_pointers_to",
		.key  = 'f',
		.arg  = "CLASS_NAME",
		.doc  = "Find pointers to CLASS_NAME"
	},
	{
		.name = "format_path",
		.key  = 'F',
		.arg  = "FORMAT_LIST",
		.doc  = "List of debugging formats to try"
	},
	{
		.name = "contains",
		.key  = 'i',
		.arg  = "CLASS_NAME",
		.doc  = "Show classes that contains CLASS_NAME"
	},
	{
		.name = "show_decl_info",
		.key  = 'I',
		.doc  = "Show the file and line number where the tags were defined"
	},
	{
		.name = "holes",
		.key  = 'H',
		.arg  = "NR_HOLES",
		.doc  = "show only structs with at least NR_HOLES holes",
	},
	{
		.name = "hole_size_ge",
		.key  = 'z',
		.arg  = "HOLE_SIZE",
		.doc  = "show only structs with at least one hole greater "
			"or equal to HOLE_SIZE",
	},
	{
		.name = "packable",
		.key  = 'P',
		.doc  = "show only structs that has holes that can be packed",
	},
	{
		.name = "expand_types",
		.key  = 'E',
		.doc  = "expand class members",
	},
	{
		.name = "nr_members",
		.key  = 'n',
		.doc  = "show number of members",
	},
	{
		.name = "rel_offset",
		.key  = 'r',
		.doc  = "show relative offsets of members in inner structs"
	},
	{
		.name = "recursive",
		.key  = 'd',
		.doc  = "recursive mode, affects several other flags",
	},
	{
		.name = "reorganize",
		.key  = 'R',
		.doc  = "reorg struct trying to kill holes",
	},
	{
		.name = "show_reorg_steps",
		.key  = 'S',
		.doc  = "show the struct layout at each reorganization step",
	},
	{
		.name = "class_name_len",
		.key  = 'N',
		.doc  = "show size of classes",
	},
	{
		.name = "show_first_biggest_size_base_type_member",
		.key  = 'l',
		.doc  = "show first biggest size base_type member",
	},
	{
		.name = "nr_methods",
		.key  = 'm',
		.doc  = "show number of methods",
	},
	{
		.name = "show_only_data_members",
		.key  = 'M',
		.doc  = "show only the members that use space in the class layout",
	},
	{
		.name = "expand_pointers",
		.key  = 'p',
		.doc  = "expand class pointer members",
	},
	{
		.name = "sizes",
		.key  = 's',
		.doc  = "show size of classes",
	},
	{
		.name = "separator",
		.key  = 't',
		.arg  = "SEP",
		.doc  = "use SEP as the field separator",
	},
	{
		.name = "nr_definitions",
		.key  = 'T',
		.doc  = "show how many times struct was defined",
	},
	{
		.name = "decl_exclude",
		.key  = 'D',
		.arg  = "PREFIX",
		.doc  = "exclude classes declared in files with PREFIX",
	},
	{
		.name = "exclude",
		.key  = 'x',
		.arg  = "PREFIX",
		.doc  = "exclude PREFIXed classes",
	},
	{
		.name = "prefix_filter",
		.key  = 'y',
		.arg  = "PREFIX",
		.doc  = "include PREFIXed classes",
	},
	{
		.name = "cu_exclude",
		.key  = 'X',
		.arg  = "PREFIX",
		.doc  = "exclude PREFIXed compilation units",
	},
	{
		.name = "anon_include",
		.key  = 'a',
		.doc  = "include anonymous classes",
	},
	{
		.name = "nested_anon_include",
		.key  = 'A',
		.doc  = "include nested (inside other structs) anonymous classes",
	},
	{
		.name = "quiet",
		.key  = 'q',
		.doc  = "be quieter",
	},
	{
		.name = "defined_in",
		.key  = 'u',
		.doc  = "show CUs where CLASS_NAME (-C) is defined",
	},
	{
		.name = "verbose",
		.key  = 'V',
		.doc  = "be verbose",
	},
	{
		.name = "word_size",
		.key  = 'w',
		.arg  = "WORD_SIZE",
		.doc  = "change the arch word size to WORD_SIZE"
	},
	{
		.name = "ctf_encode",
		.key  = 'Z',
		.doc  = "Encode as CTF",
	},
	{
		.name = "flat_arrays",
		.key  = ARGP_flat_arrays,
		.doc  = "Flat arrays",
	},
	{
		.name = "show_private_classes",
		.key  = ARGP_show_private_classes,
		.doc  = "Show classes that are defined inside other classes or in functions",
	},
	{
		.name = "fixup_silly_bitfields",
		.key  = ARGP_fixup_silly_bitfields,
		.doc  = "Fix silly bitfields such as int foo:32",
	},
	{
		.name = "first_obj_only",
		.key  = ARGP_first_obj_only,
		.doc  = "Only process the first object file in the binary",
	},
	{
		.name = "classes_as_structs",
		.key  = ARGP_classes_as_structs,
		.doc  = "Use 'struct' when printing classes",
	},
	{
		.name = "hex",
		.key  = ARGP_hex_fmt,
		.doc  = "Print offsets and sizes in hexadecimal",
	},
	{
		.name = NULL,
	}
};

static error_t pahole__options_parser(int key, char *arg,
				      struct argp_state *state)
{
	switch (key) {
	case ARGP_KEY_INIT:
		if (state->child_inputs != NULL)
			state->child_inputs[0] = state->input;
		break;
	case 'A': class__include_nested_anonymous = 1;	break;
	case 'a': class__include_anonymous = 1;		break;
	case 'B': nr_bit_holes = atoi(arg);		break;
	case 'C': class_name = arg;			break;
	case 'c': cacheline_size = atoi(arg);		break;
	case 'D': decl_exclude_prefix = arg;
		  decl_exclude_prefix_len = strlen(decl_exclude_prefix);
		  conf_load.extra_dbg_info = 1;		break;
	case 'd': recursive = 1;			break;
	case 'E': conf.expand_types = 1;		break;
	case 'f': find_pointers_in_structs = 1;
		  class_name = arg;			break;
	case 'F': conf_load.format_path = arg;		break;
	case 'H': nr_holes = atoi(arg);			break;
	case 'I': conf.show_decl_info = 1;
		  conf_load.extra_dbg_info = 1;		break;
	case 'i': find_containers = 1;
		  class_name = arg;			break;
	case 'l': conf.show_first_biggest_size_base_type_member = 1;	break;
	case 'M': conf.show_only_data_members = 1;	break;
	case 'm': stats_formatter = nr_methods_formatter; break;
	case 'N': formatter = class_name_len_formatter;	break;
	case 'n': formatter = nr_members_formatter;	break;
	case 'P': show_packable	= 1;
		  conf_load.extra_dbg_info = 1;		break;
	case 'p': conf.expand_pointers = 1;		break;
	case 'q': conf.emit_stats = 0;
		  conf.suppress_comments = 1;
		  conf.suppress_offset_comment = 1;	break;
	case 'R': reorganize = 1;			break;
	case 'r': conf.rel_offset = 1;			break;
	case 'S': show_reorg_steps = 1;			break;
	case 's': formatter = size_formatter;		break;
	case 'T': stats_formatter = nr_definitions_formatter;
		  formatter = NULL;			break;
	case 't': separator = arg[0];			break;
	case 'u': defined_in = 1;			break;
	case 'V': global_verbose = 1;			break;
	case 'w': word_size = atoi(arg);		break;
	case 'X': cu__exclude_prefix = arg;
		  cu__exclude_prefix_len = strlen(cu__exclude_prefix);
							break;
	case 'x': class__exclude_prefix = arg;
		  class__exclude_prefix_len = strlen(class__exclude_prefix);
							break;
	case 'y': class__include_prefix = arg;
		  class__include_prefix_len = strlen(class__include_prefix);
							break;
	case 'z':
		hole_size_ge = atoi(arg);
		if (!global_verbose)
			formatter = class_name_formatter;
		break;
	case 'Z': ctf_encode = 1;			break;
	case ARGP_flat_arrays: conf.flat_arrays = 1;	break;
	case ARGP_show_private_classes:
		show_private_classes = true;
		conf.show_only_data_members = 1;	break;
	case ARGP_fixup_silly_bitfields:
		conf_load.fixup_silly_bitfields = 1;	break;
	case ARGP_first_obj_only:
		first_obj_only = true;			break;
	case ARGP_classes_as_structs:
		conf.classes_as_structs = 1;		break;
	case ARGP_hex_fmt:
		conf.hex_fmt = 1;			break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char pahole__args_doc[] = "FILE";

static struct argp pahole__argp = {
	.options  = pahole__options,
	.parser	  = pahole__options_parser,
	.args_doc = pahole__args_doc,
};

static void do_reorg(struct tag *class, struct cu *cu)
{
	int savings;
	const uint8_t reorg_verbose =
			show_reorg_steps ? 2 : global_verbose;
	struct class *clone = class__clone(tag__class(class), NULL, cu);
	if (clone == NULL) {
		fprintf(stderr, "pahole: out of memory!\n");
		exit(EXIT_FAILURE);
	}
	class__reorganize(clone, cu, reorg_verbose, stdout);
	savings = class__size(tag__class(class)) - class__size(clone);
	if (savings != 0 && reorg_verbose) {
		putchar('\n');
		if (show_reorg_steps)
			puts("/* Final reorganized struct: */");
	}
	tag__fprintf(class__tag(clone), cu, &conf, stdout);
	if (savings != 0) {
		const size_t cacheline_savings =
		      (tag__nr_cachelines(class, cu) -
		       tag__nr_cachelines(class__tag(clone), cu));

		printf("   /* saved %d byte%s", savings,
		       savings != 1 ? "s" : "");
		if (cacheline_savings != 0)
			printf(" and %zu cacheline%s",
			       cacheline_savings,
			       cacheline_savings != 1 ?
					"s" : "");
		puts("! */");
	} else
		putchar('\n');

	/* FIXME: we need to free in the right order,
	 *	  cu->obstack is being corrupted...
	 class__delete(clone, cu);
	*/
}

static enum load_steal_kind pahole_stealer(struct cu *cu,
					   struct conf_load *conf_load __unused)
{
	int ret = LSK__DELETE;

	if (!cu__filter(cu))
		goto filter_it;

	if (ctf_encode) {
		cu__encode_ctf(cu, global_verbose);
		/*
		 * We still have to get the type signature code merged to eliminate
		 * dups, reference another CTF file, etc, so for now just encode the
		 * first cu that is let thru by cu__filter.
		 */
		goto dump_and_stop;
	}

	if (class_name == NULL) {
		if (stats_formatter == nr_methods_formatter) {
			cu__account_nr_methods(cu);
			goto dump_it;
		}

		if (word_size != 0)
			cu_fixup_word_size_iterator(cu);

		memset(tab, ' ', sizeof(tab) - 1);

		print_classes(cu);
		goto dump_it;
	}

	struct str_node *pos;
	struct rb_node *next = rb_first(&class_names->entries);

	while (next) {
		pos = rb_entry(next, struct str_node, rb_node);
		next = rb_next(&pos->rb_node);

		static uint16_t class_id;
		bool include_decls = find_pointers_in_structs != 0 ||
				     stats_formatter == nr_methods_formatter;
		struct tag *class = cu__find_struct_by_name(cu, pos->s,
							    include_decls,
							    &class_id);
		if (class == NULL)
			continue;

		if (defined_in) {
			puts(cu->name);
			goto dump_it;
		}
		/*
		 * Ok, found it, so remove from the list to avoid printing it
		 * twice, in another CU.
		 */
		strlist__remove(class_names, pos);

		class__find_holes(tag__class(class));
		if (reorganize)
			do_reorg(class, cu);
		else if (find_containers)
			print_containers(cu, class_id, 0);
		else if (find_pointers_in_structs)
			print_structs_with_pointer_to(cu, class_id);
		else {
			/*
			 * We don't need to print it for every compile unit
			 * but the previous options need
			 */
			tag__fprintf(class, cu, &conf, stdout);
			putchar('\n');
		}
	}

	/*
	 * If we found all the entries in --class_name, stop
	 */
	if (strlist__empty(class_names)) {
dump_and_stop:
		ret = LSK__STOP_LOADING;
	}
dump_it:
	if (first_obj_only)
		ret = LSK__STOP_LOADING;
filter_it:
	return ret;
}

static int add_class_name_entry(const char *s)
{
	if (strncmp(s, "file://", 7) == 0) {
		if (strlist__load(class_names, s + 7))
			return -1;
	} else switch (strlist__add(class_names, s)) {
	case -EEXIST:
		if (global_verbose)
			fprintf(stderr,
				"pahole: %s dup in -C, ignoring\n", s);
		break;
	case -ENOMEM:
		return -1;
	}
	return 0;
}

static int populate_class_names(void)
{
	char *s = class_name, *sep;

	while ((sep = strchr(s, ',')) != NULL) {
		*sep = '\0';
		if (add_class_name_entry(s))
			return -1;
		*sep = ',';
		s = sep + 1;
	}

	return *s ? add_class_name_entry(s) : 0;
}

int main(int argc, char *argv[])
{
	int err, remaining, rc = EXIT_FAILURE;

	if (argp_parse(&pahole__argp, argc, argv, 0, &remaining, NULL) ||
	    remaining == argc) {
		argp_help(&pahole__argp, stderr, ARGP_HELP_SEE, argv[0]);
		goto out;
	}

	class_names = strlist__new(true);

	if (class_names == NULL || dwarves__init(cacheline_size)) {
		fputs("pahole: insufficient memory\n", stderr);
		goto out;
	}

	if (class_name && populate_class_names())
		goto out_dwarves_exit;

	struct cus *cus = cus__new();
	if (cus == NULL) {
		fputs("pahole: insufficient memory\n", stderr);
		goto out_dwarves_exit;
	}

	conf_load.steal = pahole_stealer;

	err = cus__load_files(cus, &conf_load, argv + remaining);
	if (err != 0) {
		fputs("pahole: No debugging information found\n", stderr);
		goto out_cus_delete;
	}

	if (stats_formatter != NULL)
		print_stats();
	rc = EXIT_SUCCESS;
out_cus_delete:
#ifdef DEBUG_CHECK_LEAKS
	cus__delete(cus);
	structures__delete();
#endif
out_dwarves_exit:
#ifdef DEBUG_CHECK_LEAKS
	dwarves__exit();
#endif
out:
#ifdef DEBUG_CHECK_LEAKS
	strlist__delete(class_names);
#endif
	return rc;
}
