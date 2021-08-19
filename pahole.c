/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007- Arnaldo Carvalho de Melo <acme@redhat.com>
*/

#include <argp.h>
#include <assert.h>
#include <stdio.h>
#include <dwarf.h>
#include <elfutils/version.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <search.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/btf.h>
#include "bpf/libbpf.h"

#include "dwarves_reorganize.h"
#include "dwarves.h"
#include "dutil.h"
//#include "ctf_encoder.h" FIXME: disabled, probably its better to move to Oracle's libctf
#include "btf_encoder.h"

static struct btf_encoder *btf_encoder;
static char *detached_btf_filename;
static bool btf_encode;
static bool btf_gen_floats;
static bool ctf_encode;
static bool sort_output;
static bool need_resort;
static bool first_obj_only;
static bool skip_encoding_btf_vars;
static bool btf_encode_force;
static const char *base_btf_file;

static const char *prettify_input_filename;
static FILE *prettify_input;

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
static bool show_with_flexible_array;
static uint8_t global_verbose;
static uint8_t recursive;
static size_t cacheline_size;
static uint8_t find_containers;
static uint8_t find_pointers_in_structs;
static int reorganize;
static bool show_private_classes;
static bool defined_in;
static bool just_unions;
static bool just_structs;
static bool just_packed_structs;
static int show_reorg_steps;
static const char *class_name;
static LIST_HEAD(class_names);
static char separator = '\t';

static struct conf_fprintf conf = {
	.emit_stats = 1,
};

static struct conf_load conf_load = {
	.conf_fprintf = &conf,
};

struct structure {
	struct list_head  node;
	struct rb_node	  rb_node;
	struct class	  *class;
	struct cu	  *cu;
	uint32_t	  id;
	uint32_t	  nr_files;
	uint32_t	  nr_methods;
};

static struct structure *structure__new(struct class *class, struct cu *cu, uint32_t id)
{
	struct structure *st = malloc(sizeof(*st));

	if (st != NULL) {
		st->nr_files   = 1;
		st->nr_methods = 0;
		st->class      = class;
		st->cu	       = cu;
		st->id	       = id;
	}

	return st;
}

static void structure__delete(struct structure *st)
{
	if (st == NULL)
		return;

	free(st);
}

static struct rb_root structures__tree = RB_ROOT;
static LIST_HEAD(structures__list);
static pthread_mutex_t structures_lock = PTHREAD_MUTEX_INITIALIZER;

static int type__compare_members_types(struct type *a, struct cu *cu_a, struct type *b, struct cu *cu_b)
{
	int ret = strcmp(type__name(a), type__name(b));

	if (ret)
		return ret;

	// a->nr_members should be equal to b->nr_members at this point

	if (a->nr_members == 0)
		return 0;

	struct class_member *ma, *mb = type__first_member(b);

	type__for_each_member(a, ma) {
		struct tag *type_ma = cu__type(cu_a, ma->tag.type),
			   *type_mb = cu__type(cu_b, mb->tag.type);

		if (type_ma && !type_mb && class_member__name(mb) == NULL) {
			/*
			 * FIXME This is happening with a vmlinux built with
			 * clang and thin-LTO, and since this is not
			 * multithreadeded, we can get the previous behaviour
			 * by considering just the first occurence, the one with
			 * all the class member names and proper types, and since
			 * the name, size, number of members is the same, consider them equal
			 * and use the complete type (the first one found).
			 * With this btfdiff works for both non-thin-LTO and thin-LTO vmlinux files
			 */
			return 0;
		}

		if (!type_ma || !type_mb) // shuldn't happen
			return type_ma ? 1 : -1; // best effort

		const char *name_a = class_member__name(ma),
			   *name_b = class_member__name(mb);

		if (name_a && name_b) {
			ret = strcmp(name_a, name_b);
			if (ret)
				return ret;
		}

		ret = (int)ma->bit_offset - (int)mb->bit_offset;
		if (ret)
			return ret;

		ret = (int)ma->bitfield_size - (int)mb->bitfield_size;
		if (ret)
			return ret;

		char bf_a[1024], bf_b[1024];

		ret = strcmp(tag__name(type_ma, cu_a, bf_a, sizeof(bf_a), NULL),
			     tag__name(type_mb, cu_b, bf_b, sizeof(bf_b), NULL));
		if (ret)
			return ret;

		mb = class_member__next(mb);
	}

	return 0;
}

static int type__compare_members(struct type *a, struct type *b)
{
	int ret;

	// a->nr_members should be equal to b->nr_members at this point

	if (a->nr_members == 0)
		return 0;

	struct class_member *ma, *mb = type__first_member(b);

	// Don't look at the types, as we may be referring to a CU being loaded
	// in another thread and since we're not locking the ptr_table's, we
	// may race When printing all the types using --sort we'll do an extra
	// check that takes into account the types, since at that time all the
	// ptr_tables/cus are quiescent.

	type__for_each_member(a, ma) {
		const char *name_a = class_member__name(ma),
			   *name_b = class_member__name(mb);

		if (name_a && name_b) {
			ret = strcmp(name_a, name_b);
			if (ret)
				return ret;
		}

		ret = (int)ma->bit_offset - (int)mb->bit_offset;
		if (ret)
			return ret;

		ret = (int)ma->bitfield_size - (int)mb->bitfield_size;
		if (ret)
			return ret;

		mb = class_member__next(mb);
	}

	/*
	   Since we didn't check the types, we may end with at least this btfdiff output:

+++ /tmp/btfdiff.btf.b5DJu4	2021-08-18 12:06:27.773932193 -0300
@@ -31035,7 +31035,7 @@ struct elf_note_info {
	struct memelfnote          auxv;                 / *    56    24 * /
	/ * --- cacheline 1 boundary (64 bytes) was 16 bytes ago --- * /
	struct memelfnote          files;                / *    80    24 * /
-	compat_siginfo_t           csigdata;             / *   104   128 * /
+	siginfo_t                  csigdata;             / *   104   128 * /

	   So if we're printing everything, consider the types as different and
	   at the end with type__compare_members_types() when using --sort,
	   we'll need as well to resort, to avoid things like:

@@ -47965,8 +47965,8 @@ struct instance_attribute {

	/ * XXX last struct has 6 bytes of padding * /

-	ssize_t                    (*show)(struct edac_device_instance *, char *);                 / *    16     8 * /
-	ssize_t                    (*store)(struct edac_device_instance *, const char  *, size_t); / *    24     8 * /
+	ssize_t                    (*show)(struct edac_pci_ctl_info *, char *);                    / *    16     8 * /
+	ssize_t                    (*store)(struct edac_pci_ctl_info *, const char  *, size_t);    / *    24     8 * /

	/ * size: 32, cachelines: 1, members: 3 * /
	/ * paddings: 1, sum paddings: 6 * /
@@ -47977,8 +47977,8 @@ struct instance_attribute {

	/ * XXX last struct has 6 bytes of padding * /

-	ssize_t                    (*show)(struct edac_pci_ctl_info *, char *);                    / *    16     8 * /
-	ssize_t                    (*store)(struct edac_pci_ctl_info *, const char  *, size_t);    / *    24     8 * /
+	ssize_t                    (*show)(struct edac_device_instance *, char *);                 / *    16     8 * /
+	ssize_t                    (*store)(struct edac_device_instance *, const char  *, size_t); / *    24     8 * /

	/ * size: 32, cachelines: 1, members: 3 * /
	/ * paddings: 1, sum paddings: 6 * /

	   I.e. the difference is in the arguments to those show/store function
	   pointers, but since we didn't took the types into account when first
	   sorting, we need to resort.

	   So the first sort weeds out duplicates when loading from multiple
	   CUs, i.e. DWARF, the second will make sure both BTF and DWARF are
	   sorted taking into account types and then btfdiff finally will be
	   happy and we can continue to depend on it for regression tests for
	   the BTF and DWARF encoder and loader

	 */

	if (sort_output) {
		need_resort = true;
		return 1;
	}

	return 0;
}

static int type__compare(struct type *a, struct cu *cu_a, struct type *b, struct cu *cu_b)
{
	int ret = strcmp(type__name(a), type__name(b));

	if (ret)
		goto found;

	ret = (int)a->size - (int)b->size;
	if (ret)
		goto found;

	ret = (int)a->nr_members - (int)b->nr_members;
	if (ret)
		goto found;

	ret = type__compare_members(a, b);
found:
	return ret;
}

static struct structure *__structures__add(struct class *class, struct cu *cu, uint32_t id, bool *existing_entry)
{
        struct rb_node **p = &structures__tree.rb_node;
        struct rb_node *parent = NULL;
	struct structure *str;

        while (*p != NULL) {
		int rc;

                parent = *p;
                str = rb_entry(parent, struct structure, rb_node);
		rc = type__compare(&str->class->type, str->cu, &class->type, cu);

		if (rc > 0)
                        p = &(*p)->rb_left;
                else if (rc < 0)
                        p = &(*p)->rb_right;
		else {
			*existing_entry = true;
			return str;
		}
        }

	str = structure__new(class, cu, id);
	if (str == NULL)
		return NULL;

	*existing_entry = false;
        rb_link_node(&str->rb_node, parent, p);
        rb_insert_color(&str->rb_node, &structures__tree);

	/* For linear traversals */
	list_add_tail(&str->node, &structures__list);

	return str;
}

static struct structure *structures__add(struct class *class, struct cu *cu, uint32_t id, bool *existing_entry)
{
	struct structure *str;

	pthread_mutex_lock(&structures_lock);
	str = __structures__add(class, cu, id, existing_entry);
	pthread_mutex_unlock(&structures_lock);

	return str;
}

static void __structures__delete(void)
{
	struct rb_node *next = rb_first(&structures__tree);

	while (next) {
		struct structure *pos = rb_entry(next, struct structure, rb_node);
		next = rb_next(&pos->rb_node);
		rb_erase(&pos->rb_node, &structures__tree);
		structure__delete(pos);
	}
}

void structures__delete(void)
{
	pthread_mutex_lock(&structures_lock);
	__structures__delete();
	pthread_mutex_unlock(&structures_lock);
}

static void nr_definitions_formatter(struct structure *st)
{
	printf("%s%c%u\n", class__name(st->class), separator, st->nr_files);
}

static void nr_members_formatter(struct class *class, struct cu *cu __maybe_unused, uint32_t id __maybe_unused)
{
	printf("%s%c%u\n", class__name(class), separator, class__nr_members(class));
}

static void nr_methods_formatter(struct structure *st)
{
	printf("%s%c%u\n", class__name(st->class), separator, st->nr_methods);
}

static void size_formatter(struct class *class, struct cu *cu __maybe_unused, uint32_t id __maybe_unused)
{
	printf("%s%c%d%c%u\n", class__name(class), separator,
	       class__size(class), separator, tag__is_union(class__tag(class)) ? 0 : class->nr_holes);
}

static void class_name_len_formatter(struct class *class, struct cu *cu __maybe_unused, uint32_t id __maybe_unused)
{
	const char *name = class__name(class);
	printf("%s%c%zd\n", name, separator, strlen(name));
}

static void class_name_formatter(struct class *class, struct cu *cu __maybe_unused, uint32_t id __maybe_unused)
{
	puts(class__name(class));
}

static void class_formatter(struct class *class, struct cu *cu, uint32_t id)
{
	struct tag *typedef_alias = NULL;
	struct tag *tag = class__tag(class);
	const char *name = class__name(class);

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
		conf.suffix = type__name(tdef);
	} else
		conf.prefix = conf.suffix = NULL;

	tag__fprintf(tag, cu, &conf, stdout);

	putchar('\n');
}

static void print_packable_info(struct class *c, struct cu *cu, uint32_t id)
{
	const struct tag *t = class__tag(c);
	const size_t orig_size = class__size(c);
	const size_t new_size = class__size(c->priv);
	const size_t savings = orig_size - new_size;
	const char *name = class__name(c);

	/* Anonymous struct? Try finding a typedef */
	if (name == NULL) {
		const struct tag *tdef =
		      cu__find_first_typedef_of_type(cu, id);

		if (tdef != NULL)
			name = class__name(tag__class(tdef));
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

static void (*stats_formatter)(struct structure *st);

static void print_stats(void)
{
	struct structure *pos;

	list_for_each_entry(pos, &structures__list, node)
		stats_formatter(pos);
}

static struct class *class__filter(struct class *class, struct cu *cu,
				   uint32_t tag_id);

static void (*formatter)(struct class *class,
			 struct cu *cu, uint32_t id) = class_formatter;

static void print_classes(struct cu *cu)
{
	uint32_t id;
	struct class *pos;

	cu__for_each_struct_or_union(cu, id, pos) {
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
			str = structures__add(pos, cu, id, &existing_entry);
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
		else if (sort_output && formatter == class_formatter)
			continue; // we'll print it at the end, in order, out of structures__tree
		else if (formatter != NULL)
			formatter(pos, cu, id);
	}
}

static void __print_ordered_classes(struct rb_root *root)
{
	struct rb_node *next = rb_first(root);

	while (next) {
		struct structure *st = rb_entry(next, struct structure, rb_node);

		class_formatter(st->class, st->cu, st->id);

		next = rb_next(&st->rb_node);
	}

}

static void resort_add(struct rb_root *resorted, struct structure *str)
{
	struct rb_node **p = &resorted->rb_node;
	struct rb_node *parent = NULL;
	struct structure *node;

	while (*p != NULL) {
		int rc;

		parent = *p;
		node = rb_entry(parent, struct structure, rb_node);
		rc = type__compare_members_types(&node->class->type, node->cu, &str->class->type, str->cu);

		if (rc > 0)
			p = &(*p)->rb_left;
		else if (rc < 0)
			p = &(*p)->rb_right;
		else
			return; // Duplicate, ignore it
	}

	rb_link_node(&str->rb_node, parent, p);
	rb_insert_color(&str->rb_node, resorted);
}

static void resort_classes(struct rb_root *resorted, struct list_head *head)
{
	struct structure *str;

	list_for_each_entry(str, head, node)
		resort_add(resorted, str);
}

static void print_ordered_classes(void)
{
	if (!need_resort) {
		__print_ordered_classes(&structures__tree);
	} else {
		struct rb_root resorted = RB_ROOT;

		resort_classes(&resorted, &structures__list);
		__print_ordered_classes(&resorted);
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

static int class__packable(struct class *class, struct cu *cu)
{
	struct class *clone;

	if (class->nr_holes == 0 && class->nr_bit_holes == 0)
		return 0;

	clone = class__clone(class, NULL);
	if (clone == NULL)
		return 0;
	class__reorganize(clone, cu, 0, stdout);
	if (class__size(class) > class__size(clone)) {
		class->priv = clone;
		return 1;
	}
	class__delete(clone);
	return 0;
}

static bool class__has_flexible_array(struct class *class, struct cu *cu)
{
	struct class_member *member = type__last_member(&class->type);

	if (member == NULL)
		return false;

	struct tag *type = cu__type(cu, member->tag.type);

	if (type->tag != DW_TAG_array_type)
		return false;

	struct array_type *array = tag__array_type(type);

	if (array->dimensions > 1)
		return false;

	if (array->nr_entries == NULL || array->nr_entries[0] == 0)
		return true;

	return false;
}

static struct class *class__filter(struct class *class, struct cu *cu,
				   uint32_t tag_id)
{
	struct tag *tag = class__tag(class);
	const char *name;

	if (just_unions && !tag__is_union(tag))
		return NULL;

	if (just_structs && !tag__is_struct(tag))
		return NULL;

	if (just_packed_structs) {
		/* Is it not packed? */
		if (!class__infer_packed_attributes(class, cu))
			return NULL;
	}

	if (!tag->top_level) {
		class__find_holes(class);

		if (!show_private_classes)
			return NULL;
	}

	name = class__name(class);

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

				name = class__name(c);
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

				name = class__name(c);
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
	/*
	 * if --unions was used and we got here, its a union and we satisfy the other
	 * filters/options, so don't filter it.
	 */
	if (just_unions)
		return class;
	/*
	 * The following only make sense for structs, i.e. 'struct class',
	 * and as we can get here with a union, that is represented by a 'struct type',
	 * bail out if we get here with an union and we are not looking for things
	 * that need finding holes, like --packable, --nr_holes, etc
	 */
	if (!tag__is_struct(tag))
		return (just_structs || show_packable || nr_holes || nr_bit_holes || hole_size_ge) ? NULL : class;

	if (tag->top_level)
		class__find_holes(class);

	if (class->nr_holes < nr_holes ||
	    class->nr_bit_holes < nr_bit_holes ||
	    (hole_size_ge != 0 && !class__has_hole_ge(class, hole_size_ge)))
		return NULL;

	if (show_packable && !class__packable(class, cu))
		return NULL;

	if (show_with_flexible_array && !class__has_flexible_array(class, cu))
		return NULL;

	return class;
}

static void union__find_new_size(struct tag *tag, struct cu *cu);

static void class__resize_LP(struct tag *tag, struct cu *cu)
{
	struct tag *tag_pos;
	struct class *class = tag__class(tag);
	size_t word_size_diff;
	size_t orig_size = class->type.size;

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
			const char *name = base_type__name(bt, bf, sizeof(bf));
			if (strcmp(name, "long int") != 0 &&
			    strcmp(name, "long unsigned int") != 0)
				break;
		}
			/* fallthru */
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
				class->type.size -= diff;
				class__subtract_offsets_from(class, m, diff);
			} else {
				class->type.size += diff;
				class__add_offsets_from(class, m, diff);
			}
		}
	}

	if (original_word_size > word_size)
		tag__type(tag)->size_diff = orig_size - class->type.size;
	else
		tag__type(tag)->size_diff = class->type.size - orig_size;

	class__find_holes(class);
	class__fixup_alignment(class, cu);
}

static void union__find_new_size(struct tag *tag, struct cu *cu)
{
	struct tag *tag_pos;
	struct type *type = tag__type(tag);
	size_t max_size = 0;

	if (type->resized)
		return;

	type->resized = 1;

	type__for_each_tag(type, tag_pos) {
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

	if (max_size > type->size)
		type->size_diff = max_size - type->size;
	else
		type->size_diff = type->size - max_size;

	type->size = max_size;
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
		const char *name = base_type__name(bt, bf, sizeof(bf));

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

	uint32_t id;
	struct tag *pos;
	cu__for_each_type(cu, id, pos)
		tag__fixup_word_size(pos, cu);
}

static void cu__account_nr_methods(struct cu *cu)
{
	struct function *pos_function;
	struct structure *str;
	uint32_t id;

	cu__for_each_function(cu, id, pos_function) {
		struct class_member *pos;

		function__for_each_parameter(pos_function, cu, pos) {
			struct tag *type = cu__type(cu, pos->tag.type);

			if (type == NULL || !tag__is_pointer(type))
				continue;

			type = cu__type(cu, type->type);
			if (type == NULL || !tag__is_struct(type))
				continue;

			struct type *ctype = tag__type(type);
			if (ctype->namespace.name == 0)
				continue;

			struct class *class = tag__class(type);

			if (!class__filter(class, cu, 0))
				continue;

			bool existing_entry;
			str = structures__add(class, cu, id, &existing_entry);
			if (str == NULL) {
				fprintf(stderr, "pahole: insufficient memory "
					"for processing %s, skipping it...\n",
					cu->name);
				return;
			}

			if (!existing_entry)
				class__find_holes(class);
			++str->nr_methods;
		}
	}
}

static char tab[128];

static void print_structs_with_pointer_to(struct cu *cu, uint32_t type)
{
	struct class *pos;
	struct class_member *pos_member;
	uint32_t id;

	cu__for_each_struct_or_union(cu, id, pos) {
		bool looked = false;
		/*
		 * Set it to NULL just to silence the compiler, as the printf
		 * at the end of the type__for_each_member() loop is only reached
		 * after str _is_ set, as looked starts as false, str is used with
		 * structures_add and if it is NULL, we return.
		 */
		struct structure *str = NULL;

		if (pos->type.namespace.name == 0)
			continue;

		if (!class__filter(pos, cu, id))
			continue;

		type__for_each_member(&pos->type, pos_member) {
			struct tag *ctype = cu__type(cu, pos_member->tag.type);

			tag__assert_search_result(ctype);
			if (!tag__is_pointer_to(ctype, type))
				continue;

			if (!looked) {
				bool existing_entry;

				str = structures__add(pos, cu, id, &existing_entry);
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
			printf("%s: %s\n", class__name(str->class),
			       class_member__name(pos_member));
		}
	}
}

static int type__print_containers(struct type *type, struct cu *cu, uint32_t contained_type_id, int ident)
{
	const uint32_t n = type__nr_members_of_type(type, contained_type_id);
	if (n == 0)
		return 0;

	if (ident == 0) {
		bool existing_entry; // FIXME: This should really just search, no need to try to add it.
		struct structure *str = structures__add(type__class(type), cu, 0, &existing_entry);
		if (str == NULL) {
			fprintf(stderr, "pahole: insufficient memory for "
				"processing %s, skipping it...\n",
				cu->name);
			return -1;
		}
		/*
		 * We already printed this struct in another CU
		 */
		if (existing_entry)
			return 0;
	}

	printf("%.*s%s", ident * 2, tab, type__name(type));
	if (global_verbose)
		printf(": %u", n);
	putchar('\n');
	if (recursive) {
		struct class_member *member;

		type__for_each_member(type, member) {
			struct tag *member_type = cu__type(cu, member->tag.type);

			if (tag__is_struct(member_type) || tag__is_union(member_type))
				type__print_containers(tag__type(member_type), cu, contained_type_id, ident + 1);
		}
	}

	return 0;
}

static void print_containers(struct cu *cu, uint32_t type, int ident)
{
	struct class *pos;
	uint32_t id;

	cu__for_each_struct_or_union(cu, id, pos) {
		if (pos->type.namespace.name == 0)
			continue;

		if (!class__filter(pos, cu, id))
			continue;

		if (type__print_containers(&pos->type, cu, type, ident))
			break;
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
#define ARGP_suppress_aligned_attribute	306
#define ARGP_suppress_force_paddings	307
#define ARGP_suppress_packed	   308
#define ARGP_just_unions	   309
#define ARGP_just_structs	   310
#define ARGP_count		   311
#define ARGP_skip		   312
#define ARGP_seek_bytes		   313
#define ARGP_header_type	   314
#define ARGP_size_bytes		   315
#define ARGP_range		   316
#define ARGP_skip_encoding_btf_vars 317
#define ARGP_btf_encode_force	   318
#define ARGP_just_packed_structs   319
#define ARGP_numeric_version       320
#define ARGP_btf_base		   321
#define ARGP_btf_gen_floats	   322
#define ARGP_btf_gen_all	   323
#define ARGP_with_flexible_array   324
#define ARGP_kabi_prefix	   325
#define ARGP_btf_encode_detached   326
#define ARGP_prettify_input_filename 327
#define ARGP_sort_output	   328
#define ARGP_hashbits		   329
#define ARGP_devel_stats	   330

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
		.name = "count",
		.key  = ARGP_count,
		.arg  = "COUNT",
		.doc  = "Print only COUNT input records"
	},
	{
		.name = "skip",
		.key  = ARGP_skip,
		.arg  = "COUNT",
		.doc  = "Skip COUNT input records"
	},
	{
		.name = "seek_bytes",
		.key  = ARGP_seek_bytes,
		.arg  = "BYTES",
		.doc  = "Seek COUNT input records"
	},
	{
		.name = "size_bytes",
		.key  = ARGP_size_bytes,
		.arg  = "BYTES",
		.doc  = "Read only this number of bytes from this point onwards"
	},
	{
		.name = "range",
		.key  = ARGP_range,
		.arg  = "STRUCT",
		.doc  = "Data struct with 'offset' and 'size' fields to determine --seek_bytes and --size_bytes"
	},
	{
		.name = "header_type",
		.key  = ARGP_header_type,
		.arg  = "TYPE",
		.doc  = "File header type"
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
		.name = "with_flexible_array",
		.key  = ARGP_with_flexible_array,
		.doc  = "show only structs with a flexible array",
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
		.doc  = "Encode as CTF: DISABLED, consider helping porting to libctf",
	},
	{
		.name = "flat_arrays",
		.key  = ARGP_flat_arrays,
		.doc  = "Flat arrays",
	},
	{
		.name = "suppress_aligned_attribute",
		.key  = ARGP_suppress_aligned_attribute,
		.doc  = "Suppress __attribute__((aligned(N))",
	},
	{
		.name = "suppress_force_paddings",
		.key  = ARGP_suppress_force_paddings,
		.doc  = "Suppress int :N paddings at the end",
	},
	{
		.name = "suppress_packed",
		.key  = ARGP_suppress_packed,
		.doc  = "Suppress output of inferred __attribute__((__packed__))",
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
		.name = "btf_base",
		.key  = ARGP_btf_base,
		.arg  = "PATH",
		.doc  = "Path to the base BTF file",
	},
	{
		.name = "kabi_prefix",
		.key  = ARGP_kabi_prefix,
		.arg  = "STRING",
		.doc  = "When the prefix of the string is STRING, treat the string as STRING.",
	},
	{
		.name  = "jobs",
		.key   = 'j',
		.arg   = "NR_JOBS",
		.flags = OPTION_ARG_OPTIONAL, // Use sysconf(_SC_NPROCESSORS_ONLN) * 1.1 by default
		.doc   = "run N jobs in parallel [default to number of online processors + 10%]",
	},
	{
		.name = "btf_encode",
		.key  = 'J',
		.doc  = "Encode as BTF",
	},
	{
		.name = "btf_encode_detached",
		.key  = ARGP_btf_encode_detached,
		.arg  = "FILENAME",
		.doc  = "Encode as BTF in a detached file",
	},
	{
		.name = "skip_encoding_btf_vars",
		.key  = ARGP_skip_encoding_btf_vars,
		.doc  = "Do not encode VARs in BTF."
	},
	{
		.name = "btf_encode_force",
		.key  = ARGP_btf_encode_force,
		.doc  = "Ignore those symbols found invalid when encoding BTF."
	},
	{
		.name = "btf_gen_floats",
		.key  = ARGP_btf_gen_floats,
		.doc  = "Allow producing BTF_KIND_FLOAT entries."
	},
	{
		.name = "btf_gen_all",
		.key  = ARGP_btf_gen_all,
		.doc  = "Allow using all the BTF features supported by pahole."
	},
	{
		.name = "structs",
		.key  = ARGP_just_structs,
		.doc  = "Show just structs",
	},
	{
		.name = "unions",
		.key  = ARGP_just_unions,
		.doc  = "Show just unions",
	},
	{
		.name = "packed",
		.key  = ARGP_just_packed_structs,
		.doc  = "Show just packed structs",
	},
	{
		.name = "numeric_version",
		.key  = ARGP_numeric_version,
		.doc  = "Print a numeric version, i.e. 119 instead of v1.19"
	},
	{
		.name = "sort",
		.key  = ARGP_sort_output,
		.doc  = "Sort types by name",
	},
	{
		.name = "prettify",
		.key  = ARGP_prettify_input_filename,
		.arg  = "PATH",
		.doc  = "Path to the raw data to pretty print",
	},
	{
		.name = "hashbits",
		.key  = ARGP_hashbits,
		.arg  = "BITS",
		.doc  = "Number of bits for the hash table key",
	},
	{
		.name = "ptr_table_stats",
		.key  = ARGP_devel_stats,
		.doc  = "Print internal data structures stats",
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
	case 'j':
#if _ELFUTILS_PREREQ(0, 178)
		  conf_load.nr_jobs = arg ? atoi(arg) :
					    sysconf(_SC_NPROCESSORS_ONLN) * 1.1;
#else
		  fputs("pahole: Multithreading requires elfutils >= 0.178. Continuing with a single thread...\n", stderr);
#endif
							break;
	case ARGP_btf_encode_detached:
		  detached_btf_filename = arg; // fallthru
	case 'J': btf_encode = 1;
		  conf_load.get_addr_info = true;
		  conf_load.ignore_alignment_attr = true;
		  // XXX for now, test this more thoroughly
		  // We may have some references from formal parameters, etc, (abstract_origin)
		  // conf_load.ignore_inline_expansions = true;
		  conf_load.ignore_labels	     = true;
		  conf_load.use_obstack		     = true;
		  no_bitfield_type_recode = true;	break;
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
	// case 'Z': ctf_encode = 1;			break; // FIXME: Disabled
	case ARGP_flat_arrays: conf.flat_arrays = 1;	break;
	case ARGP_suppress_aligned_attribute:
		conf.suppress_aligned_attribute = 1;	break;
	case ARGP_suppress_force_paddings:
		conf.suppress_force_paddings = 1;	break;
	case ARGP_suppress_packed:
		conf.suppress_packed = 1;		break;
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
	case ARGP_just_unions:
		just_unions = true;			break;
	case ARGP_just_structs:
		just_structs = true;			break;
	case ARGP_just_packed_structs:
		just_structs = true;
		just_packed_structs = true;		break;
	case ARGP_count:
		conf.count = atoi(arg);			break;
	case ARGP_skip:
		conf.skip = atoi(arg);			break;
	case ARGP_seek_bytes:
		conf.seek_bytes = arg;			break;
	case ARGP_size_bytes:
		conf.size_bytes = arg;			break;
	case ARGP_range:
		conf.range = arg;			break;
	case ARGP_header_type:
		conf.header_type = arg;			break;
	case ARGP_skip_encoding_btf_vars:
		skip_encoding_btf_vars = true;		break;
	case ARGP_btf_encode_force:
		btf_encode_force = true;		break;
	case ARGP_btf_base:
		base_btf_file = arg;			break;
	case ARGP_kabi_prefix:
		conf_load.kabi_prefix = arg;
		conf_load.kabi_prefix_len = strlen(arg); break;
	case ARGP_numeric_version:
		print_numeric_version = true;		break;
	case ARGP_btf_gen_floats:
		btf_gen_floats = true;			break;
	case ARGP_btf_gen_all:
		btf_gen_floats = true;			break;
	case ARGP_with_flexible_array:
		show_with_flexible_array = true;	break;
	case ARGP_prettify_input_filename:
		prettify_input_filename = arg;		break;
	case ARGP_sort_output:
		sort_output = true;			break;
	case ARGP_hashbits:
		conf_load.hashtable_bits = atoi(arg);	break;
	case ARGP_devel_stats:
		conf_load.ptr_table_stats = true;	break;
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
	struct class *clone = class__clone(tag__class(class), NULL);
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

	 class__delete(clone);
}

static int instance__fprintf_hexdump_value(void *instance, int _sizeof, FILE *fp)
{
	uint8_t *contents = instance;
	int i, printed = 0;

	for (i = 0; i < _sizeof; ++i) {
		if (i != 0) {
			fputc(' ', fp);
			++printed;
		}

		printed += fprintf(fp, "0x%02x", contents[i]);
	}

	return printed;
}

static uint64_t base_type__value(void *instance, int _sizeof)
{
	if (_sizeof == sizeof(int))
		return *(int *)instance;
	else if (_sizeof == sizeof(long))
		return *(long *)instance;
	else if (_sizeof == sizeof(long long))
		return *(long long *)instance;
	else if (_sizeof == sizeof(char))
		return *(char *)instance;
	else if (_sizeof == sizeof(short))
		return *(short *)instance;

	return 0;
}

static int fprintf__value(FILE* fp, uint64_t value)
{
	const char *format = conf.hex_fmt ? "%#" PRIx64 : "%" PRIi64;

	return fprintf(fp, format, value);
}

static int base_type__fprintf_value(void *instance, int _sizeof, FILE *fp)
{
	uint64_t value = base_type__value(instance, _sizeof);
	return fprintf__value(fp, value);
}

static uint64_t class_member__bitfield_value(struct class_member *member, void *instance)
{
	int byte_size = member->byte_size;
	uint64_t value = base_type__value(instance, byte_size);
	uint64_t mask = 0;
	int bits = member->bitfield_size;

	while (bits) {
		mask |= 1;
		if (--bits)
			mask <<= 1;
	}

	mask <<= member->bitfield_offset;

	return (value & mask) >> member->bitfield_offset;
}

static int class_member__fprintf_bitfield_value(struct class_member *member, void *instance, FILE *fp)
{
	const char *format = conf.hex_fmt ? "%#" PRIx64 : "%" PRIi64;
	return fprintf(fp, format, class_member__bitfield_value(member, instance));
}

static const char *enumeration__lookup_value(struct type *enumeration, uint64_t value)
{
	struct enumerator *entry;

	type__for_each_enumerator(enumeration, entry) {
		if (entry->value == value)
			return enumerator__name(entry);
	}

	return NULL;
}

static const char *enumerations__lookup_value(struct list_head *enumerations, uint64_t value)
{
	struct tag_cu_node *pos;

	list_for_each_entry(pos, enumerations, node) {
		const char *s = enumeration__lookup_value(tag__type(pos->tc.tag), value);
		if (s)
			return s;
	}

	return NULL;
}

static struct enumerator *enumeration__lookup_entry_from_value(struct type *enumeration, uint64_t value)
{
	struct enumerator *entry;

	type__for_each_enumerator(enumeration, entry) {
		if (entry->value == value)
			return entry;
	}

	return NULL;
}

static struct enumerator *enumerations__lookup_entry_from_value(struct list_head *enumerations, uint64_t value)
{
	struct tag_cu_node *pos;

	list_for_each_entry(pos, enumerations, node) {
		struct enumerator *enumerator = enumeration__lookup_entry_from_value(tag__type(pos->tc.tag), value);
		if (enumerator) {
			return enumerator;
		}
	}

	return NULL;
}

static int64_t enumeration__lookup_enumerator(struct type *enumeration, const char *enumerator)
{
	struct enumerator *entry;

	type__for_each_enumerator(enumeration, entry) {
		const char *entry_name = enumerator__name(entry);

		if (!strcmp(entry_name, enumerator))
			return entry->value;

		if (enumeration->member_prefix_len &&
		    !strcmp(entry_name + enumeration->member_prefix_len, enumerator))
			return entry->value;
	}

	return -1;
}

static int64_t enumerations__lookup_enumerator(struct list_head *enumerations, const char *enumerator)
{
	struct tag_cu_node *pos;

	list_for_each_entry(pos, enumerations, node) {
		int64_t value = enumeration__lookup_enumerator(tag__type(pos->tc.tag), enumerator);
		if (value != -1)
			return value;
	}

	return -1;
}

static int base_type__fprintf_enum_value(void *instance, int _sizeof, struct list_head *enumerations, FILE *fp)
{
	uint64_t value = base_type__value(instance, _sizeof);

	const char *entry = enumerations__lookup_value(enumerations, value);

	if (entry)
		return fprintf(fp, "%s", entry);

	return fprintf__value(fp, value);
}

static int string__fprintf_value(char *instance, int _sizeof, FILE *fp)
{
	return fprintf(fp, "\"%-.*s\"", _sizeof, instance);
}

static int array__fprintf_base_type_value(struct tag *tag, struct cu *cu, void *instance, int _sizeof, FILE *fp)
{
	struct array_type *array = tag__array_type(tag);
	struct tag *array_type = cu__type(cu, tag->type);
	void *contents = instance;

	if (array->dimensions != 1) {
		// Support multi dimensional arrays later
		return instance__fprintf_hexdump_value(instance, _sizeof, fp);
	}

	if (tag__is_typedef(array_type))
		array_type = tag__follow_typedef(array_type, cu);

	int i, printed = 0, sizeof_entry = base_type__size(array_type);

	printed += fprintf(fp, "{ ");

	int nr_entries = array->nr_entries[0];

	// Look for zero sized arrays
	if (nr_entries == 0)
		nr_entries = _sizeof / sizeof_entry;

	for (i = 0; i < nr_entries; ++i) {
		if (i > 0)
			printed += fprintf(fp, ", ");
		printed += base_type__fprintf_value(contents, sizeof_entry, fp);
		contents += sizeof_entry;
	}

	return printed + fprintf(fp, " }");
}

static int array__fprintf_value(struct tag *tag, struct cu *cu, void *instance, int _sizeof, FILE *fp)
{
	struct tag *array_type = cu__type(cu, tag->type);
	char type_name[1024];

	if (strcmp(tag__name(array_type, cu, type_name, sizeof(type_name), NULL), "char") == 0)
		return string__fprintf_value(instance, _sizeof, fp);

	if (tag__is_base_type(array_type, cu))
		return array__fprintf_base_type_value(tag, cu, instance, _sizeof, fp);

	return instance__fprintf_hexdump_value(instance, _sizeof, fp);
}

static int __class__fprintf_value(struct tag *tag, struct cu *cu, void *instance, int _sizeof, int indent, bool brackets, FILE *fp)
{
	struct type *type = tag__type(tag);
	struct class_member *member;
	int printed = 0;

	if (brackets)
		printed += fprintf(fp, "{");

	type__for_each_member(type, member) {
		void *member_contents = instance + member->byte_offset;
		struct tag *member_type = cu__type(cu, member->tag.type);
		const char *name = class_member__name(member);

		if (name)
			printed += fprintf(fp, "\n%.*s\t.%s = ", indent, tabs, name);

		if (member == type->type_member && !list_empty(&type->type_enum)) {
			printed += base_type__fprintf_enum_value(member_contents, member->byte_size, &type->type_enum, fp);
		} else if (member->bitfield_size) {
			printed += class_member__fprintf_bitfield_value(member, member_contents, fp);
		} else if (tag__is_base_type(member_type, cu)) {
			printed += base_type__fprintf_value(member_contents, member->byte_size, fp);
		} else if (tag__is_array(member_type, cu)) {
			int sizeof_member = member->byte_size;

			// zero sized array, at the end of the struct?
			if (sizeof_member == 0 && list_is_last(&member->tag.node, &type->namespace.tags))
				sizeof_member = _sizeof - member->byte_offset;
			printed += array__fprintf_value(member_type, cu, member_contents, sizeof_member, fp);
		} else if (tag__is_struct(member_type)) {
			printed += __class__fprintf_value(member_type, cu, member_contents, member->byte_size, indent + 1, true, fp);
		} else if (tag__is_union(member_type)) {
			printed += __class__fprintf_value(member_type, cu, member_contents, member->byte_size, indent + (name ? 1 : 0), !!name, fp);
			if (!name)
				continue;
		} else {
			printed += instance__fprintf_hexdump_value(member_contents, member->byte_size, fp);
		}

		fputc(',', fp);
		++printed;
	}

	if (brackets)
		printed += fprintf(fp, "\n%.*s}", indent, tabs);
	return printed;
}

static int class__fprintf_value(struct tag *tag, struct cu *cu, void *instance, int _sizeof, int indent, FILE *fp)
{
	return __class__fprintf_value(tag, cu, instance, _sizeof, indent, true, fp);
}

static int tag__fprintf_value(struct tag *type, struct cu *cu, void *instance, int _sizeof, FILE *fp)
{
	if (tag__is_struct(type))
		return class__fprintf_value(type, cu, instance, _sizeof, 0, fp);

	return instance__fprintf_hexdump_value(instance, _sizeof, fp);
}

static int pipe_seek(FILE *fp, off_t offset)
{
	char bf[4096];
	int chunk = sizeof(bf);

	if (chunk > offset)
		chunk = offset;

	while (fread(bf, chunk, 1, fp) == 1) {
		offset -= chunk;
		if (offset == 0)
			return 0;
		if (chunk > offset)
			chunk = offset;
	}

	return offset == 0 ? 0 : -1;
}

static uint64_t tag__real_sizeof(struct tag *tag, int _sizeof, void *instance)
{
	if (tag__is_struct(tag)) {
		struct type *type = tag__type(tag);

		if (type->sizeof_member) {
			struct class_member *member = type->sizeof_member;
			return base_type__value(instance + member->byte_offset, member->byte_size);
		}
	}

	return _sizeof;
}

/*
 * Classes should start close to where they are needed, then moved elsewhere, remember:
 * "Premature optimization is the root of all evil" (Knuth till unproven).
 *
 * So far just the '==' operator is supported, so just a struct member + a value are
 * needed, no, strings are not supported so far.
 *
 * If the class member is the 'type=' and we have a 'type_enum=' in place, then we will
 * resolve that at parse time and convert that to an uint64_t and it'll do the trick.
 *
 * More to come, when needed.
 */
struct class_member_filter {
	struct class_member *left;
	uint64_t	    right;
};

static bool type__filter_value(struct tag *tag, void *instance)
{
	// this has to be a type, otherwise we'd not have a type->filter
	struct type *type = tag__type(tag);
	struct class_member_filter *filter = type->filter;
	struct class_member *member = filter->left;
	uint64_t value = base_type__value(instance + member->byte_offset, member->byte_size);

	// Only operator supported so far is '=='
	return value != filter->right;
}

static struct tag *tag__real_type(struct tag *tag, struct cu **cup, void *instance)
{
	if (tag__is_struct(tag)) {
		struct type *type = tag__type(tag);

		if (!list_empty(&type->type_enum) && type->type_member) {
			struct class_member *member = type->type_member;
			uint64_t value = base_type__value(instance + member->byte_offset, member->byte_size);
			struct enumerator *enumerator = enumerations__lookup_entry_from_value(&type->type_enum, value);
			char name[1024];

			if (!enumerator)
				return tag;

			if (enumerator->type_enum.tag) {
				*cup = enumerator->type_enum.cu;
				return enumerator->type_enum.tag;
			}

			snprintf(name, sizeof(name), "%s", enumerator__name(enumerator));
			strlwr(name);

			struct tag *real_type = cu__find_type_by_name(*cup, name, false, NULL);

			if (!real_type)
				return NULL;

			if (tag__is_struct(real_type)) {
				enumerator->type_enum.tag = real_type;
				enumerator->type_enum.cu  = *cup;
				return real_type;
			}
		}
	}

	return tag;
}

struct type_instance {
	struct type *type;
	struct cu   *cu;
	bool	    read_already;
	char	    instance[0];
};

static struct type_instance *type_instance__new(struct type *type, struct cu *cu)
{
	if (type == NULL)
		return NULL;

	struct type_instance *instance = malloc(sizeof(*instance) + type->size);

	if (instance) {
		instance->type = type;
		instance->cu   = cu;
		instance->read_already = false;
	}

	return instance;
}

static void type_instance__delete(struct type_instance *instance)
{
	if (!instance)
		return;
	instance->type = NULL;
	free(instance);
}

static int64_t type_instance__int_value(struct type_instance *instance, const char *member_name_orig)
{
	struct cu *cu = instance->cu;
	struct class_member *member = type__find_member_by_name(instance->type, member_name_orig);
	int byte_offset = 0;

	if (!member) {
		char *sep = strchr(member_name_orig, '.');

		if (!sep)
			return -1;

		char *member_name_alloc = strdup(member_name_orig);

		if (!member_name_alloc)
			return -1;

		char *member_name = member_name_alloc;
		struct type *type = instance->type;

		sep = member_name_alloc + (sep - member_name_orig);
		*sep = 0;

		while (1) {
			member = type__find_member_by_name(type, member_name);
			if (!member) {
out_free_member_name:
				free(member_name_alloc);
				return -1;
			}
			byte_offset += member->byte_offset;
			type = tag__type(cu__type(cu, member->tag.type));
			if (type == NULL)
				goto out_free_member_name;
			member_name = sep + 1;
			sep = strchr(member_name, '.');
			if (!sep)
				break;

		}

		member = type__find_member_by_name(type, member_name);
		free(member_name_alloc);
		if (member == NULL)
			return -1;
	}

	byte_offset += member->byte_offset;

	struct tag *member_type = cu__type(cu, member->tag.type);

	if (!tag__is_base_type(member_type, cu))
		return -1;

	return base_type__value(&instance->instance[byte_offset], member->byte_size);
}

static int64_t type__instance_read_once(struct type_instance *instance, FILE *fp)
{
 	if (!instance || instance->read_already)
		return 0;

 	instance->read_already = true;

	return fread(instance->instance, instance->type->size, 1, fp) != 1 ? -1 : (int64_t)instance->type->size;
}

/*
 * struct prototype - split arguments to a type
 *
 * @name - type name
 * @type - name of the member containing a type id
 * @type_enum - translate @type into a enum entry/string
 * @type_enum_resolved - if this was already resolved, i.e. if the enums were find in some CU
 * @size - the member with the size for variable sized records
 * @filter - filter expression using record contents and values or enum entries
 * @range - from where to get seek_bytes and size_bytes where to pretty print this specific class
 */
struct prototype {
	struct list_head node;
	struct tag	 *class;
	struct cu	 *cu;
	const char *type,
		   *type_enum,
		   *size,
		   *range;
	char	   *filter;
	uint16_t   nr_args;
	bool	   type_enum_resolved;
	char name[0];

};

static int prototype__stdio_fprintf_value(struct prototype *prototype, struct type_instance *header, FILE *input, FILE *output)
{
	struct tag *type = prototype->class;
	struct cu *cu = prototype->cu;
	int _sizeof = tag__size(type, cu), printed = 0;
	int max_sizeof = _sizeof;
	void *instance = malloc(_sizeof);
	uint64_t size_bytes = ULLONG_MAX;
	uint32_t count = 0;
	uint32_t skip = conf.skip;

	if (instance == NULL)
		return -ENOMEM;

	if (type__instance_read_once(header, input) < 0) {
		int err = --errno;
		fprintf(stderr, "pahole: --header (%s) type couldn't be read\n", conf.header_type);
		return err;
	}

	if (conf.range || prototype->range) {
		off_t seek_bytes;
		const char *range = conf.range ?: prototype->range;

		if (!header) {
			if (conf.header_type)
				fprintf(stderr, "pahole: --header_type=%s not found\n", conf.header_type);
			else
				fprintf(stderr, "pahole: range (%s) requires --header\n", range);
			return -ESRCH;
		}

		char *member_name = NULL;

		if (asprintf(&member_name, "%s.%s", range, "offset") == -1) {
			fprintf(stderr, "pahole: not enough memory for range=%s\n", range);
			return -ENOMEM;
		}

		int64_t value = type_instance__int_value(header, member_name);

		if (value < 0) {
			fprintf(stderr, "pahole: couldn't read the '%s' member of '%s' for evaluating range=%s\n",
				member_name, conf.header_type, range);
			free(member_name);
			return -ESRCH;
		}

		seek_bytes = value;

		free(member_name);

		off_t total_read_bytes = ftell(input);

		// Since we're reading input, we need to account for what we already read
		// FIXME: we now have a FILE pointer that _may_ be stdin, but not necessarily
		if (seek_bytes < total_read_bytes) {
			fprintf(stderr, "pahole: can't go back in input, already read %" PRIu64 " bytes, can't go to position %#" PRIx64 "\n",
					total_read_bytes, seek_bytes);
			return -ENOMEM;
		}

		if (global_verbose) {
			fprintf(output, "pahole: range.seek_bytes evaluated from range=%s is %#" PRIx64 " \n",
				range, seek_bytes);
		}

		seek_bytes -= total_read_bytes;

		if (asprintf(&member_name, "%s.%s", range, "size") == -1) {
			fprintf(stderr, "pahole: not enough memory for range=%s\n", range);
			return -ENOMEM;
		}

		value = type_instance__int_value(header, member_name);

		if (value < 0) {
			fprintf(stderr, "pahole: couldn't read the '%s' member of '%s' for evaluating range=%s\n",
				member_name, conf.header_type, range);
			free(member_name);
			return -ESRCH;
		}

		size_bytes = value;
		if (global_verbose) {
			fprintf(output, "pahole: range.size_bytes evaluated from range=%s is %#" PRIx64 " \n",
				range, size_bytes);
		}

		free(member_name);

		if (pipe_seek(input, seek_bytes) < 0) {
			int err = --errno;
			fprintf(stderr, "Couldn't --seek_bytes %s (%" PRIu64 "\n", conf.seek_bytes, seek_bytes);
			return err;
		}

		goto do_read;
	}

	if (conf.seek_bytes) {
		off_t seek_bytes;

		if (strstarts(conf.seek_bytes, "$header.")) {
			if (!header) {
				fprintf(stderr, "pahole: --seek_bytes (%s) makes reference to --header but it wasn't specified\n",
					conf.seek_bytes);
				return -ESRCH;
			}

			const char *member_name = conf.seek_bytes + sizeof("$header.") - 1;
			int64_t value = type_instance__int_value(header, member_name);
			if (value < 0) {
				fprintf(stderr, "pahole: couldn't read the '%s' member of '%s' for evaluating --seek_bytes=%s\n",
					member_name, conf.header_type, conf.seek_bytes);
				return -ESRCH;
			}

			seek_bytes = value;

			if (global_verbose)
				fprintf(stdout, "pahole: seek bytes evaluated from --seek_bytes=%s is %#" PRIx64 " \n",
					conf.seek_bytes, seek_bytes);

			if (seek_bytes < header->type->size) {
				fprintf(stderr, "pahole: seek bytes evaluated from --seek_bytes=%s is less than the header type size\n",
					conf.seek_bytes);
				return -EINVAL;
			}
		} else  {
			seek_bytes = strtol(conf.seek_bytes, NULL, 0);
		}


		if (header) {
			// Since we're reading input, we need to account for already read header:
			seek_bytes -= ftell(input);
		}

		if (pipe_seek(input, seek_bytes) < 0) {
			int err = --errno;
			fprintf(stderr, "Couldn't --seek_bytes %s (%" PRIu64 "\n", conf.seek_bytes, seek_bytes);
			return err;
		}
	}

	if (conf.size_bytes) {
		if (strstarts(conf.size_bytes, "$header.")) {
			if (!header) {
				fprintf(stderr, "pahole: --size_bytes (%s) makes reference to --header but it wasn't specified\n",
					conf.size_bytes);
				return -ESRCH;
			}

			const char *member_name = conf.size_bytes + sizeof("$header.") - 1;
			int64_t value = type_instance__int_value(header, member_name);
			if (value < 0) {
				fprintf(stderr, "pahole: couldn't read the '%s' member of '%s' for evaluating --size_bytes=%s\n",
					member_name, conf.header_type, conf.size_bytes);
				return -ESRCH;
			}

			size_bytes = value;

			if (global_verbose)
				fprintf(stdout, "pahole: size bytes evaluated from --size_bytes=%s is %#" PRIx64 " \n",
					conf.size_bytes, size_bytes);
		} else  {
			size_bytes = strtol(conf.size_bytes, NULL, 0);
		}
	}
do_read:
{
	uint64_t read_bytes = 0;
	off_t record_offset = ftell(input);

	while (fread(instance, _sizeof, 1, input) == 1) {
		// Read it from each record/instance
		int real_sizeof = tag__real_sizeof(type, _sizeof, instance);

		if (real_sizeof > _sizeof) {
			if (real_sizeof > max_sizeof) {
				void *new_instance = realloc(instance, real_sizeof);
				if (!new_instance) {
					fprintf(stderr, "Couldn't allocate space for a record, too big: %d bytes\n", real_sizeof);
					printed = -1;
					goto out;
				}
				instance = new_instance;
				max_sizeof = real_sizeof;
			}
			if (fread(instance + _sizeof, real_sizeof - _sizeof, 1, input) != 1) {
				fprintf(stderr, "Couldn't read record: %d bytes\n", real_sizeof);
				printed = -1;
				goto out;
			}
		}

		read_bytes += real_sizeof;

		if (tag__type(type)->filter && type__filter_value(type, instance))
			goto next_record;

		if (skip) {
			--skip;
			goto next_record;
		}

		/*
		 * pahole -C 'perf_event_header(sizeof=size,typeid=type,enum2type=perf_event_type)
		 *
		 * So that it gets the 'type' field as the type id, look this
		 * up in the 'enum perf_event_type' and find the type to cast the
		 * whole shebang, i.e.:
		 *

		 $ pahole ~/bin/perf -C perf_event_header
		   struct perf_event_header {
			  __u32        type;       / *  0  4 * /
			  __u16        misc;       / *  4  2 * /
			  __u16        size;       / *  6  2 * /

			  / * size: 8, cachelines: 1, members: 3 * /
			  / * last cacheline: 8 bytes * /
		   };
		 $

		 enum perf_event_type {
			PERF_RECORD_MMAP = 1,
			PERF_RECORD_LOST = 2,
			PERF_RECORD_COMM = 3,
			PERF_RECORD_EXIT = 4,
			<SNIP>
		 }

		 * So from the type field get the lookup into the enum and from the result, look
		 * for a type with that name as-is or in lower case, which will produce, when type = 3:

		 $ pahole -C perf_record_comm ~/bin/perf
		   struct perf_record_comm {
			   struct perf_event_header   header;   / *     0     8 * /
			   __u32                      pid;      / *     8     4 * /
			   __u32                      tid;      / *    12     4 * /
			   char                       comm[16]; / *    16    16 * /

			   / * size: 32, cachelines: 1, members: 4 * /
			   / * last cacheline: 32 bytes * /
		   };
		   $
		 */

		struct cu *real_type_cu = cu;
		struct tag *real_type = tag__real_type(type, &real_type_cu, instance);

		if (real_type == NULL)
			real_type = type;

		if (global_verbose) {
			printed += fprintf(output, "// type=%s, offset=%#" PRIx64 ", sizeof=%d", type__name(tag__type(type)), record_offset, _sizeof);
			if (real_sizeof != _sizeof)
				printed += fprintf(output, ", real_sizeof=%d\n", real_sizeof);
			else
				printed += fprintf(output, "\n");
		}
		printed += tag__fprintf_value(real_type, real_type_cu, instance, real_sizeof, output);
		printed += fprintf(output, ",\n");

		if (conf.count && ++count == conf.count)
			break;
next_record:
		if (read_bytes >= size_bytes)
			break;

		record_offset = ftell(input);
	}
}
out:
	free(instance);
	return printed;
}

static int class_member_filter__parse(struct class_member_filter *filter, struct type *type, char *sfilter)
{
	const char *member_name = sfilter;
	char *sep = strstr(sfilter, "==");

	if (!sep) {
		if (global_verbose)
			fprintf(stderr, "No supported operator ('==' so far) found in filter '%s'\n", sfilter);
		return -1;
	}

	char *value = sep + 2, *s = sep;

	while (isspace(*--s))
		if (s == sfilter) {
			if (global_verbose)
				fprintf(stderr, "No left operand (struct field) found in filter '%s'\n", sfilter);
			return -1; // nothing before ==
		}

	char before = s[1];
	s[1] = '\0';

	filter->left = type__find_member_by_name(type, member_name);

	if (!filter->left) {
		if (global_verbose)
			fprintf(stderr, "The '%s' member wasn't found in '%s'\n", member_name, type__name(type));
		s[1] = before;
		return -1;
	}

	s[1] = before;

	while (isspace(*value))
		if (*++value == '\0') {
			if (global_verbose)
				fprintf(stderr, "The '%s' member was asked without a value to filter '%s'\n", member_name, type__name(type));
			return -1; // no value
		}

	char *endptr;
	filter->right = strtoll(value, &endptr, 0);

	if (endptr > value && (*endptr == '\0' || isspace(*endptr)))
		return 0;

	// If t he filter member is the 'type=' one:

	if (list_empty(&type->type_enum) || type->type_member != filter->left) {
		if (global_verbose)
			fprintf(stderr, "Symbolic right operand in '%s' but no way to resolve it to a number (type= + type_enum= so far)\n", sfilter);
		return -1;
	}

	enumerations__calc_prefix(&type->type_enum);

	int64_t enumerator_value = enumerations__lookup_enumerator(&type->type_enum, value);

	if (enumerator_value < 0) {
		if (global_verbose)
			fprintf(stderr, "Couldn't resolve right operand ('%s') in '%s' with the specified 'type=%s' and type_enum' \n",
				value, sfilter, class_member__name(type->type_member));
		return -1;
	}

	filter->right = enumerator_value;

	return 0;
}

static struct class_member_filter *class_member_filter__new(struct type *type, char *sfilter)
{
	struct class_member_filter *filter = malloc(sizeof(*filter));

	if (filter && class_member_filter__parse(filter, type, sfilter)) {
		free(filter);
		filter = NULL;
	}

	return filter;
}

static struct prototype *prototype__new(const char *expression)
{
	struct prototype *prototype = zalloc(sizeof(*prototype) + strlen(expression) + 1);

	if (prototype == NULL)
		goto out_enomem;

	strcpy(prototype->name, expression);

	const char *name = prototype->name;

	prototype->nr_args = 0;

	char *args_open = strchr(name, '(');

	if (!args_open)
		goto out;

	char *args_close = strchr(args_open, ')');

	if (args_close == NULL)
		goto out_no_closing_parens;

	char *args = args_open;

	*args++ = *args_close = '\0';

	while (isspace(*args))
		++args;

	if (args == args_close)
		goto out; // empty args, just ignore the parens, i.e. 'foo()'
next_arg:
{
	char *comma = strchr(args, ','), *value;

	if (comma)
		*comma = '\0';

	char *assign = strchr(args, '=');

	if (assign == NULL) {
		if (strcmp(args, "sizeof") == 0) {
			value = "size";
			goto do_sizeof;
		} else if (strcmp(args, "type") == 0) {
			value = "type";
			goto do_type;
		}
		goto out_missing_assign;
	}

	// accept foo==bar as filter=foo==bar
	if (assign[1] == '=') {
		value = args;
		goto do_filter;
	}

	*assign = 0;

	value = assign + 1;

	while (isspace(*value))
		++value;

	if (value == args_close)
		goto out_missing_value;

	if (strcmp(args, "sizeof") == 0) {
do_sizeof:
		if (global_verbose)
			printf("pahole: sizeof_operator for '%s' is '%s'\n", name, value);

		prototype->size = value;
	} else if (strcmp(args, "type") == 0) {
do_type:
		if (global_verbose)
			printf("pahole: type member for '%s' is '%s'\n", name, value);

		prototype->type = value;
	} else if (strcmp(args, "type_enum") == 0) {
		if (global_verbose)
			printf("pahole: type enum for '%s' is '%s'\n", name, value);
		prototype->type_enum = value;
	} else if (strcmp(args, "filter") == 0) {
do_filter:
		if (global_verbose)
			printf("pahole: filter for '%s' is '%s'\n", name, value);

		prototype->filter = value;
	} else if (strcmp(args, "range") == 0) {
		if (global_verbose)
			printf("pahole: range for '%s' is '%s'\n", name, value);
		prototype->range = value;
	} else
		goto out_invalid_arg;

	++prototype->nr_args;

	if (comma) {
		args = comma + 1;
		goto next_arg;
	}
}
out:
	return prototype;

out_enomem:
	fprintf(stderr, "pahole: not enough memory for '%s'\n", expression);
	goto out;

out_invalid_arg:
	fprintf(stderr, "pahole: invalid arg '%s' in '%s' (known args: sizeof=member, type=member, type_enum=enum)\n", args, expression);
	goto out_free;

out_missing_value:
	fprintf(stderr, "pahole: invalid, missing value in '%s'\n", expression);
	goto out_free;

out_no_closing_parens:
	fprintf(stderr, "pahole: invalid, no closing parens in '%s'\n", expression);
	goto out_free;

out_missing_assign:
	fprintf(stderr, "pahole: invalid, missing '=' in '%s'\n", args);
	goto out_free;

out_free:
	free(prototype);
	return NULL;
}

#ifdef DEBUG_CHECK_LEAKS
static void prototype__delete(struct prototype *prototype)
{
	if (prototype) {
		memset(prototype, 0xff, sizeof(*prototype));
		free(prototype);
	}
}
#endif

static struct tag_cu_node *tag_cu_node__new(struct tag *tag, struct cu *cu)
{
	struct tag_cu_node *tc = malloc(sizeof(*tc));

	if (tc) {
		tc->tc.tag = tag;
		tc->tc.cu  = cu;
	}

	return tc;
}

static int type__add_type_enum(struct type *type, struct tag *type_enum, struct cu *cu)
{
	struct tag_cu_node *tc = tag_cu_node__new(type_enum, cu);

	if (!tc)
		return -1;

	list_add_tail(&tc->node, &type->type_enum);
	return 0;
}

static int type__find_type_enum(struct type *type, struct cu *cu, const char *type_enum)
{
	struct tag *te = cu__find_enumeration_by_name(cu, type_enum, NULL);

	if (te)
		return type__add_type_enum(type, te, cu);

	// Now look at a 'virtual enum', i.e. the concatenation of multiple enums
	char *sep = strchr(type_enum, '+');

	if (!sep)
		return -1;

	char *type_enums = strdup(type_enum);

	if (!type_enums)
		return -1;

	int ret = -1;

	sep = type_enums + (sep - type_enum);

	type_enum = type_enums;
	*sep = '\0';

	while (1) {
		te = cu__find_enumeration_by_name(cu, type_enum, NULL);

		if (!te)
			goto out;

		ret = type__add_type_enum(type, te, cu);
		if (ret)
			goto out;

		if (sep == NULL)
			break;
		type_enum = sep + 1;
		sep = strchr(type_enum, '+');
	}

	ret = 0;
out:
	free(type_enums);
	return ret;
}

static struct type_instance *header;

static enum load_steal_kind pahole_stealer(struct cu *cu,
					   struct conf_load *conf_load)
{
	int ret = LSK__DELETE;

	if (!cu__filter(cu))
		goto filter_it;

	if (conf_load->ptr_table_stats) {
		static bool first = true;

		if (first) {
			cus__fprintf_ptr_table_stats_csv_header(stderr);
			first = false;
		}
		cu__fprintf_ptr_table_stats_csv(cu, stderr);
	}

	if (btf_encode) {
		static pthread_mutex_t btf_lock = PTHREAD_MUTEX_INITIALIZER;

		pthread_mutex_lock(&btf_lock);
		/*
		 * FIXME:
		 *
		 * This should be really done at main(), but since in the current codebase only at this
		 * point we'll have cu->elf setup...
		 */
		if (!btf_encoder) {
			btf_encoder = btf_encoder__new(cu, detached_btf_filename, conf_load->base_btf, skip_encoding_btf_vars,
						       btf_encode_force, btf_gen_floats, global_verbose);
			if (btf_encoder == NULL) {
				ret = LSK__STOP_LOADING;
				goto out_btf;
			}
		}

		if (btf_encoder__encode_cu(btf_encoder, cu)) {
			fprintf(stderr, "Encountered error while encoding BTF.\n");
			exit(1);
		}
		ret = LSK__DELETE;
out_btf:
		pthread_mutex_unlock(&btf_lock);
		return ret;
	}
#if 0
	if (ctf_encode) {
		cu__encode_ctf(cu, global_verbose);
		/*
		 * We still have to get the type signature code merged to eliminate
		 * dups, reference another CTF file, etc, so for now just encode the
		 * first cu that is let thru by cu__filter.
		 *
		 * FIXME: Disabled, should use Oracle's libctf
		 */
		goto dump_and_stop;
	}
#endif
	if (class_name == NULL) {
		if (stats_formatter == nr_methods_formatter) {
			cu__account_nr_methods(cu);
			goto dump_it;
		}

		if (word_size != 0)
			cu_fixup_word_size_iterator(cu);

		print_classes(cu);

		if (sort_output && formatter == class_formatter)
			ret = LSK__KEEPIT;

		goto dump_it;
	}

	if (header == NULL && conf.header_type) {
		header = type_instance__new(tag__type(cu__find_type_by_name(cu, conf.header_type, false, NULL)), cu);
		if (header)
			ret = LSK__KEEPIT;
	}

	bool include_decls = find_pointers_in_structs != 0 || stats_formatter == nr_methods_formatter;
	struct prototype *prototype, *n;

	list_for_each_entry_safe(prototype, n, &class_names, node) {

		/* See if we already found it */
		if (prototype->class) {
			if (prototype->type_enum && !prototype->type_enum_resolved)
				prototype->type_enum_resolved = type__find_type_enum(tag__type(prototype->class), cu, prototype->type_enum) == 0;
			continue;
		}

		static type_id_t class_id;
		struct tag *class = cu__find_type_by_name(cu, prototype->name, include_decls, &class_id);

		if (class == NULL)
			return ret; // couldn't find that class name in this CU, continue to the next one.

		if (prototype->nr_args != 0 && !tag__is_struct(class)) {
			fprintf(stderr, "pahole: attributes are only supported with 'class' and 'struct' types\n");
			goto dump_and_stop;
		}

		struct type *type = tag__type(class);

		if (prototype->size) {
			type->sizeof_member = type__find_member_by_name(type, prototype->size);
			if (type->sizeof_member == NULL) {
				fprintf(stderr, "pahole: the sizeof member '%s' wasn't found in the '%s' type\n",
					prototype->size, prototype->name);
				goto dump_and_stop;
			}
		}

		if (prototype->type) {
			type->type_member = type__find_member_by_name(type, prototype->type);
			if (type->type_member == NULL) {
				fprintf(stderr, "pahole: the type member '%s' wasn't found in the '%s' type\n",
					prototype->type, prototype->name);
				goto dump_and_stop;
			}
		}

		if (prototype->type_enum) {
			prototype->type_enum_resolved = type__find_type_enum(type, cu, prototype->type_enum) == 0;
		}

		if (prototype->filter) {
			type->filter = class_member_filter__new(type, prototype->filter);
			if (type->filter == NULL) {
				fprintf(stderr, "pahole: invalid filter '%s' for '%s'\n",
					prototype->filter, prototype->name);
				goto dump_and_stop;
			}
		}

		if (class == NULL) {
			if (strcmp(prototype->name, "void"))
				continue;
			class_id = 0;
		}

		if (prettify_input) {
			prototype->class = class;
			prototype->cu	 = cu;
			continue;
		}

		/*
		 * Ok, found it, so remove from the list to avoid printing it
		 * twice, in another CU.
		 */
		list_del_init(&prototype->node);

		if (defined_in) {
			puts(cu->name);
			goto dump_it;
		}

		if (class)
			class__find_holes(tag__class(class));
		if (reorganize) {
			if (class && tag__is_struct(class))
				do_reorg(class, cu);
		} else if (find_containers)
			print_containers(cu, class_id, 0);
		else if (find_pointers_in_structs)
			print_structs_with_pointer_to(cu, class_id);
		else if (class) {
			/*
			 * We don't need to print it for every compile unit
			 * but the previous options need
			 */
			tag__fprintf(class, cu, &conf, stdout);
			putchar('\n');
		}
	}

	// If we got here with pretty printing is because we have everything solved except for type_enum or --header

	if (prettify_input) {
		// Check if we need to continue loading CUs to get those type_enum= and --header resolved
		if (header == NULL && conf.header_type)
			return LSK__KEEPIT;

		list_for_each_entry(prototype, &class_names, node) {
			if (prototype->type_enum && !prototype->type_enum_resolved)
				return LSK__KEEPIT;
		}

		// All set, pretty print it!
		list_for_each_entry_safe(prototype, n, &class_names, node) {
			list_del_init(&prototype->node);
			if (prototype__stdio_fprintf_value(prototype, header, prettify_input, stdout) < 0)
				break;
		}

		return LSK__STOP_LOADING;
	}

	/*
	 * If we found all the entries in --class_name, stop
	 */
	if (list_empty(&class_names)) {
dump_and_stop:
		ret = LSK__STOP_LOADING;
	}
dump_it:
	if (first_obj_only)
		ret = LSK__STOP_LOADING;
filter_it:
	return ret;
}

static int prototypes__add(struct list_head *prototypes, const char *entry)
{
	struct prototype *prototype = prototype__new(entry);

	if (prototype == NULL)
		return -ENOMEM;

	list_add_tail(&prototype->node, prototypes);
	return 0;
}

#ifdef DEBUG_CHECK_LEAKS
static void prototypes__delete(struct list_head *prototypes)
{
	struct prototype *prototype, *n;

	if (prototypes == NULL)
		return;

	list_for_each_entry_safe(prototype, n, prototypes, node) {
		list_del_init(&prototype->node);
		prototype__delete(prototype);
	}
}
#endif

static int prototypes__load(struct list_head *prototypes, const char *filename)
{
	char entry[1024];
	int err = -1;
	FILE *fp = fopen(filename, "r");

	if (fp == NULL)
		return -1;

	while (fgets(entry, sizeof(entry), fp) != NULL) {
		const size_t len = strlen(entry);

		if (len == 0)
			continue;
		entry[len - 1] = '\0';
		if (prototypes__add(prototypes, entry))
			goto out;
	}

	err = 0;
out:
	fclose(fp);
	return err;
}

static int add_class_name_entry(const char *s)
{
	if (strncmp(s, "file://", 7) == 0) {
		if (prototypes__load(&class_names, s + 7))
			return -1;
	} else switch (prototypes__add(&class_names, s)) {
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
	char *s = strdup(class_name), *sep;
	char *sdup = s, *end = s + strlen(s);
	int ret = 0;

	if (!s) {
		fprintf(stderr, "Not enough memory for populating class names ('%s')\n", class_name);
		return -1;
	}

	/*
	 * Commas inside parameters shouldn't be considered, as those don't
	 * separate classes, but arguments to a particular class hack a simple
	 * parser, but really this will end up needing lex/yacc...
	 */
	while ((sep = strchr(s, ',')) != NULL) {
		char *parens = strchr(s, '(');

		// perf_event_header(sizeof=size),a

		if (parens && parens < sep) {
			char *close_parens = strchr(parens, ')');
			ret = -1;
			if (!close_parens) {
				fprintf(stderr, "Unterminated '(' in '%s'\n", class_name);
				fprintf(stderr, "                     %*.s^\n", (int)(parens - sdup), "");
				goto out_free;
			}
			if (close_parens > sep)
				sep = close_parens + 1;
		}

		*sep = '\0';
		ret = add_class_name_entry(s);
		if (ret)
			goto out_free;

		while (isspace(*sep))
			++sep;

		if (sep == end)
			goto out_free;

		s = sep + 1;
	}

	ret = add_class_name_entry(s);
out_free:
	free(sdup);
	return ret;
}

int main(int argc, char *argv[])
{
	int err, remaining, rc = EXIT_FAILURE;

	if (argp_parse(&pahole__argp, argc, argv, 0, &remaining, NULL)) {
		argp_help(&pahole__argp, stderr, ARGP_HELP_SEE, argv[0]);
		goto out;
	}

	if (class_name != NULL && stats_formatter == nr_methods_formatter) {
		fputs("pahole: -m/nr_methods doesn't work with --class/-C, it shows all classes and the number of its methods\n", stderr);
		return rc;
	}

	if (print_numeric_version) {
		dwarves_print_numeric_version(stdout);
		return 0;
	}

	if (conf_load.hashtable_bits > 31) {
		fprintf(stderr, "Invalid --hashbits value (%d) should be less than 32\n", conf_load.hashtable_bits);
		goto out;
	}

	if (dwarves__init(cacheline_size)) {
		fputs("pahole: insufficient memory\n", stderr);
		goto out;
	}

	if (prettify_input_filename) {
		if (strcmp(prettify_input_filename, "-") == 0) {
			prettify_input = stdin;
		} else {
			prettify_input = fopen(prettify_input_filename, "r");
			if (prettify_input == NULL) {
				fprintf(stderr, "Failed to read input '%s': %s\n",
					prettify_input_filename, strerror(errno));
				goto out_dwarves_exit;
			}
		}
	}

	if (base_btf_file) {
		conf_load.base_btf = btf__parse(base_btf_file, NULL);
		if (libbpf_get_error(conf_load.base_btf)) {
			fprintf(stderr, "Failed to parse base BTF '%s': %ld\n",
				base_btf_file, libbpf_get_error(conf_load.base_btf));
			goto out;
		}
		if (!btf_encode && !ctf_encode) {
			// Force "btf" since a btf_base is being informed
			conf_load.format_path = "btf";
		}
	}

	struct cus *cus = cus__new();
	if (cus == NULL) {
		fputs("pahole: insufficient memory\n", stderr);
		goto out_dwarves_exit;
	}

	memset(tab, ' ', sizeof(tab) - 1);

	conf_load.steal = pahole_stealer;

	// Make 'pahole --header type < file' a shorter form of 'pahole -C type --count 1 < file'
	if (conf.header_type && !class_name && prettify_input) {
		conf.count = 1;
		class_name = conf.header_type;
		conf.header_type = 0; // so that we don't read it and then try to read the -C type
	}

try_sole_arg_as_class_names:
	if (class_name && populate_class_names())
		goto out_dwarves_exit;

	if (base_btf_file == NULL) {
		const char *filename = argv[remaining];

		if (filename &&
		    strstarts(filename, "/sys/kernel/btf/") &&
		    strstr(filename, "/vmlinux") == NULL) {
			base_btf_file = "/sys/kernel/btf/vmlinux";
			conf_load.base_btf = btf__parse(base_btf_file, NULL);
			if (libbpf_get_error(conf_load.base_btf)) {
				fprintf(stderr, "Failed to parse base BTF '%s': %ld\n",
					base_btf_file, libbpf_get_error(conf_load.base_btf));
				goto out;
			}
		}
	}

	err = cus__load_files(cus, &conf_load, argv + remaining);
	if (err != 0) {
		if (class_name == NULL && !btf_encode && !ctf_encode) {
			class_name = argv[remaining];
			if (access(class_name, R_OK) == 0) {
				fprintf(stderr, "pahole: file '%s' has no %s type information.\n",
						class_name, conf_load.format_path ?: "supported");
				goto out_dwarves_exit;
			}
			remaining = argc;
			goto try_sole_arg_as_class_names;
		}
		cus__fprintf_load_files_err(cus, "pahole", argv + remaining, err, stderr);
		goto out_cus_delete;
	}

	if (sort_output && formatter == class_formatter) {
		print_ordered_classes();
		goto out_ok;
	}

	if (!list_empty(&class_names)) {
		struct prototype *prototype;

		list_for_each_entry(prototype, &class_names, node) {
			if (prototype->class == NULL) {
				fprintf(stderr, "pahole: type '%s' not found%s\n", prototype->name,
					prototype->nr_args ? " or arguments not validated" : "");
				break;
			} else {
				struct type *type = tag__type(prototype->class);

				if (prototype->type && !type->type_member) {
					fprintf(stderr, "pahole: member 'type=%s' not found in '%s' type\n",
						prototype->type, prototype->name);
				}

				if (prototype->size && !type->sizeof_member) {
					fprintf(stderr, "pahole: member 'sizeof=%s' not found in '%s' type\n",
						prototype->size, prototype->name);
				}

				if (prototype->filter && !type->filter) {
					fprintf(stderr, "pahole: filter 'filter=%s' couldn't be evaluated for '%s' type\n",
						prototype->filter, prototype->name);
				}

				if (prototype->type_enum && !prototype->type_enum_resolved) {
					fprintf(stderr, "pahole: 'type_enum=%s' couldn't be evaluated for '%s' type\n",
						prototype->type_enum, prototype->name);
				}
			}
		}
	}

	type_instance__delete(header);
	header = NULL;

	if (btf_encode) {
		err = btf_encoder__encode(btf_encoder);
		if (err) {
			fputs("Failed to encode BTF\n", stderr);
			goto out_cus_delete;
		}
	}
out_ok:
	if (stats_formatter != NULL)
		print_stats();

	rc = EXIT_SUCCESS;
out_cus_delete:
#ifdef DEBUG_CHECK_LEAKS
	cus__delete(cus);
	structures__delete();
	btf__free(conf_load.base_btf);
	conf_load.base_btf = NULL;
#endif
out_dwarves_exit:
	if (prettify_input && prettify_input != stdin) {
		fclose(prettify_input);
		prettify_input = NULL;
	}
#ifdef DEBUG_CHECK_LEAKS
	dwarves__exit();
#endif
out:
#ifdef DEBUG_CHECK_LEAKS
	prototypes__delete(&class_names);
#endif
	return rc;
}
