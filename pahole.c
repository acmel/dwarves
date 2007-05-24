/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <argp.h>
#include <stdio.h>
#include <dwarf.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "dwarves_reorganize.h"
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
static uint16_t hole_size_ge;
static uint8_t show_packable;
static uint8_t global_verbose;
static uint8_t expand_types;
static uint8_t rel_offset;
static uint8_t recursive;
static size_t cacheline_size;
static uint8_t find_containers;
static int reorganize;
static int show_reorg_steps;
static char *class_name;
static char separator = '\t';

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
		const struct class *c = pos->class;
		const char *cname = class__name(c);

		if (cname == NULL) {
			if (class__include_anonymous) {
				const struct tag *tdef =
				      cu__find_first_typedef_of_type(pos->cu,
							   class__tag(c)->id);
				if (tdef == NULL)
					continue;

				cname = class__name(tag__class(tdef));
				if (cname == NULL)
					continue;
			} else
				continue;
		}

		if (strcmp(cname, name) == 0)
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
	printf("%s%c%u\n", class__name(self->class), separator,
	       self->nr_files);
}

static void nr_members_formatter(const struct structure *self)
{
	printf("%s%c%u\n", class__name(self->class), separator,
	       class__nr_members(self->class));
}

static void nr_methods_formatter(const struct structure *self)
{
	printf("%s%c%u\n", class__name(self->class), separator,
	       self->nr_methods);
}

static void size_formatter(const struct structure *self)
{
	printf("%s%c%zd%c%u\n", class__name(self->class), separator,
	       class__size(self->class), separator,
	       self->class->nr_holes);
}

static void class_name_len_formatter(const struct structure *self)
{
	const char *name = class__name(self->class);
	printf("%s%c%zd\n", name, separator, strlen(name));
}

static void class_name_formatter(const struct structure *self)
{
	puts(class__name(self->class));
}

static void class_formatter(const struct structure *self)
{
	struct tag *typedef_alias = NULL;
	struct tag *tag = class__tag(self->class);
	const char *name = class__name(self->class);
	struct conf_fprintf conf = {
		.expand_types = expand_types,
		.rel_offset   = rel_offset,
		.emit_stats   = 1,
	};

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

		conf.prefix = "typedef";
		conf.suffix = type__name(tdef);
	}

	tag__fprintf(tag, self->cu, &conf, stdout);

	printf("   /* definitions: %u */\n", self->nr_files);
	putchar('\n');
}

static void print_classes(void (*formatter)(const struct structure *s))
{
	struct structure *pos;

	list_for_each_entry(pos, &structures__list, node)
		if (show_packable && !global_verbose) {
			const struct class *c = pos->class;
			const struct tag *t = class__tag(c);
			const size_t orig_size = class__size(c);
			const size_t new_size = class__size(c->priv);
			const size_t savings = orig_size - new_size;
			const char *name = class__name(c);

			/* Anonymous struct? Try finding a typedef */
			if (name == NULL) {
				const struct tag *tdef =
				      cu__find_first_typedef_of_type(pos->cu,
				      				     t->id);
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
				       t->decl_file, t->decl_line, separator,
				       orig_size, separator,
				       new_size, separator,
				       savings);
		} else
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

static int class__packable(struct class *self, const struct cu *cu)
{
 	struct class *clone;
	size_t savings;

	if (self->nr_holes == 0 && self->nr_bit_holes == 0)
		return 0;

 	clone = class__clone(self, NULL);
 	if (clone == NULL)
		return 0;
 	class__reorganize(clone, cu, 0, stdout);
	savings = class__size(self) - class__size(clone);
	if (savings != 0) {
		self->priv = clone;
		return 1;
	}
	class__delete(clone);
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

	if (class__exclude_prefix != NULL) {
		if (name == NULL) {
			const struct tag *tdef =
				cu__find_first_typedef_of_type(cu, tag->id);
			if (tdef != NULL)
				name = class__name(tag__class(tdef));
		}

		if (name != NULL && strncmp(class__exclude_prefix, name,
					    class__exclude_prefix_len) == 0)
			return NULL;
	}

	if (decl_exclude_prefix != NULL &&
	    (tag->decl_file == NULL ||
	     strncmp(decl_exclude_prefix, tag->decl_file,
		     decl_exclude_prefix_len) == 0))
		return NULL;

	class__find_holes(class, cu);

	if (class->nr_holes < nr_holes ||
	    class->nr_bit_holes < nr_bit_holes ||
	    (hole_size_ge != 0 && !class__has_hole_ge(class, hole_size_ge)))
		return NULL;

	str = structures__find(name);
	if (str != NULL) {
		if (global_verbose)
			class__chkdupdef(str->class, str->cu, class, cu);
		str->nr_files++;
		return NULL;
	}

	if (show_packable && !class__packable(class, cu))
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
		if (type__name(ctype) == NULL)
			continue;

		str = structures__find(type__name(ctype));
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

static char tab[128];

static void print_containers(const struct structure *s, int ident)
{
	struct structure *pos;
	const Dwarf_Off type = s->class->type.namespace.tag.id;

	list_for_each_entry(pos, &structures__list, node) {
		const struct class *c = pos->class;
		const uint32_t n = type__nr_members_of_type(&c->type, type);

		if (n != 0) {
			printf("%.*s%s", ident * 2, tab, class__name(c));
			if (global_verbose)
				printf(": %u", n);
			putchar('\n');
			if (recursive)
				print_containers(pos, ident + 1);
		}
	}
}

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
		.name = "contains",
		.key  = 'i',
		.arg  = "CLASS_NAME",
		.doc  = "Show classes that contains CLASS_NAME"
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
		.name = "nr_methods",
		.key  = 'm',
		.doc  = "show number of methods",
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
		.name = "verbose",
		.key  = 'V',
		.doc  = "be verbose",
	},
	{
		.name = NULL,
	}
};

static void (*formatter)(const struct structure *s) = class_formatter;

static error_t pahole__options_parser(int key, char *arg,
				      struct argp_state *state)
{
	switch (key) {
	case ARGP_KEY_INIT: state->child_inputs[0] = state->input; break;
	case 'c': cacheline_size = atoi(arg);		break;
	case 'C': class_name = arg;			break;
	case 'd': recursive = 1;			break;
	case 'i': find_containers = 1;
		  class_name = arg;			break;
	case 'H': nr_holes = atoi(arg);			break;
	case 'z':
		hole_size_ge = atoi(arg);
		if (!global_verbose)
			formatter = class_name_formatter;
		break;
	case 'B': nr_bit_holes = atoi(arg);		break;
	case 'E': expand_types = 1;			break;
	case 'r': rel_offset = 1;			break;
	case 'R': reorganize = 1;			break;
	case 'S': show_reorg_steps = 1;			break;
	case 's': formatter = size_formatter;		break;
	case 'n': formatter = nr_members_formatter;	break;
	case 'N': formatter = class_name_len_formatter;	break;
	case 'm': formatter = nr_methods_formatter;	break;
	case 'P': show_packable	= 1;			break;
	case 't': separator = arg[0];			break;
	case 'T': formatter = nr_definitions_formatter;	break;
	case 'a': class__include_anonymous = 1;		break;
	case 'A': class__include_nested_anonymous = 1;	break;
	case 'D': decl_exclude_prefix = arg;
		  decl_exclude_prefix_len = strlen(decl_exclude_prefix);
							break;
	case 'x': class__exclude_prefix = arg;
		  class__exclude_prefix_len = strlen(class__exclude_prefix);
							break;
	case 'X': cu__exclude_prefix = arg;
		  cu__exclude_prefix_len = strlen(cu__exclude_prefix);
							break;
	case 'V': global_verbose = 1;			break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char pahole__args_doc[] = "[FILE]";

static struct argp pahole__argp = {
	.options  = pahole__options,
	.parser	  = pahole__options_parser,
	.args_doc = pahole__args_doc,
};

int main(int argc, char *argv[])
{
	struct cus *cus;
	int err;

	cus = cus__new(NULL, NULL);
	if (cus == NULL) {
		fputs("pahole: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}

	err = cus__loadfl(cus, &pahole__argp, argc, argv);
	if (err != 0)
		return EXIT_FAILURE;

	dwarves__init(cacheline_size);

	cus__for_each_cu(cus, cu_unique_iterator, NULL, cu__filter);
	if (formatter == nr_methods_formatter)
		cus__for_each_cu(cus, cu_nr_methods_iterator, NULL, cu__filter);

	memset(tab, ' ', sizeof(tab) - 1);

	if (class_name != NULL) {
		struct structure *s = structures__find(class_name);
		struct conf_fprintf conf = {
			.expand_types	= expand_types,
			.rel_offset	= rel_offset,
			.show_decl_info	= global_verbose,
			.emit_stats	= 1,
		};

		if (s == NULL) {
			fprintf(stderr, "struct %s not found!\n", class_name);
			return EXIT_FAILURE;
		}
 		if (reorganize) {
			size_t savings;
			const uint8_t reorg_verbose =
					show_reorg_steps ? 2 : global_verbose;
 			struct class *clone = class__clone(s->class, NULL);
 			if (clone == NULL) {
 				fprintf(stderr, "pahole: out of memory!\n");
 				return EXIT_FAILURE;
 			}
 			class__reorganize(clone, s->cu, reorg_verbose, stdout);
			savings = class__size(s->class) - class__size(clone);
			if (savings != 0 && reorg_verbose) {
				putchar('\n');
				if (show_reorg_steps)
					puts("/* Final reorganized struct: */");
			}
 			tag__fprintf(class__tag(clone), s->cu, &conf, stdout);
			if (savings != 0) {
				const size_t cacheline_savings =
				      (tag__nr_cachelines(class__tag(s->class),
					 		  s->cu) -
				       tag__nr_cachelines(class__tag(clone),
							  s->cu));

				printf("   /* saved %zd byte%s", savings,
				       savings != 1 ? "s" : "");
				if (cacheline_savings != 0)
					printf(" and %zu cacheline%s",
					       cacheline_savings,
					       cacheline_savings != 1 ?
					       		"s" : "");
				puts("! */");
			}
 		} else if (find_containers)
			print_containers(s, 0);
		else
 			tag__fprintf(class__tag(s->class), s->cu, &conf, stdout);
	} else
		print_classes(formatter);

	return EXIT_SUCCESS;
}
