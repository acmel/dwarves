/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

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

#include "classes.h"

static char *class__exclude_prefix;
static size_t class__exclude_prefix_len;

static char *cu__exclude_prefix;
static size_t cu__exclude_prefix_len;

static char *decl_exclude_prefix;
static size_t decl_exclude_prefix_len;

static unsigned short nr_holes;
static unsigned short nr_bit_holes;
static uint8_t show_packable;

struct structure {
	struct list_head   node;
	const struct class *class;
	unsigned int	   nr_files;
};

static struct structure *structure__new(const struct class *class)
{
	struct structure *self = malloc(sizeof(*self));

	if (self != NULL) {
		self->class = class;
		self->nr_files = 1;
	}

	return self;
}

static LIST_HEAD(structures__list);

static struct structure *structures__find(const char *name)
{
	struct structure *pos;

	list_for_each_entry(pos, &structures__list, node)
		if (strcmp(pos->class->name, name) == 0)
			return pos;
	return NULL;
}

static void structures__add(const struct class *class)
{
	struct structure *str = structure__new(class);

	if (str != NULL)
		list_add(&str->node, &structures__list);
}

static void nr_definitions_formatter(const struct structure *self)
{
	printf("%s: %u\n", self->class->name, self->nr_files);
}

static void nr_members_formatter(const struct structure *self)
{
	printf("%s: %u\n", self->class->name, self->class->nr_members);
}

static void size_formatter(const struct structure *self)
{
	printf("%s: %llu %u\n", self->class->name, self->class->size,
	       self->class->nr_holes);
}

static void class_name_len_formatter(const struct structure *self)
{
	printf("%s: %u\n", self->class->name, strlen(self->class->name));
}

static void class_formatter(const struct structure *self)
{
	class__print(self->class);
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

	list_for_each_entry(pos, &self->members, tag.node)
		if (pos->hole != 0 &&
		    class__find_bit_hole(self, pos, pos->hole * 8) != NULL)
			return 1;
		else if (pos->bit_hole != 0 &&
			 class__find_bit_hole(self, pos, pos->bit_hole) != NULL)
			return 1;

	return 0;
}

static void class__dupmsg(const struct class *self, const struct class *dup,
			  char *hdr, const char *fmt, ...)
{
	va_list args;

	if (!*hdr)
		printf("class: %s\nfirst: %s\ncurrent: %s\n",
		       self->name, self->cu->name, dup->cu->name);
	
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	*hdr = 1;
}

static void class__chkdupdef(const struct class *self, struct class *dup)
{
	char hdr = 0;

	if (self->size != dup->size)
		class__dupmsg(self, dup, &hdr, "size: %llu != %llu\n",
			      self->size, dup->size);

	if (self->nr_members != dup->nr_members)
		class__dupmsg(self, dup, &hdr, "nr_members: %u != %u\n",
			      self->nr_members, dup->nr_members);

	if (self->nr_holes != dup->nr_holes)
		class__dupmsg(self, dup, &hdr, "nr_holes: %u != %u\n",
			      self->nr_holes, dup->nr_holes);

	if (self->nr_bit_holes != dup->nr_bit_holes)
		class__dupmsg(self, dup, &hdr, "nr_bit_holes: %u != %u\n",
			      self->nr_bit_holes, dup->nr_bit_holes);

	if (self->padding != dup->padding)
		class__dupmsg(self, dup, &hdr, "padding: %u != %u\n",
			      self->padding, dup->padding);

	/* XXX put more checks here: member types, member ordering, etc */

	if (hdr)
		putchar('\n');
}

static struct class *class__to_struct(struct class *class)
{
	struct class *typedef_alias;

	if (!class__is_struct(class, &typedef_alias))
		return NULL;
	return typedef_alias ?: class;
}

static struct class *class__filter(struct class *class)
{
	struct structure *str;

	class = class__to_struct(class);
	if (class == NULL) /* Not a structure */
		return NULL;

	if (class->name == NULL)
		return NULL;

	if (class->declaration)
		return NULL;

	if (class__exclude_prefix != NULL &&
	    strncmp(class__exclude_prefix, class->name,
		    class__exclude_prefix_len) == 0)
		return NULL;

	if (decl_exclude_prefix != NULL &&
	    (class->tag.decl_file == NULL ||
	     strncmp(decl_exclude_prefix, class->tag.decl_file,
		     decl_exclude_prefix_len) == 0))
		return NULL;

	class__find_holes(class);

	if (class->nr_holes < nr_holes ||
	    class->nr_bit_holes < nr_bit_holes)
		return NULL;

	str = structures__find(class->name);
	if (str != NULL) {
		class__chkdupdef(str->class, class);
		str->nr_files++;
		return NULL;
	}

	if (show_packable && !class__packable(class))
		return NULL;

	return class;
}

static int unique_iterator(struct class *class, void *cookie)
{
	structures__add(class);
	return 0;
}

static int cu_unique_iterator(struct cu *cu, void *cookie)
{
	return cu__for_each_class(cu, unique_iterator, cookie,
				  class__filter);
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
	{ "exclude",		required_argument,	NULL, 'x' },
	{ "cu_exclude",		required_argument,	NULL, 'X' },
	{ "decl_exclude",	required_argument,	NULL, 'D' },
	{ "packable",		no_argument,		NULL, 'p' },
	{ NULL, 0, NULL, 0, }
};

static void usage(void)
{
	fprintf(stderr,
		"usage: pahole [options] <file_name> {<function_name>}\n"
		" where: \n"
		"   -h, --help                   show usage info\n"
		"   -B, --bit_holes <nr_holes>   show only structs at least <nr_holes> bit holes\n"
		"   -H, --holes <nr_holes>       show only structs at least <nr_holes> holes\n"
		"   -p, --packable		 show only structs that has holes that can be packed\n"
		"   -c, --cacheline_size <size>  set cacheline size (default=%d)\n"
		"   -n, --nr_members             show number of members\n"
		"   -N, --class_name_len         show size of classes\n"
		"   -s, --sizes                  show size of classes\n"
		"   -t, --nr_definitions         show how many times struct was defined\n"
		"   -D, --decl_exclude <prefix>  exclude classes declared in files with prefix\n"
		"   -x, --exclude <prefix>       exclude prefixed classes from reports\n"
		"   -X, --cu_exclude <prefix>    exclude prefixed compilation units from reports\n",
		DEFAULT_CACHELINE_SIZE);
}

int main(int argc, char *argv[])
{
	int option, option_index;
	struct cus *cus;
	char *file_name;
	char *class_name = NULL;
	void (*formatter)(const struct structure *s) = class_formatter;

	while ((option = getopt_long(argc, argv, "B:c:D:hH:nNpstx:X:",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 'c': cacheline_size = atoi(optarg);  break;
		case 'H': nr_holes = atoi(optarg);	  break;
		case 'B': nr_bit_holes = atoi(optarg);	  break;
		case 's': formatter = size_formatter;		break;
		case 'n': formatter = nr_members_formatter;	break;
		case 'N': formatter = class_name_len_formatter;	break;
		case 'p': show_packable	= 1;			break;
		case 't': formatter = nr_definitions_formatter;	break;
		case 'D': decl_exclude_prefix = optarg;
			  decl_exclude_prefix_len = strlen(decl_exclude_prefix);
							  break;
		case 'x': class__exclude_prefix = optarg;
			  class__exclude_prefix_len = strlen(class__exclude_prefix);
							  break;
		case 'X': cu__exclude_prefix = optarg;
			  cu__exclude_prefix_len = strlen(cu__exclude_prefix);
							  break;
		case 'h': usage();			  return EXIT_SUCCESS;
		default:  usage();			  return EXIT_FAILURE;
		}

	if (optind < argc) {
		switch (argc - optind) {
		case 1:	 file_name = argv[optind++];	break;
		case 2:	 file_name = argv[optind++];
			 class_name = argv[optind++];	break;
		default: usage();			return EXIT_FAILURE;
		}
	} else {
		usage();
		return EXIT_FAILURE;
	}

	cus = cus__new(file_name);
	if (cus == NULL) {
		fputs("pahole: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}

	if (cus__load(cus) != 0) {
		fprintf(stderr, "pahole: couldn't load DWARF info from %s\n",
		       file_name);
		return EXIT_FAILURE;
	}

	cus__for_each_cu(cus, cu_unique_iterator, NULL, cu__filter);

	if (class_name != NULL) {
		struct structure *s = structures__find(class_name);

		if (s == NULL) {
			printf("struct %s not found!\n", class_name);
			return EXIT_FAILURE;
		}
		class__print(s->class);
	} else
		print_classes(formatter);

	return EXIT_SUCCESS;
}
