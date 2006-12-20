/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "classes.h"

static void method__add(struct cu *cu, struct function *function)
{
	list_add(&function->tool_node, &cu->tool_list);
}

static struct function *function__filter(struct function *function,
					 void *cookie)
{
	if (function__inlined(function) ||
	    !function__has_parameter_of_type(function, cookie))
		return NULL;

	return function;
}

static int find_methods_iterator(struct function *function, void *cookie)
{
	method__add(function->cu, function);
	return 0;
}

static int cu_find_methods_iterator(struct cu *cu, void *cookie)
{
	struct class *target = cu__find_class_by_name(cu, cookie);

	if (target == NULL)
		return 0;

	return cu__for_each_function(cu, find_methods_iterator, target,
				     function__filter);
}

static int function__fwd_decl(const struct function *self)
{
	struct parameter *pos;
	/* First check the function return type */
	int printed = tag__fwd_decl(self->cu, &self->tag);

	/* Then its parameters */
	list_for_each_entry(pos, &self->parameters, tag.node)
		if (tag__fwd_decl(self->cu, &pos->tag))
			printed = 1;

	if (printed)
		putchar('\n');
}

static int function__emit_kprobes(const struct function *self,
				  const struct class *target)
{
	char bf[128];
	size_t bodyl = 2048, printed;
	char body[bodyl], *bodyp = body;
	char class_name[128], parm_name[256];
	struct parameter *pos;
	struct class *type = cu__find_class_by_id(self->cu, self->tag.type);
	const char *stype = class__name(type, bf, sizeof(bf));
	int first = 1;

	body[0] = '\0';
	/*
	 * FIXME: how to handle enums, forward declarations doesn't help...
	 */
	if (type != NULL && type->tag.tag == DW_TAG_enumeration_type)
		stype = "int";
	printf("static %s jprobe_entry__%s(", stype, self->name);

	list_for_each_entry(pos, &self->parameters, tag.node) {
		type = cu__find_class_by_id(self->cu, pos->tag.type);
		parameter__names(pos, class_name, sizeof(class_name),
				 parm_name, sizeof(parm_name));

		if (!first)
			fputs(", ", stdout);
		else
			first = 0;

		printf("%s %s", class_name, parm_name);

		if (type->tag.tag != DW_TAG_pointer_type)
			continue;

		type = cu__find_class_by_id(self->cu, type->tag.type);
		if (type == NULL || type->tag.id != target->tag.id)
			continue;

		printed = snprintf(bodyp, bodyl,
				   "\tprintk(\"%s: %s=%%p\\n\", %s);\n",
				   self->name, pos->name, pos->name);
		bodyp += printed;
		bodyl -= printed;
	}
	printf(")\n{\n%s\n\tjprobe_return();\n\t/* NOTREACHED */%s\n}\n\n",
	       body, self->tag.type != 0 ? "\n\treturn 0;" : "");
	printf("static struct jprobe jprobe__%s = {\n"
	       "\t.kp = { .symbol_name = \"%s\", },\n"
	       "\t.entry = JPROBE_ENTRY(jprobe_entry__%s),\n"
	       "};\n\n", self->name, self->name, self->name);
	return 0;
}

static int cu_emit_kprobes_iterator(struct cu *cu, void *cookie)
{
	struct class *target = cu__find_class_by_name(cu, cookie);
	struct function *pos;

	list_for_each_entry(pos, &cu->tool_list, tool_node) {
		function__fwd_decl(pos);
		function__emit_kprobes(pos, target);
	}

	return 0;
}

static int cu_emit_kprobes_table_iterator(struct cu *cu, void *cookie)
{
	struct function *pos;

	list_for_each_entry(pos, &cu->tool_list, tool_node)
		printf("\t&jprobe__%s,\n", pos->name);

	return 0;
}

static void emit_module_preamble(void)
{
	puts("#include <linux/kernel.h>\n"
	     "#include <linux/module.h>\n"
	     "#include <linux/fs.h>\n"
	     "#include <linux/uio.h>\n"
	     "#include <linux/kprobes.h>\n");
}

static void emit_module_init(void)
{
	printf("static int __init jprobe_init(void)\n"
	       "{\n"
	       "	int i = 0;\n"
	       "	while (jprobes[i] != NULL) {\n"
	       "		int err = register_jprobe(jprobes[i]);\n"
	       "		if (err != 0)\n"
	       "			printk(\"register_jprobe(%%s) failed, "
					        "returned %%d\\n\",\n"
	       "			       jprobes[i]->kp.symbol_name, err);\n"
	       "		++i;\n"
	       "	}\n\n"
	       "        return 0;\n"
	       "}\n\n"
	       "module_init(jprobe_init);\n\n");
}

static void emit_module_exit(void)
{
	printf("static void __exit jprobe_exit(void)\n"
	       "{\n"
	       "	int i = 0;\n"
	       "	while (jprobes[i] != NULL) {\n"
	       "		unregister_jprobe(jprobes[i]);\n"
	       "		++i;\n"
	       "	}\n\n"
	       "}\n\n"
	       "module_exit(jprobe_exit);\n\n"
	       "MODULE_AUTHOR(\"ctracer\");\n"
	       "MODULE_LICENSE(\"GPL\");\n");
}

static struct option long_options[] = {
	{ "help",			no_argument,		NULL, 'h' },
	{ NULL, 0, NULL, 0, }
};

static void usage(void)
{
	fprintf(stdout,
		"usage: ctracer [options] <file_name> <class_name>\n"
		" where: \n"
		"   -h, --help	show this help message\n");
}

int main(int argc, char *argv[])
{
	int option, option_index;
	const char *file_name;
	struct cus *cus;
	char *class_name = NULL;

	while ((option = getopt_long(argc, argv, "h",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 'h': usage(); return EXIT_SUCCESS;
		default:  usage(); return EXIT_FAILURE;
		}

	if (optind < argc) {
		switch (argc - optind) {
		case 2:	 file_name  = argv[optind++];
			 class_name = argv[optind++];	break;
		default: usage();			return EXIT_FAILURE;
		}
	} else {
		usage();
		return EXIT_FAILURE;
	}

	cus = cus__new();
	if (cus == NULL) {
		fputs("ctracer: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}

	if (cus__load(cus, file_name) != 0) {
		fprintf(stderr, "ctracer: couldn't load DWARF info from %s\n",
			file_name);
		return EXIT_FAILURE;
	}

	emit_module_preamble();
	cus__for_each_cu(cus, cu_find_methods_iterator, class_name, NULL);
	cus__for_each_cu(cus, cu_emit_kprobes_iterator, class_name, NULL);
	puts("static struct jprobe *jprobes[] = {");
	cus__for_each_cu(cus, cu_emit_kprobes_table_iterator, NULL, NULL);
	puts("\tNULL,\n};\n");
	emit_module_init();
	emit_module_exit();

	return EXIT_SUCCESS;
}
