/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <getopt.h>
#include <limits.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "dwarves.h"

static struct cus *cus;
static struct cus *kprobes_cus;

static LIST_HEAD(cus__definitions);
static LIST_HEAD(cus__fwd_decls);

static void *jprobes_emitted;
static void *kretprobes_emitted;

static int methods__compare(const void *a, const void *b)
{
	return strcmp(a, b);
}

static int methods__add(void **table, const char *str)
{
	char **s = tsearch(str, table, methods__compare);

	if (s != NULL) {
		if (*s == str) {
			char *dup = strdup(str);
			if (dup != NULL)
				*s = dup;
			else {
				tdelete(str, table, methods__compare);
				return -1;
			}
		} else
			return -1;
	} else
		return -1;

	return 0;
}

static void method__add(struct cu *cu, struct function *function)
{
	list_add(&function->tool_node, &cu->tool_list);
}

static struct tag *function__filter(struct tag *tag, struct cu *cu, void *cookie)
{
	struct function *function;

	if (tag->tag != DW_TAG_subprogram)
		return NULL;

	function = tag__function(tag);
	if (function__inlined(function) ||
	    function->abstract_origin != 0 ||
	    !ftype__has_parm_of_type(&function->proto, cookie, cu))
		return NULL;

	return tag;
}

static int find_methods_iterator(struct tag *tag, struct cu *cu, void *cookie)
{
	if (tag->tag == DW_TAG_subprogram) {
		struct function *function = tag__function(tag);
		method__add(cu, function);
	}
	return 0;
}

static int cu_find_methods_iterator(struct cu *cu, void *cookie)
{
	struct tag *target = cu__find_struct_by_name(cu, cookie);

	if (target == NULL)
		return 0;

	return cu__for_each_tag(cu, find_methods_iterator, target, function__filter);
}

static int function__emit_kprobes(struct function *self, const struct cu *cu,
				  const struct tag *target)
{
	char bf[2048];
	char jprobe_name[256];
	struct parameter *pos;
	const char *name = function__name(self, cu);

	snprintf(jprobe_name, sizeof(jprobe_name), "jprobe_entry__%s", name);
	ftype__snprintf(&self->proto, cu, bf, sizeof(bf), jprobe_name, 0, 0, 0);
	printf("static %s\n"
	       "{\n", bf);

	list_for_each_entry(pos, &self->proto.parms, tag.node) {
		struct tag *type = cu__find_tag_by_id(cu, pos->tag.type);

		if (type->tag != DW_TAG_pointer_type)
			continue;

		type = cu__find_tag_by_id(cu, type->type);
		if (type == NULL || type->id != target->id)
			continue;

		printf("\tprintk(\"-> %s: %s=%%p\\n\", %s);\n",
		       name, pos->name, pos->name);
	}

	printf("\n\tjprobe_return();\n"
	       "\t/* NOTREACHED */%s\n}\n\n",
	       self->proto.tag.type != 0 ? "\n\treturn 0;" : "");

	printf("static struct jprobe jprobe__%s = {\n"
	       "\t.kp = { .symbol_name = \"%s\", },\n"
	       "\t.entry = (kprobe_opcode_t *)jprobe_entry__%s,\n"
	       "};\n\n", name, name, name);
	return 0;
}

static int cu_emit_kprobes_iterator(struct cu *cu, void *cookie)
{
	struct tag *target = cu__find_struct_by_name(cu, cookie);
	struct function *pos;

	list_for_each_entry(pos, &cu->tool_list, tool_node) {
		if (methods__add(&jprobes_emitted, function__name(pos, cu)) != 0)
			continue;
		pos->priv = (void *)1; /* Mark as visited, for the table iterator */
		cus__emit_ftype_definitions(cus, cu, &pos->proto);
		function__emit_kprobes(pos, cu, target);
	}

	return 0;
}

static int cu_emit_kprobes_table_iterator(struct cu *cu, void *cookie)
{
	struct function *pos;

	list_for_each_entry(pos, &cu->tool_list, tool_node)
		if (pos->priv != NULL)
			printf("\t&jprobe__%s,\n", function__name(pos, cu));

	return 0;
}

static int function__emit_kretprobes(struct function *self,
				     const struct cu *cu)
{
	const char *name = function__name(self, cu);

	printf("static int kretprobe_handler__%s(struct kretprobe_instance *ri, "
	       "struct pt_regs *regs)\n"
	       "{\n"
	       "\tprintk(\"<- %s\\n\");\n"
	       "\treturn 0;\n"
	       "}\n\n", name, name);
	printf("static struct kretprobe kretprobe__%s = {\n"
	       "\t.kp = { .symbol_name = \"%s\", },\n"
	       "\t.handler = (kretprobe_handler_t)kretprobe_handler__%s,\n"
	       "\t.maxactive = -1,\n\n"
	       "};\n\n", name, name, name);
}

static int cu_emit_kretprobes_iterator(struct cu *cu, void *cookie)
{
	struct function *pos;

	list_for_each_entry(pos, &cu->tool_list, tool_node) {
		if (methods__add(&kretprobes_emitted,
				 function__name(pos, cu)) != 0)
			continue;
		pos->priv = (void *)1; /* Mark as visited, for the table iterator */
		function__emit_kretprobes(pos, cu);
	}

	return 0;
}

static int cu_emit_kretprobes_table_iterator(struct cu *cu, void *cookie)
{
	struct function *pos;

	list_for_each_entry(pos, &cu->tool_list, tool_node)
		if (pos->priv != NULL)
			printf("\t&kretprobe__%s,\n", function__name(pos, cu));

	return 0;
}

static void emit_function_defs(const char *fn)
{
	struct cu *cu;
	struct tag *f = cus__find_function_by_name(kprobes_cus, &cu, fn);

	if (f != NULL) {
		cus__emit_ftype_definitions(kprobes_cus, cu,
					    &tag__function(f)->proto);
		tag__print(f, cu, NULL, NULL);
		puts(";\n");
	}
}

static void emit_struct_defs(const char *name)
{
	struct cu *cu;
	struct tag *c = cus__find_struct_by_name(kprobes_cus, &cu, name);
	if (c != NULL) {
		cus__emit_type_definitions(kprobes_cus, cu, c);
		type__emit(c, cu, NULL, NULL);
	}
}

static void emit_class_fwd_decl(const char *name)
{
	struct cu *cu;
	struct tag *c = cus__find_struct_by_name(kprobes_cus, &cu, name);
	if (c != NULL)
		cus__emit_fwd_decl(kprobes_cus, tag__type(c));
}

static void emit_module_preamble(void)
{
	emit_struct_defs("jprobe");
	emit_struct_defs("kretprobe");

	emit_class_fwd_decl("pt_regs");
	emit_class_fwd_decl("kretprobe_instance");

	emit_function_defs("yield");
	emit_function_defs("printk");
	emit_function_defs("register_jprobe");
	emit_function_defs("unregister_jprobe");
	emit_function_defs("register_kretprobe");
	emit_function_defs("unregister_kretprobe");
	emit_function_defs("jprobe_return");
}

static void emit_module_initcall(const char *fn)
{
	printf("int init_module(void) __attribute__((alias(\"%s\")));\n\n", fn);
}

static void emit_module_exitcall(const char *fn)
{
	printf("int cleanup_module(void) __attribute__((alias(\"%s\")));\n\n", fn);
}

static void emit_module_license(const char *license)
{
	printf("static const char __mod_license[] "
	       "__attribute__((__used__)) \n"
	       "\t__attribute__((section(\".modinfo\"),unused)) = "
	       "\"license=%s\";\n\n", license);
}

static void emit_module_init(void)
{
	printf("static int __attribute__ "
	       "((__section__ (\".init.text\"))) jprobe_init(void)\n"
	       "{\n"
	       "	unsigned int i = 0, nj = 0, nr = 0;\n"
	       "	while (jprobes[i] != (void *)0) {\n"
	       "		int err = register_jprobe(jprobes[i]);\n"
	       "		if (err != 0)\n"
	       "			printk(\"register_jprobe(%%s) failed, "
					        "returned %%d\\n\",\n"
	       "			       jprobes[i]->kp.symbol_name, err);\n"
	       "		else\n"
	       "			++nj;\n"
	       "		err = register_kretprobe(kretprobes[i]);\n"
	       "		if (err != 0)\n"
	       "			printk(\"register_kretprobe(%%s) failed, "
					        "returned %%d\\n\",\n"
	       "			       kretprobes[i]->kp.symbol_name, err);\n"
	       "		else\n"
	       "			++nr;\n"
	       "		++i;\n"
	       "		if ((i % 5) == 0)\n"
	       "			yield();"
	       "	}\n\n"
	       "	printk(\"ctracer: registered %%u entry probes\\n\", nj);\n"
	       "	printk(\"ctracer: registered %%u exit probes\\n\", nr);\n"
	       "\n"
	       "        return 0;\n"
	       "}\n\n");
	emit_module_initcall("jprobe_init");
}

static void emit_module_exit(void)
{
	printf("static void __attribute__ "
	       "((__section__ (\".exit.text\"))) jprobe_exit(void)\n"
	       "{\n"
	       "	int i = 0;\n"
	       "	while (jprobes[i] != (void *)0) {\n"
	       "		unregister_jprobe(jprobes[i]);\n"
	       "		unregister_kretprobe(kretprobes[i]);\n"
	       "		++i;\n"
	       "		if ((i % 5) == 0)\n"
	       "			yield();"
	       "	}\n\n"
	       "}\n\n");
	emit_module_exitcall("jprobe_exit");
}

static struct option long_options[] = {
	{ "dir",			required_argument,	NULL, 'D' },
	{ "glob",			required_argument,	NULL, 'g' },
	{ "kprobes",			required_argument,	NULL, 'k' },
	{ "recursive",			no_argument,		NULL, 'r' },
	{ "help",			no_argument,		NULL, 'h' },
	{ NULL, 0, NULL, 0, }
};

static void usage(void)
{
	fprintf(stdout,
		"usage: ctracer [options] <filename> <class_name>\n"
		" where: \n"
		"   -D, --dir		load files in this directory\n"
		"   -g, --glob		file mask to load\n"
		"   -k, --kprobes	kprobes object file\n"
		"   -r, --recursive	recursively load files\n"
		"   -h, --help		show this help message\n");
}

int main(int argc, char *argv[])
{
	int option, option_index, recursive = 0;
	const char *filename = NULL, *dirname = NULL, *glob = NULL,
		   *kprobes_filename = NULL;
	char *class_name = NULL;

	while ((option = getopt_long(argc, argv, "D:g:k:rh",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 'D': dirname = optarg;		break;
		case 'g': glob = optarg;		break;
		case 'k': kprobes_filename = optarg;	break;
		case 'r': recursive = 1;		break;
		case 'h': usage();			return EXIT_SUCCESS;
		default:  usage();			return EXIT_FAILURE;
		}

	if (optind < argc) {
		switch (argc - optind) {
		case 1:	 if (kprobes_filename == NULL) {
				usage();
				return EXIT_FAILURE;
			 }
			 class_name = argv[optind++];	break;
		case 2:	 filename  = argv[optind++];
			 class_name = argv[optind++];	break;
		default: usage();			return EXIT_FAILURE;
		}
	} else {
		usage();
		return EXIT_FAILURE;
	}

	dwarves__init(0);

	cus = cus__new(&cus__definitions, &cus__fwd_decls);
	if (cus == NULL) {
out_enomem:
		fputs("ctracer: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}
	
	if (kprobes_filename != NULL) {
		kprobes_cus = cus__new(&cus__definitions, &cus__fwd_decls);
		if (kprobes_cus == NULL)
			goto out_enomem;
		if (cus__load(kprobes_cus, kprobes_filename) != 0) {
			filename = kprobes_filename;
			goto out_dwarf_err;
		}
	} else
		kprobes_cus = cus;

	if (dirname != NULL && cus__load_dir(cus, dirname, glob,
					     recursive) != 0) {
		fprintf(stderr, "ctracer: couldn't load DWARF info "
				"from %s dir with glob %s\n",
			dirname, glob);
		return EXIT_FAILURE;
	}

	if (filename != NULL && cus__load(cus, filename) != 0) {
out_dwarf_err:
		fprintf(stderr, "ctracer: couldn't load DWARF info from %s\n",
			filename);
		return EXIT_FAILURE;
	}

	emit_module_preamble();
	cus__for_each_cu(cus, cu_find_methods_iterator, class_name, NULL);
	cus__for_each_cu(cus, cu_emit_kprobes_iterator, class_name, NULL);
	cus__for_each_cu(cus, cu_emit_kretprobes_iterator, NULL, NULL);
	puts("static struct jprobe *jprobes[] = {");
	cus__for_each_cu(cus, cu_emit_kprobes_table_iterator, NULL, NULL);
	puts("\t(void *)0,\n};\n");
	puts("static struct kretprobe *kretprobes[] = {");
	cus__for_each_cu(cus, cu_emit_kretprobes_table_iterator, NULL, NULL);
	puts("\t(void *)0,\n};\n\n");
	emit_module_init();
	emit_module_exit();
	emit_module_license("GPL");

	return EXIT_SUCCESS;
}
