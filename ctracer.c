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

/*
 * List of compilation units being looked for functions with
 * pointers to the specified struct.
 */
static struct cus *methods_cus;

/**
 * Compilation units with the definitions for the kprobes functions and struct
 * definitions for the, can point to methods_cus if those definitions are
 * available there (example: when using 'ctracer vmlinux sk_buff', vmlinux
 * will have the sk_buff "methods" and the kprobes "classes" and "methods".
 */
static struct cus *kprobes_cus;

/*
 * List of definitions and forward declarations already emitted for
 * methods_cus and kprobes_cus, to avoid duplication.
 */
static LIST_HEAD(cus__definitions);
static LIST_HEAD(cus__fwd_decls);

/*
 * List of jprobes and kretprobes already emitted, this is a hack to cope with
 * name space collisions, a better solution would be to in these cases to use the
 * compilation unit name (net/ipv4/tcp.o, for instance) as a prefix when a
 * static function has the same name in multiple compilation units (aka object
 * files).
 */
static void *jprobes_emitted;
static void *kretprobes_emitted;

static int methods__compare(const void *a, const void *b)
{
	return strcmp(a, b);
}

/*
 * Add a method to jprobes_emitted or kretprobes_emitted, see comment above.
 */
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

/* 
 * We want just the DW_TAG_subprogram tags that have as one of its parameters
 * a pointer to the specified "class" (a struct, unions can be added later).
 */
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

/*
 * Add the function to the list of methods since it matches function__filter
 * criteria.
 */
static int find_methods_iterator(struct tag *tag, struct cu *cu, void *cookie)
{
	struct function *function = tag__function(tag);
	method__add(cu, function);
	return 0;
}

/*
 * Iterate thru all the tags in the compilation unit, looking just for the
 * DW_TAG_subprogram tags that have as one of its parameters a pointer to
 * the specified "class" (struct).
 */
static int cu_find_methods_iterator(struct cu *cu, void *cookie)
{
	struct tag *target = cu__find_struct_by_name(cu, cookie);

	if (target == NULL)
		return 0;

	return cu__for_each_tag(cu, find_methods_iterator, target, function__filter);
}

/*
 * Emit the kprobes routine for one of the selected "methods", later we'll
 * put this into the 'kprobes' table, in cu_emit_kprobes_table_iterator.
 *
 * This marks the function entry, function__emit_kretprobes will emit the
 * probe for the function exit.
 *
 * For now it just printks the function name and the pointer, upcoming patches
 * will use relayfs, just like blktrace does, using the struct definition to
 * collect the specified subset of the struct members, just like OSTRA did,
 * see an example of post processing at:
 *
 * http://oops.ghostprotocols.net:81/dccp/ostra/delay_100ms_loss20percent_packet_size_256/
 */
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

/*
 * Iterate thru the list of methods previously collected by
 * cu_find_methods_iterator, emitting the probes for function entry.
 */
static int cu_emit_kprobes_iterator(struct cu *cu, void *cookie)
{
	struct tag *target = cu__find_struct_by_name(cu, cookie);
	struct function *pos;

	list_for_each_entry(pos, &cu->tool_list, tool_node) {
		if (methods__add(&jprobes_emitted, function__name(pos, cu)) != 0)
			continue;
		pos->priv = (void *)1; /* Mark as visited, for the table iterator */
		cus__emit_ftype_definitions(methods_cus, cu, &pos->proto);
		function__emit_kprobes(pos, cu, target);
	}

	return 0;
}

/*
 * Iterate thru the list of methods previously collected by
 * cu_find_methods_iterator, creating the 'kprobes' table, that will
 * be used at the module init routine to register the kprobes for function
 * entry, and at module exit time to unregister the kprobes.
 */
static int cu_emit_kprobes_table_iterator(struct cu *cu, void *cookie)
{
	struct function *pos;

	list_for_each_entry(pos, &cu->tool_list, tool_node)
		if (pos->priv != NULL)
			printf("\t&jprobe__%s,\n", function__name(pos, cu));

	return 0;
}

/*
 * Emit the kprobes routine for one of the selected "methods", later we'll
 * put this into the 'kprobes' table, in cu_emit_kprobes_table_iterator.
 *
 * This marks the function exit.
 *
 * We still need to get the pointer to the "class instance", i.e. the pointer
 * to the specified struct, this will be done using the "data pouch" mentioned
 * in the kprobes mailing list, where we at the entry kprobes we store the
 * pointer to be used here, or possibly using plain kprobes at the function
 * entry and using DW_AT_location to discover where in the stack or in a
 * processor register were the parameters for the function.
 */
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

/*
 * Iterate thru the list of methods previously collected by
 * cu_find_methods_iterator, emitting the probes for function exit.
 */
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

/*
 * Iterate thru the list of methods previously collected by
 * cu_find_methods_iterator, creating the 'kretprobes' table, that will
 * be used at the module init routine to register the kprobes for function
 * entry, and at module exit time to unregister the kretprobes.
 */
static int cu_emit_kretprobes_table_iterator(struct cu *cu, void *cookie)
{
	struct function *pos;

	list_for_each_entry(pos, &cu->tool_list, tool_node)
		if (pos->priv != NULL)
			printf("\t&kretprobe__%s,\n", function__name(pos, cu));

	return 0;
}

/*
 * Emit a definition for the specified function, looking for it in the
 * tags previously collected, cus__emit_ftype_definitions will look at the
 * function return type and recursively emit all the definitions needed,
 * ditto for all the function parameters, emitting just a forward declaration
 * if the parameter is just a pointer, or all of the enums, struct, unions,
 * etc that are required for the resulting C source code to be built.
 */
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

/*
 * Emit a struct definition, looking at all the function members and recursively
 * emitting its type definitions (enums, structs, unions, etc).
 */
static void emit_struct_defs(const char *name)
{
	struct cu *cu;
	struct tag *c = cus__find_struct_by_name(kprobes_cus, &cu, name);
	if (c != NULL) {
		cus__emit_type_definitions(kprobes_cus, cu, c);
		type__emit(c, cu, NULL, NULL);
	}
}

/*
 * Emit a forward declaration ("struct foo;" or "union bar").
 */
static void emit_class_fwd_decl(const char *name)
{
	struct cu *cu;
	struct tag *c = cus__find_struct_by_name(kprobes_cus, &cu, name);
	if (c != NULL)
		cus__emit_fwd_decl(kprobes_cus, tag__type(c));
}

/*
 * Emit the definitions used in the resulting kernel module C source code,
 * we do this to avoid using #includes, that would emit definitions for
 * things we emit, causing redefinitions.
 */
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

/*
 * Emit a module initcall, as we don't use any #includes for the reason
 * explained in emit_module_preamble().
 */
static void emit_module_initcall(const char *fn)
{
	printf("int init_module(void) __attribute__((alias(\"%s\")));\n\n", fn);
}

/*
 * Emit a module exitcall, as we don't use any #includes for the reason
 * explained in emit_module_preamble().
 */
static void emit_module_exitcall(const char *fn)
{
	printf("int cleanup_module(void) __attribute__((alias(\"%s\")));\n\n", fn);
}

/*
 * Emit a module license, as we don't use any #includes for the reason
 * explained in emit_module_preamble().
 */
static void emit_module_license(const char *license)
{
	printf("static const char __mod_license[] "
	       "__attribute__((__used__)) \n"
	       "\t__attribute__((section(\".modinfo\"),unused)) = "
	       "\"license=%s\";\n\n", license);
}

/*
 * Emit the module init routine, iterating thru the kprobes and kretprobes
 * tables generated in cu_emit_kprobes_table_iterator and
 * cu_emit_kretprobes_table_iterator to register the kprobes and kretprobes.
 */
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

/*
 * Emit the module exit routine, iterating thru the kprobes and kretprobes
 * tables generated in cu_emit_kprobes_table_iterator and
 * cu_emit_kretprobes_table_iterator to unregister the kprobes and kretprobes.
 */
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

	/*
         * Initialize libdwarves, for now just to get the machine L1 cacheline
         * size, in the future may do more stuff.
	 */
	dwarves__init(0);

        /*
         * Create the methods_cus (Compilation Units) object where we will
	 * load the objects where we'll look for functions pointers to the
	 * specified class, i.e. to find its "methods", where we'll insert
	 * the entry and exit hooks.
         */
	methods_cus = cus__new(&cus__definitions, &cus__fwd_decls);
	if (methods_cus == NULL) {
out_enomem:
		fputs("ctracer: insufficient memory\n", stderr);
		return EXIT_FAILURE;
	}
	
        /*
         * If --kprobes was specified load the binary with the definitions
         * for the kprobes structs and functions used in the generated kernel
         * module C source file.
         */
	if (kprobes_filename != NULL) {
		kprobes_cus = cus__new(&cus__definitions, &cus__fwd_decls);
		if (kprobes_cus == NULL)
			goto out_enomem;
		if (cus__load(kprobes_cus, kprobes_filename) != 0) {
			filename = kprobes_filename;
			goto out_dwarf_err;
		}
	} else {
		/*
		 * Or use the methods_cus specified for the methods as the
		 * source for the kprobes structs and functions definitions.
		 */
		kprobes_cus = methods_cus;
	}

	/*
         * if --dir/-D was specified, recursively traverse the path looking for
         * object files (compilation units) that match the glob specified (*.ko)
         * for kernel modules, but could be "*.o" in the future when we support
         * uprobes for user space tracing.
	 */
	if (dirname != NULL && cus__load_dir(methods_cus, dirname, glob,
					     recursive) != 0) {
		fprintf(stderr, "ctracer: couldn't load DWARF info "
				"from %s dir with glob %s\n",
			dirname, glob);
		return EXIT_FAILURE;
	}

        /*
         * If a filename was specified, for instance "vmlinux", load it too.
         */
	if (filename != NULL && cus__load(methods_cus, filename) != 0) {
out_dwarf_err:
		fprintf(stderr, "ctracer: couldn't load DWARF info from %s\n",
			filename);
		return EXIT_FAILURE;
	}

	emit_module_preamble();
	cus__for_each_cu(methods_cus, cu_find_methods_iterator,
			 class_name, NULL);
	cus__for_each_cu(methods_cus, cu_emit_kprobes_iterator,
			 class_name, NULL);
	cus__for_each_cu(methods_cus, cu_emit_kretprobes_iterator,
			 NULL, NULL);
	puts("static struct jprobe *jprobes[] = {");
	cus__for_each_cu(methods_cus, cu_emit_kprobes_table_iterator,
			 NULL, NULL);
	/* Emit the sentinel */
	puts("\t(void *)0,\n};\n");
	puts("static struct kretprobe *kretprobes[] = {");
	cus__for_each_cu(methods_cus, cu_emit_kretprobes_table_iterator,
			 NULL, NULL);
	/* Emit the sentinel */
	puts("\t(void *)0,\n};\n\n");
	emit_module_init();
	emit_module_exit();
	emit_module_license("GPL");

	return EXIT_SUCCESS;
}
