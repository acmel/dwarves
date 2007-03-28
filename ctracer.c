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

/**
 * Mini class, the subset of the traced class that is collected at the probes
 */

static struct class *mini_class;

/*
 * Directory where to generate source files
 */
static const char *src_dir = ".";

/*
 * Where to print the ctracer_methods.c file
 */
static FILE *fp_methods;

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
static int find_methods_iterator(struct tag *tag, struct cu *cu,
				 void *cookie __unused)
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

static void class__remove_member(struct class *self, const struct cu *cu,
				 struct class_member *member)
{
	const size_t size = class_member__size(member, cu);
	/*
	 * Is this the first member?
	 */
	if (member->tag.node.prev == &self->type.members) {
		self->type.size -= size;
		class__subtract_offsets_from(self, cu, member, size);
	} else {
		struct class_member *from_prev =
				list_entry(member->tag.node.prev,
					   struct class_member, tag.node);
		if (member->hole + size >= cu->addr_size) {
			self->type.size -= size + member->hole;
			class__subtract_offsets_from(self, cu, member,
						     size + member->hole);
		} else
			from_prev->hole += size + member->hole;
	}
	if (member->hole != 0)
		self->nr_holes--;
	list_del(&member->tag.node);
	class_member__delete(member);
}

static size_t class__find_biggest_member_name(const struct class *self)
{
	struct class_member *pos;
	size_t biggest_name_len = 0;

	list_for_each_entry(pos, &self->type.members, tag.node) {
		const size_t len = strlen(pos->name);

		if (len > biggest_name_len)
			biggest_name_len = len;
	}

	return biggest_name_len;
}

static void class__emit_class_state_collector(const struct class *self,
					      const struct class *clone)
{
	struct class_member *pos;
	int len = class__find_biggest_member_name(clone);

	fprintf(fp_methods,
		"void ctracer__class_state(const void *from, void *to)\n"
	        "{\n"
		"\tconst struct %s *obj = from;\n"
		"\tstruct %s *mini_obj = to;\n\n",
		class__name(self), class__name(clone));
	list_for_each_entry(pos, &clone->type.members, tag.node) {
		fprintf(fp_methods, "\tmini_obj->%-*s = obj->%s;\n",
			len, pos->name, pos->name);
	}
	fputs("}\n\n", fp_methods);
}

static struct class *class__clone_base_types(const struct tag *tag_self,
					     const struct cu *cu,
					     const char *new_class_name)
{
	struct class *self = tag__class(tag_self);
	struct class_member *pos, *next;
	struct class *clone = class__clone(self, new_class_name);

	if (clone == NULL)
		return NULL;

	class__find_holes(clone, cu);

	list_for_each_entry_safe(pos, next, &clone->type.members, tag.node) {
		struct tag *member_type = cu__find_tag_by_id(cu, pos->tag.type);

		if (member_type->tag != DW_TAG_base_type)
			class__remove_member(clone, cu, pos);
	}
	class__reorganize(clone, cu, 0, NULL);
	return clone;
}

/**
 * Converter to the legacy ostra tables, will be much improved in the future.
 */
static void emit_struct_member_table_entry(FILE *fp,
					   int field, const char *name,
					   int traced, const char *hooks)
{
	fprintf(fp, "%u:%s:", field, name);
	if (traced)
		fprintf(fp, "yes:%%object->%s:u:%s:none\n", name, hooks);
	else
		fprintf(fp, "no:None:None:%s:dev_null\n", hooks);
}

/**
 * Generates a converter to the ostra lebacy tables format, needef by
 * ostra-cg to preprocess the raw data collected from the debugfs/relay
 * channel.
 */
static int class__emit_ostra_converter(const struct tag *tag_self,
				       const struct cu *cu)
{
	const struct class *self = tag__class(tag_self);
	struct class_member *pos;
	struct type *type = &mini_class->type;
	int field = 0, first = 1;
	char filename[128];
	char parm_list[1024];
	char *p = parm_list;
	size_t n;
	size_t plen = sizeof(parm_list);
	FILE *fp_fields, *fp_converter;

	snprintf(filename, sizeof(filename), "%s/%s.fields",
		 src_dir, class__name(self));
	fp_fields = fopen(filename, "w");
	if (fp_fields == NULL) {
		fprintf(stderr, "ctracer: couldn't create %s\n", filename);
		exit(EXIT_FAILURE);
	}

	snprintf(filename, sizeof(filename), "%s/ctracer2ostra.c", src_dir);

	fp_converter = fopen(filename, "w");
	if (fp_converter == NULL) {
		fprintf(stderr, "ctracer: couldn't create %s\n", filename);
		exit(EXIT_FAILURE);
	}

	fputs("#include <stdio.h>\n"
	      "#include <string.h>\n"
	      "#include \"ctracer_relay.h\"\n\n", fp_converter);
	class__fprintf(mini_class, cu, NULL, NULL, 0, 0, 26, 23, 1,
		       fp_converter);
	emit_struct_member_table_entry(fp_fields, field++, "action", 0,
				       "entry,exit");
	emit_struct_member_table_entry(fp_fields, field++, "function_id", 0,
				       "entry,exit");
	emit_struct_member_table_entry(fp_fields, field++, "object", 1,
				       "entry,exit");

	fputs("\n"
	      "int main(void)\n"
	      "{\n"
	      "\twhile (1) {\n"
	      "\t\tstruct trace_entry hdr;\n"
	      "\t\tstruct ctracer__mini_sock obj;\n"
	      "\n"
	      "\t\tif (read(0, &hdr, sizeof(hdr)) != sizeof(hdr))\n"
	      "\t\t\tbreak;\n"
	      "\n"
	      "\t\tfprintf(stdout, \"%u.%06u %c:%llu:%p\",\n"
	      "\t\t\thdr.sec, hdr.usec,\n"
	      "\t\t\thdr.probe_type ? 'o' : 'i',\n"
	      "\t\t\thdr.function_id,\n"
	      "\t\t\thdr.object);\n"
	      "\n"
	      "\t\tif (hdr.probe_type) {\n"
	      "\t\t\tfputc('\\n', stdout);\n"
	      "\t\t\tcontinue;\n"
	      "\t\t}\n"
	      "\n"
	      "\t\tif (read(0, &obj, sizeof(obj)) != sizeof(obj))\n"
	      "\t\t\tbreak;\n"
	      "\t\tfprintf(stdout,\n"
	      "\t\t\t\":",
	      fp_converter);

	list_for_each_entry(pos, &type->members, tag.node) {
		if (first)
			first = 0;
		else {
			fputc(':', fp_converter);
			n = snprintf(p, plen, ",\n\t\t\t ");
			plen -= n; p += n;
		}
		fprintf(fp_converter, "%%u");
		n = snprintf(p, plen, "obj.%s", pos->name);
		plen -= n; p += n;
		emit_struct_member_table_entry(fp_fields, field++,
					       pos->name, 1, "entry");
	}
	fprintf(fp_converter,
		"\\n\",\n\t\t\t %s);\n"
		"\t}\n"
		"\treturn 0;\n"
		"}\n", parm_list);
	fclose(fp_fields);
	fclose(fp_converter);
	return 0;
}

static int class__emit_subset(const struct tag *tag_self, const struct cu *cu)
{
	struct class *self = tag__class(tag_self);
	int err = -1;
	char mini_class_name[128];

	snprintf(mini_class_name, sizeof(mini_class_name), "ctracer__mini_%s",
		 class__name(self));

	mini_class = class__clone_base_types(tag_self, cu, mini_class_name);
	if (mini_class == NULL)
		goto out;

	class__fprintf(mini_class, cu, NULL, NULL, 0, 0, 26, 23, 1,
		       fp_methods);
	fputc('\n', fp_methods);
	class__emit_class_state_collector(self, mini_class);
	err = 0;
out:
	return err;
}

/*
 * Emit the kprobes routine for one of the selected "methods", later we'll
 * put this into the 'kprobes' table, in cu_emit_kprobes_table_iterator.
 *
 * This marks the function entry, function__emit_kretprobes will emit the
 * probe for the function exit.
 */
static int function__emit_kprobes(struct function *self, const struct cu *cu,
				  const struct tag *target)
{
	char jprobe_name[256];
	struct parameter *pos;
	const char *name = function__name(self, cu);

	fputs("static ", fp_methods);
	snprintf(jprobe_name, sizeof(jprobe_name), "jprobe_entry__%s", name);
	ftype__fprintf(&self->proto, cu, jprobe_name, 0, 0, 0, fp_methods);
	fputs("\n{\n", fp_methods);

	list_for_each_entry(pos, &self->proto.parms, tag.node) {
		struct tag *type = cu__find_tag_by_id(cu, pos->tag.type);

		if (type->tag != DW_TAG_pointer_type)
			continue;

		type = cu__find_tag_by_id(cu, type->type);
		if (type == NULL || type->id != target->id)
			continue;

		fprintf(fp_methods,
			"\tctracer__method_entry(%#llx, %s, %zd);\n",
			(unsigned long long)self->proto.tag.id, pos->name,
			class__size(mini_class));
		break;
	}

	fprintf(fp_methods, "\tjprobe_return();\n"
		"\t/* NOTREACHED */%s\n}\n\n",
		self->proto.tag.type != 0 ? "\n\treturn 0;" : "");

	fprintf(fp_methods, "static struct jprobe jprobe__%s = {\n"
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
		cus__emit_ftype_definitions(methods_cus, cu,
					    &pos->proto, fp_methods);
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
static int cu_emit_kprobes_table_iterator(struct cu *cu, void *cookie __unused)
{
	struct function *pos;

	list_for_each_entry(pos, &cu->tool_list, tool_node)
		if (pos->priv != NULL) {
			const char *name = function__name(pos, cu);
			fprintf(fp_methods, "\t&jprobe__%s,\n", name);
			fprintf(cookie, "%llu:%s\n",
				(unsigned long long)pos->proto.tag.id, name);
		}

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
static void function__emit_kretprobes(struct function *self,
				      const struct cu *cu)
{
	const char *name = function__name(self, cu);

	fprintf(fp_methods,
		"static int kretprobe_handler__%s(struct kretprobe_instance *ri, "
		"struct pt_regs *regs)\n"
		"{\n"
		"\tctracer__method_exit(%#llx);\n"
		"\treturn 0;\n"
		"}\n\n", name, (unsigned long long)self->proto.tag.id);
	fprintf(fp_methods,
		"static struct kretprobe kretprobe__%s = {\n"
		"\t.kp = { .symbol_name = \"%s\", },\n"
		"\t.handler = (kretprobe_handler_t)kretprobe_handler__%s,\n"
		"};\n\n", name, name, name);
}

/*
 * Iterate thru the list of methods previously collected by
 * cu_find_methods_iterator, emitting the probes for function exit.
 */
static int cu_emit_kretprobes_iterator(struct cu *cu, void *cookie __unused)
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
static int cu_emit_kretprobes_table_iterator(struct cu *cu,
					     void *cookie __unused)
{
	struct function *pos;

	list_for_each_entry(pos, &cu->tool_list, tool_node)
		if (pos->priv != NULL)
			fprintf(fp_methods, "\t&kretprobe__%s,\n",
				function__name(pos, cu));

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
					    &tag__function(f)->proto,
					    fp_methods);
		tag__fprintf(f, cu, NULL, NULL, 0, fp_methods);
		fputs(";\n", fp_methods);
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
		cus__emit_type_definitions(kprobes_cus, cu, c, fp_methods);
		type__emit(c, cu, NULL, NULL, fp_methods);
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
		cus__emit_fwd_decl(kprobes_cus, tag__type(c), fp_methods);
}

/*
 * Emit the definitions used in the resulting kernel module C source code,
 * we do this to avoid using #includes, that would emit definitions for
 * things we emit, causing redefinitions.
 */
static void emit_module_preamble(void)
{
	fputs("#include \"ctracer_relay.h\"\n", fp_methods);

	emit_struct_defs("jprobe");
	emit_struct_defs("kretprobe");

	emit_class_fwd_decl("pt_regs");
	emit_class_fwd_decl("kretprobe_instance");

	emit_function_defs("printk");
	emit_function_defs("jprobe_return");
}

static struct option long_options[] = {
	{ "dir",			required_argument,	NULL, 'D' },
	{ "src_dir",			required_argument,	NULL, 'd' },
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
		"   -d, --src_dir	generate source files in this "
				       "directory\n"
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
	struct tag *class;
	struct cu *cu;
	char functions_filename[PATH_MAX];
	char methods_filename[PATH_MAX];
	FILE *fp;

	while ((option = getopt_long(argc, argv, "d:D:g:k:rh",
				     long_options, &option_index)) >= 0)
		switch (option) {
		case 'd': src_dir = optarg;		break;
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

	/*
	 * See if the specified struct exists:
	 */
	class = cus__find_struct_by_name(methods_cus, &cu, class_name);
	if (class == NULL) {
		fprintf(stderr, "ctracer: struct %s not found!\n", class_name);
		return EXIT_FAILURE;
	}

	snprintf(functions_filename, sizeof(functions_filename),
		 "%s/%s.functions", src_dir, class__name(tag__class(class)));
	fp = fopen(functions_filename, "w");
	if (fp == NULL) {
		fprintf(stderr, "ctracer: couldn't create %s\n",
			functions_filename);
		exit(EXIT_FAILURE);
	}

	snprintf(methods_filename, sizeof(methods_filename),
		 "%s/ctracer_methods.c", src_dir);
	fp_methods = fopen(methods_filename, "w");
	if (fp_methods == NULL) {
		fprintf(stderr, "ctracer: couldn't create %s\n",
			methods_filename);
		exit(EXIT_FAILURE);
	}

	emit_module_preamble();

	cus__emit_type_definitions(methods_cus, cu, class, fp_methods);
	type__emit(class, cu, NULL, NULL, fp_methods);
	class__emit_subset(class, cu);
	class__emit_ostra_converter(class, cu);
	cus__for_each_cu(methods_cus, cu_find_methods_iterator,
			 class_name, NULL);
	cus__for_each_cu(methods_cus, cu_emit_kprobes_iterator,
			 class_name, NULL);
	cus__for_each_cu(methods_cus, cu_emit_kretprobes_iterator,
			 NULL, NULL);

	fputs("struct jprobe *ctracer__jprobes[] = {", fp_methods);
	cus__for_each_cu(methods_cus, cu_emit_kprobes_table_iterator,
			 fp, NULL);
	/* Emit the sentinel */
	fputs("\t(void *)0,\n};\n", fp_methods);
	fclose(fp);
	fputs("struct kretprobe *ctracer__kretprobes[] = {", fp_methods);
	cus__for_each_cu(methods_cus, cu_emit_kretprobes_table_iterator,
			 NULL, NULL);
	/* Emit the sentinel */
	fputs("\t(void *)0,\n};\n", fp_methods);

	return EXIT_SUCCESS;
}
