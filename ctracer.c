/* 
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <argp.h>
#include <limits.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "dwarves_reorganize.h"
#include "dwarves_emit.h"
#include "dwarves.h"

/*
 * List of compilation units being looked for functions with
 * pointers to the specified struct.
 */
static struct cus *methods_cus;

/**
 * Mini class, the subset of the traced class that is collected at the probes
 */

static struct class *mini_class;

/*
 * Directory where to generate source files
 */
static const char *src_dir = ".";

/*
 * Where to print the ctracer_methods.stp file
 */
static FILE *fp_methods;

/*
 * Where to print the ctracer_collector.c file
 */
static FILE *fp_collector;

/*
 * List of definitions and forward declarations already emitted for
 * methods_cus, to avoid duplication.
 */
static LIST_HEAD(cus__definitions);
static LIST_HEAD(cus__fwd_decls);

/*
 * List of probes and kretprobes already emitted, this is a hack to cope with
 * name space collisions, a better solution would be to in these cases to use the
 * compilation unit name (net/ipv4/tcp.o, for instance) as a prefix when a
 * static function has the same name in multiple compilation units (aka object
 * files).
 */
static void *probes_emitted;

static int methods__compare(const void *a, const void *b)
{
	return strcmp(a, b);
}

/*
 * Add a method to probes_emitted, see comment above.
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
	size_t size = class_member__size(member, cu);
	/*
	 * Is this the first member?
	 */
	if (member->tag.node.prev == class__tags(self)) {
		self->type.size -= size + member->hole;
		class__subtract_offsets_from(self, cu, member,
					     size + member->hole);
	/*
	 * Is this the last member?
	 */
	} else if (member->tag.node.next == class__tags(self)) {
		if (size + self->padding >= cu->addr_size) {
			self->type.size -= size + self->padding;
			self->padding = 0;
		} else
			self->padding += size;
	} else {
		if (size + member->hole >= cu->addr_size) {
			self->type.size -= size + member->hole;
			class__subtract_offsets_from(self, cu, member,
						     size + member->hole);
		} else {
			struct class_member *from_prev =
					list_entry(member->tag.node.prev,
						   struct class_member,
						   tag.node);
			if (from_prev->hole == 0)
				self->nr_holes++;
			from_prev->hole += size + member->hole;
		}
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

	type__for_each_data_member(&self->type, pos) {
		const size_t len = strlen(pos->name);

		if (len > biggest_name_len)
			biggest_name_len = len;
	}

	return biggest_name_len;
}

static void class__emit_class_state_collector(struct class *self,
					      struct class *clone,
					      const struct cu *cu)
{
	struct class_member *pos;
	int len = class__find_biggest_member_name(clone);

	fprintf(fp_collector,
		"void ctracer__class_state(const void *from, void *to)\n"
	        "{\n"
		"\tconst struct %s *obj = from;\n"
		"\tstruct %s *mini_obj = to;\n\n",
		class__name(self, cu), class__name(clone, cu));
	type__for_each_data_member(&clone->type, pos)
		fprintf(fp_collector, "\tmini_obj->%-*s = obj->%s;\n",
			len, pos->name, pos->name);
	fputs("}\n\n", fp_collector);
}

static void class__add_offsets_from(struct class *self, struct class_member *from,
				    const uint16_t size)
{
	struct class_member *member =
		list_prepare_entry(from, class__tags(self), tag.node);

	list_for_each_entry_continue(member, class__tags(self), tag.node)
		if (member->tag.tag == DW_TAG_member)
			member->offset += size;
}

/*
 * XXX: Check this more thoroughly. Right now it is used because I was
 * to lazy to do class__remove_member properly, adjusting alignments and
 * holes as we go removing fields. Ditto for class__add_offsets_from.
 */
static void class__fixup_alignment(struct class *self, const struct cu *cu)
{
	struct class_member *pos, *last_member = NULL;
	size_t power2;

	type__for_each_data_member(&self->type, pos) {
		size_t member_size = class_member__size(pos, cu);

		if (last_member == NULL && pos->offset != 0) { /* paranoid! */
			class__subtract_offsets_from(self, cu, pos,
						     pos->offset - member_size);
			pos->offset = 0;
		} else for (power2 = 2; power2 <= cu->addr_size; power2 *= 2) {
			const size_t remainder = pos->offset % power2;

			if (member_size == power2 && remainder != 0) {
				if (last_member->hole >= remainder) {
					last_member->hole -= remainder;
					if (last_member->hole == 0)
						--self->nr_holes;
					pos->offset -= remainder;
					class__subtract_offsets_from(self, cu, pos, remainder);
				} else {
					if (last_member->hole == 0)
						++self->nr_holes;
					last_member->hole += 2 - remainder;
					pos->offset += 2 - remainder;
					class__add_offsets_from(self, pos, 2 - remainder);
				}
			}
		}
		 	
		last_member = pos;
	}
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

	type__for_each_data_member_safe(&clone->type, pos, next) {
		struct tag *member_type = cu__find_tag_by_id(cu, pos->tag.type);

		if (member_type->tag != DW_TAG_base_type)
			class__remove_member(clone, cu, pos);
	}
	class__find_holes(clone, cu);
	class__fixup_alignment(clone, cu);
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
static int class__emit_ostra_converter(struct tag *tag_self,
				       const struct cu *cu)
{
	struct class *self = tag__class(tag_self);
	struct class_member *pos;
	struct type *type = &mini_class->type;
	int field = 0, first = 1;
	char filename[128];
	char parm_list[1024];
	char *p = parm_list;
	size_t n;
	size_t plen = sizeof(parm_list);
	FILE *fp_fields, *fp_converter;
	const char *name = class__name(self, cu);

	snprintf(filename, sizeof(filename), "%s/%s.fields", src_dir, name);
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
	class__fprintf(mini_class, cu, NULL, fp_converter);
	fputs(";\n\n", fp_converter);
	emit_struct_member_table_entry(fp_fields, field++, "action", 0,
				       "entry,exit");
	emit_struct_member_table_entry(fp_fields, field++, "function_id", 0,
				       "entry,exit");
	emit_struct_member_table_entry(fp_fields, field++, "object", 1,
				       "entry,exit");

	fprintf(fp_converter, "\n"
	      "int main(void)\n"
	      "{\n"
	      "\twhile (1) {\n"
	      "\t\tstruct trace_entry hdr;\n"
	      "\t\tstruct ctracer__mini_%s obj;\n"
	      "\n"
	      "\t\tif (read(0, &hdr, sizeof(hdr)) != sizeof(hdr))\n"
	      "\t\t\tbreak;\n"
	      "\n"
	      "\t\tfprintf(stdout, \"%%llu %%c:%%llu:%%p\",\n"
	      "\t\t\thdr.nsec,\n"
	      "\t\t\thdr.probe_type ? 'o' : 'i',\n"
	      "\t\t\thdr.function_id,\n"
	      "\t\t\thdr.object);\n"
	      "\n"
	      "\t\tif (read(0, &obj, sizeof(obj)) != sizeof(obj))\n"
	      "\t\t\tbreak;\n"
	      "\t\tfprintf(stdout,\n"
	      "\t\t\t\":", name);

	type__for_each_data_member(type, pos) {
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
					       pos->name, 1, "entry,exit");
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

static int class__emit_subset(struct tag *tag_self, const struct cu *cu)
{
	struct class *self = tag__class(tag_self);
	int err = -1;
	char mini_class_name[128];

	snprintf(mini_class_name, sizeof(mini_class_name), "ctracer__mini_%s",
		 class__name(self, cu));

	mini_class = class__clone_base_types(tag_self, cu, mini_class_name);
	if (mini_class == NULL)
		goto out;

	class__fprintf(mini_class, cu, NULL, fp_collector);
	fputs(";\n\n", fp_collector);
	class__emit_class_state_collector(self, mini_class, cu);
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
static int function__emit_probes(struct function *self, const struct cu *cu,
				 const struct tag *target, int probe_type)
{
	struct parameter *pos;
	const char *name = function__name(self, cu);

	fprintf(fp_methods, "probe %s%s = kernel.function(\"%s\")%s\n"
			    "{\n"
			    "}\n\n"
			    "probe %s%s\n"
			    "{\n", name,
			    probe_type == 0 ? "" : "__return",
			    name,
			    probe_type == 0 ? "" : ".return",
			    name,
			    probe_type == 0 ? "" : "__return");

	list_for_each_entry(pos, &self->proto.parms, tag.node) {
		struct tag *type = cu__find_tag_by_id(cu, pos->tag.type);

		if (type->tag != DW_TAG_pointer_type)
			continue;

		type = cu__find_tag_by_id(cu, type->type);
		if (type == NULL || type->id != target->id)
			continue;

		fprintf(fp_methods,
			"\tctracer__method_hook(%d, %#llx, $%s, %zd);\n",
			probe_type,
			(unsigned long long)self->proto.tag.id, pos->name,
			class__size(mini_class));
		break;
	}

	fputs("}\n\n", fp_methods);

	return 0;
}

/*
 * Iterate thru the list of methods previously collected by
 * cu_find_methods_iterator, emitting the probes for function entry.
 */
static int cu_emit_probes_iterator(struct cu *cu, void *cookie)
{
	struct tag *target = cu__find_struct_by_name(cu, cookie);
	struct function *pos;

	list_for_each_entry(pos, &cu->tool_list, tool_node) {
		if (methods__add(&probes_emitted, function__name(pos, cu)) != 0)
			continue;
		pos->priv = (void *)1; /* Mark as visited, for the table iterator */
		function__emit_probes(pos, cu, target, 0); /* entry */
		function__emit_probes(pos, cu, target, 1); /* exit */ 
	}

	return 0;
}

/*
 * Iterate thru the list of methods previously collected by
 * cu_find_methods_iterator, creating the functions table that will
 * be used by ostra-cg
 */
static int cu_emit_functions_table(struct cu *cu, void *fp)
{
       struct function *pos;

       list_for_each_entry(pos, &cu->tool_list, tool_node)
               if (pos->priv != NULL)
                       fprintf(fp, "%llu:%s\n",
                               (unsigned long long)pos->proto.tag.id,
			       function__name(pos, cu));

       return 0;
}

static const struct argp_option ctracer__options[] = {
	{
		.key  = 'd',
		.name = "src_dir",
		.arg  = "SRC_DIR",
		.doc  = "generate source files in this directory",
	},
	{
		.key  = 'D',
		.name = "dir",
		.arg  = "DIR",
		.doc  = "load files in this directory",
	},
	{
		.key  = 'g',
		.name = "glob",
		.arg  = "GLOB",
		.doc  = "file mask to load",
	},
	{
		.key  = 'r',
		.name = "recursive",
		.doc  = "recursively load files",
	},
	{
		.name = NULL,
	}
};

static const char *dirname, *glob;
static char *class_name;
static int recursive;

static error_t ctracer__options_parser(int key, char *arg,
				      struct argp_state *state __unused)
{
	switch (key) {
	case 'd': src_dir = arg;		break;
	case 'D': dirname = arg;		break;
	case 'g': glob = arg;			break;
	case 'r': recursive = 1;		break;
	default:  return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char ctracer__args_doc[] = "[FILE] [CLASS]";

static struct argp ctracer__argp = {
	.options  = ctracer__options,
	.parser	  = ctracer__options_parser,
	.args_doc = ctracer__args_doc,
};

int main(int argc, char *argv[])
{
	int remaining, err;
	struct tag *class;
	struct cu *cu;
	const char *filename;
	char functions_filename[PATH_MAX];
	char methods_filename[PATH_MAX];
	char collector_filename[PATH_MAX];
	FILE *fp_functions;

	argp_parse(&ctracer__argp, argc, argv, 0, &remaining, NULL);

	if (remaining < argc) {
		switch (argc - remaining) {
		case 1:	 goto failure;
		case 2:	 filename  = argv[remaining++];
			 class_name = argv[remaining++];	break;
		default: goto failure;
		}
	} else {
failure:
		argp_help(&ctracer__argp, stderr, ARGP_HELP_SEE, "ctracer");
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
		fputs("ctracer: insufficient memory\n", stderr);
		return EXIT_FAILURE;
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
	if (filename != NULL) {
		err = cus__load(methods_cus, filename);
		if (err != 0) {
			cus__print_error_msg("ctracer", filename, err);
			return EXIT_FAILURE;
		}
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
		 "%s/%s.functions", src_dir,
		 class__name(tag__class(class), cu));
	fp_functions = fopen(functions_filename, "w");
	if (fp_functions == NULL) {
		fprintf(stderr, "ctracer: couldn't create %s\n",
			functions_filename);
		exit(EXIT_FAILURE);
	}

	snprintf(methods_filename, sizeof(methods_filename),
		 "%s/ctracer_methods.stp", src_dir);
	fp_methods = fopen(methods_filename, "w");
	if (fp_methods == NULL) {
		fprintf(stderr, "ctracer: couldn't create %s\n",
			methods_filename);
		exit(EXIT_FAILURE);
	}

	snprintf(collector_filename, sizeof(collector_filename),
		 "%s/ctracer_collector.c", src_dir);
	fp_collector = fopen(collector_filename, "w");
	if (fp_collector == NULL) {
		fprintf(stderr, "ctracer: couldn't create %s\n",
			collector_filename);
		exit(EXIT_FAILURE);
	}

	fputs("%{\n"
	      "#include </home/acme/git/pahole/lib/ctracer_relay.h>\n"
	      "%}\n"
	      "function ctracer__method_hook(probe_type, func, object, state_len)\n"
	      "%{\n"
	      "\tctracer__method_hook(_stp_gettimeofday_ns(), THIS->probe_type, THIS->func, (void *)THIS->object, THIS->state_len);\n"
	      "%}\n\n", fp_methods);

	cus__emit_type_definitions(methods_cus, cu, class, fp_collector);
	type__emit(class, cu, NULL, NULL, fp_collector);
	fputc('\n', fp_collector);
	class__emit_subset(class, cu);

	class__emit_ostra_converter(class, cu);

	cus__for_each_cu(methods_cus, cu_find_methods_iterator,
			 class_name, NULL);
	cus__for_each_cu(methods_cus, cu_emit_probes_iterator,
			 class_name, NULL);

	cus__for_each_cu(methods_cus, cu_emit_functions_table, fp_functions, NULL);
	fclose(fp_methods);
	fclose(fp_collector);
	fclose(fp_functions);

	return EXIT_SUCCESS;
}
