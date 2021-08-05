/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
*/

#include <argp.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dwarves_reorganize.h"
#include "dwarves_emit.h"
#include "dwarves.h"
#include "dutil.h"
#include "elf_symtab.h"

/*
 * target class name
 */
static char *class_name;

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
 * Where to print the ctracer_classes.h file
 */
static FILE *fp_classes;

/*
 * blacklist __init marked functions, i.e. functions that are
 * in the ".init.text" ELF section and are thus discarded after
 * boot.
 */
static struct strlist *init_blacklist;

/*
 * List of definitions and forward declarations already emitted for
 * methods_cus, to avoid duplication.
 */
static struct type_emissions emissions;

/*
 * CU blacklist: if a "blacklist.cu" file is present, don't consider the
 * CUs listed. Use a default of blacklist.cu.
 */
static const char *cu_blacklist_filename = "blacklist.cu";

static struct strlist *cu_blacklist;

static struct cu *cu_filter(struct cu *cu)
{
	if (strlist__has_entry(cu_blacklist, cu->name))
		return NULL;
	return cu;
}

/*
 * List of probes and kretprobes already emitted, this is a hack to cope with
 * name space collisions, a better solution would be to in these cases to use the
 * compilation unit name (net/ipv4/tcp.o, for instance) as a prefix when a
 * static function has the same name in multiple compilation units (aka object
 * files).
 */
static void *probes_emitted;

struct structure {
	struct list_head  node;
	struct tag	  *class;
	struct cu	  *cu;
};

static struct structure *structure__new(struct tag *class, struct cu *cu)
{
	struct structure *st = malloc(sizeof(*st));

	if (st != NULL) {
		st->class = class;
		st->cu    = cu;
	}

	return st;
}

/*
 * structs that can be casted to the target class, e.g. i.e. that has the target
 * class at its first member.
 */
static LIST_HEAD(aliases);

/*
 * structs have pointers to the target class.
 */
static LIST_HEAD(pointers);

static const char *structure__name(const struct structure *st)
{
	return class__name(tag__class(st->class));
}

static struct structure *structures__find(struct list_head *list, const char *name)
{
	struct structure *pos;

	if (name == NULL)
		return NULL;

	list_for_each_entry(pos, list, node)
		if (strcmp(structure__name(pos), name) == 0)
			return pos;

	return NULL;
}

static void structures__add(struct list_head *list, struct tag *class, struct cu *cu)
{
	struct structure *str = structure__new(class, cu);

	if (str != NULL)
		list_add(&str->node, list);
}

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

static void method__add(struct cu *cu, struct function *function, uint32_t id)
{
	list_add(&function->tool_node, &cu->tool_list);
	function->priv = (void *)(long)id;
}

/*
 * We want just the function tags that have as one of its parameters
 * a pointer to the specified "class" (a struct, unions can be added later).
 */
static struct function *function__filter(struct function *function,
					 struct cu *cu, type_id_t target_type_id)
{
	if (function__inlined(function) ||
	    function->abstract_origin != 0 ||
	    !list_empty(&function->tool_node) ||
	    !ftype__has_parm_of_type(&function->proto, target_type_id, cu) ||
	    strlist__has_entry(init_blacklist, function__name(function))) {
		return NULL;
	}

	return function;
}

/*
 * Iterate thru all the tags in the compilation unit, looking just for the
 * function tags that have as one of its parameters a pointer to
 * the specified "class" (struct).
 */
static int cu_find_methods_iterator(struct cu *cu, void *cookie)
{
	type_id_t target_type_id;
	uint32_t function_id;
	struct function *function;
	struct tag *target = cu__find_struct_by_name(cu, cookie, 0,
						     &target_type_id);

	INIT_LIST_HEAD(&cu->tool_list);

	if (target == NULL)
		return 0;

	cu__for_each_function(cu, function_id, function)
		if (function__filter(function, cu, target_type_id))
			method__add(cu, function, function_id);

	return 0;
}

static struct class_member *class_member__bitfield_tail(struct class_member *head,
							struct class *class)
{
        struct class_member *tail = head,
			    *member = list_prepare_entry(head,
							 class__tags(class),
							 tag.node);
        list_for_each_entry_continue(member, class__tags(class), tag.node)
		if (member->byte_offset == head->byte_offset)
			tail = member;
		else
			break;

	return tail;
}

/*
 * Bitfields are removed as one for simplification right now.
 */
static struct class_member *class__remove_member(struct class *class, const struct cu *cu,
						 struct class_member *member)
{
	size_t size = member->byte_size;
	struct class_member *bitfield_tail = NULL;
	struct list_head *next;
	uint16_t member_hole = member->hole;

	if (member->bitfield_size != 0) {
		bitfield_tail = class_member__bitfield_tail(member, class);
		member_hole = bitfield_tail->hole;
	}
	/*
	 * Is this the first member?
	 */
	if (member->tag.node.prev == class__tags(class)) {
		class->type.size -= size + member_hole;
		class__subtract_offsets_from(class, bitfield_tail ?: member,
					     size + member_hole);
	/*
	 * Is this the last member?
	 */
	} else if (member->tag.node.next == class__tags(class)) {
		if (size + class->padding >= cu->addr_size) {
			class->type.size -= size + class->padding;
			class->padding = 0;
		} else
			class->padding += size;
	} else {
		if (size + member_hole >= cu->addr_size) {
			class->type.size -= size + member_hole;
			class__subtract_offsets_from(class,
						     bitfield_tail ?: member,
						     size + member_hole);
		} else {
			struct class_member *from_prev =
					list_entry(member->tag.node.prev,
						   struct class_member,
						   tag.node);
			if (from_prev->hole == 0)
				class->nr_holes++;
			from_prev->hole += size + member_hole;
		}
	}
	if (member_hole != 0)
		class->nr_holes--;

	if (bitfield_tail != NULL) {
		next = bitfield_tail->tag.node.next;
		list_del_range(&member->tag.node, &bitfield_tail->tag.node);
		if (bitfield_tail->bit_hole != 0)
			class->nr_bit_holes--;
	} else {
		next = member->tag.node.next;
		list_del(&member->tag.node);
	}

	return list_entry(next, struct class_member, tag.node);
}

static size_t class__find_biggest_member_name(const struct class *class)
{
	struct class_member *pos;
	size_t biggest_name_len = 0;

	type__for_each_data_member(&class->type, pos) {
		const size_t len = pos->name ?
					strlen(class_member__name(pos)) : 0;

		if (len > biggest_name_len)
			biggest_name_len = len;
	}

	return biggest_name_len;
}

static void class__emit_class_state_collector(struct class *class, struct class *clone)
{
	struct class_member *pos;
	int len = class__find_biggest_member_name(clone);

	fprintf(fp_collector,
		"void ctracer__class_state(const void *from, void *to)\n"
	        "{\n"
		"\tconst struct %s *obj = from;\n"
		"\tstruct %s *mini_obj = to;\n\n",
		class__name(class), class__name(clone));
	type__for_each_data_member(&clone->type, pos)
		fprintf(fp_collector, "\tmini_obj->%-*s = obj->%s;\n", len,
			class_member__name(pos),
			class_member__name(pos));
	fputs("}\n\n", fp_collector);
}

static struct class *class__clone_base_types(const struct tag *tag,
					     struct cu *cu,
					     const char *new_class_name)
{
	struct class *class = tag__class(tag);
	struct class_member *pos, *next;
	struct class *clone = class__clone(class, new_class_name);

	if (clone == NULL)
		return NULL;

	type__for_each_data_member_safe(&clone->type, pos, next) {
		struct tag *member_type = cu__type(cu, pos->tag.type);

		tag__assert_search_result(member_type);
		if (!tag__is_base_type(member_type, cu)) {
			next = class__remove_member(clone, cu, pos);
			class_member__delete(pos);
		}
	}
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
static int class__emit_ostra_converter(struct tag *tag)
{
	struct class *class = tag__class(tag);
	struct class_member *pos;
	struct type *type = &mini_class->type;
	int field = 0, first = 1;
	char filename[128];
	char parm_list[1024] = "";
	char *p = parm_list;
	size_t n;
	size_t plen = sizeof(parm_list);
	FILE *fp_fields, *fp_converter;
	const char *name = class__name(class);

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

	fputs("#include \"ctracer_classes.h\"\n"
	      "#include <stdio.h>\n"
	      "#include <string.h>\n"
	      "#include \"ctracer_relay.h\"\n\n", fp_converter);
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
		n = snprintf(p, plen, "obj.%s", class_member__name(pos));
		plen -= n; p += n;
		emit_struct_member_table_entry(fp_fields, field++,
					       class_member__name(pos),
					       1, "entry,exit");
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

/*
 * We want just the DW_TAG_structure_type tags that have a member that is a pointer
 * to the target class.
 */
static struct tag *pointer_filter(struct tag *tag, struct cu *cu,
				  type_id_t target_type_id)
{
	struct type *type;
	struct class_member *pos;
	const char *class_name;

	if (!tag__is_struct(tag))
		return NULL;

	type = tag__type(tag);
	if (type->nr_members == 0)
		return NULL;

	class_name = class__name(tag__class(tag));
	if (class_name == NULL || structures__find(&pointers, class_name))
		return NULL;

	type__for_each_member(type, pos) {
		struct tag *ctype = cu__type(cu, pos->tag.type);

		tag__assert_search_result(ctype);
		if (tag__is_pointer_to(ctype, target_type_id))
			return tag;
	}

	return NULL;
}

/*
 * Iterate thru all the tags in the compilation unit, looking for classes
 * that have as one member that is a pointer to the target type.
 */
static int cu_find_pointers_iterator(struct cu *cu, void *class_name)
{
	type_id_t target_type_id, id;
	struct tag *target = cu__find_struct_by_name(cu, class_name, 0,
						     &target_type_id), *pos;

	if (target == NULL)
		return 0;

	cu__for_each_type(cu, id, pos)
		if (pointer_filter(pos, cu, target_type_id))
			structures__add(&pointers, pos, cu);

	return 0;
}

static void class__find_pointers(const char *class_name)
{
	cus__for_each_cu(methods_cus, cu_find_pointers_iterator, (void *)class_name, cu_filter);
}

/*
 * We want just the DW_TAG_structure_type tags that have as its first member
 * a struct of type target.
 */
static struct tag *alias_filter(struct tag *tag, type_id_t target_type_id)
{
	struct type *type;
	struct class_member *first_member;

	if (!tag__is_struct(tag))
		return NULL;

	type = tag__type(tag);
	if (type->nr_members == 0)
		return NULL;

	first_member = list_first_entry(&type->namespace.tags,
					struct class_member, tag.node);
	if (first_member->tag.type != target_type_id)
		return NULL;

	if (structures__find(&aliases, class__name(tag__class(tag))))
		return NULL;

	return tag;
}

static void class__find_aliases(const char *class_name);

/*
 * Iterate thru all the tags in the compilation unit, looking for classes
 * that have as its first member the specified "class" (struct).
 */
static int cu_find_aliases_iterator(struct cu *cu, void *class_name)
{
	type_id_t target_type_id, id;
	struct tag *target = cu__find_struct_by_name(cu, class_name, 0,
						     &target_type_id), *pos;
	if (target == NULL)
		return 0;

	cu__for_each_type(cu, id, pos) {
		if (alias_filter(pos, target_type_id)) {
			const char *alias_name = class__name(tag__class(pos));

			structures__add(&aliases, pos, cu);

			/*
			 * Now find aliases to this alias, e.g.:
			 *
			 * struct tcp_sock {
			 * 	struct inet_connection_sock {
			 * 		struct inet_sock {
			 * 			struct sock {
			 * 			}
			 * 		}
			 * 	}
			 * }
			 */
			class__find_aliases(alias_name);
		}
	}

	return 0;
}

static void class__find_aliases(const char *class_name)
{
	cus__for_each_cu(methods_cus, cu_find_aliases_iterator, (void *)class_name, cu_filter);
}

static void emit_list_of_types(struct list_head *list)
{
	struct structure *pos;

	list_for_each_entry(pos, list, node) {
		struct type *type = tag__type(pos->class);
		/*
		 * Lets look at the other CUs, perhaps we have already
		 * emmited this one
		 */
		if (type_emissions__find_definition(&emissions, structure__name(pos))) {
			type->definition_emitted = 1;
			continue;
		}
		type__emit_definitions(pos->class, pos->cu, &emissions,
				       fp_classes);
		type->definition_emitted = 1;
		type__emit(pos->class, pos->cu, NULL, NULL, fp_classes);
		tag__type(pos->class)->definition_emitted = 1;
		fputc('\n', fp_classes);
	}
}

static int class__emit_classes(struct tag *tag, struct cu *cu)
{
	struct class *class = tag__class(tag);
	int err = -1;
	char mini_class_name[128];

	snprintf(mini_class_name, sizeof(mini_class_name), "ctracer__mini_%s",
		 class__name(class));

	mini_class = class__clone_base_types(tag, cu, mini_class_name);
	if (mini_class == NULL)
		goto out;

	type__emit_definitions(tag, cu, &emissions, fp_classes);

	type__emit(tag, cu, NULL, NULL, fp_classes);
	fputs("\n/* class aliases */\n\n", fp_classes);

	emit_list_of_types(&aliases);

	fputs("\n/* class with pointers */\n\n", fp_classes);

	emit_list_of_types(&pointers);

	class__fprintf(mini_class, cu, fp_classes);
	fputs(";\n\n", fp_classes);
	class__emit_class_state_collector(class, mini_class);
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
static int function__emit_probes(struct function *func, uint32_t function_id,
				 const struct cu *cu,
				 const type_id_t target_type_id, int probe_type,
				 const char *member)
{
	struct parameter *pos;
	const char *name = function__name(func);

	fprintf(fp_methods, "probe %s%s = kernel.function(\"%s@%s\")%s\n"
			    "{\n"
			    "}\n\n"
			    "probe %s%s\n"
			    "{\n", name,
			    probe_type == 0 ? "" : "__return",
			    name,
			    cu->name,
			    probe_type == 0 ? "" : ".return",
			    name,
			    probe_type == 0 ? "" : "__return");

	list_for_each_entry(pos, &func->proto.parms, tag.node) {
		struct tag *type = cu__type(cu, pos->tag.type);

		tag__assert_search_result(type);
		if (!tag__is_pointer_to(type, target_type_id))
			continue;

		if (member != NULL)
			fprintf(fp_methods, "\tif ($%s)\n\t", parameter__name(pos));

		fprintf(fp_methods,
			"\tctracer__method_hook(%d, %d, $%s%s%s, %d);\n",
			probe_type,
			function_id,
			parameter__name(pos),
			member ? "->" : "", member ?: "",
			class__size(mini_class));
		break;
	}

	fputs("}\n\n", fp_methods);
	fflush(fp_methods);

	return 0;
}

/*
 * Iterate thru the list of methods previously collected by
 * cu_find_methods_iterator, emitting the probes for function entry.
 */
static int cu_emit_probes_iterator(struct cu *cu, void *cookie)
{
	type_id_t target_type_id;
	struct tag *target = cu__find_struct_by_name(cu, cookie, 0, &target_type_id);
	struct function *pos;

	/* OK, this type is not present in this compile unit */
	if (target == NULL)
		return 0;

	list_for_each_entry(pos, &cu->tool_list, tool_node) {
		uint32_t function_id = (long)pos->priv;

		if (methods__add(&probes_emitted, function__name(pos)) != 0)
			continue;
		function__emit_probes(pos, function_id, cu, target_type_id, 0, NULL); /* entry */
		function__emit_probes(pos, function_id, cu, target_type_id, 1, NULL); /* exit */
	}

	return 0;
}

/*
 * Iterate thru the list of methods previously collected by
 * cu_find_methods_iterator, emitting the probes for function entry.
 */
static int cu_emit_pointer_probes_iterator(struct cu *cu, void *cookie)
{
	type_id_t target_type_id, pointer_id;
	struct tag *target, *pointer;
	struct function *pos_tag;
	struct class_member *pos_member;

	/* This CU doesn't have our classes */
	if (list_empty(&cu->tool_list))
		return 0;

	target = cu__find_struct_by_name(cu, class_name, 1, &target_type_id);
	pointer = cu__find_struct_by_name(cu, cookie, 0, &pointer_id);

	/* OK, this type is not present in this compile unit */
	if (target == NULL || pointer == NULL)
		return 0;

	/* for now just for the first member that is a pointer */
	type__for_each_member(tag__type(pointer), pos_member) {
		struct tag *ctype = cu__type(cu, pos_member->tag.type);

		tag__assert_search_result(ctype);
		if (tag__is_pointer_to(ctype, target_type_id))
			break;
	}

	list_for_each_entry(pos_tag, &cu->tool_list, tool_node) {
		uint32_t function_id = (long)pos_tag->priv;

		if (methods__add(&probes_emitted, function__name(pos_tag)) != 0)
			continue;

		function__emit_probes(pos_tag, function_id, cu, target_type_id, 0,
				      class_member__name(pos_member)); /* entry */
		function__emit_probes(pos_tag, function_id, cu, target_type_id, 1,
				      class_member__name(pos_member)); /* exit */
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
               if (pos->priv != NULL) {
			uint32_t function_id = (long)pos->priv;
			fprintf(fp, "%d:%s\n", function_id, function__name(pos));
			pos->priv = NULL;
		}

       return 0;
}

static int elf__open(const char *filename)
{
	int fd = open(filename, O_RDONLY);

	if (fd < 0)
		return -1;

	int err = -1;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "%s: cannot set libelf version.\n", __func__);
		goto out_close;
	}

	Elf *elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL) {
		fprintf(stderr, "%s: cannot read %s ELF file.\n",
			__func__, filename);
		goto out_close;
	}

	GElf_Shdr shdr;
	size_t init_index;
	Elf_Scn *init = elf_section_by_name(elf, &shdr, ".init.text", &init_index);
	if (init == NULL)
		goto out_elf_end;

	struct elf_symtab *symtab = elf_symtab__new(".symtab", elf);
	if (symtab == NULL)
		goto out_elf_end;

	init_blacklist = strlist__new(true);
	if (init_blacklist == NULL)
		goto out_elf_symtab_delete;

	uint32_t index;
	GElf_Sym sym;
	elf_symtab__for_each_symbol(symtab, index, sym) {
		if (!elf_sym__is_local_function(&sym))
			continue;
		if (elf_sym__section(&sym) != init_index)
			continue;
		err = strlist__add(init_blacklist, elf_sym__name(&sym, symtab));
		if (err == -ENOMEM) {
			fprintf(stderr, "failed for %s(%d,%zd)\n", elf_sym__name(&sym, symtab),elf_sym__section(&sym),init_index);
			goto out_delete_blacklist;
		}
	}

	err = 0;
out_elf_symtab_delete:
	elf_symtab__delete(symtab);
out_elf_end:
	elf_end(elf);
out_close:
	close(fd);
	return err;
out_delete_blacklist:
	strlist__delete(init_blacklist);
	goto out_elf_symtab_delete;
}

/* Name and version of program.  */
ARGP_PROGRAM_VERSION_HOOK_DEF = dwarves_print_version;

static const struct argp_option ctracer__options[] = {
	{
		.key  = 'd',
		.name = "src_dir",
		.arg  = "SRC_DIR",
		.doc  = "generate source files in this directory",
	},
	{
		.key  = 'C',
		.name = "cu_blacklist",
		.arg  = "FILE",
		.doc  = "Blacklist the CUs in FILE",
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
static int recursive;

static error_t ctracer__options_parser(int key, char *arg,
				      struct argp_state *state __maybe_unused)
{
	switch (key) {
	case 'd': src_dir = arg;		break;
	case 'C': cu_blacklist_filename = arg;	break;
	case 'D': dirname = arg;		break;
	case 'g': glob = arg;			break;
	case 'r': recursive = 1;		break;
	default:  return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char ctracer__args_doc[] = "FILE CLASS";

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
	char *filename;
	char functions_filename[PATH_MAX];
	char methods_filename[PATH_MAX];
	char collector_filename[PATH_MAX];
	char classes_filename[PATH_MAX];
	struct structure *pos;
	FILE *fp_functions;
	int rc = EXIT_FAILURE;

	if (dwarves__init(0)) {
		fputs("ctracer: insufficient memory\n", stderr);
		goto out;
	}

	if (argp_parse(&ctracer__argp, argc, argv, 0, &remaining, NULL) ||
	    remaining < argc) {
		switch (argc - remaining) {
		case 1:	 goto failure;
		case 2:	 filename  = argv[remaining++];
			 class_name = argv[remaining++];	break;
		default: goto failure;
		}
	} else {
failure:
		argp_help(&ctracer__argp, stderr, ARGP_HELP_SEE, argv[0]);
		goto out;
	}

	type_emissions__init(&emissions);

        /*
         * Create the methods_cus (Compilation Units) object where we will
	 * load the objects where we'll look for functions pointers to the
	 * specified class, i.e. to find its "methods", where we'll insert
	 * the entry and exit hooks.
         */
	methods_cus = cus__new();
	if (methods_cus == NULL) {
		fputs("ctracer: insufficient memory\n", stderr);
		goto out;
	}

	/*
         * if --dir/-D was specified, recursively traverse the path looking for
         * object files (compilation units) that match the glob specified (*.ko)
         * for kernel modules, but could be "*.o" in the future when we support
         * uprobes for user space tracing.
	 */
	if (dirname != NULL && cus__load_dir(methods_cus, NULL, dirname, glob,
					     recursive) != 0) {
		fprintf(stderr, "ctracer: couldn't load DWARF info "
				"from %s dir with glob %s\n",
			dirname, glob);
		goto out;
	}

        /*
         * If a filename was specified, for instance "vmlinux", load it too.
         */
	if (filename != NULL) {
		if (elf__open(filename)) {
			fprintf(stderr, "ctracer: couldn't load ELF symtab "
					"info from %s\n", filename);
			goto out;
		}
		err = cus__load_file(methods_cus, NULL, filename);
		if (err != 0) {
			cus__print_error_msg("ctracer", methods_cus, filename, err);
			goto out;
		}
	}

	/*
	 * See if the specified struct exists:
	 */
	class = cus__find_struct_by_name(methods_cus, &cu, class_name, 0, NULL);
	if (class == NULL) {
		fprintf(stderr, "ctracer: struct %s not found!\n", class_name);
		goto out;
	}

	snprintf(functions_filename, sizeof(functions_filename),
		 "%s/%s.functions", src_dir, class__name(tag__class(class)));
	fp_functions = fopen(functions_filename, "w");
	if (fp_functions == NULL) {
		fprintf(stderr, "ctracer: couldn't create %s\n",
			functions_filename);
		goto out;
	}

	snprintf(methods_filename, sizeof(methods_filename),
		 "%s/ctracer_methods.stp", src_dir);
	fp_methods = fopen(methods_filename, "w");
	if (fp_methods == NULL) {
		fprintf(stderr, "ctracer: couldn't create %s\n",
			methods_filename);
		goto out;
	}

	snprintf(collector_filename, sizeof(collector_filename),
		 "%s/ctracer_collector.c", src_dir);
	fp_collector = fopen(collector_filename, "w");
	if (fp_collector == NULL) {
		fprintf(stderr, "ctracer: couldn't create %s\n",
			collector_filename);
		goto out;
	}

	snprintf(classes_filename, sizeof(classes_filename),
		 "%s/ctracer_classes.h", src_dir);
	fp_classes = fopen(classes_filename, "w");
	if (fp_classes == NULL) {
		fprintf(stderr, "ctracer: couldn't create %s\n",
			classes_filename);
		goto out;
	}

	fputs("%{\n"
	      "#include </home/acme/git/pahole/lib/ctracer_relay.h>\n"
	      "%}\n"
	      "function ctracer__method_hook(probe_type, func, object, state_len)\n"
	      "%{\n"
	      "\tctracer__method_hook(_stp_gettimeofday_ns(), "
				     "THIS->probe_type, THIS->func, "
				     "(void *)(long)THIS->object, "
				     "THIS->state_len);\n"
	      "%}\n\n", fp_methods);

	fputs("\n#include \"ctracer_classes.h\"\n\n", fp_collector);
	class__find_aliases(class_name);
	class__find_pointers(class_name);

	class__emit_classes(class, cu);
	fputc('\n', fp_collector);

	class__emit_ostra_converter(class);

	cu_blacklist = strlist__new(true);
	if (cu_blacklist != NULL)
		strlist__load(cu_blacklist, cu_blacklist_filename);

	cus__for_each_cu(methods_cus, cu_find_methods_iterator,
			 class_name, cu_filter);
	cus__for_each_cu(methods_cus, cu_emit_probes_iterator,
			 class_name, cu_filter);
	cus__for_each_cu(methods_cus, cu_emit_functions_table,
			 fp_functions, cu_filter);

	list_for_each_entry(pos, &aliases, node) {
		const char *alias_name = structure__name(pos);

		cus__for_each_cu(methods_cus, cu_find_methods_iterator,
				 (void *)alias_name, cu_filter);
		cus__for_each_cu(methods_cus, cu_emit_probes_iterator,
				 (void *)alias_name, cu_filter);
		cus__for_each_cu(methods_cus, cu_emit_functions_table,
				 fp_functions, cu_filter);
	}

	list_for_each_entry(pos, &pointers, node) {
		const char *pointer_name = structure__name(pos);
		cus__for_each_cu(methods_cus, cu_find_methods_iterator,
				 (void *)pointer_name, cu_filter);
		cus__for_each_cu(methods_cus, cu_emit_pointer_probes_iterator,
				 (void *)pointer_name, cu_filter);
		cus__for_each_cu(methods_cus, cu_emit_functions_table, fp_functions,
				 cu_filter);
	}

	fclose(fp_methods);
	fclose(fp_collector);
	fclose(fp_functions);
	fclose(fp_classes);
	strlist__delete(cu_blacklist);

	rc = EXIT_SUCCESS;
out:
	cus__delete(methods_cus);
	dwarves__exit();
	return rc;
}
