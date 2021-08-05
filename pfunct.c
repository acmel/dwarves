/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
*/

#include <argp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "dwarves.h"
#include "dwarves_emit.h"
#include "dutil.h"
#include "elf_symtab.h"

static int verbose;
static int show_inline_expansions;
static int show_variables;
static int show_externals;
static int show_cc_inlined;
static int show_cc_uninlined;
static char *symtab_name;
static bool show_prototypes;
static bool expand_types;
static bool compilable_output;
static struct type_emissions emissions;
static uint64_t addr;
static char *class_name;
static char *function_name;

static struct conf_fprintf conf;

static struct conf_load conf_load = {
	.conf_fprintf = &conf,
};

struct fn_stats {
	struct list_head node;
	struct tag	 *tag;
	const struct cu	 *cu;
	uint32_t	 nr_expansions;
	uint32_t	 size_expansions;
	uint32_t	 nr_files;
};

static struct fn_stats *fn_stats__new(struct tag *tag, const struct cu *cu)
{
	struct fn_stats *stats = malloc(sizeof(*stats));

	if (stats != NULL) {
		const struct function *fn = tag__function(tag);

		stats->tag = tag;
		stats->cu = cu;
		stats->nr_files = 1;
		stats->nr_expansions = fn->cu_total_nr_inline_expansions;
		stats->size_expansions = fn->cu_total_size_inline_expansions;
	}

	return stats;
}

static void fn_stats__delete(struct fn_stats *stats)
{
	free(stats);
}

static LIST_HEAD(fn_stats__list);

static struct fn_stats *fn_stats__find(const char *name)
{
	struct fn_stats *pos;

	list_for_each_entry(pos, &fn_stats__list, node)
		if (strcmp(function__name(tag__function(pos->tag)), name) == 0)
			return pos;
	return NULL;
}

static void fn_stats__delete_list(void)
{
	struct fn_stats *pos, *n;

	list_for_each_entry_safe(pos, n, &fn_stats__list, node) {
		list_del_init(&pos->node);
		fn_stats__delete(pos);
	}
}

static void fn_stats__add(struct tag *tag, const struct cu *cu)
{
	struct fn_stats *fns = fn_stats__new(tag, cu);
	if (fns != NULL)
		list_add(&fns->node, &fn_stats__list);
}

static void fn_stats_inline_exps_fmtr(const struct fn_stats *stats)
{
	struct function *fn = tag__function(stats->tag);
	if (fn->lexblock.nr_inline_expansions > 0)
		printf("%s: %u %d\n", function__name(fn),
		       fn->lexblock.nr_inline_expansions,
		       fn->lexblock.size_inline_expansions);
}

static void fn_stats_labels_fmtr(const struct fn_stats *stats)
{
	struct function *fn = tag__function(stats->tag);
	if (fn->lexblock.nr_labels > 0)
		printf("%s: %u\n", function__name(fn), fn->lexblock.nr_labels);
}

static void fn_stats_variables_fmtr(const struct fn_stats *stats)
{
	struct function *fn = tag__function(stats->tag);
	if (fn->lexblock.nr_variables > 0)
		printf("%s: %u\n", function__name(fn), fn->lexblock.nr_variables);
}

static void fn_stats_nr_parms_fmtr(const struct fn_stats *stats)
{
	struct function *fn = tag__function(stats->tag);
	printf("%s: %u\n", function__name(fn), fn->proto.nr_parms);
}

static void fn_stats_name_len_fmtr(const struct fn_stats *stats)
{
	struct function *fn = tag__function(stats->tag);
	const char *name = function__name(fn);
	printf("%s: %zd\n", name, strlen(name));
}

static void fn_stats_size_fmtr(const struct fn_stats *stats)
{
	struct function *fn = tag__function(stats->tag);
	const size_t size = function__size(fn);

	if (size != 0)
		printf("%s: %zd\n", function__name(fn), size);
}

static void fn_stats_fmtr(const struct fn_stats *stats)
{
	if (verbose || show_prototypes) {
		tag__fprintf(stats->tag, stats->cu, &conf, stdout);
		putchar('\n');
		if (show_prototypes)
			return;
		if (show_variables || show_inline_expansions)
			function__fprintf_stats(stats->tag, stats->cu, &conf, stdout);
		printf("/* definitions: %u */\n", stats->nr_files);
		putchar('\n');
	} else {
		struct function *fn = tag__function(stats->tag);
		puts(function__name(fn));
	}
}

static void print_fn_stats(void (*formatter)(const struct fn_stats *f))
{
	struct fn_stats *pos;

	list_for_each_entry(pos, &fn_stats__list, node)
		formatter(pos);
}

static void fn_stats_inline_stats_fmtr(const struct fn_stats *stats)
{
	if (stats->nr_expansions > 1)
		printf("%-31.31s %6u %7u  %6u %6u\n",
		       function__name(tag__function(stats->tag)),
		       stats->size_expansions, stats->nr_expansions,
		       stats->size_expansions / stats->nr_expansions,
		       stats->nr_files);
}

static void print_total_inline_stats(void)
{
	printf("%-32.32s  %5.5s / %5.5s = %5.5s  %s\n",
	       "name", "totsz", "exp#", "avgsz", "src#");
	print_fn_stats(fn_stats_inline_stats_fmtr);
}

static void fn_stats__dupmsg(struct function *func,
			     const struct cu *func_cu,
			     struct function *dup __maybe_unused,
			     const struct cu *dup_cu,
			     char *hdr, const char *fmt, ...)
{
	va_list args;

	if (!*hdr)
		printf("function: %s\nfirst: %s\ncurrent: %s\n", function__name(func), func_cu->name, dup_cu->name);

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	*hdr = 1;
}

static void fn_stats__chkdupdef(struct function *func,
				const struct cu *func_cu,
				struct function *dup,
				const struct cu *dup_cu)
{
	char hdr = 0;
	const size_t func_size = function__size(func);
	const size_t dup_size = function__size(dup);

	if (func_size != dup_size)
		fn_stats__dupmsg(func, func_cu, dup, dup_cu,
				 &hdr, "size: %zd != %zd\n",
				 func_size, dup_size);

	if (func->proto.nr_parms != dup->proto.nr_parms)
		fn_stats__dupmsg(func, func_cu, dup, dup_cu,
				 &hdr, "nr_parms: %u != %u\n",
				 func->proto.nr_parms, dup->proto.nr_parms);

	/* XXX put more checks here: member types, member ordering, etc */

	if (hdr)
		putchar('\n');
}

static bool function__filter(struct function *function, struct cu *cu)
{
	struct fn_stats *fstats;
	const char *name;

	if (!function__tag(function)->top_level)
		return true;

	/*
	 * FIXME: remove this check and try to fix the parameter abstract
	 * origin code someday...
	 */
	if (!function->name)
		return true;

	name = function__name(function);
	if (show_externals && !function->external)
		return true;

	if (show_cc_uninlined &&
	    function->inlined != DW_INL_declared_not_inlined)
		return true;

	if (show_cc_inlined && function->inlined != DW_INL_inlined)
		return true;

	fstats = fn_stats__find(name);
	if (fstats != NULL) {
		struct function *fn = tag__function(fstats->tag);

		if (!fn->external)
			return false;

		if (verbose)
			fn_stats__chkdupdef(fn, fstats->cu, function, cu);
		fstats->nr_expansions   += function->cu_total_nr_inline_expansions;
		fstats->size_expansions += function->cu_total_size_inline_expansions;
		fstats->nr_files++;
		return true;
	}

	return false;
}

static int cu_unique_iterator(struct cu *cu, void *cookie __maybe_unused)
{
	cu__account_inline_expansions(cu);

	struct function *pos;
	uint32_t id;

	cu__for_each_function(cu, id, pos)
		if (!function__filter(pos, cu))
			fn_stats__add(function__tag(pos), cu);
	return 0;
}

static int cu_class_iterator(struct cu *cu, void *cookie)
{
	type_id_t target_id;
	struct tag *target = cu__find_struct_by_name(cu, cookie, 0, &target_id);

	if (target == NULL)
		return 0;

	struct function *pos;
	uint32_t id;

	cu__for_each_function(cu, id, pos) {
		if (pos->inlined ||
		    !ftype__has_parm_of_type(&pos->proto, target_id, cu))
			continue;

		if (verbose)
			tag__fprintf(function__tag(pos), cu, &conf, stdout);
		else
			fputs(function__name(pos), stdout);
		putchar('\n');
	}

	return 0;
}

static int function__emit_type_definitions(struct function *func,
					   struct cu *cu, FILE *fp)
{
	struct parameter *pos;
	struct ftype *proto = func->btf ? tag__ftype(cu__type(cu, func->proto.tag.type)) : &func->proto;
	struct tag *type = cu__type(cu, proto->tag.type);

retry_return_type:
	/* type == NULL means the return is void */
	if (type == NULL)
		goto do_parameters;

	if (tag__is_pointer(type) || tag__is_modifier(type)) {
		type = cu__type(cu, type->type);
		goto retry_return_type;
	}

	if (tag__is_type(type) && !tag__type(type)->definition_emitted) {
		type__emit_definitions(type, cu, &emissions, fp);
		type__emit(type, cu, NULL, NULL, fp);
	}
do_parameters:
	ftype__for_each_parameter(proto, pos) {
		type = cu__type(cu, pos->tag.type);
	try_again:
		if (type == NULL)
			continue;

		if (tag__is_pointer(type) || tag__is_modifier(type)) {
			type = cu__type(cu, type->type);
			goto try_again;
		}

		if (type->tag == DW_TAG_subroutine_type) {
			ftype__emit_definitions(tag__ftype(type), cu, &emissions, fp);
		} else if (tag__is_type(type) && !tag__type(type)->definition_emitted) {
			type__emit_definitions(type, cu, &emissions, fp);
			if (!tag__is_typedef(type))
				type__emit(type, cu, NULL, NULL, fp);
			putchar('\n');
		}
	}

	return 0;
}

static void function__show(struct function *func, struct cu *cu)
{
	struct tag *tag = function__tag(func);

	if (func->abstract_origin || func->external)
		return;

	if (expand_types)
		function__emit_type_definitions(func, cu, stdout);
	tag__fprintf(tag, cu, &conf, stdout);
	if (compilable_output) {
		struct tag *type = cu__type(cu, func->proto.tag.type);

		fprintf(stdout, "\n{");
		if (type != NULL && type->type != 0) { /* NULL == void */
			if (tag__is_pointer(type))
				fprintf(stdout, "\n\treturn (void *)0;");
			else if (tag__is_struct(type))
				fprintf(stdout, "\n\treturn *(struct %s *)1;", class__name(tag__class(type)));
			else if (tag__is_union(type))
				fprintf(stdout, "\n\treturn *(union %s *)1;", type__name(tag__type(type)));
			else if (tag__is_typedef(type))
				fprintf(stdout, "\n\treturn *(%s *)1;", type__name(tag__type(type)));
			else
				fprintf(stdout, "\n\treturn 0;");
		}
		fprintf(stdout, "\n}\n");
	}
	putchar('\n');
	if (show_variables || show_inline_expansions)
		function__fprintf_stats(tag, cu, &conf, stdout);
}

static int cu_function_iterator(struct cu *cu, void *cookie)
{
	struct function *function;
	uint32_t id;

	cu__for_each_function(cu, id, function) {
		if (cookie && strcmp(function__name(function), cookie) != 0)
			continue;
		function__show(function, cu);
		if (!expand_types)
			return 1;
	}
	return 0;
}

int elf_symtab__show(char *filename)
{
	int fd = open(filename, O_RDONLY), err = -1;
	if (fd < 0)
		return -1;

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

	GElf_Ehdr ehdr;
	if (gelf_getehdr(elf, &ehdr) == NULL) {
		fprintf(stderr, "%s: cannot get elf header.\n", __func__);
		goto out_elf_end;
	}

	struct elf_symtab *symtab = elf_symtab__new(symtab_name, elf);
	if (symtab == NULL)
		goto out_elf_end;

	GElf_Sym sym;
	uint32_t index;
	int longest_name = 0;
	elf_symtab__for_each_symbol(symtab, index, sym) {
		if (!elf_sym__is_local_function(&sym))
			continue;
		int len = strlen(elf_sym__name(&sym, symtab));
		if (len > longest_name)
			longest_name = len;
	}

	if (longest_name > 32)
		longest_name = 32;

	int index_spacing = 0;
	int nr = elf_symtab__nr_symbols(symtab);
	while (nr) {
		++index_spacing;
		nr /= 10;
	}

	elf_symtab__for_each_symbol(symtab, index, sym) {
		if (!elf_sym__is_local_function(&sym))
			continue;
		printf("%*d: %-*s %#llx %5u\n",
		       index_spacing, index, longest_name,
		       elf_sym__name(&sym, symtab),
		       (unsigned long long)elf_sym__value(&sym),
		       elf_sym__size(&sym));
	}

	elf_symtab__delete(symtab);
	err = 0;
out_elf_end:
	elf_end(elf);
out_close:
	close(fd);
	return err;
}

int elf_symtabs__show(char *filenames[])
{
	int i = 0;

	while (filenames[i] != NULL) {
		if (elf_symtab__show(filenames[i]))
			return EXIT_FAILURE;
		++i;
	}

	return EXIT_SUCCESS;
}

static enum load_steal_kind pfunct_stealer(struct cu *cu, struct conf_load *conf_load __maybe_unused)
{

	if (function_name) {
		struct tag *tag = cu__find_function_by_name(cu, function_name);

		if (tag) {
			function__show(tag__function(tag), cu);
			return LSK__STOP_LOADING;
		}
	} else if (class_name) {
		cu_class_iterator(cu, class_name);
	}

	return LSK__DELETE;
}

/* Name and version of program.  */
ARGP_PROGRAM_VERSION_HOOK_DEF = dwarves_print_version;

#define ARGP_symtab		300
#define ARGP_no_parm_names	301
#define ARGP_compile		302

static const struct argp_option pfunct__options[] = {
	{
		.key  = 'a',
		.name = "addr",
		.arg  = "ADDR",
		.doc  = "show just the function that where ADDR is",
	},
	{
		.key  = 'b',
		.name = "expand_types",
		.doc  = "Expand types needed by the prototype",
	},
	{
		.key  = 'c',
		.name = "class",
		.arg  = "CLASS",
		.doc  = "functions that have CLASS pointer parameters",
	},
	{
		.key  = 'E',
		.name = "externals",
		.doc  = "show just external functions",
	},
	{
		.key  = 'f',
		.name = "function",
		.arg  = "FUNCTION",
		.doc  = "show just FUNCTION",
	},
	{
		.name = "format_path",
		.key  = 'F',
		.arg  = "FORMAT_LIST",
		.doc  = "List of debugging formats to try"
	},
	{
		.key  = 'g',
		.name = "goto_labels",
		.doc  = "show number of goto labels",
	},
	{
		.key  = 'G',
		.name = "cc_uninlined",
		.doc  = "declared inline, uninlined by compiler",
	},
	{
		.key  = 'H',
		.name = "cc_inlined",
		.doc  = "not declared inline, inlined by compiler",
	},
	{
		.key  = 'i',
		.name = "inline_expansions",
		.doc  = "show inline expansions",
	},
	{
		.key  = 'I',
		.name = "inline_expansions_stats",
		.doc  = "show inline expansions stats",
	},
	{
		.key  = 'l',
		.name = "decl_info",
		.doc  = "show source code info",
	},
	{
		.key  = 't',
		.name = "total_inline_stats",
		.doc  = "show Multi-CU total inline expansions stats",
	},
	{
		.key  = 's',
		.name = "sizes",
		.doc  = "show size of functions",
	},
	{
		.key  = 'N',
		.name = "function_name_len",
		.doc  = "show size of functions names",
	},
	{
		.key  = 'p',
		.name = "nr_parms",
		.doc  = "show number of parameters",
	},
	{
		.key  = 'P',
		.name = "prototypes",
		.doc  = "show function prototypes",
	},
	{
		.key  = 'S',
		.name = "nr_variables",
		.doc  = "show number of variables",
	},
	{
		.key  = 'T',
		.name = "variables",
		.doc  = "show variables",
	},
	{
		.key  = 'V',
		.name = "verbose",
		.doc  = "be verbose",
	},
	{
		.name  = "symtab",
		.key   = ARGP_symtab,
		.arg   = "NAME",
		.flags = OPTION_ARG_OPTIONAL,
		.doc   = "show symbol table NAME (Default .symtab)",
	},
	{
		.name  = "compile",
		.key   = ARGP_compile,
		.arg   = "FUNCTION",
		.flags = OPTION_ARG_OPTIONAL,
		.doc   = "Generate compilable source code with types expanded (Default all functions)",
	},
	{
		.name  = "no_parm_names",
		.key   = ARGP_no_parm_names,
		.doc   = "Don't show parameter names",
	},
	{
		.name = NULL,
	}
};

static void (*formatter)(const struct fn_stats *f) = fn_stats_fmtr;
static int show_total_inline_expansion_stats;

static error_t pfunct__options_parser(int key, char *arg,
				      struct argp_state *state)
{
	switch (key) {
	case ARGP_KEY_INIT:
		if (state->child_inputs != NULL)
			state->child_inputs[0] = state->input;
		break;
	case 'a': addr = strtoull(arg, NULL, 0);
		  conf_load.get_addr_info = true;	 break;
	case 'b': expand_types = true;
		  type_emissions__init(&emissions);	 break;
	case 'c': class_name = arg;			 break;
	case 'f': function_name = arg;			 break;
	case 'F': conf_load.format_path = arg;		 break;
	case 'E': show_externals = 1;			 break;
	case 's': formatter = fn_stats_size_fmtr;
		  conf_load.get_addr_info = true;	 break;
	case 'S': formatter = fn_stats_variables_fmtr;	 break;
	case 'p': formatter = fn_stats_nr_parms_fmtr;	 break;
	case 'P': show_prototypes = true;		 break;
	case 'g': formatter = fn_stats_labels_fmtr;	 break;
	case 'G': show_cc_uninlined = 1;		 break;
	case 'H': show_cc_inlined = 1;			 break;
	case 'i': show_inline_expansions = verbose = 1;
		  conf_load.extra_dbg_info = true;
		  conf_load.get_addr_info = true;	 break;
	case 'I': formatter = fn_stats_inline_exps_fmtr;
		  conf_load.get_addr_info = true;	 break;
	case 'l': conf.show_decl_info = 1;
		  conf_load.extra_dbg_info = 1;		 break;
	case 't': show_total_inline_expansion_stats = true;
		  conf_load.get_addr_info = true;	 break;
	case 'T': show_variables = 1;			 break;
	case 'N': formatter = fn_stats_name_len_fmtr;	 break;
	case 'V': verbose = 1;
		  conf_load.extra_dbg_info = true;
		  conf_load.get_addr_info = true;	 break;
	case ARGP_symtab: symtab_name = arg ?: ".symtab";  break;
	case ARGP_no_parm_names: conf.no_parm_names = 1; break;
	case ARGP_compile:
		  expand_types = true;
		  type_emissions__init(&emissions);
		  compilable_output = true;
		  conf.no_semicolon = true;
		  conf.strip_inline = true;
		  if (arg)
			  function_name = arg;
		  break;
	default:  return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static const char pfunct__args_doc[] = "FILE";

static struct argp pfunct__argp = {
	.options  = pfunct__options,
	.parser	  = pfunct__options_parser,
	.args_doc = pfunct__args_doc,
};

int main(int argc, char *argv[])
{
	int err, remaining, rc = EXIT_FAILURE;

	if (argp_parse(&pfunct__argp, argc, argv, 0, &remaining, NULL) ||
	    (remaining == argc && class_name == NULL && function_name == NULL)) {
                argp_help(&pfunct__argp, stderr, ARGP_HELP_SEE, argv[0]);
                goto out;
	}

	if (symtab_name != NULL)
		return elf_symtabs__show(argv + remaining);

	if (dwarves__init(0)) {
		fputs("pfunct: insufficient memory\n", stderr);
		goto out;
	}

	struct cus *cus = cus__new();
	if (cus == NULL) {
		fputs("pfunct: insufficient memory\n", stderr);
		goto out_dwarves_exit;
	}

	if (function_name || class_name)
		conf_load.steal = pfunct_stealer;

try_sole_arg_as_function_name:
	err = cus__load_files(cus, &conf_load, argv + remaining);
	if (err != 0) {
		if (function_name == NULL) {
                        function_name = argv[remaining];
                        if (access(function_name, R_OK) == 0) {
                                fprintf(stderr, "pfunct: file '%s' has no %s type information.\n",
                                                function_name, conf_load.format_path ?: "supported");
                                goto out_dwarves_exit;
                        }
			conf_load.steal = pfunct_stealer;
                        remaining = argc;
			goto try_sole_arg_as_function_name;
		}
		cus__fprintf_load_files_err(cus, "pfunct", argv + remaining, err, stderr);
		goto out_cus_delete;
	}


	cus__for_each_cu(cus, cu_unique_iterator, NULL, NULL);

	if (addr) {
		struct cu *cu;
		struct function *f = cus__find_function_at_addr(cus, addr, &cu);

		if (f == NULL) {
			fprintf(stderr, "pfunct: No function found at %#llx!\n",
				(unsigned long long)addr);
			goto out_cus_delete;
		}
		function__show(f, cu);
	} else if (show_total_inline_expansion_stats)
		print_total_inline_stats();
	else if (function_name != NULL || expand_types)
		cus__for_each_cu(cus, cu_function_iterator,
				 function_name, NULL);
	else
		print_fn_stats(formatter);

	rc = EXIT_SUCCESS;
out_cus_delete:
	cus__delete(cus);
	fn_stats__delete_list();
out_dwarves_exit:
	dwarves__exit();
out:
	return rc;
}
