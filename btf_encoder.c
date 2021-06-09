/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook

  Derived from ctf_encoder.c, which is:

  Copyright (C) Arnaldo Carvalho de Melo <acme@redhat.com>
  Copyright (C) Red Hat Inc
 */

#include "dwarves.h"
#include "libbtf.h"
#include "lib/bpf/include/uapi/linux/btf.h"
#include "lib/bpf/src/libbpf.h"
#include "elf_symtab.h"
#include "btf_encoder.h"

#include <ctype.h> /* for isalpha() and isalnum() */
#include <stdlib.h> /* for qsort() and bsearch() */
#include <inttypes.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>

#include <errno.h>

bool btf_encoder__verbose;

/*
 * This depends on the GNU extension to eliminate the stray comma in the zero
 * arguments case.
 *
 * The difference between elf_errmsg(-1) and elf_errmsg(elf_errno()) is that the
 * latter clears the current error.
 */
#define elf_error(fmt, ...) \
        fprintf(stderr, "%s: " fmt ": %s.\n", __func__, ##__VA_ARGS__, elf_errmsg(-1))

/*
 * This corresponds to the same macro defined in
 * include/linux/kallsyms.h
 */
#define KSYM_NAME_LEN 128

struct elf_function {
	const char	*name;
	bool		 generated;
};

static int functions_cmp(const void *_a, const void *_b)
{
	const struct elf_function *a = _a;
	const struct elf_function *b = _b;

	return strcmp(a->name, b->name);
}

#ifndef max
#define max(x, y) ((x) < (y) ? (y) : (x))
#endif

static int btf_encoder__collect_function(struct btf_encoder *encoder, GElf_Sym *sym)
{
	struct elf_function *new;
	const char *name;

	if (elf_sym__type(sym) != STT_FUNC)
		return 0;
	name = elf_sym__name(sym, encoder->symtab);
	if (!name)
		return 0;

	if (encoder->functions.cnt == encoder->functions.allocated) {
		encoder->functions.allocated = max(1000, encoder->functions.allocated * 3 / 2);
		new = realloc(encoder->functions.entries, encoder->functions.allocated * sizeof(*encoder->functions.entries));
		if (!new) {
			/*
			 * The cleanup - delete_functions is called
			 * in btf_encoder__encode_cu error path.
			 */
			return -1;
		}
		encoder->functions.entries = new;
	}

	encoder->functions.entries[encoder->functions.cnt].name = name;
	encoder->functions.entries[encoder->functions.cnt].generated = false;
	encoder->functions.cnt++;
	return 0;
}

static struct elf_function *btf_encoder__find_function(const struct btf_encoder *encoder, const char *name)
{
	struct elf_function key = { .name = name };

	return bsearch(&key, encoder->functions.entries, encoder->functions.cnt, sizeof(key), functions_cmp);
}

static bool btf_name_char_ok(char c, bool first)
{
	if (c == '_' || c == '.')
		return true;

	return first ? isalpha(c) : isalnum(c);
}

/* Check whether the given name is valid in vmlinux btf. */
static bool btf_name_valid(const char *p)
{
	const char *limit;

	if (!btf_name_char_ok(*p, true))
		return false;

	/* set a limit on identifier length */
	limit = p + KSYM_NAME_LEN;
	p++;
	while (*p && p < limit) {
		if (!btf_name_char_ok(*p, false))
			return false;
		p++;
	}

	return !*p;
}

static void dump_invalid_symbol(const char *msg, const char *sym,
				int verbose, bool force)
{
	if (force) {
		if (verbose)
			fprintf(stderr, "PAHOLE: Warning: %s, ignored (sym: '%s').\n",
				msg, sym);
		return;
	}

	fprintf(stderr, "PAHOLE: Error: %s (sym: '%s').\n", msg, sym);
	fprintf(stderr, "PAHOLE: Error: Use '--btf_encode_force' to ignore such symbols and force emit the btf.\n");
}

extern struct debug_fmt_ops *dwarves__active_loader;

static int tag__check_id_drift(const struct tag *tag,
			       uint32_t core_id, uint32_t btf_type_id,
			       uint32_t type_id_off)
{
	if (btf_type_id != (core_id + type_id_off)) {
		fprintf(stderr,
			"%s: %s id drift, core_id: %u, btf_type_id: %u, type_id_off: %u\n",
			__func__, dwarf_tag_name(tag->tag),
			core_id, btf_type_id, type_id_off);
		return -1;
	}

	return 0;
}

static int32_t btf_encoder__add_struct_type(struct btf_encoder *encoder, struct cu *cu, struct tag *tag, uint32_t type_id_off)
{
	struct type *type = tag__type(tag);
	struct class_member *pos;
	const char *name;
	int32_t type_id;
	uint8_t kind;

	kind = (tag->tag == DW_TAG_union_type) ?
		BTF_KIND_UNION : BTF_KIND_STRUCT;

	name = dwarves__active_loader->strings__ptr(cu, type->namespace.name);
	type_id = btf_encoder__add_struct(encoder, kind, name, type->size);
	if (type_id < 0)
		return type_id;

	type__for_each_data_member(type, pos) {
		/*
		 * dwarf_loader uses DWARF's recommended bit offset addressing
		 * scheme, which conforms to BTF requirement, so no conversion
		 * is required.
		 */
		name = dwarves__active_loader->strings__ptr(cu, pos->name);
		if (btf_encoder__add_field(encoder, name, type_id_off + pos->tag.type, pos->bitfield_size, pos->bit_offset))
			return -1;
	}

	return type_id;
}

static uint32_t array_type__nelems(struct tag *tag)
{
	int i;
	uint32_t nelem = 1;
	struct array_type *array = tag__array_type(tag);

	for (i = array->dimensions - 1; i >= 0; --i)
		nelem *= array->nr_entries[i];

	return nelem;
}

static int32_t btf__encode_enumeration_type(struct btf *btf, struct cu *cu, struct tag *tag)
{
	struct type *etype = tag__type(tag);
	struct enumerator *pos;
	const char *name;
	int32_t type_id;

	name = dwarves__active_loader->strings__ptr(cu, etype->namespace.name);
	type_id = btf__encode_enum(btf, name, etype->size);
	if (type_id < 0)
		return type_id;

	type__for_each_enumerator(etype, pos) {
		name = dwarves__active_loader->strings__ptr(cu, pos->name);
		if (btf__encode_enum_val(btf, name, pos->value))
			return -1;
	}

	return type_id;
}

static int btf_encoder__encode_tag(struct btf_encoder *encoder, struct cu *cu, struct tag *tag,
				   uint32_t core_id, uint32_t type_id_off)
{
	/* single out type 0 as it represents special type "void" */
	uint32_t ref_type_id = tag->type == 0 ? 0 : type_id_off + tag->type;
	struct btf *btf = encoder->btf;
	const char *name;

	switch (tag->tag) {
	case DW_TAG_base_type:
		name = dwarves__active_loader->strings__ptr(cu, tag__base_type(tag)->name);
		return btf_encoder__add_base_type(encoder, tag__base_type(tag), name);
	case DW_TAG_const_type:
		return btf_encoder__add_ref_type(encoder, BTF_KIND_CONST, ref_type_id, NULL, false);
	case DW_TAG_pointer_type:
		return btf_encoder__add_ref_type(encoder, BTF_KIND_PTR, ref_type_id, NULL, false);
	case DW_TAG_restrict_type:
		return btf_encoder__add_ref_type(encoder, BTF_KIND_RESTRICT, ref_type_id, NULL, false);
	case DW_TAG_volatile_type:
		return btf_encoder__add_ref_type(encoder, BTF_KIND_VOLATILE, ref_type_id, NULL, false);
	case DW_TAG_typedef:
		name = dwarves__active_loader->strings__ptr(cu, tag__namespace(tag)->name);
		return btf_encoder__add_ref_type(encoder, BTF_KIND_TYPEDEF, ref_type_id, name, false);
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
	case DW_TAG_class_type:
		name = dwarves__active_loader->strings__ptr(cu, tag__namespace(tag)->name);
		if (tag__type(tag)->declaration)
			return btf_encoder__add_ref_type(encoder, BTF_KIND_FWD, 0, name, tag->tag == DW_TAG_union_type);
		else
			return btf_encoder__add_struct_type(encoder, cu, tag, type_id_off);
	case DW_TAG_array_type:
		/* TODO: Encode one dimension at a time. */
		encoder->need_index_type = true;
		return btf_encoder__add_array(encoder, ref_type_id, encoder->array_index_id, array_type__nelems(tag));
	case DW_TAG_enumeration_type:
		return btf__encode_enumeration_type(btf, cu, tag);
	case DW_TAG_subroutine_type:
		return btf__encode_func_proto(btf, cu, tag__ftype(tag), type_id_off);
	default:
		fprintf(stderr, "Unsupported DW_TAG_%s(0x%x)\n",
			dwarf_tag_name(tag->tag), tag->tag);
		return -1;
	}
}

static int btf__encode_as_raw_file(struct btf *btf, const char *filename)
{
	uint32_t raw_btf_size;
	const void *raw_btf_data;
	int fd, err;

	/* Empty file, nothing to do, so... done! */
	if (btf__get_nr_types(btf) == 0)
		return 0;

	if (btf__dedup(btf, NULL, NULL)) {
		fprintf(stderr, "%s: btf__dedup failed!\n", __func__);
		return -1;
	}

	raw_btf_data = btf__get_raw_data(btf, &raw_btf_size);
	if (raw_btf_data == NULL) {
		fprintf(stderr, "%s: btf__get_raw_data failed!\n", __func__);
		return -1;
	}

	fd = open(filename, O_WRONLY | O_CREAT, 0640);
	if (fd < 0) {
		fprintf(stderr, "%s: Couldn't open %s for writing the raw BTF info: %s\n", __func__, filename, strerror(errno));
		return -1;
	}
	err = write(fd, raw_btf_data, raw_btf_size);
	if (err < 0)
		fprintf(stderr, "%s: Couldn't write the raw BTF info to %s: %s\n", __func__, filename, strerror(errno));

	close(fd);

	if (err != raw_btf_size) {
		fprintf(stderr, "%s: Could only write %d bytes to %s of raw BTF info out of %d, aborting\n", __func__, err, filename, raw_btf_size);
		unlink(filename);
		err = -1;
	} else {
		/* go from bytes written == raw_btf_size to an indication that all went fine */
		err = 0;
	}

	return err;
}

static int btf__write_elf(struct btf *btf, const char *filename)
{
	GElf_Shdr shdr_mem, *shdr;
	GElf_Ehdr ehdr_mem, *ehdr;
	Elf_Data *btf_data = NULL;
	Elf_Scn *scn = NULL;
	Elf *elf = NULL;
	const void *raw_btf_data;
	uint32_t raw_btf_size;
	int fd, err = -1;
	size_t strndx;

	fd = open(filename, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s\n", filename);
		return -1;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		elf_error("Cannot set libelf version");
		goto out;
	}

	elf = elf_begin(fd, ELF_C_RDWR, NULL);
	if (elf == NULL) {
		elf_error("Cannot update ELF file");
		goto out;
	}

	elf_flagelf(elf, ELF_C_SET, ELF_F_DIRTY);

	ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (ehdr == NULL) {
		elf_error("elf_getehdr failed");
		goto out;
	}

	switch (ehdr_mem.e_ident[EI_DATA]) {
	case ELFDATA2LSB:
		btf__set_endianness(btf, BTF_LITTLE_ENDIAN);
		break;
	case ELFDATA2MSB:
		btf__set_endianness(btf, BTF_BIG_ENDIAN);
		break;
	default:
		fprintf(stderr, "%s: unknown ELF endianness.\n", __func__);
		goto out;
	}

	/*
	 * First we look if there was already a .BTF section to overwrite.
	 */

	elf_getshdrstrndx(elf, &strndx);
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		shdr = gelf_getshdr(scn, &shdr_mem);
		if (shdr == NULL)
			continue;
		char *secname = elf_strptr(elf, strndx, shdr->sh_name);
		if (strcmp(secname, ".BTF") == 0) {
			btf_data = elf_getdata(scn, btf_data);
			break;
		}
	}

	raw_btf_data = btf__get_raw_data(btf, &raw_btf_size);

	if (btf_data) {
		/* Existing .BTF section found */
		btf_data->d_buf = (void *)raw_btf_data;
		btf_data->d_size = raw_btf_size;
		elf_flagdata(btf_data, ELF_C_SET, ELF_F_DIRTY);

		if (elf_update(elf, ELF_C_NULL) >= 0 &&
		    elf_update(elf, ELF_C_WRITE) >= 0)
			err = 0;
		else
			elf_error("elf_update failed");
	} else {
		const char *llvm_objcopy;
		char tmp_fn[PATH_MAX];
		char cmd[PATH_MAX * 2];

		llvm_objcopy = getenv("LLVM_OBJCOPY");
		if (!llvm_objcopy)
			llvm_objcopy = "llvm-objcopy";

		/* Use objcopy to add a .BTF section */
		snprintf(tmp_fn, sizeof(tmp_fn), "%s.btf", filename);
		close(fd);
		fd = creat(tmp_fn, S_IRUSR | S_IWUSR);
		if (fd == -1) {
			fprintf(stderr, "%s: open(%s) failed!\n", __func__,
				tmp_fn);
			goto out;
		}

		if (write(fd, raw_btf_data, raw_btf_size) != raw_btf_size) {
			fprintf(stderr, "%s: write of %d bytes to '%s' failed: %d!\n",
				__func__, raw_btf_size, tmp_fn, errno);
			goto unlink;
		}

		snprintf(cmd, sizeof(cmd), "%s --add-section .BTF=%s %s",
			 llvm_objcopy, tmp_fn, filename);
		if (system(cmd)) {
			fprintf(stderr, "%s: failed to add .BTF section to '%s': %d!\n",
				__func__, filename, errno);
			goto unlink;
		}

		err = 0;
	unlink:
		unlink(tmp_fn);
	}

out:
	if (fd != -1)
		close(fd);
	if (elf)
		elf_end(elf);
	return err;
}

int btf__encode_in_elf(struct btf *btf, const char *filename, uint8_t flags)
{
	/* Empty file, nothing to do, so... done! */
	if (btf__get_nr_types(btf) == 0)
		return 0;

	if (btf__dedup(btf, NULL, NULL)) {
		fprintf(stderr, "%s: btf__dedup failed!\n", __func__);
		return -1;
	}

	return btf__write_elf(btf, filename);
}

int btf_encoder__encode(struct btf_encoder *encoder, const char *detached_filename)
{
	int err;

	if (gobuffer__size(&encoder->percpu_secinfo) != 0)
		btf__encode_datasec_type(encoder->btf, PERCPU_SECTION, &encoder->percpu_secinfo);

	if (detached_filename == NULL)
		err = btf__encode_in_elf(encoder->btf, encoder->filename, 0);
	else
		err = btf__encode_as_raw_file(encoder->btf, detached_filename);

	return err;
}

static int percpu_var_cmp(const void *_a, const void *_b)
{
	const struct var_info *a = _a;
	const struct var_info *b = _b;

	if (a->addr == b->addr)
		return 0;
	return a->addr < b->addr ? -1 : 1;
}

static bool btf_encoder__percpu_var_exists(struct btf_encoder *encoder, uint64_t addr, uint32_t *sz, const char **name)
{
	struct var_info key = { .addr = addr };
	const struct var_info *p = bsearch(&key, encoder->percpu.vars, encoder->percpu.var_cnt,
					   sizeof(encoder->percpu.vars[0]), percpu_var_cmp);
	if (!p)
		return false;

	*sz = p->sz;
	*name = p->name;
	return true;
}

static int btf_encoder__collect_percpu_var(struct btf_encoder *encoder, GElf_Sym *sym, size_t sym_sec_idx)
{
	const char *sym_name;
	uint64_t addr;
	uint32_t size;

	/* compare a symbol's shndx to determine if it's a percpu variable */
	if (sym_sec_idx != encoder->percpu.shndx)
		return 0;
	if (elf_sym__type(sym) != STT_OBJECT)
		return 0;

	addr = elf_sym__value(sym);

	size = elf_sym__size(sym);
	if (!size)
		return 0; /* ignore zero-sized symbols */

	sym_name = elf_sym__name(sym, encoder->symtab);
	if (!btf_name_valid(sym_name)) {
		dump_invalid_symbol("Found symbol of invalid name when encoding btf",
				    sym_name, encoder->verbose, encoder->force);
		if (encoder->force)
			return 0;
		return -1;
	}

	if (encoder->verbose)
		printf("Found per-CPU symbol '%s' at address 0x%" PRIx64 "\n", sym_name, addr);

	if (encoder->percpu.var_cnt == MAX_PERCPU_VAR_CNT) {
		fprintf(stderr, "Reached the limit of per-CPU variables: %d\n",
			MAX_PERCPU_VAR_CNT);
		return -1;
	}
	encoder->percpu.vars[encoder->percpu.var_cnt].addr = addr;
	encoder->percpu.vars[encoder->percpu.var_cnt].sz = size;
	encoder->percpu.vars[encoder->percpu.var_cnt].name = sym_name;
	encoder->percpu.var_cnt++;

	return 0;
}

static int btf_encoder__collect_symbols(struct btf_encoder *encoder, bool collect_percpu_vars)
{
	Elf32_Word sym_sec_idx;
	uint32_t core_id;
	GElf_Sym sym;

	/* cache variables' addresses, preparing for searching in symtab. */
	encoder->percpu.var_cnt = 0;

	/* search within symtab for percpu variables */
	elf_symtab__for_each_symbol_index(encoder->symtab, core_id, sym, sym_sec_idx) {
		if (collect_percpu_vars && btf_encoder__collect_percpu_var(encoder, &sym, sym_sec_idx))
			return -1;
		if (btf_encoder__collect_function(encoder, &sym))
			return -1;
	}

	if (collect_percpu_vars) {
		if (encoder->percpu.var_cnt)
			qsort(encoder->percpu.vars, encoder->percpu.var_cnt, sizeof(encoder->percpu.vars[0]), percpu_var_cmp);

		if (encoder->verbose)
			printf("Found %d per-CPU variables!\n", encoder->percpu.var_cnt);
	}

	if (encoder->functions.cnt) {
		qsort(encoder->functions.entries, encoder->functions.cnt, sizeof(encoder->functions.entries[0]),
		      functions_cmp);
		if (encoder->verbose)
			printf("Found %d functions!\n", encoder->functions.cnt);
	}

	return 0;
}

static bool has_arg_names(struct cu *cu, struct ftype *ftype)
{
	struct parameter *param;
	const char *name;

	ftype__for_each_parameter(ftype, param) {
		name = dwarves__active_loader->strings__ptr(cu, param->name);
		if (name == NULL)
			return false;
	}
	return true;
}

struct btf_encoder *btf_encoder__new(struct cu *cu, struct btf *base_btf, bool skip_encoding_vars, bool force, bool verbose)
{
	struct btf_encoder *encoder = zalloc(sizeof(*encoder));

	if (encoder) {
		encoder->filename = strdup(cu->filename);
		if (encoder->filename == NULL)
			goto out_delete;

		encoder->btf = btf__new_empty_split(base_btf);
		if (encoder->btf == NULL)
			goto out_delete;

		encoder->force		 = force;
		encoder->verbose	 = verbose;
		encoder->has_index_type  = false;
		encoder->need_index_type = false;
		encoder->array_index_id  = 0;

		if (gelf_getehdr(cu->elf, &encoder->ehdr) == NULL) {
			if (encoder->verbose)
				elf_error("cannot get ELF header");
			goto out_delete;
		}

		switch (encoder->ehdr.e_ident[EI_DATA]) {
		case ELFDATA2LSB:
			btf__set_endianness(encoder->btf, BTF_LITTLE_ENDIAN);
			break;
		case ELFDATA2MSB:
			btf__set_endianness(encoder->btf, BTF_BIG_ENDIAN);
			break;
		default:
			fprintf(stderr, "%s: unknown ELF endianness.\n", __func__);
			goto out_delete;
		}

		encoder->symtab = elf_symtab__new(NULL, cu->elf, &encoder->ehdr);
		if (!encoder->symtab) {
			if (encoder->verbose)
				printf("%s: '%s' doesn't have symtab.\n", __func__, encoder->filename);
			goto out;
		}

		/* find percpu section's shndx */

		GElf_Shdr shdr;
		Elf_Scn *sec = elf_section_by_name(cu->elf, &encoder->ehdr, &shdr, PERCPU_SECTION, NULL);

		if (!sec) {
			if (encoder->verbose)
				printf("%s: '%s' doesn't have '%s' section\n", __func__, encoder->filename, PERCPU_SECTION);
		} else {
			encoder->percpu.shndx	  = elf_ndxscn(sec);
			encoder->percpu.base_addr = shdr.sh_addr;
			encoder->percpu.sec_sz	  = shdr.sh_size;
		}

		if (btf_encoder__collect_symbols(encoder, !skip_encoding_vars))
			goto out_delete;

		if (encoder->verbose)
			printf("File %s:\n", encoder->filename);
	}
out:
	return encoder;

out_delete:
	btf_encoder__delete(encoder);
	return NULL;
}

void btf_encoder__delete(struct btf_encoder *encoder)
{
	if (encoder == NULL)
		return;

	__gobuffer__delete(&encoder->percpu_secinfo);
	zfree(&encoder->filename);
	btf__free(encoder->btf);
	encoder->btf = NULL;
	elf_symtab__delete(encoder->symtab);

	encoder->functions.allocated = encoder->functions.cnt = 0;
	free(encoder->functions.entries);
	encoder->functions.entries = NULL;

	free(encoder);
}

int btf_encoder__encode_cu(struct btf_encoder *encoder, struct cu *cu, bool skip_encoding_vars)
{
	uint32_t type_id_off = btf__get_nr_types(encoder->btf);
	uint32_t core_id;
	struct variable *var;
	struct function *fn;
	struct tag *pos;
	int err = 0;


	if (!encoder->has_index_type) {
		/* cu__find_base_type_by_name() takes "type_id_t *id" */
		type_id_t id;
		if (cu__find_base_type_by_name(cu, "int", &id)) {
			encoder->has_index_type = true;
			encoder->array_index_id = type_id_off + id;
		} else {
			encoder->has_index_type = false;
			encoder->array_index_id = type_id_off + cu->types_table.nr_entries;
		}
	}

	cu__for_each_type(cu, core_id, pos) {
		int32_t btf_type_id = btf_encoder__encode_tag(encoder, cu, pos, core_id, type_id_off);

		if (btf_type_id < 0 ||
		    tag__check_id_drift(pos, core_id, btf_type_id, type_id_off)) {
			err = -1;
			goto out;
		}
	}

	if (encoder->need_index_type && !encoder->has_index_type) {
		struct base_type bt = {};

		bt.name = 0;
		bt.bit_size = 32;
		btf_encoder__add_base_type(encoder, &bt, "__ARRAY_SIZE_TYPE__");
		encoder->has_index_type = true;
	}

	cu__for_each_function(cu, core_id, fn) {
		int btf_fnproto_id, btf_fn_id;
		const char *name;

		/*
		 * Skip functions that:
		 *   - are marked as declarations
		 *   - do not have full argument names
		 *   - are not in ftrace list (if it's available)
		 *   - are not external (in case ftrace filter is not available)
		 */
		if (fn->declaration)
			continue;
		if (!has_arg_names(cu, &fn->proto))
			continue;
		if (encoder->functions.cnt) {
			struct elf_function *func;
			const char *name;

			name = function__name(fn, cu);
			if (!name)
				continue;

			func = btf_encoder__find_function(encoder, name);
			if (!func || func->generated)
				continue;
			func->generated = true;
		} else {
			if (!fn->external)
				continue;
		}

		btf_fnproto_id = btf__encode_func_proto(encoder->btf, cu, &fn->proto, type_id_off);
		name = dwarves__active_loader->strings__ptr(cu, fn->name);
		btf_fn_id = btf_encoder__add_ref_type(encoder, BTF_KIND_FUNC, btf_fnproto_id, name, false);
		if (btf_fnproto_id < 0 || btf_fn_id < 0) {
			err = -1;
			printf("error: failed to encode function '%s'\n", function__name(fn, cu));
			goto out;
		}
	}

	if (skip_encoding_vars)
		goto out;

	if (encoder->percpu.shndx == 0 || !encoder->symtab)
		goto out;

	if (encoder->verbose)
		printf("search cu '%s' for percpu global variables.\n", cu->name);

	cu__for_each_variable(cu, core_id, pos) {
		uint32_t size, type, linkage;
		const char *name, *dwarf_name;
		const struct tag *tag;
		uint64_t addr;
		int id;

		var = tag__variable(pos);
		if (var->declaration && !var->spec)
			continue;
		/* percpu variables are allocated in global space */
		if (variable__scope(var) != VSCOPE_GLOBAL && !var->spec)
			continue;

		/* addr has to be recorded before we follow spec */
		addr = var->ip.addr;
		dwarf_name = variable__name(var, cu);

		/* DWARF takes into account .data..percpu section offset
		 * within its segment, which for vmlinux is 0, but for kernel
		 * modules is >0. ELF symbols, on the other hand, don't take
		 * into account these offsets (as they are relative to the
		 * section start), so to match DWARF and ELF symbols we need
		 * to negate the section base address here.
		 */
		if (addr < encoder->percpu.base_addr || addr >= encoder->percpu.base_addr + encoder->percpu.sec_sz)
			continue;
		addr -= encoder->percpu.base_addr;

		if (!btf_encoder__percpu_var_exists(encoder, addr, &size, &name))
			continue; /* not a per-CPU variable */

		/* A lot of "special" DWARF variables (e.g, __UNIQUE_ID___xxx)
		 * have addr == 0, which is the same as, say, valid
		 * fixed_percpu_data per-CPU variable. To distinguish between
		 * them, additionally compare DWARF and ELF symbol names. If
		 * DWARF doesn't provide proper name, pessimistically assume
		 * bad variable.
		 *
		 * Examples of such special variables are:
		 *
		 *  1. __ADDRESSABLE(sym), which are forcely emitted as symbols.
		 *  2. __UNIQUE_ID(prefix), which are introduced to generate unique ids.
		 *  3. __exitcall(fn), functions which are labeled as exit calls.
		 *
		 *  This is relevant only for vmlinux image, as for kernel
		 *  modules per-CPU data section has non-zero offset so all
		 *  per-CPU symbols have non-zero values.
		 */
		if (var->ip.addr == 0) {
			if (!dwarf_name || strcmp(dwarf_name, name))
				continue;
		}

		if (var->spec)
			var = var->spec;

		if (var->ip.tag.type == 0) {
			fprintf(stderr, "error: found variable '%s' in CU '%s' that has void type\n",
				name, cu->name);
			if (encoder->force)
				continue;
			err = -1;
			break;
		}

		tag = cu__type(cu, var->ip.tag.type);
		if (tag__size(tag, cu) == 0) {
			if (encoder->verbose)
				fprintf(stderr, "Ignoring zero-sized per-CPU variable '%s'...\n", dwarf_name ?: "<missing name>");
			continue;
		}

		type = var->ip.tag.type + type_id_off;
		linkage = var->external ? BTF_VAR_GLOBAL_ALLOCATED : BTF_VAR_STATIC;

		if (encoder->verbose) {
			printf("Variable '%s' from CU '%s' at address 0x%" PRIx64 " encoded\n",
			       name, cu->name, addr);
		}

		/* add a BTF_KIND_VAR in encoder->types */
		id = btf__encode_var_type(encoder->btf, type, name, linkage);
		if (id < 0) {
			err = -1;
			fprintf(stderr, "error: failed to encode variable '%s' at addr 0x%" PRIx64 "\n",
			        name, addr);
			break;
		}

		/*
		 * add a BTF_VAR_SECINFO in encoder->percpu_secinfo, which will be added into
		 * encoder->types later when we add BTF_VAR_DATASEC.
		 */
		id = btf__encode_var_secinfo(&encoder->percpu_secinfo, id, addr, size);
		if (id < 0) {
			err = -1;
			fprintf(stderr, "error: failed to encode section info for variable '%s' at addr 0x%" PRIx64 "\n",
			        name, addr);
			break;
		}
	}
out:
	return err;
}
