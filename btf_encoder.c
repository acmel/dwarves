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
#include "hash.h"
#include "elf_symtab.h"
#include "btf_encoder.h"

#include <ctype.h> /* for isalpha() and isalnum() */
#include <inttypes.h>

/*
 * This corresponds to the same macro defined in
 * include/linux/kallsyms.h
 */
#define KSYM_NAME_LEN 128

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

static void dump_invalid_symbol(const char *msg, const char *sym, const char *cu,
				int verbose, bool force)
{
	if (force) {
		if (verbose)
			fprintf(stderr, "PAHOLE: Warning: %s, ignored (sym: '%s', cu: '%s').\n",
				msg, sym, cu);
		return;
	}

	fprintf(stderr, "PAHOLE: Error: %s (sym: '%s', cu: '%s').\n", msg, sym, cu);
	fprintf(stderr, "PAHOLE: Error: Use '-j' or '--force' to ignore such symbols and force emit the btf.\n");
}

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

static int32_t structure_type__encode(struct btf_elf *btfe, struct tag *tag, uint32_t type_id_off)
{
	struct type *type = tag__type(tag);
	struct class_member *pos;
	bool kind_flag = false;
	int32_t type_id;
	uint8_t kind;

	kind = (tag->tag == DW_TAG_union_type) ?
		BTF_KIND_UNION : BTF_KIND_STRUCT;

	/* Although no_bitfield_type_recode has been set true
	 * in pahole.c if BTF encoding is requested, we still check
	 * the value here. So if no_bitfield_type_recode is set
	 * to false for whatever reason, we do not accidentally
	 * set kind_flag incorrectly.
	 */
	if (no_bitfield_type_recode) {
		/* kind_flag only set where there is a bitfield
		 * in the struct.
		 */
		type__for_each_data_member(type, pos) {
			if (pos->bitfield_size) {
				kind_flag = true;
				break;
			}
		}
	}

	type_id = btf_elf__add_struct(btfe, kind, type->namespace.name, kind_flag, type->size, type->nr_members);
	if (type_id < 0)
		return type_id;

	type__for_each_data_member(type, pos) {
		/*
		 * dwarf_loader uses DWARF's recommended bit offset addressing
		 * scheme, which conforms to BTF requirement, so no conversion
		 * is required.
		 */
		if (btf_elf__add_member(btfe, pos->name, type_id_off + pos->tag.type, kind_flag, pos->bitfield_size, pos->bit_offset))
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

static int32_t enumeration_type__encode(struct btf_elf *btfe, struct tag *tag)
{
	struct type *etype = tag__type(tag);
	struct enumerator *pos;
	int32_t type_id;

	type_id = btf_elf__add_enum(btfe, etype->namespace.name, etype->size, etype->nr_members);
	if (type_id < 0)
		return type_id;

	type__for_each_enumerator(etype, pos)
		if (btf_elf__add_enum_val(btfe, pos->name, pos->value))
			return -1;

	return type_id;
}

static int tag__encode_btf(struct tag *tag, uint32_t core_id, struct btf_elf *btfe,
			   uint32_t array_index_id, uint32_t type_id_off)
{
	/* single out type 0 as it represents special type "void" */
	uint32_t ref_type_id = tag->type == 0 ? 0 : type_id_off + tag->type;

	switch (tag->tag) {
	case DW_TAG_base_type:
		return btf_elf__add_base_type(btfe, tag__base_type(tag));
	case DW_TAG_const_type:
		return btf_elf__add_ref_type(btfe, BTF_KIND_CONST, ref_type_id, 0, false);
	case DW_TAG_pointer_type:
		return btf_elf__add_ref_type(btfe, BTF_KIND_PTR, ref_type_id, 0, false);
	case DW_TAG_restrict_type:
		return btf_elf__add_ref_type(btfe, BTF_KIND_RESTRICT, ref_type_id, 0, false);
	case DW_TAG_volatile_type:
		return btf_elf__add_ref_type(btfe, BTF_KIND_VOLATILE, ref_type_id, 0, false);
	case DW_TAG_typedef:
		return btf_elf__add_ref_type(btfe, BTF_KIND_TYPEDEF, ref_type_id, tag__namespace(tag)->name, false);
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
	case DW_TAG_class_type:
		if (tag__type(tag)->declaration)
			return btf_elf__add_ref_type(btfe, BTF_KIND_FWD, 0, tag__namespace(tag)->name, tag->tag == DW_TAG_union_type);
		else
			return structure_type__encode(btfe, tag, type_id_off);
	case DW_TAG_array_type:
		/* TODO: Encode one dimension at a time. */
		return btf_elf__add_array(btfe, ref_type_id, array_index_id, array_type__nelems(tag));
	case DW_TAG_enumeration_type:
		return enumeration_type__encode(btfe, tag);
	case DW_TAG_subroutine_type:
		return btf_elf__add_func_proto(btfe, tag__ftype(tag), type_id_off);
	default:
		fprintf(stderr, "Unsupported DW_TAG_%s(0x%x)\n",
			dwarf_tag_name(tag->tag), tag->tag);
		return -1;
	}
}

/*
 * FIXME: Its in the DWARF loader, we have to find a better handoff
 * mechanizm...
 */
extern struct strings *strings;

static struct btf_elf *btfe;
static uint32_t array_index_id;

int btf_encoder__encode()
{
	int err;

	err = btf_elf__encode(btfe, 0);
	btf_elf__delete(btfe);
	btfe = NULL;

	return err;
}

#define HASHADDR__BITS 8
#define HASHADDR__SIZE (1UL << HASHADDR__BITS)
#define hashaddr__fn(key) hash_64(key, HASHADDR__BITS)

static struct variable *hashaddr__find_variable(const struct hlist_head hashtable[],
						const uint64_t addr)
{
	struct variable *variable;
	struct hlist_node *pos;
	uint16_t bucket = hashaddr__fn(addr);
	const struct hlist_head *head = &hashtable[bucket];

	hlist_for_each_entry(variable, pos, head, tool_hnode) {
		if (variable->ip.addr == addr)
			return variable;
	}

	return NULL;
}

int cu__encode_btf(struct cu *cu, int verbose, bool force,
		   bool skip_encoding_vars)
{
	bool add_index_type = false;
	uint32_t type_id_off;
	uint32_t core_id;
	struct function *fn;
	struct tag *pos;
	int err = 0;
	struct hlist_head hash_addr[HASHADDR__SIZE];
	struct variable *var;
	bool has_global_var = false;
	GElf_Sym sym;

	if (btfe && strcmp(btfe->filename, cu->filename)) {
		err = btf_encoder__encode();
		if (err)
			goto out;

		/* Finished one file, add one empty line */
		if (verbose)
			printf("\n");
	}

	if (!btfe) {
		btfe = btf_elf__new(cu->filename, cu->elf);
		if (!btfe)
			return -1;
		btf_elf__set_strings(btfe, &strings->gb);

		/* cu__find_base_type_by_name() takes "type_id_t *id" */
		type_id_t id;
		if (!cu__find_base_type_by_name(cu, "int", &id)) {
			add_index_type = true;
			id = cu->types_table.nr_entries;
		}
		array_index_id = id;

		if (verbose)
			printf("File %s:\n", btfe->filename);
	}

	btf_elf__verbose = verbose;
	type_id_off = btfe->type_index;

	cu__for_each_type(cu, core_id, pos) {
		int32_t btf_type_id = tag__encode_btf(pos, core_id, btfe, array_index_id, type_id_off);

		if (btf_type_id < 0 ||
		    tag__check_id_drift(pos, core_id, btf_type_id, type_id_off)) {
			err = -1;
			goto out;
		}
	}

	if (add_index_type) {
		struct base_type bt = {};

		bt.name = 0;
		bt.bit_size = 32;
		btf_elf__add_base_type(btfe, &bt);
	}

	cu__for_each_function(cu, core_id, fn) {
		int btf_fnproto_id, btf_fn_id;

		if (fn->declaration || !fn->external)
			continue;

		btf_fnproto_id = btf_elf__add_func_proto(btfe, &fn->proto, type_id_off);
		btf_fn_id = btf_elf__add_ref_type(btfe, BTF_KIND_FUNC, btf_fnproto_id, fn->name, false);
		if (btf_fnproto_id < 0 || btf_fn_id < 0) {
			err = -1;
			printf("error: failed to encode function '%s'\n", function__name(fn, cu));
			goto out;
		}
	}

	if (skip_encoding_vars)
		goto out;

	if (btfe->percpu_shndx == 0 || !btfe->symtab)
		goto out;

	if (verbose)
		printf("search cu '%s' for percpu global variables.\n", cu->name);

	/* cache variables' addresses, preparing for searching in symtab. */
	for (core_id = 0; core_id < HASHADDR__SIZE; ++core_id)
		INIT_HLIST_HEAD(&hash_addr[core_id]);

	cu__for_each_variable(cu, core_id, pos) {
		struct hlist_head *head;

		var = tag__variable(pos);
		if (var->declaration)
			continue;
		/* percpu variables are allocated in global space */
		if (variable__scope(var) != VSCOPE_GLOBAL)
			continue;
		has_global_var = true;
		head = &hash_addr[hashaddr__fn(var->ip.addr)];
		hlist_add_head(&var->tool_hnode, head);
	}
	if (!has_global_var) {
		if (verbose)
			printf("cu has no global variable defined, skip.\n");
		goto out;
	}

	/* search within symtab for percpu variables */
	elf_symtab__for_each_symbol(btfe->symtab, core_id, sym) {
		uint32_t linkage, type, size, offset, name;
		int32_t btf_var_id, btf_var_secinfo_id;
		uint64_t addr;
		const char *sym_name;

		/* compare a symbol's shndx to determine if it's a percpu variable */
		if (elf_sym__section(&sym) != btfe->percpu_shndx)
			continue;
		if (elf_sym__type(&sym) != STT_OBJECT)
			continue;

		addr = elf_sym__value(&sym);
		/*
		 * Store only those symbols that have allocated space in the percpu section.
		 * This excludes the following three types of symbols:
		 *
		 *  1. __ADDRESSABLE(sym), which are forcely emitted as symbols.
		 *  2. __UNIQUE_ID(prefix), which are introduced to generate unique ids.
		 *  3. __exitcall(fn), functions which are labeled as exit calls.
		 *
		 * In addition, the variables defined using DEFINE_PERCPU_FIRST are
		 * also not included, which currently includes:
		 *
		 *  1. fixed_percpu_data
		 */
		if (!addr)
			continue;
		var = hashaddr__find_variable(hash_addr, addr);
		if (var == NULL)
			continue;

		sym_name = elf_sym__name(&sym, btfe->symtab);
		if (!btf_name_valid(sym_name)) {
			dump_invalid_symbol("Found symbol of invalid name when encoding btf",
					    sym_name, cu->name, verbose, force);
			if (force)
				continue;
			err = -1;
			break;
		}
		name = strings__add(strings, sym_name);
		type = var->ip.tag.type + type_id_off;
		size = elf_sym__size(&sym);
		if (!size) {
			dump_invalid_symbol("Found symbol of zero size when encoding btf",
					    sym_name, cu->name, verbose, force);
			if (force)
				continue;
			err = -1;
			break;
		}

		if (verbose)
			printf("symbol '%s' of address 0x%lx encoded\n",
			       sym_name, addr);

		/* add a BTF_KIND_VAR in btfe->types */
		linkage = var->external ? BTF_VAR_GLOBAL_ALLOCATED : BTF_VAR_STATIC;
		btf_var_id = btf_elf__add_var_type(btfe, type, name, linkage);
		if (btf_var_id < 0) {
			err = -1;
			printf("error: failed to encode variable '%s'\n", sym_name);
			break;
		}

		/*
		 * add a BTF_VAR_SECINFO in btfe->percpu_secinfo, which will be added into
		 * btfe->types later when we add BTF_VAR_DATASEC.
		 */
		type = btf_var_id;
		offset = addr - btfe->percpu_base_addr;
		btf_var_secinfo_id = btf_elf__add_var_secinfo(&btfe->percpu_secinfo,
							      type, offset, size);
		if (btf_var_secinfo_id < 0) {
			err = -1;
			printf("error: failed to encode var secinfo '%s'\n", sym_name);
			break;
		}
	}

out:
	if (err)
		btf_elf__delete(btfe);
	return err;
}
