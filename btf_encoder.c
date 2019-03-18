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

#include <inttypes.h>

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

int cu__encode_btf(struct cu *cu, int verbose)
{
	bool add_index_type = false;
	uint32_t type_id_off;
	uint32_t core_id;
	struct tag *pos;
	int err = 0;

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

out:
	if (err)
		btf_elf__delete(btfe);
	return err;
}
