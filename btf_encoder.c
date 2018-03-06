#include "dwarves.h"
#include "libbtf.h"
#include "btf.h"
#include "hash.h"
#include "elf_symtab.h"
#include "btf_encoder.h"

#include <inttypes.h>

static int tag__check_id_drift(const struct tag *tag,
			       uint32_t core_id, uint32_t btf_type_id)
{
	if (btf_type_id != core_id) {
		fprintf(stderr, "%s: %s id drift, core_id: %u, btf_type_id: %u\n",
			__func__, dwarf_tag_name(tag->tag),
			core_id, btf_type_id);
		return -1;
	}

	return 0;
}

static int32_t structure_type__encode(struct btf *btf, struct tag *tag)
{
	struct type *type = tag__type(tag);
	struct class_member *pos;
	int32_t type_id;
	uint8_t kind;

	kind = (tag->tag == DW_TAG_union_type) ?
		BTF_KIND_UNION : BTF_KIND_STRUCT;
	type_id = btf__add_struct(btf, kind, type->namespace.name,
				  type->size, type->nr_members);
	if (type_id < 0)
		return type_id;

	type__for_each_data_member(type, pos)
		if (btf__add_member(btf, pos->name, pos->tag.type,
				    pos->bit_offset))
			return -1;

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

static int32_t enumeration_type__encode(struct btf *btf, struct tag *tag)
{
	struct type *etype = tag__type(tag);
	struct enumerator *pos;
	int32_t type_id;

	type_id = btf__add_enum(btf, etype->namespace.name,
				etype->size, etype->nr_members);
	if (type_id < 0)
		return type_id;

	type__for_each_enumerator(etype, pos)
		if (btf__add_enum_val(btf, pos->name, pos->value))
			return -1;

	return type_id;
}

static int tag__encode_btf(struct tag *tag, uint32_t core_id, struct btf *btf,
			   uint32_t array_index_id)
{
	switch (tag->tag) {
	case DW_TAG_base_type:
		return btf__add_base_type(btf, tag__base_type(tag));
	case DW_TAG_const_type:
		return btf__add_ref_type(btf, BTF_KIND_CONST, tag->type, 0);
	case DW_TAG_pointer_type:
		return btf__add_ref_type(btf, BTF_KIND_PTR, tag->type, 0);
	case DW_TAG_restrict_type:
		return btf__add_ref_type(btf, BTF_KIND_RESTRICT, tag->type, 0);
	case DW_TAG_volatile_type:
		return btf__add_ref_type(btf, BTF_KIND_VOLATILE, tag->type, 0);
	case DW_TAG_typedef:
		return btf__add_ref_type(btf, BTF_KIND_TYPEDEF, tag->type,
					 tag__namespace(tag)->name);
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
	case DW_TAG_class_type:
		if (tag__type(tag)->declaration)
			return btf__add_ref_type(btf, BTF_KIND_FWD, 0,
						 tag__namespace(tag)->name);
		else
			return structure_type__encode(btf, tag);
	case DW_TAG_array_type:
		return btf__add_array(btf, tag->type, array_index_id,
				      /*TODO: Encode one dimension
				       *       at a time.
				       */
				      array_type__nelems(tag));
	case DW_TAG_enumeration_type:
		return enumeration_type__encode(btf, tag);
	case DW_TAG_subroutine_type:
		/* A dummy void * to avoid a shift in btf->type_index */
		btf_verbose_log("Filling unsupported DW_TAG_%s(0x%x) with void *\n",
				dwarf_tag_name(tag->tag), tag->tag);
		return btf__add_ref_type(btf, BTF_KIND_PTR, 0, 0);
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

int cu__encode_btf(struct cu *cu, int verbose)
{
	struct btf *btf = btf__new(cu->filename, cu->elf);
	struct tag *pos;
	uint32_t core_id, array_index_id;
	uint16_t id;
	int err;

	btf_verbose = verbose;

	if (btf == NULL)
		return -1;

	btf__set_strings(btf, &strings->gb);

	/* cu__find_base_type_by_name() takes "uint16_t *id" */
	if (!cu__find_base_type_by_name(cu, "int", &id))
		id = cu->types_table.nr_entries;
	array_index_id = id;

	cu__for_each_type(cu, core_id, pos) {
		int32_t btf_type_id = tag__encode_btf(pos, core_id, btf,
						      array_index_id);

		if (btf_type_id < 0 ||
		    tag__check_id_drift(pos, core_id, btf_type_id)) {
			err = -1;
			goto out;
		}

		id = btf_type_id;
	}

	if (array_index_id == cu->types_table.nr_entries) {
		struct base_type bt = {};

		bt.name = 0;
		bt.bit_size = 32;
		btf__add_base_type(btf, &bt);
	}

	err = btf__encode(btf, 0);

out:
	btf__free(btf);
	if (err)
		fprintf(stderr, "Failed to encode BTF\n");
	return err;
}
