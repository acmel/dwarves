/*
 * btf_loader.c
 *
 * Copyright (C) 2018 Arnaldo Carvalho de Melo <acme@kernel.org>
 *
 * Based on ctf_loader.c that, in turn, was based on ctfdump.c: CTF dumper.
 *
 * Copyright (C) 2008 David S. Miller <davem@davemloft.net>
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <malloc.h>
#include <string.h>
#include <limits.h>
#include <libgen.h>
#include <zlib.h>

#include <gelf.h>

#include "libbtf.h"
#include "lib/bpf/include/uapi/linux/btf.h"
#include "dutil.h"
#include "dwarves.h"

/*
 * FIXME: We should just get the table from the BTF ELF section
 * and use it directly
 */
extern struct strings *strings;

static void *tag__alloc(const size_t size)
{
	struct tag *tag = zalloc(size);

	if (tag != NULL)
		tag->top_level = 1;

	return tag;
}

static int btf_elf__load_ftype(struct btf_elf *btfe, struct ftype *proto, uint32_t tag,
			       const struct btf_type *tp, uint32_t id)
{
	const struct btf_param *param = btf_params(tp);
	int i, vlen = btf_vlen(tp);

	proto->tag.tag	= tag;
	proto->tag.type = tp->type;
	INIT_LIST_HEAD(&proto->parms);

	for (i = 0; i < vlen; ++i, param++) {
		if (param->type == 0)
			proto->unspec_parms = 1;
		else {
			struct parameter *p = tag__alloc(sizeof(*p));

			if (p == NULL)
				goto out_free_parameters;
			p->tag.tag  = DW_TAG_formal_parameter;
			p->tag.type = param->type;
			p->name	    = param->name_off;
			ftype__add_parameter(proto, p);
		}
	}

	cu__add_tag_with_id(btfe->priv, &proto->tag, id);

	return 0;
out_free_parameters:
	ftype__delete(proto, btfe->priv);
	return -ENOMEM;
}

static int create_new_function(struct btf_elf *btfe, const struct btf_type *tp, uint32_t id)
{
	struct function *func = tag__alloc(sizeof(*func));

	if (func == NULL)
		return -ENOMEM;

	// for BTF this is not really the type of the return of the function,
	// but the prototype, the return type is the one in type_id
	func->btf = 1;
	func->proto.tag.tag = DW_TAG_subprogram;
	func->proto.tag.type = tp->type;
	func->name = tp->name_off;
	INIT_LIST_HEAD(&func->lexblock.tags);
	cu__add_tag_with_id(btfe->priv, &func->proto.tag, id);

	return 0;
}

static struct base_type *base_type__new(strings_t name, uint32_t attrs,
					uint8_t float_type, size_t size)
{
        struct base_type *bt = tag__alloc(sizeof(*bt));

	if (bt != NULL) {
		bt->name = name;
		bt->bit_size = size;
		bt->is_signed = attrs & BTF_INT_SIGNED;
		bt->is_bool = attrs & BTF_INT_BOOL;
		bt->name_has_encoding = false;
		bt->float_type = float_type;
	}
	return bt;
}

static void type__init(struct type *type, uint32_t tag,
		       strings_t name, size_t size)
{
	__type__init(type);
	INIT_LIST_HEAD(&type->namespace.tags);
	type->size = size;
	type->namespace.tag.tag = tag;
	type->namespace.name = name;
	type->namespace.sname = 0;
}

static struct type *type__new(uint16_t tag, strings_t name, size_t size)
{
        struct type *type = tag__alloc(sizeof(*type));

	if (type != NULL)
		type__init(type, tag, name, size);

	return type;
}

static struct class *class__new(strings_t name, size_t size, bool is_union)
{
	struct class *class = tag__alloc(sizeof(*class));
	uint32_t tag = is_union ? DW_TAG_union_type : DW_TAG_structure_type;

	if (class != NULL) {
		type__init(&class->type, tag, name, size);
		INIT_LIST_HEAD(&class->vtable);
	}

	return class;
}

static struct variable *variable__new(strings_t name, uint32_t linkage)
{
	struct variable *var = tag__alloc(sizeof(*var));

	if (var != NULL) {
		var->external = linkage == BTF_VAR_GLOBAL_ALLOCATED;
		var->name = name;
		var->ip.tag.tag = DW_TAG_variable;
	}

	return var;
}

static int create_new_base_type(struct btf_elf *btfe, const struct btf_type *tp, uint32_t id)
{
	uint32_t attrs = btf_int_encoding(tp);
	strings_t name = tp->name_off;
	struct base_type *base = base_type__new(name, attrs, 0, btf_int_bits(tp));

	if (base == NULL)
		return -ENOMEM;

	base->tag.tag = DW_TAG_base_type;
	cu__add_tag_with_id(btfe->priv, &base->tag, id);

	return 0;
}

static int create_new_array(struct btf_elf *btfe, const struct btf_type *tp, uint32_t id)
{
	struct btf_array *ap = btf_array(tp);
	struct array_type *array = tag__alloc(sizeof(*array));

	if (array == NULL)
		return -ENOMEM;

	/* FIXME: where to get the number of dimensions?
	 * it it flattened? */
	array->dimensions = 1;
	array->nr_entries = malloc(sizeof(uint32_t));

	if (array->nr_entries == NULL) {
		free(array);
		return -ENOMEM;
	}

	array->nr_entries[0] = ap->nelems;
	array->tag.tag = DW_TAG_array_type;
	array->tag.type = ap->type;

	cu__add_tag_with_id(btfe->priv, &array->tag, id);

	return 0;
}

static int create_members(struct btf_elf *btfe, const struct btf_type *tp,
			  struct type *class)
{
	struct btf_member *mp = btf_members(tp);
	int i, vlen = btf_vlen(tp);

	for (i = 0; i < vlen; i++) {
		struct class_member *member = zalloc(sizeof(*member));

		if (member == NULL)
			return -ENOMEM;

		member->tag.tag    = DW_TAG_member;
		member->tag.type   = mp[i].type;
		member->name	   = mp[i].name_off;
		member->bit_offset = btf_member_bit_offset(tp, i);
		member->bitfield_size = btf_member_bitfield_size(tp, i);
		member->byte_offset = member->bit_offset / 8;
		/* sizes and offsets will be corrected at class__fixup_btf_bitfields */
		type__add_member(class, member);
	}

	return 0;
}

static int create_new_class(struct btf_elf *btfe, const struct btf_type *tp, uint32_t id)
{
	struct class *class = class__new(tp->name_off, tp->size, false);
	int member_size = create_members(btfe, tp, &class->type);

	if (member_size < 0)
		goto out_free;

	cu__add_tag_with_id(btfe->priv, &class->type.namespace.tag, id);

	return 0;
out_free:
	class__delete(class, btfe->priv);
	return -ENOMEM;
}

static int create_new_union(struct btf_elf *btfe, const struct btf_type *tp, uint32_t id)
{
	struct type *un = type__new(DW_TAG_union_type, tp->name_off, tp->size);
	int member_size = create_members(btfe, tp, un);

	if (member_size < 0)
		goto out_free;

	cu__add_tag_with_id(btfe->priv, &un->namespace.tag, id);

	return 0;
out_free:
	type__delete(un, btfe->priv);
	return -ENOMEM;
}

static struct enumerator *enumerator__new(strings_t name, uint32_t value)
{
	struct enumerator *en = tag__alloc(sizeof(*en));

	if (en != NULL) {
		en->name = name;
		en->value = value;
		en->tag.tag = DW_TAG_enumerator;
	}

	return en;
}

static int create_new_enumeration(struct btf_elf *btfe, const struct btf_type *tp, uint32_t id)
{
	struct btf_enum *ep = btf_enum(tp);
	uint16_t i, vlen = btf_vlen(tp);
	struct type *enumeration = type__new(DW_TAG_enumeration_type,
					     tp->name_off,
					     tp->size ? tp->size * 8 : (sizeof(int) * 8));

	if (enumeration == NULL)
		return -ENOMEM;

	for (i = 0; i < vlen; i++) {
		strings_t name = ep[i].name_off;
		uint32_t value = ep[i].val;
		struct enumerator *enumerator = enumerator__new(name, value);

		if (enumerator == NULL)
			goto out_free;

		enumeration__add(enumeration, enumerator);
	}

	cu__add_tag_with_id(btfe->priv, &enumeration->namespace.tag, id);

	return 0;
out_free:
	enumeration__delete(enumeration, btfe->priv);
	return -ENOMEM;
}

static int create_new_subroutine_type(struct btf_elf *btfe, const struct btf_type *tp, uint32_t id)
{
	struct ftype *proto = tag__alloc(sizeof(*proto));

	if (proto == NULL)
		return -ENOMEM;

	return btf_elf__load_ftype(btfe, proto, DW_TAG_subroutine_type, tp, id);
}

static int create_new_forward_decl(struct btf_elf *btfe, const struct btf_type *tp, uint32_t id)
{
	struct class *fwd = class__new(tp->name_off, 0, btf_kflag(tp));

	if (fwd == NULL)
		return -ENOMEM;
	fwd->type.declaration = 1;
	cu__add_tag_with_id(btfe->priv, &fwd->type.namespace.tag, id);
	return 0;
}

static int create_new_typedef(struct btf_elf *btfe, const struct btf_type *tp, uint32_t id)
{
	struct type *type = type__new(DW_TAG_typedef, tp->name_off, 0);

	if (type == NULL)
		return -ENOMEM;

	type->namespace.tag.type = tp->type;
	cu__add_tag_with_id(btfe->priv, &type->namespace.tag, id);

	return 0;
}

static int create_new_variable(struct btf_elf *btfe, const struct btf_type *tp, uint32_t id)
{
	struct btf_var *bvar = btf_var(tp);
	struct variable *var = variable__new(tp->name_off, bvar->linkage);

	if (var == NULL)
		return -ENOMEM;

	var->ip.tag.type = tp->type;
	cu__add_tag_with_id(btfe->priv, &var->ip.tag, id);
	return 0;
}

static int create_new_datasec(struct btf_elf *btfe, const struct btf_type *tp, uint32_t id)
{
	//strings_t name = btf_elf__get32(btfe, &tp->name_off);

	//cu__add_tag_with_id(btfe->priv, &datasec->tag, id);

	/*
	 * FIXME: this will not be used to reconstruct some original C code,
	 * its about runtime placement of variables so just ignore this for now
	 */
	return 0;
}

static int create_new_tag(struct btf_elf *btfe, int type, const struct btf_type *tp, uint32_t id)
{
	struct tag *tag = zalloc(sizeof(*tag));

	if (tag == NULL)
		return -ENOMEM;

	switch (type) {
	case BTF_KIND_CONST:	tag->tag = DW_TAG_const_type;	 break;
	case BTF_KIND_PTR:	tag->tag = DW_TAG_pointer_type;  break;
	case BTF_KIND_RESTRICT:	tag->tag = DW_TAG_restrict_type; break;
	case BTF_KIND_VOLATILE:	tag->tag = DW_TAG_volatile_type; break;
	default:
		free(tag);
		printf("%s: Unknown type %d\n\n", __func__, type);
		return 0;
	}

	tag->type = tp->type;
	cu__add_tag_with_id(btfe->priv, tag, id);

	return 0;
}

static int btf_elf__load_types(struct btf_elf *btfe)
{
	uint32_t type_index;
	int err;

	for (type_index = 1; type_index <= btf__get_nr_types(btfe->btf); type_index++) {
		const struct btf_type *type_ptr = btf__type_by_id(btfe->btf, type_index);
		uint32_t type = btf_kind(type_ptr);

		switch (type) {
		case BTF_KIND_INT:
			err = create_new_base_type(btfe, type_ptr, type_index);
			break;
		case BTF_KIND_ARRAY:
			err = create_new_array(btfe, type_ptr, type_index);
			break;
		case BTF_KIND_STRUCT:
			err = create_new_class(btfe, type_ptr, type_index);
			break;
		case BTF_KIND_UNION:
			err = create_new_union(btfe, type_ptr, type_index);
			break;
		case BTF_KIND_ENUM:
			err = create_new_enumeration(btfe, type_ptr, type_index);
			break;
		case BTF_KIND_FWD:
			err = create_new_forward_decl(btfe, type_ptr, type_index);
			break;
		case BTF_KIND_TYPEDEF:
			err = create_new_typedef(btfe, type_ptr, type_index);
			break;
		case BTF_KIND_VAR:
			err = create_new_variable(btfe, type_ptr, type_index);
			break;
		case BTF_KIND_DATASEC:
			err = create_new_datasec(btfe, type_ptr, type_index);
			break;
		case BTF_KIND_VOLATILE:
		case BTF_KIND_PTR:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
			err = create_new_tag(btfe, type, type_ptr, type_index);
			break;
		case BTF_KIND_UNKN:
			cu__table_nullify_type_entry(btfe->priv, type_index);
			fprintf(stderr, "BTF: idx: %d, Unknown kind %d\n", type_index, type);
			fflush(stderr);
			err = 0;
			break;
		case BTF_KIND_FUNC_PROTO:
			err = create_new_subroutine_type(btfe, type_ptr, type_index);
			break;
		case BTF_KIND_FUNC:
			// BTF_KIND_FUNC corresponding to a defined subprogram.
			err = create_new_function(btfe, type_ptr, type_index);
			break;
		default:
			fprintf(stderr, "BTF: idx: %d, Unknown kind %d\n", type_index, type);
			fflush(stderr);
			err = 0;
			break;
		}

		if (err < 0)
			return err;
	}
	return 0;
}

static int btf_elf__load_sections(struct btf_elf *btfe)
{
	return btf_elf__load_types(btfe);
}

static int class__fixup_btf_bitfields(struct tag *tag, struct cu *cu, struct btf_elf *btfe)
{
	struct class_member *pos;
	struct type *tag_type = tag__type(tag);

	type__for_each_data_member(tag_type, pos) {
		struct tag *type = tag__strip_typedefs_and_modifiers(&pos->tag, cu);

		if (type == NULL) /* FIXME: C++ BTF... */
			continue;

		pos->bitfield_offset = 0;
		pos->byte_size = tag__size(type, cu);
		pos->bit_size = pos->byte_size * 8;

		/* bitfield fixup is needed for enums and base types only */
		if (type->tag != DW_TAG_base_type && type->tag != DW_TAG_enumeration_type)
			continue;

		/* if BTF data is incorrect and has size == 0, skip field,
		 * instead of crashing */
		if (pos->byte_size == 0) {
			continue;
		}

		if (pos->bitfield_size) {
			/* bitfields seem to be always aligned, no matter the packing */
			pos->byte_offset = pos->bit_offset / pos->bit_size * pos->bit_size / 8;
			pos->bitfield_offset = pos->bit_offset - pos->byte_offset * 8;
			/* re-adjust bitfield offset if it is negative */
			if (pos->bitfield_offset < 0) {
				pos->bitfield_offset += pos->bit_size;
				pos->byte_offset -= pos->byte_size;
				pos->bit_offset = pos->byte_offset * 8 + pos->bitfield_offset;
			}
		} else {
			pos->byte_offset = pos->bit_offset / 8;
		}
	}

	return 0;
}

static int cu__fixup_btf_bitfields(struct cu *cu, struct btf_elf *btfe)
{
	int err = 0;
	struct tag *pos;

	list_for_each_entry(pos, &cu->tags, node)
		if (tag__is_struct(pos) || tag__is_union(pos)) {
			err = class__fixup_btf_bitfields(pos, cu, btfe);
			if (err)
				break;
		}

	return err;
}

static void btf_elf__cu_delete(struct cu *cu)
{
	btf_elf__delete(cu->priv);
	cu->priv = NULL;
}

static const char *btf_elf__strings_ptr(const struct cu *cu, strings_t s)
{
	return btf_elf__string(cu->priv, s);
}

struct debug_fmt_ops btf_elf__ops;

int btf_elf__load_file(struct cus *cus, struct conf_load *conf, const char *filename)
{
	int err;
	struct btf_elf *btfe = btf_elf__new(filename, NULL);

	if (btfe == NULL)
		return -1;

	struct cu *cu = cu__new(filename, btfe->wordsize, NULL, 0, filename);
	if (cu == NULL)
		return -1;

	cu->language = LANG_C;
	cu->uses_global_strings = false;
	cu->little_endian = !btfe->is_big_endian;
	cu->dfops = &btf_elf__ops;
	cu->priv = btfe;
	btfe->priv = cu;
	if (btf_elf__load(btfe) != 0)
		return -1;

	err = btf_elf__load_sections(btfe);

	if (err != 0) {
		cu__delete(cu);
		return err;
	}

	err = cu__fixup_btf_bitfields(cu, btfe);
	/*
	 * The app stole this cu, possibly deleting it,
	 * so forget about it
	 */
	if (conf && conf->steal && conf->steal(cu, conf))
		return 0;

	cus__add(cus, cu);
	return err;
}

struct debug_fmt_ops btf_elf__ops = {
	.name		= "btf",
	.load_file	= btf_elf__load_file,
	.strings__ptr	= btf_elf__strings_ptr,
	.cu__delete	= btf_elf__cu_delete,
};
