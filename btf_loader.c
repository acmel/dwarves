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
#include <linux/btf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <zlib.h>

#include <gelf.h>

#include "dutil.h"
#include "dwarves.h"

static const char *cu__btf_str(struct cu *cu, uint32_t offset)
{
	return offset ? btf__str_by_offset(cu->priv, offset) : NULL;
}

static void *tag__alloc(const size_t size)
{
	struct tag *tag = zalloc(size);

	if (tag != NULL)
		tag->top_level = 1;

	return tag;
}

static int cu__load_ftype(struct cu *cu, struct ftype *proto, uint32_t tag, const struct btf_type *tp, uint32_t id)
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
			p->name	    = cu__btf_str(cu, param->name_off);
			ftype__add_parameter(proto, p);
		}
	}

	cu__add_tag_with_id(cu, &proto->tag, id);

	return 0;
out_free_parameters:
	ftype__delete(proto);
	return -ENOMEM;
}

static int create_new_function(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct function *func = tag__alloc(sizeof(*func));

	if (func == NULL)
		return -ENOMEM;

	// for BTF this is not really the type of the return of the function,
	// but the prototype, the return type is the one in type_id
	func->btf = 1;
	func->proto.tag.tag = DW_TAG_subprogram;
	func->proto.tag.type = tp->type;
	func->name = cu__btf_str(cu, tp->name_off);
	INIT_LIST_HEAD(&func->lexblock.tags);
	cu__add_tag_with_id(cu, &func->proto.tag, id);

	return 0;
}

static struct base_type *base_type__new(const char *name, uint32_t attrs,
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

static void type__init(struct type *type, uint32_t tag, const char *name, size_t size)
{
	__type__init(type);
	INIT_LIST_HEAD(&type->namespace.tags);
	type->size = size;
	type->namespace.tag.tag = tag;
	type->namespace.name = name;
}

static struct type *type__new(uint16_t tag, const char *name, size_t size)
{
        struct type *type = tag__alloc(sizeof(*type));

	if (type != NULL)
		type__init(type, tag, name, size);

	return type;
}

static struct class *class__new(const char *name, size_t size, bool is_union)
{
	struct class *class = tag__alloc(sizeof(*class));
	uint32_t tag = is_union ? DW_TAG_union_type : DW_TAG_structure_type;

	if (class != NULL) {
		type__init(&class->type, tag, name, size);
		INIT_LIST_HEAD(&class->vtable);
	}

	return class;
}

static struct variable *variable__new(const char *name, uint32_t linkage)
{
	struct variable *var = tag__alloc(sizeof(*var));

	if (var != NULL) {
		var->external = linkage == BTF_VAR_GLOBAL_ALLOCATED;
		var->name = name;
		var->ip.tag.tag = DW_TAG_variable;
	}

	return var;
}

static int create_new_int_type(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	uint32_t attrs = btf_int_encoding(tp);
	const char *name = cu__btf_str(cu, tp->name_off);
	struct base_type *base = base_type__new(name, attrs, 0, btf_int_bits(tp));

	if (base == NULL)
		return -ENOMEM;

	base->tag.tag = DW_TAG_base_type;
	cu__add_tag_with_id(cu, &base->tag, id);

	return 0;
}

static int create_new_float_type(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	const char *name = cu__btf_str(cu, tp->name_off);
	struct base_type *base = base_type__new(name, 0, BT_FP_SINGLE, tp->size * 8);

	if (base == NULL)
		return -ENOMEM;

	base->tag.tag = DW_TAG_base_type;
	cu__add_tag_with_id(cu, &base->tag, id);

	return 0;
}

static int create_new_array(struct cu *cu, const struct btf_type *tp, uint32_t id)
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

	cu__add_tag_with_id(cu, &array->tag, id);

	return 0;
}

static int create_members(struct cu *cu, const struct btf_type *tp, struct type *class)
{
	struct btf_member *mp = btf_members(tp);
	int i, vlen = btf_vlen(tp);

	for (i = 0; i < vlen; i++) {
		struct class_member *member = zalloc(sizeof(*member));

		if (member == NULL)
			return -ENOMEM;

		member->tag.tag    = DW_TAG_member;
		member->tag.type   = mp[i].type;
		member->name	   = cu__btf_str(cu, mp[i].name_off);
		member->bit_offset = btf_member_bit_offset(tp, i);
		member->bitfield_size = btf_member_bitfield_size(tp, i);
		member->byte_offset = member->bit_offset / 8;
		/* sizes and offsets will be corrected at class__fixup_btf_bitfields */
		type__add_member(class, member);
	}

	return 0;
}

static int create_new_class(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct class *class = class__new(cu__btf_str(cu, tp->name_off), tp->size, false);
	int member_size = create_members(cu, tp, &class->type);

	if (member_size < 0)
		goto out_free;

	cu__add_tag_with_id(cu, &class->type.namespace.tag, id);

	return 0;
out_free:
	class__delete(class);
	return -ENOMEM;
}

static int create_new_union(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct type *un = type__new(DW_TAG_union_type, cu__btf_str(cu, tp->name_off), tp->size);
	int member_size = create_members(cu, tp, un);

	if (member_size < 0)
		goto out_free;

	cu__add_tag_with_id(cu, &un->namespace.tag, id);

	return 0;
out_free:
	type__delete(un);
	return -ENOMEM;
}

static struct enumerator *enumerator__new(const char *name, uint32_t value)
{
	struct enumerator *en = tag__alloc(sizeof(*en));

	if (en != NULL) {
		en->name = name;
		en->value = value;
		en->tag.tag = DW_TAG_enumerator;
	}

	return en;
}

static int create_new_enumeration(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct btf_enum *ep = btf_enum(tp);
	uint16_t i, vlen = btf_vlen(tp);
	struct type *enumeration = type__new(DW_TAG_enumeration_type,
					     cu__btf_str(cu, tp->name_off),
					     tp->size ? tp->size * 8 : (sizeof(int) * 8));

	if (enumeration == NULL)
		return -ENOMEM;

	for (i = 0; i < vlen; i++) {
		const char *name = cu__btf_str(cu, ep[i].name_off);
		uint32_t value = ep[i].val;
		struct enumerator *enumerator = enumerator__new(name, value);

		if (enumerator == NULL)
			goto out_free;

		enumeration__add(enumeration, enumerator);
	}

	cu__add_tag_with_id(cu, &enumeration->namespace.tag, id);

	return 0;
out_free:
	enumeration__delete(enumeration);
	return -ENOMEM;
}

static int create_new_subroutine_type(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct ftype *proto = tag__alloc(sizeof(*proto));

	if (proto == NULL)
		return -ENOMEM;

	return cu__load_ftype(cu, proto, DW_TAG_subroutine_type, tp, id);
}

static int create_new_forward_decl(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct class *fwd = class__new(cu__btf_str(cu, tp->name_off), 0, btf_kflag(tp));

	if (fwd == NULL)
		return -ENOMEM;
	fwd->type.declaration = 1;
	cu__add_tag_with_id(cu, &fwd->type.namespace.tag, id);
	return 0;
}

static int create_new_typedef(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct type *type = type__new(DW_TAG_typedef, cu__btf_str(cu, tp->name_off), 0);

	if (type == NULL)
		return -ENOMEM;

	type->namespace.tag.type = tp->type;
	cu__add_tag_with_id(cu, &type->namespace.tag, id);

	return 0;
}

static int create_new_variable(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct btf_var *bvar = btf_var(tp);
	struct variable *var = variable__new(cu__btf_str(cu, tp->name_off), bvar->linkage);

	if (var == NULL)
		return -ENOMEM;

	var->ip.tag.type = tp->type;
	cu__add_tag_with_id(cu, &var->ip.tag, id);
	return 0;
}

static int create_new_datasec(struct cu *cu __maybe_unused, const struct btf_type *tp __maybe_unused, uint32_t id __maybe_unused)
{
	//cu__add_tag_with_id(cu, &datasec->tag, id);

	/*
	 * FIXME: this will not be used to reconstruct some original C code,
	 * its about runtime placement of variables so just ignore this for now
	 */
	return 0;
}

static int create_new_tag(struct cu *cu, int type, const struct btf_type *tp, uint32_t id)
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
	cu__add_tag_with_id(cu, tag, id);

	return 0;
}

static int btf__load_types(struct btf *btf, struct cu *cu)
{
	uint32_t type_index;
	int err;

	for (type_index = 1; type_index <= btf__get_nr_types(btf); type_index++) {
		const struct btf_type *type_ptr = btf__type_by_id(btf, type_index);
		uint32_t type = btf_kind(type_ptr);

		switch (type) {
		case BTF_KIND_INT:
			err = create_new_int_type(cu, type_ptr, type_index);
			break;
		case BTF_KIND_ARRAY:
			err = create_new_array(cu, type_ptr, type_index);
			break;
		case BTF_KIND_STRUCT:
			err = create_new_class(cu, type_ptr, type_index);
			break;
		case BTF_KIND_UNION:
			err = create_new_union(cu, type_ptr, type_index);
			break;
		case BTF_KIND_ENUM:
			err = create_new_enumeration(cu, type_ptr, type_index);
			break;
		case BTF_KIND_FWD:
			err = create_new_forward_decl(cu, type_ptr, type_index);
			break;
		case BTF_KIND_TYPEDEF:
			err = create_new_typedef(cu, type_ptr, type_index);
			break;
		case BTF_KIND_VAR:
			err = create_new_variable(cu, type_ptr, type_index);
			break;
		case BTF_KIND_DATASEC:
			err = create_new_datasec(cu, type_ptr, type_index);
			break;
		case BTF_KIND_VOLATILE:
		case BTF_KIND_PTR:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
			err = create_new_tag(cu, type, type_ptr, type_index);
			break;
		case BTF_KIND_UNKN:
			cu__table_nullify_type_entry(cu, type_index);
			fprintf(stderr, "BTF: idx: %d, Unknown kind %d\n", type_index, type);
			fflush(stderr);
			err = 0;
			break;
		case BTF_KIND_FUNC_PROTO:
			err = create_new_subroutine_type(cu, type_ptr, type_index);
			break;
		case BTF_KIND_FUNC:
			// BTF_KIND_FUNC corresponding to a defined subprogram.
			err = create_new_function(cu, type_ptr, type_index);
			break;
		case BTF_KIND_FLOAT:
			err = create_new_float_type(cu, type_ptr, type_index);
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

static int btf__load_sections(struct btf *btf, struct cu *cu)
{
	return btf__load_types(btf, cu);
}

static int class__fixup_btf_bitfields(struct tag *tag, struct cu *cu)
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

static int cu__fixup_btf_bitfields(struct cu *cu)
{
	int err = 0;
	struct tag *pos;

	list_for_each_entry(pos, &cu->tags, node)
		if (tag__is_struct(pos) || tag__is_union(pos)) {
			err = class__fixup_btf_bitfields(pos, cu);
			if (err)
				break;
		}

	return err;
}

static void btf__cu_delete(struct cu *cu)
{
	btf__free(cu->priv);
	cu->priv = NULL;
}

static int libbpf_log(enum libbpf_print_level level __maybe_unused, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

struct debug_fmt_ops btf__ops;

static int cus__load_btf(struct cus *cus, struct conf_load *conf, const char *filename)
{
	int err = -1;

	// Pass a zero for addr_size, we'll get it after we load via btf__pointer_size()
	struct cu *cu = cu__new(filename, 0, NULL, 0, filename, false);
	if (cu == NULL)
		return -1;

	cu->language = LANG_C;
	cu->uses_global_strings = false;
	cu->dfops = &btf__ops;

	libbpf_set_print(libbpf_log);

	struct btf *btf = btf__parse_split(filename, conf->base_btf);

	err = libbpf_get_error(btf);
	if (err)
		goto out_free;

	cu->priv = btf;
	cu->little_endian = btf__endianness(btf) == BTF_LITTLE_ENDIAN;
	cu->addr_size	  = btf__pointer_size(btf);

	err = btf__load_sections(btf, cu);
	if (err != 0)
		goto out_free;

	err = cu__fixup_btf_bitfields(cu);
	/*
	 * The app stole this cu, possibly deleting it,
	 * so forget about it
	 */
	if (conf && conf->steal && conf->steal(cu, conf))
		return 0;

	cus__add(cus, cu);
	return err;

out_free:
	cu__delete(cu); // will call btf__free(cu->priv);
	return err;
}

struct debug_fmt_ops btf__ops = {
	.name		= "btf",
	.load_file	= cus__load_btf,
	.cu__delete	= btf__cu_delete,
};
