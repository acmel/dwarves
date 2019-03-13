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
			       uint32_t type, uint16_t vlen, struct btf_param *args, uint32_t id)
{
	int i;

	proto->tag.tag	= tag;
	proto->tag.type = type;
	INIT_LIST_HEAD(&proto->parms);

	for (i = 0; i < vlen; ++i) {
		struct btf_param param = {
		       .name_off = btf_elf__get32(btfe, &args[i].name_off),
		       .type	 = btf_elf__get32(btfe, &args[i].type),
		};

		if (param.type == 0)
			proto->unspec_parms = 1;
		else {
			struct parameter *p = tag__alloc(sizeof(*p));

			if (p == NULL)
				goto out_free_parameters;
			p->tag.tag  = DW_TAG_formal_parameter;
			p->tag.type = param.type;
			p->name	    = param.name_off;
			ftype__add_parameter(proto, p);
		}
	}

	vlen *= sizeof(*args);
	cu__add_tag_with_id(btfe->priv, &proto->tag, id);

	return vlen;
out_free_parameters:
	ftype__delete(proto, btfe->priv);
	return -ENOMEM;
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
	INIT_LIST_HEAD(&type->node);
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

static struct class *class__new(strings_t name, size_t size)
{
	struct class *class = tag__alloc(sizeof(*class));

	if (class != NULL) {
		type__init(&class->type, DW_TAG_structure_type, name, size);
		INIT_LIST_HEAD(&class->vtable);
	}

	return class;
}

static int create_new_base_type(struct btf_elf *btfe, void *ptr, struct btf_type *tp, uint32_t id)
{
	uint32_t *enc = ptr;
	uint32_t eval = btf_elf__get32(btfe, enc);
	uint32_t attrs = BTF_INT_ENCODING(eval);
	strings_t name = btf_elf__get32(btfe, &tp->name_off);
	struct base_type *base = base_type__new(name, attrs, 0,
						BTF_INT_BITS(eval));
	if (base == NULL)
		return -ENOMEM;

	base->tag.tag = DW_TAG_base_type;
	cu__add_tag_with_id(btfe->priv, &base->tag, id);

	return sizeof(*enc);
}

static int create_new_array(struct btf_elf *btfe, void *ptr, uint32_t id)
{
	struct btf_array *ap = ptr;
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

	array->nr_entries[0] = btf_elf__get32(btfe, &ap->nelems);
	array->tag.tag = DW_TAG_array_type;
	array->tag.type = btf_elf__get32(btfe, &ap->type);

	cu__add_tag_with_id(btfe->priv, &array->tag, id);

	return sizeof(*ap);
}

static int create_members(struct btf_elf *btfe, void *ptr, int vlen, struct type *class,
			  bool kflag)
{
	struct btf_member *mp = ptr;
	int i;

	for (i = 0; i < vlen; i++) {
		struct class_member *member = zalloc(sizeof(*member));
		uint32_t offset;

		if (member == NULL)
			return -ENOMEM;

		member->tag.tag    = DW_TAG_member;
		member->tag.type   = btf_elf__get32(btfe, &mp[i].type);
		member->name	   = btf_elf__get32(btfe, &mp[i].name_off);
		offset = btf_elf__get32(btfe, &mp[i].offset);
		if (kflag) {
			member->bit_offset = BTF_MEMBER_BIT_OFFSET(offset);
			member->bitfield_size = BTF_MEMBER_BITFIELD_SIZE(offset);
		} else {
			member->bit_offset = offset;
			member->bitfield_size = 0;
		}
		member->byte_offset = member->bit_offset / 8;
		/* sizes and offsets will be corrected at class__fixup_btf_bitfields */
		type__add_member(class, member);
	}

	return sizeof(*mp);
}

static int create_new_class(struct btf_elf *btfe, void *ptr, int vlen,
			    struct btf_type *tp, uint64_t size, uint32_t id,
			    bool kflag)
{
	strings_t name = btf_elf__get32(btfe, &tp->name_off);
	struct class *class = class__new(name, size);
	int member_size = create_members(btfe, ptr, vlen, &class->type, kflag);

	if (member_size < 0)
		goto out_free;

	cu__add_tag_with_id(btfe->priv, &class->type.namespace.tag, id);

	return (vlen * member_size);
out_free:
	class__delete(class, btfe->priv);
	return -ENOMEM;
}

static int create_new_union(struct btf_elf *btfe, void *ptr,
			    int vlen, struct btf_type *tp,
			    uint64_t size, uint32_t id,
			    bool kflag)
{
	strings_t name = btf_elf__get32(btfe, &tp->name_off);
	struct type *un = type__new(DW_TAG_union_type, name, size);
	int member_size = create_members(btfe, ptr, vlen, un, kflag);

	if (member_size < 0)
		goto out_free;

	cu__add_tag_with_id(btfe->priv, &un->namespace.tag, id);

	return (vlen * member_size);
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

static int create_new_enumeration(struct btf_elf *btfe, void *ptr,
				  int vlen, struct btf_type *tp,
				  uint16_t size, uint32_t id)
{
	struct btf_enum *ep = ptr;
	uint16_t i;
	struct type *enumeration = type__new(DW_TAG_enumeration_type,
					     btf_elf__get32(btfe, &tp->name_off),
					     size ? size * 8 : (sizeof(int) * 8));

	if (enumeration == NULL)
		return -ENOMEM;

	for (i = 0; i < vlen; i++) {
		strings_t name = btf_elf__get32(btfe, &ep[i].name_off);
		uint32_t value = btf_elf__get32(btfe, &ep[i].val);
		struct enumerator *enumerator = enumerator__new(name, value);

		if (enumerator == NULL)
			goto out_free;

		enumeration__add(enumeration, enumerator);
	}

	cu__add_tag_with_id(btfe->priv, &enumeration->namespace.tag, id);

	return (vlen * sizeof(*ep));
out_free:
	enumeration__delete(enumeration, btfe->priv);
	return -ENOMEM;
}

static int create_new_subroutine_type(struct btf_elf *btfe, void *ptr,
				      int vlen, struct btf_type *tp,
				      uint32_t id)
{
	struct btf_param *args = ptr;
	unsigned int type = btf_elf__get32(btfe, &tp->type);
	struct ftype *proto = tag__alloc(sizeof(*proto));

	if (proto == NULL)
		return -ENOMEM;

	vlen = btf_elf__load_ftype(btfe, proto, DW_TAG_subroutine_type, type, vlen, args, id);
	return vlen < 0 ? -ENOMEM : vlen;
}

static int create_new_forward_decl(struct btf_elf *btfe, struct btf_type *tp,
				   uint64_t size, uint32_t id)
{
	strings_t name = btf_elf__get32(btfe, &tp->name_off);
	struct class *fwd = class__new(name, size);

	if (fwd == NULL)
		return -ENOMEM;
	fwd->type.declaration = 1;
	cu__add_tag_with_id(btfe->priv, &fwd->type.namespace.tag, id);
	return 0;
}

static int create_new_typedef(struct btf_elf *btfe, struct btf_type *tp, uint64_t size, uint32_t id)
{
	strings_t name = btf_elf__get32(btfe, &tp->name_off);
	unsigned int type_id = btf_elf__get32(btfe, &tp->type);
	struct type *type = type__new(DW_TAG_typedef, name, size);

	if (type == NULL)
		return -ENOMEM;

	type->namespace.tag.type = type_id;
	cu__add_tag_with_id(btfe->priv, &type->namespace.tag, id);

	return 0;
}

static int create_new_tag(struct btf_elf *btfe, int type, struct btf_type *tp, uint32_t id)
{
	unsigned int type_id = btf_elf__get32(btfe, &tp->type);
	struct tag *tag = zalloc(sizeof(*tag));

	if (tag == NULL)
		return -ENOMEM;

	switch (type) {
	case BTF_KIND_CONST:	tag->tag = DW_TAG_const_type;	 break;
	case BTF_KIND_PTR:	tag->tag = DW_TAG_pointer_type;  break;
	case BTF_KIND_RESTRICT:	tag->tag = DW_TAG_restrict_type; break;
	case BTF_KIND_VOLATILE:	tag->tag = DW_TAG_volatile_type; break;
	default:
		printf("%s: FOO %d\n\n", __func__, type);
		return 0;
	}

	tag->type = type_id;
	cu__add_tag_with_id(btfe->priv, tag, id);

	return 0;
}

void *btf_elf__get_buffer(struct btf_elf *btfe)
{
	return btfe->data;
}

size_t btf_elf__get_size(struct btf_elf *btfe)
{
	return btfe->size;
}

static int btf_elf__load_types(struct btf_elf *btfe)
{
	void *btf_buffer = btf_elf__get_buffer(btfe);
	struct btf_header *hp = btf_buffer;
	void *btf_contents = btf_buffer + sizeof(*hp),
	     *type_section = (btf_contents + btf_elf__get32(btfe, &hp->type_off)),
	     *strings_section = (btf_contents + btf_elf__get32(btfe, &hp->str_off));
	struct btf_type *type_ptr = type_section,
			*end = strings_section;
	uint32_t type_index = 0x0001;

	while (type_ptr < end) {
		uint32_t val  = btf_elf__get32(btfe, &type_ptr->info);
		uint32_t type = BTF_INFO_KIND(val);
		int	 vlen = BTF_INFO_VLEN(val);
		void	 *ptr = type_ptr;
		uint32_t size = btf_elf__get32(btfe, &type_ptr->size);
		bool     kflag = BTF_INFO_KFLAG(val);

		ptr += sizeof(struct btf_type);

		if (type == BTF_KIND_INT) {
			vlen = create_new_base_type(btfe, ptr, type_ptr, type_index);
		} else if (type == BTF_KIND_ARRAY) {
			vlen = create_new_array(btfe, ptr, type_index);
		} else if (type == BTF_KIND_STRUCT) {
			vlen = create_new_class(btfe, ptr, vlen, type_ptr, size, type_index, kflag);
		} else if (type == BTF_KIND_UNION) {
			vlen = create_new_union(btfe, ptr, vlen, type_ptr, size, type_index, kflag);
		} else if (type == BTF_KIND_ENUM) {
			vlen = create_new_enumeration(btfe, ptr, vlen, type_ptr, size, type_index);
		} else if (type == BTF_KIND_FWD) {
			vlen = create_new_forward_decl(btfe, type_ptr, size, type_index);
		} else if (type == BTF_KIND_TYPEDEF) {
			vlen = create_new_typedef(btfe, type_ptr, size, type_index);
		} else if (type == BTF_KIND_VOLATILE ||
			   type == BTF_KIND_PTR ||
			   type == BTF_KIND_CONST ||
			   type == BTF_KIND_RESTRICT) {
			vlen = create_new_tag(btfe, type, type_ptr, type_index);
		} else if (type == BTF_KIND_UNKN) {
			cu__table_nullify_type_entry(btfe->priv, type_index);
			fprintf(stderr,
				"BTF: idx: %d, off: %zd, Unknown\n",
				type_index, ((void *)type_ptr) - type_section);
			fflush(stderr);
			vlen = 0;
		} else if (type == BTF_KIND_FUNC_PROTO) {
			vlen = create_new_subroutine_type(btfe, ptr, vlen, type_ptr, type_index);
		} else if (type == BTF_KIND_FUNC) {
			/* BTF_KIND_FUNC corresponding to a defined subprogram.
			 * This is not really a type and it won't be referred by any other types
			 * either. Since types cannot be skipped, let us replace it with
			 * a nullify_type_entry.
			 *
			 * No warning here since BTF_KIND_FUNC is a legal entry in BTF.
			 */
			cu__table_nullify_type_entry(btfe->priv, type_index);
			vlen = 0;
		} else {
			fprintf(stderr,
				"BTF: idx: %d, off: %zd, Unknown\n",
				type_index, ((void *)type_ptr) - type_section);
			fflush(stderr);
			vlen = 0;
		}

		if (vlen < 0)
			return vlen;

		type_ptr = ptr + vlen;
		type_index++;
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
			if (!btfe->is_big_endian)
				pos->bitfield_offset = pos->bit_size - pos->bitfield_offset - pos->bitfield_size;
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
