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
#include "btf.h"
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

static int btf__load_ftype(struct btf *btf, struct ftype *proto, uint16_t tag,
			   uint32_t type, uint16_t vlen, struct btf_param *args, long id)
{
	int i;

	proto->tag.tag	= tag;
	proto->tag.type = type;
	INIT_LIST_HEAD(&proto->parms);

	for (i = 0; i < vlen; ++i) {
		struct btf_param param = {
		       .name_off = btf__get32(btf, &args[i].name_off),
		       .type	 = btf__get32(btf, &args[i].type),
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
	cu__add_tag(btf->priv, &proto->tag, &id);

	return vlen;
out_free_parameters:
	ftype__delete(proto, btf->priv);
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

static void type__init(struct type *type, uint16_t tag,
		       strings_t name, size_t size, bool kflag)
{
	INIT_LIST_HEAD(&type->node);
	INIT_LIST_HEAD(&type->namespace.tags);
	type->size = size;
	type->namespace.tag.tag = tag;
	type->namespace.name = name;
	type->namespace.sname = 0;
	type->flag = kflag;
}

static struct type *type__new(uint16_t tag, strings_t name, size_t size,
			      bool kflag)
{
        struct type *type = tag__alloc(sizeof(*type));

	if (type != NULL)
		type__init(type, tag, name, size, kflag);

	return type;
}

static struct class *class__new(strings_t name, size_t size, bool kflag)
{
	struct class *class = tag__alloc(sizeof(*class));

	if (class != NULL) {
		type__init(&class->type, DW_TAG_structure_type, name, size, kflag);
		INIT_LIST_HEAD(&class->vtable);
	}

	return class;
}

static int create_new_base_type(struct btf *btf, void *ptr, struct btf_type *tp, long id)
{
	uint32_t *enc = ptr;
	uint32_t eval = btf__get32(btf, enc);
	uint32_t attrs = BTF_INT_ENCODING(eval);
	strings_t name = btf__get32(btf, &tp->name_off);
	struct base_type *base = base_type__new(name, attrs, 0,
						BTF_INT_BITS(eval));
	if (base == NULL)
		return -ENOMEM;

	base->tag.tag = DW_TAG_base_type;
	cu__add_tag(btf->priv, &base->tag, &id);

	return sizeof(*enc);
}

static int create_new_array(struct btf *btf, void *ptr, long id)
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

	array->nr_entries[0] = btf__get32(btf, &ap->nelems);
	array->tag.tag = DW_TAG_array_type;
	array->tag.type = btf__get32(btf, &ap->type);

	cu__add_tag(btf->priv, &array->tag, &id);

	return sizeof(*ap);
}

static int create_members(struct btf *btf, void *ptr, int vlen, struct type *class,
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
		member->tag.type   = btf__get32(btf, &mp[i].type);
		member->name	   = btf__get32(btf, &mp[i].name_off);
		offset = btf__get32(btf, &mp[i].offset);
		if (kflag) {
			member->bit_offset = BTF_MEMBER_BIT_OFFSET(offset);
			member->bitfield_size = BTF_MEMBER_BITFIELD_SIZE(offset);
		} else {
			member->bit_offset = offset;
			member->bitfield_size = 0;
		}
		/* sizes and offsets will be corrected at class__fixup_btf_bitfields */
		type__add_member(class, member);
	}

	return sizeof(*mp);
}

static int create_new_class(struct btf *btf, void *ptr, int vlen,
			    struct btf_type *tp, uint64_t size, long id,
			    bool kflag)
{
	strings_t name = btf__get32(btf, &tp->name_off);
	struct class *class = class__new(name, size, kflag);
	int member_size = create_members(btf, ptr, vlen, &class->type, kflag);

	if (member_size < 0)
		goto out_free;

	cu__add_tag(btf->priv, &class->type.namespace.tag, &id);

	return (vlen * member_size);
out_free:
	class__delete(class, btf->priv);
	return -ENOMEM;
}

static int create_new_union(struct btf *btf, void *ptr,
			    int vlen, struct btf_type *tp,
			    uint64_t size, long id,
			    bool kflag)
{
	strings_t name = btf__get32(btf, &tp->name_off);
	struct type *un = type__new(DW_TAG_union_type, name, size, kflag);
	int member_size = create_members(btf, ptr, vlen, un, kflag);

	if (member_size < 0)
		goto out_free;

	cu__add_tag(btf->priv, &un->namespace.tag, &id);

	return (vlen * member_size);
out_free:
	type__delete(un, btf->priv);
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

static int create_new_enumeration(struct btf *btf, void *ptr,
				  int vlen, struct btf_type *tp,
				  uint16_t size, long id)
{
	struct btf_enum *ep = ptr;
	uint16_t i;
	struct type *enumeration = type__new(DW_TAG_enumeration_type,
					     btf__get32(btf, &tp->name_off),
					     size ?: (sizeof(int) * 8), false);

	if (enumeration == NULL)
		return -ENOMEM;

	for (i = 0; i < vlen; i++) {
		strings_t name = btf__get32(btf, &ep[i].name_off);
		uint32_t value = btf__get32(btf, &ep[i].val);
		struct enumerator *enumerator = enumerator__new(name, value);

		if (enumerator == NULL)
			goto out_free;

		enumeration__add(enumeration, enumerator);
	}

	cu__add_tag(btf->priv, &enumeration->namespace.tag, &id);

	return (vlen * sizeof(*ep));
out_free:
	enumeration__delete(enumeration, btf->priv);
	return -ENOMEM;
}

static int create_new_subroutine_type(struct btf *btf, void *ptr,
				      int vlen, struct btf_type *tp,
				      long id)
{
	struct btf_param *args = ptr;
	unsigned int type = btf__get32(btf, &tp->type);
	struct ftype *proto = tag__alloc(sizeof(*proto));

	if (proto == NULL)
		return -ENOMEM;

	vlen = btf__load_ftype(btf, proto, DW_TAG_subroutine_type,
			       type, vlen, args, id);
	return vlen < 0 ? -ENOMEM : vlen;
}

static int create_new_forward_decl(struct btf *btf, struct btf_type *tp,
				   uint64_t size, long id, bool kflag)
{
	strings_t name = btf__get32(btf, &tp->name_off);
	struct class *fwd = class__new(name, size, kflag);

	if (fwd == NULL)
		return -ENOMEM;
	fwd->type.declaration = 1;
	cu__add_tag(btf->priv, &fwd->type.namespace.tag, &id);
	return 0;
}

static int create_new_typedef(struct btf *btf, struct btf_type *tp, uint64_t size, long id)
{
	strings_t name = btf__get32(btf, &tp->name_off);
	unsigned int type_id = btf__get32(btf, &tp->type);
	struct type *type = type__new(DW_TAG_typedef, name, size, false);

	if (type == NULL)
		return -ENOMEM;

	type->namespace.tag.type = type_id;
	cu__add_tag(btf->priv, &type->namespace.tag, &id);

	return 0;
}

static int create_new_tag(struct btf *btf, int type, struct btf_type *tp, long id)
{
	unsigned int type_id = btf__get32(btf, &tp->type);
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
	cu__add_tag(btf->priv, tag, &id);

	return 0;
}

void *btf__get_buffer(struct btf *btf)
{
	return btf->data;
}

size_t btf__get_size(struct btf *btf)
{
	return btf->size;
}

static int btf__load_types(struct btf *btf)
{
	void *btf_buffer = btf__get_buffer(btf);
	struct btf_header *hp = btf_buffer;
	void *btf_contents = btf_buffer + sizeof(*hp),
	     *type_section = (btf_contents + btf__get32(btf, &hp->type_off)),
	     *strings_section = (btf_contents + btf__get32(btf, &hp->str_off));
	struct btf_type *type_ptr = type_section,
			*end = strings_section;
	unsigned int type_index = 0x0001;

	while (type_ptr < end) {
		uint32_t val  = btf__get32(btf, &type_ptr->info);
		uint32_t type = BTF_INFO_KIND(val);
		int	 vlen = BTF_INFO_VLEN(val);
		void	 *ptr = type_ptr;
		uint32_t size = btf__get32(btf, &type_ptr->size);
		bool     kflag = BTF_INFO_KFLAG(val);

		ptr += sizeof(struct btf_type);

		if (type == BTF_KIND_INT) {
			vlen = create_new_base_type(btf, ptr, type_ptr, type_index);
		} else if (type == BTF_KIND_ARRAY) {
			vlen = create_new_array(btf, ptr, type_index);
		} else if (type == BTF_KIND_STRUCT) {
			vlen = create_new_class(btf, ptr, vlen, type_ptr, size, type_index, kflag);
		} else if (type == BTF_KIND_UNION) {
			vlen = create_new_union(btf, ptr, vlen, type_ptr, size, type_index, kflag);
		} else if (type == BTF_KIND_ENUM) {
			vlen = create_new_enumeration(btf, ptr, vlen, type_ptr, size, type_index);
		} else if (type == BTF_KIND_FWD) {
			vlen = create_new_forward_decl(btf, type_ptr, size, type_index, kflag);
		} else if (type == BTF_KIND_TYPEDEF) {
			vlen = create_new_typedef(btf, type_ptr, size, type_index);
		} else if (type == BTF_KIND_VOLATILE ||
			   type == BTF_KIND_PTR ||
			   type == BTF_KIND_CONST ||
			   type == BTF_KIND_RESTRICT) {
			vlen = create_new_tag(btf, type, type_ptr, type_index);
		} else if (type == BTF_KIND_UNKN) {
			cu__table_nullify_type_entry(btf->priv, type_index);
			fprintf(stderr,
				"BTF: idx: %d, off: %zd, Unknown\n",
				type_index, ((void *)type_ptr) - type_section);
			fflush(stderr);
			vlen = 0;
		} else if (type == BTF_KIND_FUNC_PROTO) {
			vlen = create_new_subroutine_type(btf, ptr, vlen, type_ptr, type_index);
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

static int btf__load_sections(struct btf *btf)
{
	return btf__load_types(btf);
}

static int class__fixup_btf_bitfields(struct tag *tag, struct cu *cu)
{
	struct class_member *pos;
	struct type *tag_type = tag__type(tag);

	type__for_each_data_member(tag_type, pos) {
		struct tag *type = tag__follow_typedef(&pos->tag, cu);

		if (type == NULL) /* FIXME: C++ BTF... */
			continue;

		pos->bitfield_offset = 0;
		pos->byte_offset = pos->bit_offset / 8;

		uint16_t type_bit_size;
		size_t integral_bit_size;

		switch (type->tag) {
		case DW_TAG_enumeration_type:
			type_bit_size = tag__type(type)->size;
			/* Best we can do to check if this is a packed enum */
			if (is_power_of_2(type_bit_size))
				integral_bit_size = roundup(type_bit_size, 8);
			else
				integral_bit_size = sizeof(int) * 8;
			break;
		case DW_TAG_base_type: {
			struct base_type *bt = tag__base_type(type);
			char name[256];
			type_bit_size = bt->bit_size;
			integral_bit_size = base_type__name_to_size(bt, cu);
			if (integral_bit_size == 0) {
				fprintf(stderr, "%s: unknown base type name \"%s\"!\n",
					__func__, base_type__name(bt, cu, name,
								  sizeof(name)));
			}
		}
			break;
		default:
			pos->byte_size = tag__size(type, cu);
			pos->bit_size = pos->byte_size * 8;
			continue;
		}

		/*
		 * XXX: integral_bit_size can be zero if base_type__name_to_size doesn't
		 * know about the base_type name, so one has to add there when
		 * such base_type isn't found. pahole will put zero on the
		 * struct output so it should be easy to spot the name when
		 * such unlikely thing happens.
		 */
		pos->byte_size = integral_bit_size / 8;

		if (integral_bit_size == 0) {
			pos->bit_size = integral_bit_size;
			continue;
		}

		pos->bitfield_offset = pos->bit_offset % integral_bit_size;
		pos->bit_size = type_bit_size;
		pos->byte_offset = (((pos->bit_offset / integral_bit_size) *
				     integral_bit_size) / 8);
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

static const char *btf__strings_ptr(const struct cu *cu, strings_t s)
{
	return btf__string(cu->priv, s);
}

struct debug_fmt_ops btf__ops;

int btf__load_file(struct cus *cus, struct conf_load *conf,
		   const char *filename)
{
	int err;
	struct btf *state = btf__new(filename, NULL);

	if (state == NULL)
		return -1;

	struct cu *cu = cu__new(filename, state->wordsize, NULL, 0, filename);
	if (cu == NULL)
		return -1;

	cu->language = LANG_C;
	cu->uses_global_strings = false;
	cu->dfops = &btf__ops;
	cu->priv = state;
	state->priv = cu;
	if (btf__load(state) != 0)
		return -1;

	err = btf__load_sections(state);

	if (err != 0) {
		cu__delete(cu);
		return err;
	}

	err = cu__fixup_btf_bitfields(cu);
	/*
	 * The app stole this cu, possibly deleting it,
	 * so forget about it
	 */
	if (conf && conf->steal && conf->steal(cu, conf))
		return 0;

	cus__add(cus, cu);
	return err;
}

struct debug_fmt_ops btf__ops = {
	.name		= "btf",
	.load_file	= btf__load_file,
	.strings__ptr	= btf__strings_ptr,
	.cu__delete	= btf__cu_delete,
};
