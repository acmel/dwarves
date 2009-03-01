/* ctfdump.c: CTF dumper.
 *
 * Copyright (C) 2008 David S. Miller <davem@davemloft.net>
 */

#include <sys/types.h>
#include <sys/stat.h>
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

#include "libctf.h"
#include "ctf.h"
#include "dutil.h"
#include "dwarves.h"

/*
 * FIXME: We should just get the table from the CTF ELF section
 * and use it directly
 */
extern struct strings *strings;

static void *zalloc(const size_t size)
{
	void *s = malloc(size);
	if (s != NULL)
		memset(s, 0, size);
	return s;
}

static void oom(const char *msg)
{
	fprintf(stderr, "libclasses: out of memory(%s)\n", msg);
	exit(EXIT_FAILURE);
}

struct ctf_state {
	struct ctf	*ctf;
	Elf		*elf;
	Elf_Data	*elf_syms;
	Elf_Data	*elf_symstrs;
	struct cu	*cu;
	int		elf_num_syms;
	int		in_fd;
};

static Elf_Scn *elf_section_by_name(Elf *elf, GElf_Ehdr *ep,
				    GElf_Shdr *shp, const char *name)
{
	Elf_Scn *sec = NULL;

	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *str;

		gelf_getshdr(sec, shp);
		str = elf_strptr(elf, ep->e_shstrndx, shp->sh_name);
		if (!strcmp(name, str))
			break;
	}

	return sec;
}

struct elf_sym_iter_state {
	int (*func)(struct ctf_state *sp, const char *sym_name,
		    int sym_index, int call_index, void *data);
	void *data;

	int st_type;
	int limit;
};

#if 0
static int ctf_ignores_elf_symbol(GElf_Sym *sym, char *name, int type)
{
	if (type == STT_OBJECT &&
	    sym->st_shndx == SHN_ABS &&
	    sym->st_value == 0)
		return 1;
	if (sym->st_name == 0)
		return 1;
	if (sym->st_shndx == SHN_UNDEF)
		return 1;
	if (!strcmp(name, "_START_") || !strcmp(name, "_END_"))
		return 1;
	return 0;
}

static void elf_symbol_iterate(struct ctf_state *sp,
			       struct elf_sym_iter_state *ep)
{
	int i, index;

	index = 0;
	for (i = 0; i < sp->elf_num_syms; i++) {
		GElf_Sym sym;
		char *name;
		int type;

		if (gelf_getsym(sp->elf_syms, i, &sym) == NULL) {
			fprintf(stderr, "Could not get ELF symbol %d.\n", i);
			exit(2);
		}
		type = GELF_ST_TYPE(sym.st_info);
		name = (char *)sp->elf_symstrs->d_buf + sym.st_name;

		if ((ep->st_type == -1 || ep->st_type == type) &&
		    !ctf_ignores_elf_symbol(&sym, name, type)) {
			if (index >= ep->limit) {
				fprintf(stderr, "Symbol limit reached "
					"([%u], %d vs %d).\n",
					ep->limit, i, sp->elf_num_syms);
				exit(2);
			}

			if (ep->func(sp, name, i, index++, ep->data) < 0)
				return;
		}
	}
}
#endif

static int parse_elf(struct ctf_state *sp, int *wordsizep)
{
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	Elf_Data *data;
	Elf_Scn *sec;

	if (gelf_getehdr(sp->elf, &ehdr) == NULL) {
		fprintf(stderr, "Cannot get elf header.\n");
		exit(2);
	}

	sec = elf_section_by_name(sp->elf, &ehdr, &shdr, ".SUNW_ctf");
	if (!sec)
		return -1;

	data = elf_getdata(sec, NULL);
	if (!data) {
		fprintf(stderr, "Cannot get data of CTF section.\n");
		return -1;
	}

	sp->ctf = ctf__new(data->d_buf, data->d_size);
	if (!sp->ctf) {
		fprintf(stderr, "Cannot initialize CTF state.\n");
		return -1;
	}

	if (shdr.sh_link != 0)
		sec = elf_getscn(sp->elf, shdr.sh_link);
	else
		sec = elf_section_by_name(sp->elf, &ehdr, &shdr, ".symtab");

	switch (ehdr.e_ident[EI_CLASS]) {
	case ELFCLASS32: *wordsizep = 4; break;
	case ELFCLASS64: *wordsizep = 8; break;
	default:	 *wordsizep = 0; break;
	}

	if (!sec)
		return 0;

	if (gelf_getshdr(sec, &shdr) != NULL) {
		sp->elf_syms = elf_getdata(sec, NULL);
		sp->elf_num_syms = shdr.sh_size / shdr.sh_entsize;

		sec = elf_getscn(sp->elf, shdr.sh_link);
		sp->elf_symstrs = elf_getdata(sec, NULL);
	}

	return 0;
}

static char *ctf_string(uint32_t ref, struct ctf_state *sp)
{
	struct ctf_header *hp = ctf__get_buffer(sp->ctf);
	uint32_t off = CTF_REF_OFFSET(ref);
	char *name;

	if (CTF_REF_TBL_ID(ref) != CTF_STR_TBL_ID_0)
		return "(external ref)";

	if (off >= ctf__get32(sp->ctf, &hp->ctf_str_len))
		return "(ref out-of-bounds)";

	if ((off + ctf__get32(sp->ctf, &hp->ctf_str_off)) >=
	    ctf__get_size(sp->ctf))
		return "(string table truncated)";

	name = ((char *)(hp + 1) + ctf__get32(sp->ctf, &hp->ctf_str_off) + off);
	if (name[0] == '\0')
		return "(anonymous)";

	return name;
}

static char *ctf_format_flt_attrs(uint32_t eval, char *buf)
{
	uint32_t attrs = CTF_TYPE_FP_ATTRS(eval);

	buf[0] = '\0';

	if (attrs < CTF_TYPE_FP_SINGLE ||
	    attrs > CTF_TYPE_FP_MAX)
		buf += sprintf(buf, "0x%02x ", attrs);
	else {
		switch (attrs) {
		case CTF_TYPE_FP_SINGLE:
			buf += sprintf(buf, "single ");
			break;
		case CTF_TYPE_FP_DOUBLE:
			buf += sprintf(buf, "double ");
			break;
		case CTF_TYPE_FP_CMPLX:
			buf += sprintf(buf, "complex ");
			break;
		case CTF_TYPE_FP_CMPLX_DBL:
			buf += sprintf(buf, "complex double ");
			break;
		case CTF_TYPE_FP_CMPLX_LDBL:
			buf += sprintf(buf, "complex long double ");
			break;
		case CTF_TYPE_FP_LDBL:
			buf += sprintf(buf, "long double ");
			break;
		case CTF_TYPE_FP_INTVL:
			buf += sprintf(buf, "interval ");
			break;
		case CTF_TYPE_FP_INTVL_DBL:
			buf += sprintf(buf, "interval double ");
			break;
		case CTF_TYPE_FP_INTVL_LDBL:
			buf += sprintf(buf, "interval long double ");
			break;
		case CTF_TYPE_FP_IMGRY:
			buf += sprintf(buf, "imaginary ");
			break;
		case CTF_TYPE_FP_IMGRY_DBL:
			buf += sprintf(buf, "imaginary double ");
			break;
		case CTF_TYPE_FP_IMGRY_LDBL:
			buf += sprintf(buf, "imaginary long double ");
			break;
		}
	}

	return buf;
}

#if 0
static int dump_one_func(struct ctf_state *sp, const char *sym_name,
			 int sym_index, int call_index, void *data)
{
	uint16_t **func_pp = data;
	uint16_t val = ctf__get16(sp->ctf, *func_pp);
	uint16_t type = CTF_GET_KIND(val);
	uint16_t vlen = CTF_GET_VLEN(val);
	uint16_t i;

	(*func_pp)++;

	if (type == CTF_TYPE_KIND_UNKN && vlen == 0)
		return 0;

	if (type != CTF_TYPE_KIND_FUNC) {
		fprintf(stderr, "Expected function type, got %u\n", type);
		exit(2);
	}

	fprintf(stdout, "  [%6d] %-36s %8d\n",
		call_index, sym_name, sym_index);
	fprintf(stdout, "           0x%04x   (",
		ctf__get16(sp->ctf, *func_pp));

	(*func_pp)++;
	for (i = 0; i < vlen; i++) {
		if (i >= 1)
			fprintf(stdout, ", ");

		fprintf(stdout, "0x%04x", ctf__get16(sp->ctf, *func_pp));
		(*func_pp)++;
	}
	fprintf(stdout, ")\n");

	return 0;
}

static void dump_funcs(struct ctf_state *sp)
{
	struct ctf_header *hp = ctf__get_buffer(sp->ctf);
	struct elf_sym_iter_state estate;
	uint16_t *func_ptr;

	fprintf(stdout, "CTF Functions:\n");
	fprintf(stdout,
		"  [  Nr  ] "
		"SymName                              "
		"SymIndex\n"
		"           Returns  "
		"Args\n");

	memset(&estate, 0, sizeof(estate));
	func_ptr = ctf__get_buffer(sp->ctf) + sizeof(*hp) +
		ctf__get32(sp->ctf, &hp->ctf_func_off);
	estate.data = &func_ptr;
	estate.func = dump_one_func;
	estate.st_type = STT_FUNC;
	estate.limit = INT_MAX;

	elf_symbol_iterate(sp, &estate);

	fprintf(stdout, "\n");
}
#endif

static struct base_type *base_type__new(const char *name, size_t size)
{
        struct base_type *self = zalloc(sizeof(*self));

	if (self != NULL) {
		self->name = strings__add(strings, name);
		self->bit_size = size;
	}
	return self;
}

static void type__init(struct type *self, uint16_t tag, unsigned int id,
		       const char *name, size_t size)
{
	INIT_LIST_HEAD(&self->node);
	INIT_LIST_HEAD(&self->namespace.tags);
	self->size = size;
	self->namespace.tag.id = id;
	self->namespace.tag.tag = tag;
	self->namespace.name = strings__add(strings, name[0] == '(' ? NULL : name);
}

static struct type *type__new(uint16_t tag, unsigned int id,
			      const char *name, size_t size)
{
        struct type *self = zalloc(sizeof(*self));

	if (self != NULL)
		type__init(self, tag, id, name, size);

	return self;
}

static struct class *class__new(const char *name, unsigned int id, size_t size)
{
	struct class *self = zalloc(sizeof(*self));

	if (self != NULL) {
		type__init(&self->type, DW_TAG_structure_type, id, name, size);
		INIT_LIST_HEAD(&self->vtable);
	}

	return self;
}

static int create_new_base_type(struct ctf_state *sp, void *ptr,
				int vlen __unused, struct ctf_full_type *tp,
				unsigned int id)
{
	uint32_t *enc = ptr, name_idx;
	char name[64], *buf = name;
	uint32_t eval = ctf__get32(sp->ctf, enc);
	uint32_t attrs = CTF_TYPE_INT_ATTRS(eval);
	struct base_type *base;

	if (attrs & CTF_TYPE_INT_SIGNED)
		buf += sprintf(buf, "signed ");
	if (attrs & CTF_TYPE_INT_CHAR)
		buf += sprintf(buf, "char ");
	if (attrs & CTF_TYPE_INT_BOOL)
		buf += sprintf(buf, "bool ");
	if (attrs & CTF_TYPE_INT_VARARGS)
		buf += sprintf(buf, "varargs ");

	name_idx = ctf__get32(sp->ctf, &tp->base.ctf_name);
	buf += sprintf(buf, "%s", ctf_string(name_idx, sp));
	base = base_type__new(name, CTF_TYPE_INT_BITS(eval));
	if (base == NULL)
		oom("base_type__new");
		
	base->tag.tag = DW_TAG_base_type;
	base->tag.id = id;
	cu__add_tag(sp->cu, &base->tag);

	return sizeof(*enc);
}

static int create_new_base_type_float(struct ctf_state *sp, void *ptr,
				      int vlen __unused,
				      struct ctf_full_type *tp,
				      unsigned int id)
{
	uint32_t *enc = ptr, eval;
	char name[64];
	struct base_type *base;

	eval = ctf__get32(sp->ctf, enc);
	sprintf(ctf_format_flt_attrs(eval, name), "%s",
		ctf_string(ctf__get32(sp->ctf, &tp->base.ctf_name), sp));

	base = base_type__new(name, CTF_TYPE_FP_BITS(eval));
	if (base == NULL)
		oom("base_type__new");
		
	base->tag.tag = DW_TAG_base_type;
	base->tag.id = id;
	cu__add_tag(sp->cu, &base->tag);

	return sizeof(*enc);
}

static int create_new_array(struct ctf_state *sp, void *ptr,
			    int vlen __unused,
			    struct ctf_full_type *tp __unused,
			    unsigned int id)
{
	struct ctf_array *ap = ptr;
	struct array_type *self = zalloc(sizeof(*self));

	if (self == NULL)
		oom("array_type");

	/* FIXME: where to get the number of dimensions?
	 * it it flattened? */
	self->dimensions = 1;
	self->nr_entries = malloc(sizeof(uint32_t));

	if (self->nr_entries == NULL)
		oom("array_type->nr_entries");

	self->nr_entries[0] = ctf__get32(sp->ctf, &ap->ctf_array_nelems);
	self->tag.tag = DW_TAG_array_type;
	self->tag.id = id;
	self->tag.type = ctf__get16(sp->ctf, &ap->ctf_array_type);

	cu__add_tag(sp->cu, &self->tag);

	return sizeof(*ap);
}

static int create_new_subroutine_type(struct ctf_state *sp, void *ptr,
				      int vlen, struct ctf_full_type *tp,
				      unsigned int id)
{
	uint16_t *args = ptr;
	uint16_t i;
	const char *name = ctf_string(ctf__get32(sp->ctf, &tp->base.ctf_name), sp);
	unsigned int type = ctf__get16(sp->ctf, &tp->base.ctf_type);
	struct function *self = zalloc(sizeof(*self));

	if (self == NULL)
		oom("function__new");

	self->name = strings__add(strings, name);
	INIT_LIST_HEAD(&self->vtable_node);
	INIT_LIST_HEAD(&self->tool_node);
	INIT_LIST_HEAD(&self->proto.parms);
	self->proto.tag.tag = DW_TAG_subroutine_type;
	self->proto.tag.id = id;
	self->proto.tag.type = type;
	INIT_LIST_HEAD(&self->lexblock.tags);

	for (i = 0; i < vlen; i++) {
		struct parameter *p = zalloc(sizeof(*p));

		p->tag.tag  = DW_TAG_formal_parameter;
		p->tag.type = ctf__get16(sp->ctf, &args[i]);
		ftype__add_parameter(&self->proto, p);
	}

	vlen *= sizeof(*args);

	/* Round up to next multiple of 4 to maintain
	 * 32-bit alignment.
	 */
	if (vlen & 0x2)
		vlen += 0x2;

	cu__add_tag(sp->cu, &self->proto.tag);

	return vlen;
}

static unsigned long create_full_members(struct ctf_state *sp, void *ptr,
					 int vlen, struct type *class)
{
	struct ctf_full_member *mp = ptr;
	int i;

	for (i = 0; i < vlen; i++) {
		struct class_member *member = zalloc(sizeof(*member));
		uint32_t bit_offset;

		if (member == NULL)
			oom("class_member");

		member->tag.tag = DW_TAG_member;
		member->tag.type = ctf__get16(sp->ctf, &mp[i].ctf_member_type);
		member->name = strings__add(strings, ctf_string(ctf__get32(sp->ctf, &mp[i].ctf_member_name), sp));
		bit_offset = (ctf__get32(sp->ctf, &mp[i].ctf_member_offset_high) << 16) |
			      ctf__get32(sp->ctf, &mp[i].ctf_member_offset_low);
		member->offset = bit_offset / 8;
		member->bit_offset = bit_offset % 8;
		type__add_member(class, member);
		hashtags__hash(sp->cu->hash_tags, &member->tag);
	}

	return sizeof(*mp);
}

static unsigned long create_short_members(struct ctf_state *sp, void *ptr,
					  int vlen, struct type *class)
{
	struct ctf_short_member *mp = ptr;
	int i;

	for (i = 0; i < vlen; i++) {
		struct class_member *member = zalloc(sizeof(*member));
		uint32_t bit_offset;

		if (member == NULL)
			oom("class_member");

		member->tag.tag = DW_TAG_member;
		member->tag.type = ctf__get16(sp->ctf, &mp[i].ctf_member_type);
		member->name = strings__add(strings, ctf_string(ctf__get32(sp->ctf, &mp[i].ctf_member_name), sp));
		bit_offset = ctf__get16(sp->ctf, &mp[i].ctf_member_offset);
		member->offset = bit_offset / 8;
		member->bit_offset = bit_offset % 8;

		type__add_member(class, member);
		hashtags__hash(sp->cu->hash_tags, &member->tag);
	}

	return sizeof(*mp);
}

static int create_new_class(struct ctf_state *sp, void *ptr,
			    int vlen, struct ctf_full_type *tp,
			    uint64_t size, unsigned int id)
{
	unsigned long member_size;
	const char *name = ctf_string(ctf__get32(sp->ctf, &tp->base.ctf_name), sp);
	struct class *self = class__new(name, id, size);

	if (size >= CTF_SHORT_MEMBER_LIMIT) {
		member_size = create_full_members(sp, ptr, vlen, &self->type);
	} else {
		member_size = create_short_members(sp, ptr, vlen, &self->type);
	}

	cu__add_tag(sp->cu, &self->type.namespace.tag);

	return (vlen * member_size);
}

static int create_new_union(struct ctf_state *sp, void *ptr,
			    int vlen, struct ctf_full_type *tp,
			    uint64_t size, unsigned int id)
{
	unsigned long member_size;
	const char *name = ctf_string(ctf__get32(sp->ctf, &tp->base.ctf_name), sp);
	struct type *self = type__new(DW_TAG_union_type, id, name, size);

	if (size >= CTF_SHORT_MEMBER_LIMIT) {
		member_size = create_full_members(sp, ptr, vlen, self);
	} else {
		member_size = create_short_members(sp, ptr, vlen, self);
	}

	cu__add_tag(sp->cu, &self->namespace.tag);

	return (vlen * member_size);
}

static struct enumerator *enumerator__new(const char *name,
					  uint32_t value)
{
	struct enumerator *self = zalloc(sizeof(*self));

	if (self != NULL) {
		self->name = strings__add(strings, name);
		self->value = value;
		self->tag.tag = DW_TAG_enumerator;
	}

	return self;
}

static int create_new_enumeration(struct ctf_state *sp, void *ptr,
				  int vlen, struct ctf_full_type *tp,
				  unsigned int id)
{
	struct ctf_enum *ep = ptr;
	uint16_t i;
	struct type *enumeration = type__new(DW_TAG_enumeration_type, id,
					     ctf_string(ctf__get32(sp->ctf,
							&tp->base.ctf_name), sp),
					     sizeof(int)); /* FIXME: is this always the case? */

	if (enumeration == NULL)
		oom("enumeration");

	for (i = 0; i < vlen; i++) {
		char *name = ctf_string(ctf__get32(sp->ctf, &ep[i].ctf_enum_name), sp);
		uint32_t value = ctf__get32(sp->ctf, &ep[i].ctf_enum_val);
		struct enumerator *enumerator = enumerator__new(name, value);

		if (enumerator == NULL)
			oom("enumerator__new");

		enumeration__add(enumeration, enumerator);
		hashtags__hash(sp->cu->hash_tags, &enumerator->tag);
	}

	cu__add_tag(sp->cu, &enumeration->namespace.tag);

	return (vlen * sizeof(*ep));
}

static int create_new_forward_decl(struct ctf_state *sp, void *ptr __unused,
				   int vlen __unused, struct ctf_full_type *tp,
				   uint64_t size, unsigned int id)
{
	char *name = ctf_string(ctf__get32(sp->ctf, &tp->base.ctf_name), sp);
	struct class *self = class__new(name, id, size);

	if (self == NULL)
		oom("class foward decl");
	self->type.declaration = 1;
	cu__add_tag(sp->cu, &self->type.namespace.tag);
	return 0;
}

static int create_new_typedef(struct ctf_state *sp, int type,
			      void *ptr __unused, int vlen __unused,
			      struct ctf_full_type *tp,
			      uint64_t size, unsigned int id)
{
	const char *name = ctf_string(ctf__get32(sp->ctf, &tp->base.ctf_name), sp);
	unsigned int type_id = ctf__get16(sp->ctf, &tp->base.ctf_type);
	unsigned int tag;
	struct type *self;

	switch (type) {
	case CTF_TYPE_KIND_TYPDEF: tag = DW_TAG_typedef; break;
	default:
		printf("%s: FOO %d\n\n", __func__, type);
		return 0;
	}

	self = type__new(tag, id, name, size);
	if (self == NULL)
		oom("type__new");
	self->namespace.tag.type = type_id;
	cu__add_tag(sp->cu, &self->namespace.tag);

	return 0;
}

static int create_new_tag(struct ctf_state *sp, int type,
			  void *ptr __unused, int vlen __unused,
			  struct ctf_full_type *tp, unsigned int id)
{
	unsigned int type_id = ctf__get16(sp->ctf, &tp->base.ctf_type);
	struct tag *self = zalloc(sizeof(*self));

	if (self == NULL)
		oom("tag__new");

	switch (type) {
	case CTF_TYPE_KIND_CONST:	self->tag = DW_TAG_const_type;	  break;
	case CTF_TYPE_KIND_PTR:		self->tag = DW_TAG_pointer_type;  break;
	case CTF_TYPE_KIND_RESTRICT:	self->tag = DW_TAG_restrict_type; break;
	case CTF_TYPE_KIND_VOLATILE:	self->tag = DW_TAG_volatile_type; break;
	default:
		printf("%s: FOO %d\n\n", __func__, type);
		return 0;
	}

	self->id = id;
	self->type = type_id;
	cu__add_tag(sp->cu, self);

	return 0;
}

static void load_types(struct ctf_state *sp)
{
	struct ctf_header *hp = ctf__get_buffer(sp->ctf);
	struct ctf_full_type *type_ptr, *end;
	unsigned int type_index;

	type_ptr = ctf__get_buffer(sp->ctf) + sizeof(*hp) +
		ctf__get32(sp->ctf, &hp->ctf_type_off);
	end = ctf__get_buffer(sp->ctf) + sizeof(*hp) +
		ctf__get32(sp->ctf, &hp->ctf_str_off);

	type_index = 0x0001;
	if (hp->ctf_parent_name ||
	    hp->ctf_parent_label)
		type_index += 0x8000;

	while (type_ptr < end) {
		uint16_t val, type, vlen, base_size;
		uint64_t size;
		void *ptr;

		val = ctf__get16(sp->ctf, &type_ptr->base.ctf_info);
		type = CTF_GET_KIND(val);
		vlen = CTF_GET_VLEN(val);

		base_size = ctf__get16(sp->ctf, &type_ptr->base.ctf_size);
		ptr = type_ptr;
		if (base_size == 0xffff) {
			size = ctf__get32(sp->ctf, &type_ptr->ctf_size_high);
			size <<= 32;
			size |= ctf__get32(sp->ctf, &type_ptr->ctf_size_low);
			ptr += sizeof(struct ctf_full_type);
		} else {
			size = base_size;
			ptr += sizeof(struct ctf_short_type);
		}

		if (type == CTF_TYPE_KIND_INT) {
			vlen = create_new_base_type(sp, ptr, vlen, type_ptr, type_index);
		} else if (type == CTF_TYPE_KIND_FLT) {
			vlen = create_new_base_type_float(sp, ptr, vlen, type_ptr, type_index);
		} else if (type == CTF_TYPE_KIND_ARR) {
			vlen = create_new_array(sp, ptr, vlen, type_ptr, type_index);
		} else if (type == CTF_TYPE_KIND_FUNC) {
			vlen = create_new_subroutine_type(sp, ptr, vlen, type_ptr, type_index);
		} else if (type == CTF_TYPE_KIND_STR) {
			vlen = create_new_class(sp, ptr,
						vlen, type_ptr, size, type_index);
		} else if (type == CTF_TYPE_KIND_UNION) {
			vlen = create_new_union(sp, ptr,
					        vlen, type_ptr, size, type_index);
		} else if (type == CTF_TYPE_KIND_ENUM) {
			vlen = create_new_enumeration(sp, ptr, vlen, type_ptr, type_index);
		} else if (type == CTF_TYPE_KIND_FWD) {
			vlen = create_new_forward_decl(sp, ptr, vlen, type_ptr, size, type_index);
		} else if (type == CTF_TYPE_KIND_TYPDEF) {
			vlen = create_new_typedef(sp, type, ptr, vlen, type_ptr, size, type_index);
		} else if (type == CTF_TYPE_KIND_VOLATILE ||
			   type == CTF_TYPE_KIND_PTR ||
			   type == CTF_TYPE_KIND_CONST ||
			   type == CTF_TYPE_KIND_RESTRICT) {
			vlen = create_new_tag(sp, type, ptr, vlen, type_ptr, type_index);
		} else if (type == CTF_TYPE_KIND_UNKN) {
			printf("CTF: [%#6x] %1d Unknown\n", type_index, CTF_ISROOT(val));
			vlen = 0;
		} else {
			abort();
		}

		type_ptr = ptr + vlen;
		type_index++;
	}
}

static void dump_ctf(struct ctf_state *sp)
{
	//dump_funcs(sp);
	load_types(sp);
}

static void open_files(struct ctf_state *sp, const char *in_filename)
{
	sp->in_fd = -1;
	if (in_filename) {
		sp->in_fd = open(in_filename, O_RDONLY);
		if (sp->in_fd < 0) {
			perror("open");
			exit(2);
		}
	}
}

int ctf__load(struct cus *self, char *filenames[])
{
	struct ctf_state state;
	int wordsize;

	memset(&state, 0, sizeof(state));

	open_files(&state, filenames[0]);

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "Cannot set libelf version.\n");
		return -1;
	}

	state.elf = elf_begin(state.in_fd, ELF_C_READ_MMAP, NULL);
	if (!state.elf) {
		fprintf(stderr, "Cannot read ELF file.\n");
		return -1;
	}

	if (parse_elf(&state, &wordsize))
		return -1;

	state.cu = cu__new("FIXME.c", wordsize, NULL, 0);
	if (state.cu == NULL)
		oom("cu__new");

	cus__add(self, state.cu);

	dump_ctf(&state);

	elf_end(state.elf);

	close(state.in_fd);

	return 0;
}
