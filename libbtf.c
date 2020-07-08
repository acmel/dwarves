/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook
 */

#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <malloc.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>

#include "libbtf.h"
#include "lib/bpf/include/uapi/linux/btf.h"
#include "lib/bpf/include/linux/err.h"
#include "lib/bpf/src/btf.h"
#include "lib/bpf/src/libbpf.h"
#include "dutil.h"
#include "gobuffer.h"
#include "dwarves.h"
#include "elf_symtab.h"

#define BTF_INFO_ENCODE(kind, kind_flag, vlen)				\
	((!!(kind_flag) << 31) | ((kind) << 24) | ((vlen) & BTF_MAX_VLEN))
#define BTF_INT_ENCODE(encoding, bits_offset, nr_bits)		\
	((encoding) << 24 | (bits_offset) << 16 | (nr_bits))

struct btf_int_type {
	struct btf_type type;
	uint32_t 	data;
};

struct btf_enum_type {
	struct btf_type type;
	struct btf_enum btf_enum;
};

struct btf_array_type {
	struct btf_type type;
	struct btf_array array;
};

struct btf_var_type {
	struct btf_type type;
	struct btf_var var;
};

uint8_t btf_elf__verbose;

static int btf_var_secinfo_cmp(const void *a, const void *b)
{
	const struct btf_var_secinfo *av = a;
	const struct btf_var_secinfo *bv = b;

	return av->offset - bv->offset;
}

uint32_t btf_elf__get32(struct btf_elf *btfe, uint32_t *p)
{
	uint32_t val = *p;

	if (btfe->swapped)
		val = ((val >> 24) |
		       ((val >> 8) & 0x0000ff00) |
		       ((val << 8) & 0x00ff0000) |
		       (val << 24));
	return val;
}

static int btf_raw__load(struct btf_elf *btfe)
{
        size_t read_cnt;
        struct stat st;
        void *data;
        FILE *fp;

        if (stat(btfe->filename, &st))
                return -1;

        data = malloc(st.st_size);
        if (!data)
                return -1;

        fp = fopen(btfe->filename, "rb");
        if (!fp)
                goto cleanup;

        read_cnt = fread(data, 1, st.st_size, fp);
        fclose(fp);
        if (read_cnt < st.st_size)
                goto cleanup;

	btfe->swapped	= 0;
	btfe->data	= data;
	btfe->size	= read_cnt;
	return 0;
cleanup:
        free(data);
        return -1;
}

int btf_elf__load(struct btf_elf *btfe)
{
	if (btfe->raw_btf)
		return btf_raw__load(btfe);

	int err = -ENOTSUP;
	GElf_Shdr shdr;
	Elf_Scn *sec = elf_section_by_name(btfe->elf, &btfe->ehdr, &shdr, ".BTF", NULL);

	if (sec == NULL)
		return -ESRCH;

	Elf_Data *data = elf_getdata(sec, NULL);
	if (data == NULL) {
		fprintf(stderr, "%s: cannot get data of BTF section.\n", __func__);
		return -1;
	}

	struct btf_header *hp = data->d_buf;
	size_t orig_size = data->d_size;

	if (hp->version != BTF_VERSION)
		goto out;

	err = -EINVAL;
	if (hp->magic == BTF_MAGIC)
		btfe->swapped = 0;
	else
		goto out;

	err = -ENOMEM;
	btfe->data = malloc(orig_size);
	if (btfe->data != NULL) {
		memcpy(btfe->data, hp, orig_size);
		btfe->size = orig_size;
		err = 0;
	}
out:
	return err;
}


struct btf_elf *btf_elf__new(const char *filename, Elf *elf)
{
	struct btf_elf *btfe = zalloc(sizeof(*btfe));
	GElf_Shdr shdr;
	Elf_Scn *sec;

	if (!btfe)
		return NULL;

	btfe->in_fd = -1;
	btfe->filename = strdup(filename);
	if (btfe->filename == NULL)
		goto errout;

	if (strcmp(filename, "/sys/kernel/btf/vmlinux") == 0) {
		btfe->raw_btf  = true;
		btfe->wordsize = sizeof(long);
		btfe->is_big_endian = BYTE_ORDER == BIG_ENDIAN;
		return btfe;
	}

	if (elf != NULL) {
		btfe->elf = elf;
	} else {
		btfe->in_fd = open(filename, O_RDONLY);
		if (btfe->in_fd < 0)
			goto errout;

		if (elf_version(EV_CURRENT) == EV_NONE) {
			fprintf(stderr, "%s: cannot set libelf version.\n",
				__func__);
			goto errout;
		}

		btfe->elf = elf_begin(btfe->in_fd, ELF_C_READ_MMAP, NULL);
		if (!btfe->elf) {
			fprintf(stderr, "%s: cannot read %s ELF file.\n",
				__func__, filename);
			goto errout;
		}
	}

	if (gelf_getehdr(btfe->elf, &btfe->ehdr) == NULL) {
		fprintf(stderr, "%s: cannot get elf header.\n", __func__);
		goto errout;
	}

	switch (btfe->ehdr.e_ident[EI_DATA]) {
	case ELFDATA2LSB: btfe->is_big_endian = false; break;
	case ELFDATA2MSB: btfe->is_big_endian = true;  break;
	default:
		fprintf(stderr, "%s: unknown elf endianness.\n", __func__);
		goto errout;
	}

	switch (btfe->ehdr.e_ident[EI_CLASS]) {
	case ELFCLASS32: btfe->wordsize = 4; break;
	case ELFCLASS64: btfe->wordsize = 8; break;
	default:	 btfe->wordsize = 0; break;
	}

	btfe->symtab = elf_symtab__new(NULL, btfe->elf, &btfe->ehdr);
	if (!btfe->symtab) {
		if (btf_elf__verbose)
			printf("%s: '%s' doesn't have symtab.\n", __func__,
			       btfe->filename);
		return btfe;
	}

	/* find percpu section's shndx */
	sec = elf_section_by_name(btfe->elf, &btfe->ehdr, &shdr, PERCPU_SECTION,
				  NULL);
	if (!sec) {
		if (btf_elf__verbose)
			printf("%s: '%s' doesn't have '%s' section\n", __func__,
			       btfe->filename, PERCPU_SECTION);
		return btfe;
	}
	btfe->percpu_shndx = elf_ndxscn(sec);
	btfe->percpu_base_addr = shdr.sh_addr;

	return btfe;

errout:
	btf_elf__delete(btfe);
	return NULL;
}

void btf_elf__delete(struct btf_elf *btfe)
{
	if (!btfe)
		return;

	if (btfe->in_fd != -1) {
		close(btfe->in_fd);
		if (btfe->elf)
			elf_end(btfe->elf);
	}

	elf_symtab__delete(btfe->symtab);

	__gobuffer__delete(&btfe->types);
	__gobuffer__delete(&btfe->percpu_secinfo);
	free(btfe->filename);
	free(btfe->data);
	free(btfe);
}

char *btf_elf__string(struct btf_elf *btfe, uint32_t ref)
{
	struct btf_header *hp = btfe->hdr;
	uint32_t off = ref;
	char *name;

	if (off >= btf_elf__get32(btfe, &hp->str_len))
		return "(ref out-of-bounds)";

	if ((off + btf_elf__get32(btfe, &hp->str_off)) >= btfe->size)
		return "(string table truncated)";

	name = ((char *)(hp + 1) + btf_elf__get32(btfe, &hp->str_off) + off);

	return name[0] == '\0' ? NULL : name;
}

static void *btf_elf__nohdr_data(struct btf_elf *btfe)
{
	return btfe->hdr + 1;
}

void btf_elf__set_strings(struct btf_elf *btfe, struct gobuffer *strings)
{
	btfe->strings = strings;
}

#define BITS_PER_BYTE 8
#define BITS_PER_BYTE_MASK (BITS_PER_BYTE - 1)
#define BITS_PER_BYTE_MASKED(bits) ((bits) & BITS_PER_BYTE_MASK)
#define BITS_ROUNDDOWN_BYTES(bits) ((bits) >> 3)
#define BITS_ROUNDUP_BYTES(bits) (BITS_ROUNDDOWN_BYTES(bits) + !!BITS_PER_BYTE_MASKED(bits))

static const char * const btf_kind_str[NR_BTF_KINDS] = {
	[BTF_KIND_UNKN]		= "UNKNOWN",
	[BTF_KIND_INT]		= "INT",
	[BTF_KIND_PTR]		= "PTR",
	[BTF_KIND_ARRAY]	= "ARRAY",
	[BTF_KIND_STRUCT]	= "STRUCT",
	[BTF_KIND_UNION]	= "UNION",
	[BTF_KIND_ENUM]		= "ENUM",
	[BTF_KIND_FWD]		= "FWD",
	[BTF_KIND_TYPEDEF]	= "TYPEDEF",
	[BTF_KIND_VOLATILE]	= "VOLATILE",
	[BTF_KIND_CONST]	= "CONST",
	[BTF_KIND_RESTRICT]	= "RESTRICT",
	[BTF_KIND_FUNC]		= "FUNC",
	[BTF_KIND_FUNC_PROTO]	= "FUNC_PROTO",
};

static const char *btf_elf__name_in_gobuf(const struct btf_elf *btfe, uint32_t offset)
{
	if (!offset)
		return "(anon)";
	else
		return &btfe->strings->entries[offset];
}

static const char * btf_elf__int_encoding_str(uint8_t encoding)
{
	if (encoding == 0)
		return "(none)";
	else if (encoding == BTF_INT_SIGNED)
		return "SIGNED";
	else if (encoding == BTF_INT_CHAR)
		return "CHAR";
	else if (encoding == BTF_INT_BOOL)
		return "BOOL";
	else
		return "UNKN";
}

__attribute ((format (printf, 5, 6)))
static void btf_elf__log_type(const struct btf_elf *btfe, const struct btf_type *t,
			      bool err, bool output_cr, const char *fmt, ...)
{
	uint8_t kind;
	FILE *out;

	if (!btf_elf__verbose && !err)
		return;

	kind = BTF_INFO_KIND(t->info);
	out = err ? stderr : stdout;

	fprintf(out, "[%u] %s %s",
		btfe->type_index, btf_kind_str[kind],
		btf_elf__name_in_gobuf(btfe, t->name_off));

	if (fmt && *fmt) {
		va_list ap;

		fprintf(out, " ");
		va_start(ap, fmt);
		vfprintf(out, fmt, ap);
		va_end(ap);
	}

	if (output_cr)
		fprintf(out, "\n");
}

__attribute ((format (printf, 5, 6)))
static void btf_log_member(const struct btf_elf *btfe,
			   const struct btf_member *member,
			   bool kind_flag, bool err, const char *fmt, ...)
{
	FILE *out;

	if (!btf_elf__verbose && !err)
		return;

	out = err ? stderr : stdout;

	if (kind_flag)
		fprintf(out, "\t%s type_id=%u bitfield_size=%u bits_offset=%u",
			btf_elf__name_in_gobuf(btfe, member->name_off),
			member->type,
			BTF_MEMBER_BITFIELD_SIZE(member->offset),
			BTF_MEMBER_BIT_OFFSET(member->offset));
	else
		fprintf(out, "\t%s type_id=%u bits_offset=%u",
			btf_elf__name_in_gobuf(btfe, member->name_off),
			member->type,
			member->offset);

	if (fmt && *fmt) {
		va_list ap;

		fprintf(out, " ");
		va_start(ap, fmt);
		vfprintf(out, fmt, ap);
		va_end(ap);
	}

	fprintf(out, "\n");
}

__attribute ((format (printf, 6, 7)))
static void btf_log_func_param(const struct btf_elf *btfe,
			       uint32_t name_off, uint32_t type,
			       bool err, bool is_last_param,
			       const char *fmt, ...)
{
	FILE *out;

	if (!btf_elf__verbose && !err)
		return;

	out = err ? stderr : stdout;

	if (is_last_param && !type)
		fprintf(out, "vararg)\n");
	else
		fprintf(out, "%u %s%s", type,
			btf_elf__name_in_gobuf(btfe, name_off),
			is_last_param ? ")\n" : ", ");

	if (fmt && *fmt) {
		va_list ap;

		fprintf(out, " ");
		va_start(ap, fmt);
		vfprintf(out, fmt, ap);
		va_end(ap);
	}
}

int32_t btf_elf__add_base_type(struct btf_elf *btfe, const struct base_type *bt)
{
	struct btf_int_type int_type;
	struct btf_type *t = &int_type.type;
	uint8_t encoding = 0;

	t->name_off = bt->name;
	t->info = BTF_INFO_ENCODE(BTF_KIND_INT, 0, 0);
	t->size = BITS_ROUNDUP_BYTES(bt->bit_size);
	if (bt->is_signed) {
		encoding = BTF_INT_SIGNED;
	} else if (bt->is_bool) {
		encoding = BTF_INT_BOOL;
	} else if (bt->float_type) {
		fprintf(stderr, "float_type is not supported\n");
		return -1;
	}
	int_type.data = BTF_INT_ENCODE(encoding, 0, bt->bit_size);

	++btfe->type_index;
	if (gobuffer__add(&btfe->types, &int_type, sizeof(int_type)) >= 0) {
		btf_elf__log_type(btfe, t, false, true,
			      "size=%u bit_offset=%u nr_bits=%u encoding=%s",
			      t->size, BTF_INT_OFFSET(int_type.data),
			      BTF_INT_BITS(int_type.data),
			      btf_elf__int_encoding_str(BTF_INT_ENCODING(int_type.data)));
		return btfe->type_index;
	} else {
		btf_elf__log_type(btfe, t, true, true,
			      "size=%u bit_offset=%u nr_bits=%u encoding=%s Error in adding gobuffer",
			      t->size, BTF_INT_OFFSET(int_type.data),
			      BTF_INT_BITS(int_type.data),
			      btf_elf__int_encoding_str(BTF_INT_ENCODING(int_type.data)));
		return -1;
	}
}

int32_t btf_elf__add_ref_type(struct btf_elf *btfe, uint16_t kind, uint32_t type,
			      uint32_t name, bool kind_flag)
{
	struct btf_type t;

	t.name_off = name;
	t.info = BTF_INFO_ENCODE(kind, kind_flag, 0);
	t.type = type;

	++btfe->type_index;
	if (gobuffer__add(&btfe->types, &t, sizeof(t)) >= 0) {
		if (kind == BTF_KIND_FWD)
			btf_elf__log_type(btfe, &t, false, true, "%s", kind_flag ? "union" : "struct");
		else
			btf_elf__log_type(btfe, &t, false, true, "type_id=%u", t.type);
		return btfe->type_index;
	} else {
		btf_elf__log_type(btfe, &t, true, true,
			      "kind_flag=%d type_id=%u Error in adding gobuffer",
			      kind_flag, t.type);
		return -1;
	}
}

int32_t btf_elf__add_array(struct btf_elf *btfe, uint32_t type, uint32_t index_type, uint32_t nelems)
{
	struct btf_array_type array_type;
	struct btf_type *t = &array_type.type;
	struct btf_array *array = &array_type.array;

	t->name_off = 0;
	t->info = BTF_INFO_ENCODE(BTF_KIND_ARRAY, 0, 0);
	t->size = 0;

	array->type = type;
	array->index_type = index_type;
	array->nelems = nelems;

	++btfe->type_index;
	if (gobuffer__add(&btfe->types, &array_type, sizeof(array_type)) >= 0) {
		btf_elf__log_type(btfe, t, false, true,
			      "type_id=%u index_type_id=%u nr_elems=%u",
			      array->type, array->index_type, array->nelems);
		return btfe->type_index;
	} else {
		btf_elf__log_type(btfe, t, true, true,
			      "type_id=%u index_type_id=%u nr_elems=%u Error in adding gobuffer",
			      array->type, array->index_type, array->nelems);
		return -1;
	}
}

int btf_elf__add_member(struct btf_elf *btfe, uint32_t name, uint32_t type, bool kind_flag,
			uint32_t bitfield_size, uint32_t offset)
{
	struct btf_member member = {
		.name_off   = name,
		.type   = type,
		.offset = kind_flag ? (bitfield_size << 24 | offset) : offset,
	};

	if (gobuffer__add(&btfe->types, &member, sizeof(member)) >= 0) {
		btf_log_member(btfe, &member, kind_flag, false, NULL);
		return 0;
	} else {
		btf_log_member(btfe, &member, kind_flag, true, "Error in adding gobuffer");
		return -1;
	}
}

int32_t btf_elf__add_struct(struct btf_elf *btfe, uint8_t kind, uint32_t name,
			    bool kind_flag, uint32_t size, uint16_t nr_members)
{
	struct btf_type t;

	t.name_off = name;
	t.info = BTF_INFO_ENCODE(kind, kind_flag, nr_members);
	t.size = size;

	++btfe->type_index;
	if (gobuffer__add(&btfe->types, &t, sizeof(t)) >= 0) {
		btf_elf__log_type(btfe, &t, false, true, "kind_flag=%d size=%u vlen=%u",
			      kind_flag, t.size, BTF_INFO_VLEN(t.info));
		return btfe->type_index;
	} else {
		btf_elf__log_type(btfe, &t, true, true,
			      "kind_flag=%d size=%u vlen=%u Error in adding gobuffer",
			      kind_flag, t.size, BTF_INFO_VLEN(t.info));
		return -1;
	}
}

int32_t btf_elf__add_enum(struct btf_elf *btfe, uint32_t name, uint32_t bit_size, uint16_t nr_entries)
{
	struct btf_type t;

	t.name_off = name;
	t.info = BTF_INFO_ENCODE(BTF_KIND_ENUM, 0, nr_entries);
	t.size = BITS_ROUNDUP_BYTES(bit_size);

	++btfe->type_index;
	if (gobuffer__add(&btfe->types, &t, sizeof(t)) >= 0) {
		btf_elf__log_type(btfe, &t, false, true, "size=%u vlen=%u", t.size, BTF_INFO_VLEN(t.info));
		return btfe->type_index;
	} else {
		btf_elf__log_type(btfe, &t, true, true,
			      "size=%u vlen=%u Error in adding gobuffer",
			      t.size, BTF_INFO_VLEN(t.info));
		return -1;
	}
}

int btf_elf__add_enum_val(struct btf_elf *btfe, uint32_t name, int32_t value)
{
	struct btf_enum e = {
		.name_off = name,
		.val  = value,
	};

	if (gobuffer__add(&btfe->types, &e, sizeof(e)) < 0) {
		fprintf(stderr, "\t%s val=%d Error in adding gobuffer\n",
			btf_elf__name_in_gobuf(btfe, e.name_off), e.val);
		return -1;
	} else if (btf_elf__verbose)
		printf("\t%s val=%d\n", btf_elf__name_in_gobuf(btfe, e.name_off),
		       e.val);

	return 0;
}

static int32_t btf_elf__add_func_proto_param(struct btf_elf *btfe, uint32_t name,
					     uint32_t type, bool is_last_param)
{
	struct btf_param param;

	param.name_off = name;
	param.type = type;

	if (gobuffer__add(&btfe->types, &param, sizeof(param)) >= 0) {
		btf_log_func_param(btfe, name, type, false, is_last_param, NULL);
		return 0;
	} else {
		btf_log_func_param(btfe, name, type, true, is_last_param,
				   "Error in adding gobuffer");
		return -1;
	}
}

int32_t btf_elf__add_func_proto(struct btf_elf *btfe, struct ftype *ftype, uint32_t type_id_off)
{
	uint16_t nr_params, param_idx;
	struct parameter *param;
	struct btf_type t;
	int32_t type_id;

	/* add btf_type for func_proto */
	nr_params = ftype->nr_parms + (ftype->unspec_parms ? 1 : 0);

	t.name_off = 0;
	t.info = BTF_INFO_ENCODE(BTF_KIND_FUNC_PROTO, 0, nr_params);
	t.type = ftype->tag.type == 0 ? 0 : type_id_off + ftype->tag.type;

	++btfe->type_index;
	if (gobuffer__add(&btfe->types, &t, sizeof(t)) >= 0) {
		btf_elf__log_type(btfe, &t, false, false, "return=%u args=(%s",
			      t.type, !nr_params ? "void)\n" : "");
		type_id = btfe->type_index;
	} else {
		btf_elf__log_type(btfe, &t, true, true,
			      "return=%u vlen=%u Error in adding gobuffer",
			      t.type, BTF_INFO_VLEN(t.info));
		return -1;
	}

	/* add parameters */
	param_idx = 0;
	ftype__for_each_parameter(ftype, param) {
		uint32_t param_type_id = param->tag.type == 0 ? 0 : type_id_off + param->tag.type;
		++param_idx;
		if (btf_elf__add_func_proto_param(btfe, param->name, param_type_id, param_idx == nr_params))
			return -1;
	}

	++param_idx;
	if (ftype->unspec_parms)
		if (btf_elf__add_func_proto_param(btfe, 0, 0, param_idx == nr_params))
			return -1;

	return type_id;
}

int32_t btf_elf__add_var_type(struct btf_elf *btfe, uint32_t type, uint32_t name_off,
			      uint32_t linkage)
{
	struct btf_var_type t;

	t.type.name_off = name_off;
	t.type.info = BTF_INFO_ENCODE(BTF_KIND_VAR, 0, 0);
	t.type.type = type;

	t.var.linkage = linkage;

	++btfe->type_index;
	if (gobuffer__add(&btfe->types, &t.type, sizeof(t)) < 0) {
		btf_elf__log_type(btfe, &t.type, true, true,
				  "type=%u name=%s Error in adding gobuffer",
				  t.type.type, btf_elf__name_in_gobuf(btfe, t.type.name_off));
		return -1;
	}

	btf_elf__log_type(btfe, &t.type, false, false, "type=%u name=%s",
			  t.type.type, btf_elf__name_in_gobuf(btfe, t.type.name_off));

	return btfe->type_index;
}

int32_t btf_elf__add_var_secinfo(struct gobuffer *buf, uint32_t type,
				 uint32_t offset, uint32_t size)
{
	struct btf_var_secinfo si = {
		.type = type,
		.offset = offset,
		.size = size,
	};
	return gobuffer__add(buf, &si, sizeof(si));
}

extern struct strings *strings;

int32_t btf_elf__add_datasec_type(struct btf_elf *btfe, const char *section_name,
				  struct gobuffer *var_secinfo_buf)
{
	struct btf_type type;
	size_t sz = gobuffer__size(var_secinfo_buf);
	uint16_t nr_var_secinfo = sz / sizeof(struct btf_var_secinfo);
	uint32_t name_off;
	struct btf_var_secinfo *last_vsi;

	qsort(var_secinfo_buf->entries, nr_var_secinfo,
	      sizeof(struct btf_var_secinfo), btf_var_secinfo_cmp);

	last_vsi = (struct btf_var_secinfo *)var_secinfo_buf->entries + nr_var_secinfo - 1;

	/*
	 * dwarves doesn't store section names in its string table,
	 * so we have to add it by ourselves.
	 */
	name_off = strings__add(strings, section_name);

	type.name_off = name_off;
	type.info = BTF_INFO_ENCODE(BTF_KIND_DATASEC, 0, nr_var_secinfo);
	type.size = last_vsi->offset + last_vsi->size;

	++btfe->type_index;
	if (gobuffer__add(&btfe->types, &type, sizeof(type)) < 0) {
		btf_elf__log_type(btfe, &type, true, true,
				  "name=%s vlen=%u Error in adding datasec",
				  btf_elf__name_in_gobuf(btfe, type.name_off),
				  nr_var_secinfo);
		return -1;
	}
	if (gobuffer__add(&btfe->types, var_secinfo_buf->entries, sz) < 0) {
		btf_elf__log_type(btfe, &type, true, true,
				  "name=%s vlen=%u Error in adding var_secinfo",
				  btf_elf__name_in_gobuf(btfe, type.name_off),
				  nr_var_secinfo);
		return -1;
	}

	btf_elf__log_type(btfe, &type, false, false, "type=datasec name=%s",
			  btf_elf__name_in_gobuf(btfe, type.name_off));

	return btfe->type_index;
}

static int btf_elf__write(const char *filename, struct btf *btf)
{
	GElf_Shdr shdr_mem, *shdr;
	GElf_Ehdr ehdr_mem, *ehdr;
	Elf_Data *btf_elf = NULL;
	Elf_Scn *scn = NULL;
	Elf *elf = NULL;
	const void *btf_data;
	uint32_t btf_size;
	int fd, err = -1;
	size_t strndx;

	fd = open(filename, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s\n", filename);
		return -1;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "Cannot set libelf version.\n");
		goto out;
	}

	elf = elf_begin(fd, ELF_C_RDWR, NULL);
	if (elf == NULL) {
		fprintf(stderr, "Cannot update ELF file.\n");
		goto out;
	}

	elf_flagelf(elf, ELF_C_SET, ELF_F_DIRTY);

	ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (ehdr == NULL) {
		fprintf(stderr, "%s: elf_getehdr failed.\n", __func__);
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
			btf_elf = elf_getdata(scn, btf_elf);
			break;
		}
	}

	btf_data = btf__get_raw_data(btf, &btf_size);

	if (btf_elf) {
		/* Exisiting .BTF section found */
		btf_elf->d_buf = (void *)btf_data;
		btf_elf->d_size = btf_size;
		elf_flagdata(btf_elf, ELF_C_SET, ELF_F_DIRTY);

		if (elf_update(elf, ELF_C_NULL) >= 0 &&
		    elf_update(elf, ELF_C_WRITE) >= 0)
			err = 0;
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

		snprintf(cmd, sizeof(cmd), "%s --add-section .BTF=%s %s",
			 llvm_objcopy, tmp_fn, filename);

		if (write(fd, btf_data, btf_size) == btf_size && !system(cmd))
			err = 0;

		unlink(tmp_fn);
	}

out:
	if (fd != -1)
		close(fd);
	if (elf)
		elf_end(elf);
	return err;
}

static int libbpf_log(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int btf_elf__encode(struct btf_elf *btfe, uint8_t flags)
{
	struct btf_header *hdr;
	struct btf *btf;

	/* Empty file, nothing to do, so... done! */
	if (gobuffer__size(&btfe->types) == 0)
		return 0;

	if (gobuffer__size(&btfe->percpu_secinfo) != 0)
		btf_elf__add_datasec_type(btfe, PERCPU_SECTION,
					  &btfe->percpu_secinfo);

	btfe->size = sizeof(*hdr) + (gobuffer__size(&btfe->types) + gobuffer__size(btfe->strings));
	btfe->data = zalloc(btfe->size);

	if (btfe->data == NULL) {
		fprintf(stderr, "%s: malloc failed!\n", __func__);
		return -1;
	}

	hdr = btfe->hdr;
	hdr->magic = BTF_MAGIC;
	hdr->version = 1;
	hdr->flags = flags;
	hdr->hdr_len = sizeof(*hdr);

	hdr->type_off = 0;
	hdr->type_len = gobuffer__size(&btfe->types);
	hdr->str_off  = hdr->type_len;
	hdr->str_len  = gobuffer__size(btfe->strings);

	gobuffer__copy(&btfe->types, btf_elf__nohdr_data(btfe) + hdr->type_off);
	gobuffer__copy(btfe->strings, btf_elf__nohdr_data(btfe) + hdr->str_off);

	*(char *)(btf_elf__nohdr_data(btfe) + hdr->str_off) = '\0';

	libbpf_set_print(libbpf_log);

	btf = btf__new(btfe->data, btfe->size);
	if (IS_ERR(btf)) {
		fprintf(stderr, "%s: btf__new failed!\n", __func__);
		return -1;
	}
	if (btf__dedup(btf, NULL, NULL)) {
		fprintf(stderr, "%s: btf__dedup failed!", __func__);
		return -1;
	}

	return btf_elf__write(btfe->filename, btf);
}
