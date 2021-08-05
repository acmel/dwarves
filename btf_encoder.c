/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook

  Derived from ctf_encoder.c, which is:

  Copyright (C) Arnaldo Carvalho de Melo <acme@redhat.com>
  Copyright (C) Red Hat Inc
 */

#include "dwarves.h"
#include "elf_symtab.h"
#include "btf_encoder.h"
#include "gobuffer.h"

#include <linux/btf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <ctype.h> /* for isalpha() and isalnum() */
#include <stdlib.h> /* for qsort() and bsearch() */
#include <inttypes.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>

#include <errno.h>
#include <stdint.h>

struct elf_function {
	const char	*name;
	bool		 generated;
};

#define MAX_PERCPU_VAR_CNT 4096

struct var_info {
	uint64_t    addr;
	const char *name;
	uint32_t    sz;
};

struct btf_encoder {
	struct list_head  node;
	struct btf        *btf;
	struct gobuffer   percpu_secinfo;
	const char	  *filename;
	struct elf_symtab *symtab;
	bool		  has_index_type,
			  need_index_type,
			  skip_encoding_vars,
			  raw_output,
			  verbose,
			  force,
			  gen_floats;
	uint32_t	  array_index_id;
	struct {
		struct var_info vars[MAX_PERCPU_VAR_CNT];
		int		var_cnt;
		uint32_t	shndx;
		uint64_t	base_addr;
		uint64_t	sec_sz;
	} percpu;
	struct {
		struct elf_function *entries;
		int		    allocated;
		int		    cnt;
	} functions;
};

void btf_encoders__add(struct list_head *encoders, struct btf_encoder *encoder)
{
	list_add_tail(&encoder->node, encoders);
}

struct btf_encoder *btf_encoders__first(struct list_head *encoders)
{
	return list_first_entry(encoders, struct btf_encoder, node);
}

struct btf_encoder *btf_encoders__next(struct btf_encoder *encoder)
{
	return list_next_entry(encoder, node);
}

#define PERCPU_SECTION ".data..percpu"

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
 * This depends on the GNU extension to eliminate the stray comma in the zero
 * arguments case.
 *
 * The difference between elf_errmsg(-1) and elf_errmsg(elf_errno()) is that the
 * latter clears the current error.
 */
#define elf_error(fmt, ...) \
	fprintf(stderr, "%s: " fmt ": %s.\n", __func__, ##__VA_ARGS__, elf_errmsg(-1))

static int btf_var_secinfo_cmp(const void *a, const void *b)
{
	const struct btf_var_secinfo *av = a;
	const struct btf_var_secinfo *bv = b;

	return av->offset - bv->offset;
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
	[BTF_KIND_VAR]          = "VAR",
	[BTF_KIND_DATASEC]      = "DATASEC",
	[BTF_KIND_FLOAT]        = "FLOAT",
};

static const char *btf__printable_name(const struct btf *btf, uint32_t offset)
{
	if (!offset)
		return "(anon)";
	else
		return btf__str_by_offset(btf, offset);
}

static const char * btf__int_encoding_str(uint8_t encoding)
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
static void btf__log_err(const struct btf *btf, int kind, const char *name,
			 bool output_cr, const char *fmt, ...)
{
	fprintf(stderr, "[%u] %s %s", btf__get_nr_types(btf) + 1,
		btf_kind_str[kind], name ?: "(anon)");

	if (fmt && *fmt) {
		va_list ap;

		fprintf(stderr, " ");
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	if (output_cr)
		fprintf(stderr, "\n");
}

__attribute ((format (printf, 5, 6)))
static void btf_encoder__log_type(const struct btf_encoder *encoder, const struct btf_type *t,
				  bool err, bool output_cr, const char *fmt, ...)
{
	const struct btf *btf = encoder->btf;
	uint8_t kind;
	FILE *out;

	if (!encoder->verbose && !err)
		return;

	kind = BTF_INFO_KIND(t->info);
	out = err ? stderr : stdout;

	fprintf(out, "[%u] %s %s",
		btf__get_nr_types(btf), btf_kind_str[kind],
		btf__printable_name(btf, t->name_off));

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
static void btf_encoder__log_member(const struct btf_encoder *encoder, const struct btf_type *t,
				    const struct btf_member *member, bool err, const char *fmt, ...)
{
	const struct btf *btf = encoder->btf;
	FILE *out;

	if (!encoder->verbose && !err)
		return;

	out = err ? stderr : stdout;

	if (btf_kflag(t))
		fprintf(out, "\t%s type_id=%u bitfield_size=%u bits_offset=%u",
			btf__printable_name(btf, member->name_off),
			member->type,
			BTF_MEMBER_BITFIELD_SIZE(member->offset),
			BTF_MEMBER_BIT_OFFSET(member->offset));
	else
		fprintf(out, "\t%s type_id=%u bits_offset=%u",
			btf__printable_name(btf, member->name_off),
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
static void btf_encoder__log_func_param(struct btf_encoder *encoder, const char *name, uint32_t type,
					bool err, bool is_last_param, const char *fmt, ...)
{
	FILE *out;

	if (!encoder->verbose && !err)
		return;

	out = err ? stderr : stdout;

	if (is_last_param && !type)
		fprintf(out, "vararg)\n");
	else
		fprintf(out, "%u %s%s", type, name, is_last_param ? ")\n" : ", ");

	if (fmt && *fmt) {
		va_list ap;

		fprintf(out, " ");
		va_start(ap, fmt);
		vfprintf(out, fmt, ap);
		va_end(ap);
	}
}

static int32_t btf_encoder__add_float(struct btf_encoder *encoder, const struct base_type *bt, const char *name)
{
	int32_t id = btf__add_float(encoder->btf, name, BITS_ROUNDUP_BYTES(bt->bit_size));

	if (id < 0) {
		btf__log_err(encoder->btf, BTF_KIND_FLOAT, name, true, "Error emitting BTF type");
	} else {
		const struct btf_type *t;

		t = btf__type_by_id(encoder->btf, id);
		btf_encoder__log_type(encoder, t, false, true, "size=%u nr_bits=%u", t->size, bt->bit_size);
	}

	return id;
}

static int32_t btf_encoder__add_base_type(struct btf_encoder *encoder, const struct base_type *bt, const char *name)
{
	const struct btf_type *t;
	uint8_t encoding = 0;
	uint16_t byte_sz;
	int32_t id;

	if (bt->is_signed) {
		encoding = BTF_INT_SIGNED;
	} else if (bt->is_bool) {
		encoding = BTF_INT_BOOL;
	} else if (bt->float_type && encoder->gen_floats) {
		/*
		 * Encode floats as BTF_KIND_FLOAT if allowed, otherwise (in
		 * compatibility mode) encode them as BTF_KIND_INT - that's not
		 * fully correct, but that's what it used to be.
		 */
		if (bt->float_type == BT_FP_SINGLE ||
		    bt->float_type == BT_FP_DOUBLE ||
		    bt->float_type == BT_FP_LDBL)
			return btf_encoder__add_float(encoder, bt, name);
		fprintf(stderr, "Complex, interval and imaginary float types are not supported\n");
		return -1;
	}

	/* dwarf5 may emit DW_ATE_[un]signed_{num} base types where
	 * {num} is not power of 2 and may exceed 128. Such attributes
	 * are mostly used to record operation for an actual parameter
	 * or variable.
	 * For example,
	 *     DW_AT_location        (indexed (0x3c) loclist = 0x00008fb0:
	 *         [0xffffffff82808812, 0xffffffff82808817):
	 *             DW_OP_breg0 RAX+0,
	 *             DW_OP_convert (0x000e97d5) "DW_ATE_unsigned_64",
	 *             DW_OP_convert (0x000e97df) "DW_ATE_unsigned_8",
	 *             DW_OP_stack_value,
	 *             DW_OP_piece 0x1,
	 *             DW_OP_breg0 RAX+0,
	 *             DW_OP_convert (0x000e97d5) "DW_ATE_unsigned_64",
	 *             DW_OP_convert (0x000e97da) "DW_ATE_unsigned_32",
	 *             DW_OP_lit8,
	 *             DW_OP_shr,
	 *             DW_OP_convert (0x000e97da) "DW_ATE_unsigned_32",
	 *             DW_OP_convert (0x000e97e4) "DW_ATE_unsigned_24",
	 *             DW_OP_stack_value, DW_OP_piece 0x3
	 *     DW_AT_name    ("ebx")
	 *     DW_AT_decl_file       ("/linux/arch/x86/events/intel/core.c")
	 *
	 * In the above example, at some point, one unsigned_32 value
	 * is right shifted by 8 and the result is converted to unsigned_32
	 * and then unsigned_24.
	 *
	 * BTF does not need such DW_OP_* information so let us sanitize
	 * these non-regular int types to avoid libbpf/kernel complaints.
	 */
	byte_sz = BITS_ROUNDUP_BYTES(bt->bit_size);
	if (!byte_sz || (byte_sz & (byte_sz - 1))) {
		name = "__SANITIZED_FAKE_INT__";
		byte_sz = 4;
	}

	id = btf__add_int(encoder->btf, name, byte_sz, encoding);
	if (id < 0) {
		btf__log_err(encoder->btf, BTF_KIND_INT, name, true, "Error emitting BTF type");
	} else {
		t = btf__type_by_id(encoder->btf, id);
		btf_encoder__log_type(encoder, t, false, true, "size=%u nr_bits=%u encoding=%s%s",
				      t->size, bt->bit_size, btf__int_encoding_str(encoding),
				      id < 0 ? " Error in emitting BTF" : "" );
	}

	return id;
}

static int32_t btf_encoder__add_ref_type(struct btf_encoder *encoder, uint16_t kind, uint32_t type,
					 const char *name, bool kind_flag)
{
	struct btf *btf = encoder->btf;
	const struct btf_type *t;
	int32_t id;

	switch (kind) {
	case BTF_KIND_PTR:
		id = btf__add_ptr(btf, type);
		break;
	case BTF_KIND_VOLATILE:
		id = btf__add_volatile(btf, type);
		break;
	case BTF_KIND_CONST:
		id = btf__add_const(btf, type);
		break;
	case BTF_KIND_RESTRICT:
		id = btf__add_restrict(btf, type);
		break;
	case BTF_KIND_TYPEDEF:
		id = btf__add_typedef(btf, name, type);
		break;
	case BTF_KIND_FWD:
		id = btf__add_fwd(btf, name, kind_flag);
		break;
	case BTF_KIND_FUNC:
		id = btf__add_func(btf, name, BTF_FUNC_STATIC, type);
		break;
	default:
		btf__log_err(btf, kind, name, true, "Unexpected kind for reference");
		return -1;
	}

	if (id > 0) {
		t = btf__type_by_id(btf, id);
		if (kind == BTF_KIND_FWD)
			btf_encoder__log_type(encoder, t, false, true, "%s", kind_flag ? "union" : "struct");
		else
			btf_encoder__log_type(encoder, t, false, true, "type_id=%u", t->type);
	} else {
		btf__log_err(btf, kind, name, true, "Error emitting BTF type");
	}
	return id;
}

static int32_t btf_encoder__add_array(struct btf_encoder *encoder, uint32_t type, uint32_t index_type, uint32_t nelems)
{
	struct btf *btf = encoder->btf;
	const struct btf_type *t;
	const struct btf_array *array;
	int32_t id;

	id = btf__add_array(btf, index_type, type, nelems);
	if (id > 0) {
		t = btf__type_by_id(btf, id);
		array = btf_array(t);
		btf_encoder__log_type(encoder, t, false, true, "type_id=%u index_type_id=%u nr_elems=%u",
				      array->type, array->index_type, array->nelems);
	} else {
		btf__log_err(btf, BTF_KIND_ARRAY, NULL, true,
			      "type_id=%u index_type_id=%u nr_elems=%u Error emitting BTF type",
			      type, index_type, nelems);
	}
	return id;
}

static int btf_encoder__add_field(struct btf_encoder *encoder, const char *name, uint32_t type, uint32_t bitfield_size, uint32_t offset)
{
	struct btf *btf = encoder->btf;
	const struct btf_type *t;
	const struct btf_member *m;
	int err;

	err = btf__add_field(btf, name, type, offset, bitfield_size);
	t = btf__type_by_id(btf, btf__get_nr_types(btf));
	if (err) {
		fprintf(stderr, "[%u] %s %s's field '%s' offset=%u bit_size=%u type=%u Error emitting field\n",
			btf__get_nr_types(btf), btf_kind_str[btf_kind(t)],
			btf__printable_name(btf, t->name_off),
			name, offset, bitfield_size, type);
	} else {
		m = &btf_members(t)[btf_vlen(t) - 1];
		btf_encoder__log_member(encoder, t, m, false, NULL);
	}
	return err;
}

static int32_t btf_encoder__add_struct(struct btf_encoder *encoder, uint8_t kind, const char *name, uint32_t size)
{
	struct btf *btf = encoder->btf;
	const struct btf_type *t;
	int32_t id;

	switch (kind) {
	case BTF_KIND_STRUCT:
		id = btf__add_struct(btf, name, size);
		break;
	case BTF_KIND_UNION:
		id = btf__add_union(btf, name, size);
		break;
	default:
		btf__log_err(btf, kind, name, true, "Unexpected kind of struct");
		return -1;
	}

	if (id < 0) {
		btf__log_err(btf, kind, name, true, "Error emitting BTF type");
	} else {
		t = btf__type_by_id(btf, id);
		btf_encoder__log_type(encoder, t, false, true, "size=%u", t->size);
	}

	return id;
}

static int32_t btf_encoder__add_enum(struct btf_encoder *encoder, const char *name, uint32_t bit_size)
{
	struct btf *btf = encoder->btf;
	const struct btf_type *t;
	int32_t id, size;

	size = BITS_ROUNDUP_BYTES(bit_size);
	id = btf__add_enum(btf, name, size);
	if (id > 0) {
		t = btf__type_by_id(btf, id);
		btf_encoder__log_type(encoder, t, false, true, "size=%u", t->size);
	} else {
		btf__log_err(btf, BTF_KIND_ENUM, name, true,
			      "size=%u Error emitting BTF type", size);
	}
	return id;
}

static int btf_encoder__add_enum_val(struct btf_encoder *encoder, const char *name, int32_t value)
{
	int err = btf__add_enum_value(encoder->btf, name, value);

	if (!err) {
		if (encoder->verbose)
			printf("\t%s val=%d\n", name, value);
	} else {
		fprintf(stderr, "\t%s val=%d Error emitting BTF enum value\n",
			name, value);
	}
	return err;
}

static int32_t btf_encoder__add_func_param(struct btf_encoder *encoder, const char *name, uint32_t type, bool is_last_param)
{
	int err = btf__add_func_param(encoder->btf, name, type);

	if (!err) {
		btf_encoder__log_func_param(encoder, name, type, false, is_last_param, NULL);
		return 0;
	} else {
		btf_encoder__log_func_param(encoder, name, type, true, is_last_param, "Error adding func param");
		return -1;
	}
}

static int32_t btf_encoder__add_func_proto(struct btf_encoder *encoder, struct ftype *ftype, uint32_t type_id_off)
{
	struct btf *btf = encoder->btf;
	const struct btf_type *t;
	struct parameter *param;
	uint16_t nr_params, param_idx;
	int32_t id, type_id;

	/* add btf_type for func_proto */
	nr_params = ftype->nr_parms + (ftype->unspec_parms ? 1 : 0);
	type_id = ftype->tag.type == 0 ? 0 : type_id_off + ftype->tag.type;

	id = btf__add_func_proto(btf, type_id);
	if (id > 0) {
		t = btf__type_by_id(btf, id);
		btf_encoder__log_type(encoder, t, false, false, "return=%u args=(%s", t->type, !nr_params ? "void)\n" : "");
	} else {
		btf__log_err(btf, BTF_KIND_FUNC_PROTO, NULL, true,
			      "return=%u vlen=%u Error emitting BTF type",
			      type_id, nr_params);
		return id;
	}

	/* add parameters */
	param_idx = 0;
	ftype__for_each_parameter(ftype, param) {
		const char *name = parameter__name(param);

		type_id = param->tag.type == 0 ? 0 : type_id_off + param->tag.type;
		++param_idx;
		if (btf_encoder__add_func_param(encoder, name, type_id, param_idx == nr_params))
			return -1;
	}

	++param_idx;
	if (ftype->unspec_parms)
		if (btf_encoder__add_func_param(encoder, NULL, 0, param_idx == nr_params))
			return -1;

	return id;
}

static int32_t btf_encoder__add_var(struct btf_encoder *encoder, uint32_t type, const char *name, uint32_t linkage)
{
	struct btf *btf = encoder->btf;
	const struct btf_type *t;
	int32_t id;

	id = btf__add_var(btf, name, linkage, type);
	if (id > 0) {
		t = btf__type_by_id(btf, id);
		btf_encoder__log_type(encoder, t, false, true, "type=%u linkage=%u", t->type, btf_var(t)->linkage);
	} else {
		btf__log_err(btf, BTF_KIND_VAR, name, true,
			      "type=%u linkage=%u Error emitting BTF type",
			      type, linkage);
	}
	return id;
}

static int32_t btf_encoder__add_var_secinfo(struct btf_encoder *encoder, uint32_t type,
				     uint32_t offset, uint32_t size)
{
	struct btf_var_secinfo si = {
		.type = type,
		.offset = offset,
		.size = size,
	};
	return gobuffer__add(&encoder->percpu_secinfo, &si, sizeof(si));
}

static int32_t btf_encoder__add_datasec(struct btf_encoder *encoder, const char *section_name)
{
	struct gobuffer *var_secinfo_buf = &encoder->percpu_secinfo;
	struct btf *btf = encoder->btf;
	size_t sz = gobuffer__size(var_secinfo_buf);
	uint16_t nr_var_secinfo = sz / sizeof(struct btf_var_secinfo);
	struct btf_var_secinfo *last_vsi, *vsi;
	const struct btf_type *t;
	uint32_t datasec_sz;
	int32_t err, id, i;

	qsort(var_secinfo_buf->entries, nr_var_secinfo,
	      sizeof(struct btf_var_secinfo), btf_var_secinfo_cmp);

	last_vsi = (struct btf_var_secinfo *)var_secinfo_buf->entries + nr_var_secinfo - 1;
	datasec_sz = last_vsi->offset + last_vsi->size;

	id = btf__add_datasec(btf, section_name, datasec_sz);
	if (id < 0) {
		btf__log_err(btf, BTF_KIND_DATASEC, section_name, true,
				 "size=%u vlen=%u Error emitting BTF type",
				 datasec_sz, nr_var_secinfo);
	} else {
		t = btf__type_by_id(btf, id);
		btf_encoder__log_type(encoder, t, false, true, "size=%u vlen=%u", t->size, nr_var_secinfo);
	}

	for (i = 0; i < nr_var_secinfo; i++) {
		vsi = (struct btf_var_secinfo *)var_secinfo_buf->entries + i;
		err = btf__add_datasec_var_info(btf, vsi->type, vsi->offset, vsi->size);
		if (!err) {
			if (encoder->verbose)
				printf("\ttype=%u offset=%u size=%u\n",
				       vsi->type, vsi->offset, vsi->size);
		} else {
			fprintf(stderr, "\ttype=%u offset=%u size=%u Error emitting BTF datasec var info\n",
				       vsi->type, vsi->offset, vsi->size);
			return -1;
		}
	}

	return id;
}

/*
 * This corresponds to the same macro defined in
 * include/linux/kallsyms.h
 */
#define KSYM_NAME_LEN 128

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

static int32_t btf_encoder__add_struct_type(struct btf_encoder *encoder, struct tag *tag, uint32_t type_id_off)
{
	struct type *type = tag__type(tag);
	struct class_member *pos;
	const char *name = type__name(type);
	int32_t type_id;
	uint8_t kind;

	kind = (tag->tag == DW_TAG_union_type) ?
		BTF_KIND_UNION : BTF_KIND_STRUCT;

	type_id = btf_encoder__add_struct(encoder, kind, name, type->size);
	if (type_id < 0)
		return type_id;

	type__for_each_data_member(type, pos) {
		/*
		 * dwarf_loader uses DWARF's recommended bit offset addressing
		 * scheme, which conforms to BTF requirement, so no conversion
		 * is required.
		 */
		name = class_member__name(pos);
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

static int32_t btf_encoder__add_enum_type(struct btf_encoder *encoder, struct tag *tag)
{
	struct type *etype = tag__type(tag);
	struct enumerator *pos;
	const char *name = type__name(etype);
	int32_t type_id;

	type_id = btf_encoder__add_enum(encoder, name, etype->size);
	if (type_id < 0)
		return type_id;

	type__for_each_enumerator(etype, pos) {
		name = enumerator__name(pos);
		if (btf_encoder__add_enum_val(encoder, name, pos->value))
			return -1;
	}

	return type_id;
}

static int btf_encoder__encode_tag(struct btf_encoder *encoder, struct tag *tag, uint32_t type_id_off)
{
	/* single out type 0 as it represents special type "void" */
	uint32_t ref_type_id = tag->type == 0 ? 0 : type_id_off + tag->type;
	struct base_type *bt;
	const char *name;

	switch (tag->tag) {
	case DW_TAG_base_type:
		bt   = tag__base_type(tag);
		name = __base_type__name(bt);
		return btf_encoder__add_base_type(encoder, bt, name);
	case DW_TAG_const_type:
		return btf_encoder__add_ref_type(encoder, BTF_KIND_CONST, ref_type_id, NULL, false);
	case DW_TAG_pointer_type:
		return btf_encoder__add_ref_type(encoder, BTF_KIND_PTR, ref_type_id, NULL, false);
	case DW_TAG_restrict_type:
		return btf_encoder__add_ref_type(encoder, BTF_KIND_RESTRICT, ref_type_id, NULL, false);
	case DW_TAG_volatile_type:
		return btf_encoder__add_ref_type(encoder, BTF_KIND_VOLATILE, ref_type_id, NULL, false);
	case DW_TAG_typedef:
		name = namespace__name(tag__namespace(tag));
		return btf_encoder__add_ref_type(encoder, BTF_KIND_TYPEDEF, ref_type_id, name, false);
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
	case DW_TAG_class_type:
		name = namespace__name(tag__namespace(tag));
		if (tag__type(tag)->declaration)
			return btf_encoder__add_ref_type(encoder, BTF_KIND_FWD, 0, name, tag->tag == DW_TAG_union_type);
		else
			return btf_encoder__add_struct_type(encoder, tag, type_id_off);
	case DW_TAG_array_type:
		/* TODO: Encode one dimension at a time. */
		encoder->need_index_type = true;
		return btf_encoder__add_array(encoder, ref_type_id, encoder->array_index_id, array_type__nelems(tag));
	case DW_TAG_enumeration_type:
		return btf_encoder__add_enum_type(encoder, tag);
	case DW_TAG_subroutine_type:
		return btf_encoder__add_func_proto(encoder, tag__ftype(tag), type_id_off);
	default:
		fprintf(stderr, "Unsupported DW_TAG_%s(0x%x)\n",
			dwarf_tag_name(tag->tag), tag->tag);
		return -1;
	}
}

static int btf_encoder__write_raw_file(struct btf_encoder *encoder)
{
	const char *filename = encoder->filename;
	uint32_t raw_btf_size;
	const void *raw_btf_data;
	int fd, err;

	raw_btf_data = btf__get_raw_data(encoder->btf, &raw_btf_size);
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

	if ((uint32_t)err != raw_btf_size) {
		fprintf(stderr, "%s: Could only write %d bytes to %s of raw BTF info out of %d, aborting\n", __func__, err, filename, raw_btf_size);
		unlink(filename);
		err = -1;
	} else {
		/* go from bytes written == raw_btf_size to an indication that all went fine */
		err = 0;
	}

	return err;
}

static int btf_encoder__write_elf(struct btf_encoder *encoder)
{
	struct btf *btf = encoder->btf;
	const char *filename = encoder->filename;
	GElf_Shdr shdr_mem, *shdr;
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

int btf_encoder__encode(struct btf_encoder *encoder)
{
	int err;

	if (gobuffer__size(&encoder->percpu_secinfo) != 0)
		btf_encoder__add_datasec(encoder, PERCPU_SECTION);

	/* Empty file, nothing to do, so... done! */
	if (btf__get_nr_types(encoder->btf) == 0)
		return 0;

	if (btf__dedup(encoder->btf, NULL, NULL)) {
		fprintf(stderr, "%s: btf__dedup failed!\n", __func__);
		return -1;
	}

	if (encoder->raw_output)
		err = btf_encoder__write_raw_file(encoder);
	else
		err = btf_encoder__write_elf(encoder);

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

static bool ftype__has_arg_names(const struct ftype *ftype)
{
	struct parameter *param;

	ftype__for_each_parameter(ftype, param) {
		if (parameter__name(param) == NULL)
			return false;
	}
	return true;
}

static int btf_encoder__encode_cu_variables(struct btf_encoder *encoder, struct cu *cu, uint32_t type_id_off)
{
	uint32_t core_id;
	struct tag *pos;
	int err = -1;

	if (encoder->percpu.shndx == 0 || !encoder->symtab)
		return 0;

	if (encoder->verbose)
		printf("search cu '%s' for percpu global variables.\n", cu->name);

	cu__for_each_variable(cu, core_id, pos) {
		struct variable *var = tag__variable(pos);
		uint32_t size, type, linkage;
		const char *name, *dwarf_name;
		const struct tag *tag;
		uint64_t addr;
		int id;

		if (var->declaration && !var->spec)
			continue;

		/* percpu variables are allocated in global space */
		if (variable__scope(var) != VSCOPE_GLOBAL && !var->spec)
			continue;

		/* addr has to be recorded before we follow spec */
		addr = var->ip.addr;
		dwarf_name = variable__name(var);

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
		id = btf_encoder__add_var(encoder, type, name, linkage);
		if (id < 0) {
			fprintf(stderr, "error: failed to encode variable '%s' at addr 0x%" PRIx64 "\n",
			        name, addr);
			goto out;
		}

		/*
		 * add a BTF_VAR_SECINFO in encoder->percpu_secinfo, which will be added into
		 * encoder->types later when we add BTF_VAR_DATASEC.
		 */
		id = btf_encoder__add_var_secinfo(encoder, id, addr, size);
		if (id < 0) {
			fprintf(stderr, "error: failed to encode section info for variable '%s' at addr 0x%" PRIx64 "\n",
			        name, addr);
			goto out;
		}
	}

	err = 0;
out:
	return err;
}

struct btf_encoder *btf_encoder__new(struct cu *cu, const char *detached_filename, struct btf *base_btf, bool skip_encoding_vars, bool force, bool gen_floats, bool verbose)
{
	struct btf_encoder *encoder = zalloc(sizeof(*encoder));

	if (encoder) {
		encoder->raw_output = detached_filename != NULL;
		encoder->filename = strdup(encoder->raw_output ? detached_filename : cu->filename);
		if (encoder->filename == NULL)
			goto out_delete;

		encoder->btf = btf__new_empty_split(base_btf);
		if (encoder->btf == NULL)
			goto out_delete;

		encoder->force		 = force;
		encoder->gen_floats	 = gen_floats;
		encoder->skip_encoding_vars = skip_encoding_vars;
		encoder->verbose	 = verbose;
		encoder->has_index_type  = false;
		encoder->need_index_type = false;
		encoder->array_index_id  = 0;

		GElf_Ehdr ehdr;

		if (gelf_getehdr(cu->elf, &ehdr) == NULL) {
			if (encoder->verbose)
				elf_error("cannot get ELF header");
			goto out_delete;
		}

		switch (ehdr.e_ident[EI_DATA]) {
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

		encoder->symtab = elf_symtab__new(NULL, cu->elf);
		if (!encoder->symtab) {
			if (encoder->verbose)
				printf("%s: '%s' doesn't have symtab.\n", __func__, cu->filename);
			goto out;
		}

		/* find percpu section's shndx */

		GElf_Shdr shdr;
		Elf_Scn *sec = elf_section_by_name(cu->elf, &shdr, PERCPU_SECTION, NULL);

		if (!sec) {
			if (encoder->verbose)
				printf("%s: '%s' doesn't have '%s' section\n", __func__, cu->filename, PERCPU_SECTION);
		} else {
			encoder->percpu.shndx	  = elf_ndxscn(sec);
			encoder->percpu.base_addr = shdr.sh_addr;
			encoder->percpu.sec_sz	  = shdr.sh_size;
		}

		if (btf_encoder__collect_symbols(encoder, !encoder->skip_encoding_vars))
			goto out_delete;

		if (encoder->verbose)
			printf("File %s:\n", cu->filename);
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

int btf_encoder__encode_cu(struct btf_encoder *encoder, struct cu *cu)
{
	uint32_t type_id_off = btf__get_nr_types(encoder->btf);
	uint32_t core_id;
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
		int32_t btf_type_id = btf_encoder__encode_tag(encoder, pos, type_id_off);

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
		if (!ftype__has_arg_names(&fn->proto))
			continue;
		if (encoder->functions.cnt) {
			struct elf_function *func;
			const char *name;

			name = function__name(fn);
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

		btf_fnproto_id = btf_encoder__add_func_proto(encoder, &fn->proto, type_id_off);
		name = function__name(fn);
		btf_fn_id = btf_encoder__add_ref_type(encoder, BTF_KIND_FUNC, btf_fnproto_id, name, false);
		if (btf_fnproto_id < 0 || btf_fn_id < 0) {
			err = -1;
			printf("error: failed to encode function '%s'\n", function__name(fn));
			goto out;
		}
	}

	if (!encoder->skip_encoding_vars)
		err = btf_encoder__encode_cu_variables(encoder, cu, type_id_off);
out:
	return err;
}
