/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook
 */

#include <fcntl.h>
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
#include "btf_encoder.h"

/*
 * This depends on the GNU extension to eliminate the stray comma in the zero
 * arguments case.
 *
 * The difference between elf_errmsg(-1) and elf_errmsg(elf_errno()) is that the
 * latter clears the current error.
 */
#define elf_error(fmt, ...) \
	fprintf(stderr, "%s: " fmt ": %s.\n", __func__, ##__VA_ARGS__, elf_errmsg(-1))

bool btf_gen_floats = false;

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
static void btf__log_type(const struct btf *btf, const struct btf_type *t,
			      bool err, bool output_cr, const char *fmt, ...)
{
	uint8_t kind;
	FILE *out;

	if (!btf_encoder__verbose && !err)
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
static void btf__log_member(const struct btf *btf,
			   const struct btf_type *t,
			   const struct btf_member *member,
			   bool err, const char *fmt, ...)
{
	FILE *out;

	if (!btf_encoder__verbose && !err)
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

__attribute ((format (printf, 5, 6)))
static void btf__log_func_param(const char *name, uint32_t type,
			       bool err, bool is_last_param,
			       const char *fmt, ...)
{
	FILE *out;

	if (!btf_encoder__verbose && !err)
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
		btf__log_type(encoder->btf, t, false, true, "size=%u nr_bits=%u", t->size, bt->bit_size);
	}

	return id;
}

int32_t btf_encoder__add_base_type(struct btf_encoder *encoder, const struct base_type *bt, const char *name)
{
	const struct btf_type *t;
	uint8_t encoding = 0;
	uint16_t byte_sz;
	int32_t id;

	if (bt->is_signed) {
		encoding = BTF_INT_SIGNED;
	} else if (bt->is_bool) {
		encoding = BTF_INT_BOOL;
	} else if (bt->float_type && btf_gen_floats) {
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
		btf__log_type(encoder->btf, t, false, true,
				"size=%u nr_bits=%u encoding=%s%s",
				t->size, bt->bit_size,
				btf__int_encoding_str(encoding),
				id < 0 ? " Error in emitting BTF" : "" );
	}

	return id;
}

int32_t btf_encoder__add_ref_type(struct btf_encoder *encoder, uint16_t kind, uint32_t type,
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
			btf__log_type(btf, t, false, true, "%s", kind_flag ? "union" : "struct");
		else
			btf__log_type(btf, t, false, true, "type_id=%u", t->type);
	} else {
		btf__log_err(btf, kind, name, true, "Error emitting BTF type");
	}
	return id;
}

int32_t btf_encoder__add_array(struct btf_encoder *encoder, uint32_t type, uint32_t index_type, uint32_t nelems)
{
	struct btf *btf = encoder->btf;
	const struct btf_type *t;
	const struct btf_array *array;
	int32_t id;

	id = btf__add_array(btf, index_type, type, nelems);
	if (id > 0) {
		t = btf__type_by_id(btf, id);
		array = btf_array(t);
		btf__log_type(btf, t, false, true,
			      "type_id=%u index_type_id=%u nr_elems=%u",
			      array->type, array->index_type, array->nelems);
	} else {
		btf__log_err(btf, BTF_KIND_ARRAY, NULL, true,
			      "type_id=%u index_type_id=%u nr_elems=%u Error emitting BTF type",
			      type, index_type, nelems);
	}
	return id;
}

int btf_encoder__add_field(struct btf_encoder *encoder, const char *name, uint32_t type, uint32_t bitfield_size, uint32_t offset)
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
		btf__log_member(btf, t, m, false, NULL);
	}
	return err;
}

int32_t btf_encoder__add_struct(struct btf_encoder *encoder, uint8_t kind, const char *name, uint32_t size)
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
		btf__log_type(btf, t, false, true, "size=%u", t->size);
	}

	return id;
}

int32_t btf__encode_enum(struct btf *btf, const char *name, uint32_t bit_size)
{
	const struct btf_type *t;
	int32_t id, size;

	size = BITS_ROUNDUP_BYTES(bit_size);
	id = btf__add_enum(btf, name, size);
	if (id > 0) {
		t = btf__type_by_id(btf, id);
		btf__log_type(btf, t, false, true, "size=%u", t->size);
	} else {
		btf__log_err(btf, BTF_KIND_ENUM, name, true,
			      "size=%u Error emitting BTF type", size);
	}
	return id;
}

int btf__encode_enum_val(struct btf *btf, const char *name, int32_t value)
{
	int err;

	err = btf__add_enum_value(btf, name, value);
	if (!err) {
		if (btf_encoder__verbose)
			printf("\t%s val=%d\n", name, value);
	} else {
		fprintf(stderr, "\t%s val=%d Error emitting BTF enum value\n",
			name, value);
	}
	return err;
}

static int32_t btf__encode_func_proto_param(struct btf *btf, const char *name,
					    uint32_t type, bool is_last_param)
{
	int err;

	err = btf__add_func_param(btf, name, type);
	if (!err) {
		btf__log_func_param(name, type, false, is_last_param, NULL);
		return 0;
	} else {
		btf__log_func_param(name, type, true, is_last_param,
				   "Error adding func param");
		return -1;
	}
}

extern struct debug_fmt_ops *dwarves__active_loader;

int32_t btf_encoder__add_func_proto(struct btf_encoder *encoder, struct cu *cu, struct ftype *ftype, uint32_t type_id_off)
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
		btf__log_type(btf, t, false, false, "return=%u args=(%s",
			      t->type, !nr_params ? "void)\n" : "");
	} else {
		btf__log_err(btf, BTF_KIND_FUNC_PROTO, NULL, true,
			      "return=%u vlen=%u Error emitting BTF type",
			      type_id, nr_params);
		return id;
	}

	/* add parameters */
	param_idx = 0;
	ftype__for_each_parameter(ftype, param) {
		const char *name = dwarves__active_loader->strings__ptr(cu, param->name);

		type_id = param->tag.type == 0 ? 0 : type_id_off + param->tag.type;
		++param_idx;
		if (btf__encode_func_proto_param(btf, name, type_id, param_idx == nr_params))
			return -1;
	}

	++param_idx;
	if (ftype->unspec_parms)
		if (btf__encode_func_proto_param(btf, NULL, 0, param_idx == nr_params))
			return -1;

	return id;
}

int32_t btf__encode_var_type(struct btf *btf, uint32_t type, const char *name, uint32_t linkage)
{
	const struct btf_type *t;
	int32_t id;

	id = btf__add_var(btf, name, linkage, type);
	if (id > 0) {
		t = btf__type_by_id(btf, id);
		btf__log_type(btf, t, false, true, "type=%u linkage=%u",
				  t->type, btf_var(t)->linkage);
	} else {
		btf__log_err(btf, BTF_KIND_VAR, name, true,
			      "type=%u linkage=%u Error emitting BTF type",
			      type, linkage);
	}
	return id;
}

int32_t btf__encode_var_secinfo(struct gobuffer *buf, uint32_t type,
				uint32_t offset, uint32_t size)
{
	struct btf_var_secinfo si = {
		.type = type,
		.offset = offset,
		.size = size,
	};
	return gobuffer__add(buf, &si, sizeof(si));
}

int32_t btf__encode_datasec_type(struct btf *btf, const char *section_name,
				 struct gobuffer *var_secinfo_buf)
{
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
		btf__log_type(btf, t, false, true, "size=%u vlen=%u",
				  t->size, nr_var_secinfo);
	}

	for (i = 0; i < nr_var_secinfo; i++) {
		vsi = (struct btf_var_secinfo *)var_secinfo_buf->entries + i;
		err = btf__add_datasec_var_info(btf, vsi->type, vsi->offset, vsi->size);
		if (!err) {
			if (btf_encoder__verbose)
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
