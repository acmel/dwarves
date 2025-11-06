/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook

  Derived from ctf_encoder.c, which is:

  Copyright (C) Arnaldo Carvalho de Melo <acme@redhat.com>
  Copyright (C) Red Hat Inc
 */

#include <linux/btf.h>
#include "dwarves.h"
#include "elf_symtab.h"
#include "btf_encoder.h"
#include "gobuffer.h"

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

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <search.h> /* for tsearch(), tfind() and tdestroy() */
#include <pthread.h>

#define BTF_BASE_ELF_SEC	".BTF.base"
#define BTF_IDS_SECTION		".BTF_ids"
#define BTF_ID_FUNC_PFX		"__BTF_ID__func__"
#define BTF_ID_SET8_PFX		"__BTF_ID__set8__"
#define BTF_SET8_KFUNCS		(1 << 0)
#define BTF_KFUNC_TYPE_TAG	"bpf_kfunc"
#define BTF_FASTCALL_TAG       "bpf_fastcall"
#define BPF_ARENA_ATTR         "address_space(1)"

/* kfunc flags, see include/linux/btf.h in the kernel source */
#define KF_FASTCALL   (1 << 12)
#define KF_ARENA_RET  (1 << 13)
#define KF_ARENA_ARG1 (1 << 14)
#define KF_ARENA_ARG2 (1 << 15)

struct btf_id_and_flag {
	uint32_t id;
	uint32_t flags;
};

/*
 * This corresponds to the same macro defined in
 * include/linux/kallsyms.h
 */
#define KSYM_NAME_LEN 128

/* Adapted from include/linux/btf_ids.h */
struct btf_id_set8 {
        uint32_t cnt;
        uint32_t flags;
	struct btf_id_and_flag pairs[];
};

struct btf_encoder_func_parm {
	int name_off;
	uint32_t type_id;
};

struct btf_encoder_func_annot {
	int value;
	int16_t component_idx;
};

/* state used to do later encoding of saved functions */
struct btf_encoder_func_state {
	struct elf_function *elf;
	uint32_t type_id_off;
	uint16_t nr_parms;
	uint16_t nr_annots;
	uint8_t optimized_parms:1;
	uint8_t unexpected_reg:1;
	uint8_t inconsistent_proto:1;
	uint8_t uncertain_parm_loc:1;
	uint8_t ambiguous_addr:1;
	int ret_type_id;
	struct btf_encoder_func_parm *parms;
	struct btf_encoder_func_annot *annots;
};

struct elf_function_sym {
	const char *name;
	uint64_t addr;
};

struct elf_function {
	char		*name;
	struct elf_function_sym *syms;
	uint16_t	sym_cnt;
	uint16_t 	ambiguous_addr:1;
	uint16_t	kfunc:1;
	uint32_t	kfunc_flags;
};

struct elf_secinfo {
	uint64_t    addr;
	const char *name;
	uint64_t    sz;
	uint32_t    type;
	bool        include;
	struct gobuffer secinfo;
};

struct elf_functions {
	struct list_head node; /* for elf_functions_list */
	Elf *elf; /* source ELF */
	struct elf_symtab *symtab;
	struct elf_function *entries;
	int cnt;
};

/*
 * cu: cu being processed.
 */
struct btf_encoder {
	struct list_head  node;
	struct btf        *btf;
	struct cu         *cu;
	const char	  *source_filename;
	const char	  *filename;
	struct elf_symtab *symtab;
	uint32_t	  type_id_off;
	bool		  has_index_type,
			  need_index_type,
			  raw_output,
			  verbose,
			  force,
			  gen_floats,
			  skip_encoding_decl_tag,
			  tag_kfuncs,
			  gen_distilled_base,
			  encode_attributes;
	uint32_t	  array_index_id;
	struct elf_secinfo *secinfo;
	size_t             seccnt;
	int                encode_vars;
	struct {
		struct btf_encoder_func_state *array;
		int cnt;
		int cap;
	} func_states;
	/* This is a list of elf_functions tables, one per ELF.
	 * Multiple ELF modules can be processed in one pahole run,
	 * so we have to store elf_functions tables per ELF.
	 */
	struct list_head elf_functions_list;
};

/* Half open interval representing range of addresses containing kfuncs */
struct btf_kfunc_set_range {
	uint64_t start;
	uint64_t end;
};

static inline void elf_function__clear(struct elf_function *func)
{
	free(func->name);
	if (func->sym_cnt)
		free(func->syms);
	memset(func, 0, sizeof(*func));
}

static inline void elf_functions__delete(struct elf_functions *funcs)
{
	for (int i = 0; i < funcs->cnt; i++)
		elf_function__clear(&funcs->entries[i]);
	free(funcs->entries);
	elf_symtab__delete(funcs->symtab);
	free(funcs);
}

static int elf_functions__collect(struct elf_functions *functions);

struct elf_functions *elf_functions__new(Elf *elf)
{
	struct elf_functions *funcs;
	int err;

	funcs = calloc(1, sizeof(*funcs));
	if (!funcs) {
		err = -ENOMEM;
		goto out_delete;
	}

	funcs->symtab = elf_symtab__new(NULL, elf);
	if (!funcs->symtab) {
		err = -1;
		goto out_delete;
	}

	funcs->elf = elf;
	err = elf_functions__collect(funcs);
	if (err < 0)
		goto out_delete;

	return funcs;

out_delete:
	elf_functions__delete(funcs);
	return NULL;
}

static inline void elf_functions_list__clear(struct list_head *elf_functions_list)
{
	struct elf_functions *funcs;
	struct list_head *pos, *tmp;

	list_for_each_safe(pos, tmp, elf_functions_list) {
		funcs = list_entry(pos, struct elf_functions, node);
		list_del(&funcs->node);
		elf_functions__delete(funcs);
	}
}

static struct elf_functions *elf_functions__find(const Elf *elf, const struct list_head *elf_functions_list)
{
	struct elf_functions *funcs;
	struct list_head *pos;

	list_for_each(pos, elf_functions_list) {
		funcs = list_entry(pos, struct elf_functions, node);
		if (funcs->elf == elf)
			return funcs;
	}
	return NULL;
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

static const char * const btf_kind_str[] = {
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
	[BTF_KIND_DECL_TAG]     = "DECL_TAG",
	[BTF_KIND_TYPE_TAG]     = "TYPE_TAG",
	[BTF_KIND_ENUM64]	= "ENUM64",
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

__attribute ((format (printf, 6, 7)))
static void btf__log_err(const struct btf *btf, int kind, const char *name,
			 bool output_cr, int libbpf_err, const char *fmt, ...)
{
	fprintf(stderr, "[%u] %s %s", btf__type_cnt(btf),
		btf_kind_str[kind], name ?: "(anon)");

	if (fmt && *fmt) {
		va_list ap;

		fprintf(stderr, " ");
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	if (libbpf_err < 0)
		fprintf(stderr, " (libbpf error %d)", libbpf_err);

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
		btf__type_cnt(btf) - 1, btf_kind_str[kind],
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
		btf__log_err(encoder->btf, BTF_KIND_FLOAT, name, true, id,
			     "Error emitting BTF type");
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
	if (!byte_sz || (byte_sz & (byte_sz - 1)) || byte_sz > 16) {
		name = "__SANITIZED_FAKE_INT__";
		byte_sz = 4;
	}

	id = btf__add_int(encoder->btf, name, byte_sz, encoding);
	if (id < 0) {
		btf__log_err(encoder->btf, BTF_KIND_INT, name, true, id, "Error emitting BTF type");
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
	case BTF_KIND_TYPE_TAG:
		id = btf__add_type_tag(btf, name, type);
		break;
	case BTF_KIND_FWD:
		id = btf__add_fwd(btf, name, kind_flag);
		break;
	case BTF_KIND_FUNC:
		id = btf__add_func(btf, name, BTF_FUNC_STATIC, type);
		break;
	default:
		btf__log_err(btf, kind, name, true, 0, "Unexpected kind for reference");
		return -1;
	}

	if (id > 0) {
		t = btf__type_by_id(btf, id);
		if (kind == BTF_KIND_FWD)
			btf_encoder__log_type(encoder, t, false, true, "%s", kind_flag ? "union" : "struct");
		else
			btf_encoder__log_type(encoder, t, false, true, "type_id=%u", t->type);
	} else {
		btf__log_err(btf, kind, name, true, id, "Error emitting BTF type");
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
		btf__log_err(btf, BTF_KIND_ARRAY, NULL, true, id,
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
	t = btf__type_by_id(btf, btf__type_cnt(btf) - 1);
	if (err) {
		fprintf(stderr, "[%u] %s %s's field '%s' offset=%u bit_size=%u type=%u Error emitting field\n",
			btf__type_cnt(btf) - 1, btf_kind_str[btf_kind(t)],
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
		btf__log_err(btf, kind, name, true, 0, "Unexpected kind of struct");
		return -1;
	}

	if (id < 0) {
		btf__log_err(btf, kind, name, true, id, "Error emitting BTF type");
	} else {
		t = btf__type_by_id(btf, id);
		btf_encoder__log_type(encoder, t, false, true, "size=%u", t->size);
	}

	return id;
}

static int32_t btf_encoder__add_enum(struct btf_encoder *encoder, const char *name, struct type *etype,
				     struct conf_load *conf_load)
{
	struct btf *btf = encoder->btf;
	const struct btf_type *t;
	int32_t id, size;
	bool is_enum32;

	size = BITS_ROUNDUP_BYTES(etype->size);
	is_enum32 = size <= 4 || conf_load->skip_encoding_btf_enum64;
	if (is_enum32)
		id = btf__add_enum(btf, name, size);
	else if (btf__add_enum64)
		id = btf__add_enum64(btf, name, size, etype->is_signed_enum);
	else {
		fprintf(stderr, "btf__add_enum64 is not available, is libbpf < 1.0?\n");
		return -ENOTSUP;
	}

	if (id > 0) {
		t = btf__type_by_id(btf, id);
		btf_encoder__log_type(encoder, t, false, true, "size=%u", t->size);
	} else {
		btf__log_err(btf, is_enum32 ? BTF_KIND_ENUM : BTF_KIND_ENUM64, name, true, id,
			      "size=%u Error emitting BTF type", size);
	}
	return id;
}

static int btf_encoder__add_enum_val(struct btf_encoder *encoder, const char *name, int64_t value,
				     struct type *etype, struct conf_load *conf_load)
{
	const char *fmt_str;
	int err;

	/* If enum64 is not allowed, generate enum32 with unsigned int value. In enum64-supported
	 * libbpf library, btf__add_enum_value() will set the kflag (sign bit) in common_type
	 * if the value is negative.
	 */
	if (conf_load->skip_encoding_btf_enum64)
		err = btf__add_enum_value(encoder->btf, name, (uint32_t)value);
	else if (etype->size <= 32)
		err = btf__add_enum_value(encoder->btf, name, value);
	else if (btf__add_enum64_value)
		err = btf__add_enum64_value(encoder->btf, name, value);
	else {
		fprintf(stderr, "btf__add_enum64_value is not available, is libbpf < 1.0?\n");
		return -ENOTSUP;
	}

	if (!err) {
		if (encoder->verbose) {
			if (conf_load->skip_encoding_btf_enum64) {
				printf("\t%s val=%u\n", name, (uint32_t)value);
			} else {
				fmt_str = etype->is_signed_enum ? "\t%s val=%lld\n" : "\t%s val=%llu\n";
				printf(fmt_str, name, (unsigned long long)value);
			}
		}
	} else {
		if (conf_load->skip_encoding_btf_enum64) {
			fprintf(stderr, "\t%s val=%u Error emitting BTF enum value\n", name, (uint32_t)value);
		} else {
			fmt_str = etype->is_signed_enum ? "\t%s val=%lld Error emitting BTF enum value\n"
							: "\t%s val=%llu Error emitting BTF enum value\n";
			fprintf(stderr, fmt_str, name, (unsigned long long)value);
		}
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

static int32_t btf_encoder__tag_type(struct btf_encoder *encoder, uint32_t tag_type)
{
	if (tag_type == 0)
		return 0;

	return encoder->type_id_off + tag_type;
}

static int btf__tag_bpf_arena_ptr(struct btf *btf, int ptr_id)
{
	const struct btf_type *ptr;
	int tagged_type_id;

	ptr = btf__type_by_id(btf, ptr_id);
	if (!btf_is_ptr(ptr))
		return -EINVAL;

	tagged_type_id = btf__add_type_attr(btf, BPF_ARENA_ATTR, ptr->type);
	if (tagged_type_id < 0)
		return tagged_type_id;

	return btf__add_ptr(btf, tagged_type_id);
}

static int btf__tag_bpf_arena_arg(struct btf *btf, struct btf_encoder_func_state *state, int idx)
{
	int id;

	if (state->nr_parms <= idx)
		return -EINVAL;

	id = btf__tag_bpf_arena_ptr(btf, state->parms[idx].type_id);
	if (id < 0) {
		btf__log_err(btf, BTF_KIND_TYPE_TAG, BPF_ARENA_ATTR, true, id,
			"Error adding BPF_ARENA_ATTR for an argument of kfunc '%s'", state->elf->name);
		return id;
	}
	state->parms[idx].type_id = id;

	return id;
}

static int btf__add_bpf_arena_type_tags(struct btf *btf, struct btf_encoder_func_state *state)
{
	uint32_t flags = state->elf->kfunc_flags;
	int ret_type_id;
	int err;

	if (!btf__add_type_attr) {
		fprintf(stderr, "btf__add_type_attr is not available, is libbpf < 1.6?\n");
		return -ENOTSUP;
	}

	if (KF_ARENA_RET & flags) {
		ret_type_id = btf__tag_bpf_arena_ptr(btf, state->ret_type_id);
		if (ret_type_id < 0) {
			btf__log_err(btf, BTF_KIND_TYPE_TAG, BPF_ARENA_ATTR, true, ret_type_id,
				"Error adding BPF_ARENA_ATTR for return type of kfunc '%s'", state->elf->name);
			return ret_type_id;
		}
		state->ret_type_id = ret_type_id;
	}

	if (KF_ARENA_ARG1 & flags) {
		err = btf__tag_bpf_arena_arg(btf, state, 0);
		if (err < 0)
			return err;
	}

	if (KF_ARENA_ARG2 & flags) {
		err = btf__tag_bpf_arena_arg(btf, state, 1);
		if (err < 0)
			return err;
	}

	return 0;
}

static inline bool is_kfunc_state(struct btf_encoder_func_state *state)
{
	return state && state->elf && state->elf->kfunc;
}

static int32_t btf_encoder__emit_func_proto(struct btf_encoder *encoder,
					    uint32_t type_id,
					    uint16_t nr_params)
{
	const struct btf_type *t;
	uint32_t ret;

	ret = btf__add_func_proto(encoder->btf, type_id);
	if (ret > 0) {
		t = btf__type_by_id(encoder->btf, ret);
		btf_encoder__log_type(encoder, t, false, false,
			"return=%u args=(%s", t->type, !nr_params ? "void)\n" : "");
	} else {
		btf__log_err(encoder->btf, BTF_KIND_FUNC_PROTO, NULL, true, ret,
			     "return=%u vlen=%u Error emitting BTF type",
			     type_id, nr_params);
	}

	return ret;
}

static int32_t btf_encoder__add_func_proto_for_ftype(struct btf_encoder *encoder,
						     struct ftype *ftype)
{
	uint16_t nr_params, param_idx;
	struct parameter *param;
	int32_t id, type_id;
	const char *name;

	assert(ftype != NULL);

	/* add btf_type for func_proto */
	nr_params = ftype->nr_parms + (ftype->unspec_parms ? 1 : 0);
	type_id = btf_encoder__tag_type(encoder, ftype->tag.type);

	id = btf_encoder__emit_func_proto(encoder, type_id, nr_params);
	if (id < 0)
		return id;

	/* add parameters */
	param_idx = 0;

	ftype__for_each_parameter(ftype, param) {
		name = parameter__name(param);
		type_id = param->tag.type == 0 ? 0 : encoder->type_id_off + param->tag.type;
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

static int32_t btf_encoder__add_func_proto_for_state(struct btf_encoder *encoder,
						     struct btf_encoder_func_state *state)
{
	const struct btf *btf = encoder->btf;
	struct btf_encoder_func_parm *p;
	uint16_t nr_params, param_idx;
	char tmp_name[KSYM_NAME_LEN];
	int32_t id, type_id;
	const char *name;
	bool is_last;

	/* Beware: btf__add_bpf_arena_type_tags may change some members of the state */
	if (is_kfunc_state(state) && encoder->tag_kfuncs && encoder->encode_attributes)
		if (btf__add_bpf_arena_type_tags(encoder->btf, state) < 0)
			return -1;

	type_id = state->ret_type_id;
	nr_params = state->nr_parms;

	id = btf_encoder__emit_func_proto(encoder, type_id, nr_params);
	if (id < 0)
		return id;

	/* add parameters */
	for (param_idx = 0; param_idx < nr_params; param_idx++) {
		p = &state->parms[param_idx];
		name = btf__name_by_offset(btf, p->name_off);
		is_last = param_idx == nr_params;

		/* adding BTF data may result in a move of the
		 * name string memory, so make a temporary copy.
		 */
		strncpy(tmp_name, name, sizeof(tmp_name) - 1);

		if (btf_encoder__add_func_param(encoder, tmp_name, p->type_id, is_last))
			return -1;
	}

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
		btf__log_err(btf, BTF_KIND_VAR, name, true, id,
			     "type=%u linkage=%u Error emitting BTF type",
			     type, linkage);
	}
	return id;
}

static int32_t btf_encoder__add_var_secinfo(struct btf_encoder *encoder, size_t shndx,
					    uint32_t type, uint32_t offset, uint32_t size)
{
	struct btf_var_secinfo si = {
		.type = type,
		.offset = offset,
		.size = size,
	};
	return gobuffer__add(&encoder->secinfo[shndx].secinfo, &si, sizeof(si));
}

static int32_t btf_encoder__add_datasec(struct btf_encoder *encoder, size_t shndx)
{
	struct gobuffer *var_secinfo_buf = &encoder->secinfo[shndx].secinfo;
	const char *section_name = encoder->secinfo[shndx].name;
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
		btf__log_err(btf, BTF_KIND_DATASEC, section_name, true, id,
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

static int32_t btf_encoder__add_decl_tag(struct btf_encoder *encoder, const char *value, uint32_t type,
					 int component_idx)
{
	struct btf *btf = encoder->btf;
	const struct btf_type *t;
	int32_t id;

	id = btf__add_decl_tag(btf, value, type, component_idx);
	if (id > 0) {
		t = btf__type_by_id(btf, id);
		btf_encoder__log_type(encoder, t, false, true, "type_id=%u component_idx=%d",
				      t->type, component_idx);
	} else {
		btf__log_err(btf, BTF_KIND_DECL_TAG, value, true, id,
			     "component_idx=%d Error emitting BTF type",
			     component_idx);
	}

	return id;
}

static void btf_encoder__log_func_skip(struct btf_encoder *encoder, struct elf_function *func,
				       const char *fmt, ...)
{
	va_list ap;

	if (!encoder->verbose)
		return;
	printf("%s : skipping BTF encoding of function due to ", func->name);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static bool names__match(struct btf *btf1, const struct btf_type *t1,
			struct btf *btf2, const struct btf_type *t2)
{
	const char *str1;
	const char *str2;

	if ((btf1 == btf2) && (t1->name_off == t2->name_off))
		return true;

	str1 = btf__name_by_offset(btf1, t1->name_off);
	str2 = btf__name_by_offset(btf2, t2->name_off);

	return strcmp(str1, str2) == 0;
}

static int fwd__kind(const struct btf_type *t)
{
	if (btf_kind(t) == BTF_KIND_FWD)
		return btf_kflag(t) ? BTF_KIND_UNION : BTF_KIND_STRUCT;
	return btf_kind(t);
}

static bool types__match(struct btf_encoder *encoder,
			 struct btf *btf1, int type_id1,
			 struct btf *btf2, int type_id2)
{
	uint32_t id1 = type_id1;
	uint32_t id2 = type_id2;

	do {
		const struct btf_type *t1;
		const struct btf_type *t2;
		int k1;
		int k2;

		if ((btf1 == btf2) && (id1 == id2))
			return true;
		if (!id1 || !id2)
			return id1 == id2;

		t1 = btf__type_by_id(btf1, id1);
		t2 = btf__type_by_id(btf2, id2);

		k1 = fwd__kind(t1);
		k2 = fwd__kind(t2);

		if (k1 != k2) {
			/* loose matching allows us to match const/non-const
			 * parameters.
			 */
			if (k1 == BTF_KIND_CONST) {
				id1 = t1->type;
				continue;
			}
			if (k2 == BTF_KIND_CONST) {
				id2 = t2->type;
				continue;
			}
			return false;
		}

		switch (k1) {
		case BTF_KIND_INT:
			if (t1->size != t2->size)
				return false;
			if (*(__u32 *)(t1 + 1) != *(__u32 *)(t2 + 1))
				return false;
			return names__match(btf1, t1, btf2, t2);
		case BTF_KIND_FLOAT:
			if (t1->size != t2->size)
				return false;
			return names__match(btf1, t1, btf2, t2);
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
			return names__match(btf1, t1, btf2, t2);
		case BTF_KIND_PTR:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
			id1 = t1->type;
			id2 = t2->type;
			break;
		case BTF_KIND_ARRAY: {
			const struct btf_array *a1 = btf_array(t1);
			const struct btf_array *a2 = btf_array(t2);

			if (a1->nelems != a2->nelems)
				return false;
			id1 = a1->type;
			id2 = a2->type;
			break;
		}
		case BTF_KIND_FUNC_PROTO: {
			const struct btf_param *p1 = btf_params(t1);
			const struct btf_param *p2 = btf_params(t2);
			int i, vlen = btf_vlen(t1);

			if (vlen != btf_vlen(t2))
				return false;
			if (!types__match(encoder, btf1, t1->type,
					  btf2, t2->type))
				return false;
			for (i = 0; i < vlen; i++, p1++, p2++) {
				if (!types__match(encoder, btf1, t1->type,
						  btf2, t2->type))
					return false;
			}
			return true;
		}
		default:
			return false;
		}
	} while (1);

	return false;
}

static bool funcs__match(struct btf_encoder *encoder,
			 struct btf_encoder_func_state *s1,
			 struct btf_encoder_func_state *s2)
{
	struct elf_function *func = s1->elf;
	struct btf *btf = encoder->btf;
	uint8_t i;

	if (s1->nr_parms != s2->nr_parms) {
		btf_encoder__log_func_skip(encoder, func,
					   "param count mismatch; %d params != %d params\n",
					   s1->nr_parms, s2->nr_parms);
		return false;
	}
	if (!types__match(encoder, btf, s1->ret_type_id, btf, s2->ret_type_id)) {
		btf_encoder__log_func_skip(encoder, func, "return type mismatch\n");
		return false;
	}
	if (s1->nr_parms == 0)
		return true;

	for (i = 0; i < s1->nr_parms; i++) {
		if (!types__match(encoder, btf, s1->parms[i].type_id,
				  btf, s2->parms[i].type_id)) {
			if (encoder->verbose) {
				const char *p1 = btf__name_by_offset(btf, s1->parms[i].name_off);
				const char *p2 = btf__name_by_offset(btf, s2->parms[i].name_off);

				btf_encoder__log_func_skip(encoder, func,
							   "param type mismatch for param#%d %s %s %s\n",
							   i + 1,
							   p1 ?: "",
							   p1 && p2 ? "!=" : "",
							   p2 ?: "");
			}
			return false;
		}
	}
	return true;
}

static struct btf_encoder_func_state *btf_encoder__alloc_func_state(struct btf_encoder *encoder)
{
	struct btf_encoder_func_state *state, *tmp;

	if (encoder->func_states.cnt >= encoder->func_states.cap) {

		/* We only need to grow to accommodate duplicate
		 * function declarations across different CUs, so the
		 * rate of the array growth shouldn't be high.
		 */
		encoder->func_states.cap += 64;

		tmp = realloc(encoder->func_states.array, sizeof(*tmp) * encoder->func_states.cap);
		if (!tmp)
			return NULL;

		encoder->func_states.array = tmp;
	}

	state = &encoder->func_states.array[encoder->func_states.cnt++];
	memset(state, 0, sizeof(*state));

	return state;
}

/* some "." suffixes do not correspond to real functions;
 * - .part for partial inline
 * - .cold for rarely-used codepath extracted for better code locality
 */
static bool str_contains_non_fn_suffix(const char *str) {
	static const char *skip[] = {
		".cold",
		".part"
	};
	char *suffix = strchr(str, '.');
	int i;

	if (!suffix)
		return false;
	for (i = 0; i < ARRAY_SIZE(skip); i++) {
		if (strstr(suffix, skip[i]))
			return true;
	}
	return false;
}

static bool elf_function__has_ambiguous_address(struct elf_function *func)
{
	struct elf_function_sym *sym;
	uint64_t addr;

	if (func->sym_cnt <= 1)
		return false;

	addr = 0;
	for (int i = 0; i < func->sym_cnt; i++) {
		sym = &func->syms[i];
		if (addr && addr != sym->addr)
			return true;
		else
			addr = sym->addr;
	}

	return false;
}

static int32_t btf_encoder__save_func(struct btf_encoder *encoder, struct function *fn, struct elf_function *func)
{
	struct btf_encoder_func_state *state = btf_encoder__alloc_func_state(encoder);
	struct ftype *ftype = &fn->proto;
	struct btf *btf = encoder->btf;
	struct llvm_annotation *annot;
	struct parameter *param;
	uint8_t param_idx = 0;
	int str_off, err = 0;

	if (!state)
		return -ENOMEM;

	state->elf = func;
	state->nr_parms = ftype->nr_parms + (ftype->unspec_parms ? 1 : 0);
	state->ret_type_id = ftype->tag.type == 0 ? 0 : encoder->type_id_off + ftype->tag.type;
	if (state->nr_parms > 0) {
		state->parms = zalloc(state->nr_parms * sizeof(*state->parms));
		if (!state->parms) {
			err = -ENOMEM;
			goto out;
		}
	}
	state->inconsistent_proto = ftype->inconsistent_proto;
	state->unexpected_reg = ftype->unexpected_reg;
	state->optimized_parms = ftype->optimized_parms;
	state->uncertain_parm_loc = ftype->uncertain_parm_loc;
	ftype__for_each_parameter(ftype, param) {
		const char *name = parameter__name(param) ?: "";

		str_off = btf__add_str(btf, name);
		if (str_off < 0) {
			err = str_off;
			goto out;
		}
		state->parms[param_idx].name_off = str_off;
		state->parms[param_idx].type_id = param->tag.type == 0 ? 0 :
						  encoder->type_id_off + param->tag.type;
		param_idx++;
	}
	if (ftype->unspec_parms)
		state->parms[param_idx].type_id = 0;

	list_for_each_entry(annot, &fn->annots, node)
		state->nr_annots++;
	if (state->nr_annots) {
		uint8_t idx = 0;

		state->annots = zalloc(state->nr_annots * sizeof(*state->annots));
		if (!state->annots) {
			err = -ENOMEM;
			goto out;
		}
		list_for_each_entry(annot, &fn->annots, node) {
			str_off = btf__add_str(encoder->btf, annot->value);
			if (str_off < 0) {
				err = str_off;
				goto out;
			}
			state->annots[idx].value = str_off;
			state->annots[idx].component_idx = annot->component_idx;
			idx++;
		}
	}
	return 0;
out:
	zfree(&state->annots);
	zfree(&state->parms);
	free(state);
	return err;
}

static int btf__add_kfunc_decl_tag(struct btf *btf, const char *tag, __u32 id, const char *kfunc)
{
	int err = btf__add_decl_tag(btf, tag, id, -1);

	if (err < 0) {
		fprintf(stderr, "%s: failed to insert kfunc decl tag for '%s': %d\n",
			__func__, kfunc, err);
		return err;
	}
	return 0;
}

static int btf__tag_kfunc(struct btf *btf, struct elf_function *kfunc, __u32 btf_fn_id)
{
	int err;

	/* Note we are unconditionally adding the btf_decl_tag even
	 * though vmlinux may already contain btf_decl_tags for kfuncs.
	 * We are ok to do this b/c we will later btf__dedup() to remove
	 * any duplicates.
	 */
	err = btf__add_kfunc_decl_tag(btf, BTF_KFUNC_TYPE_TAG, btf_fn_id, kfunc->name);
	if (err < 0)
		return err;

	if (kfunc->kfunc_flags & KF_FASTCALL) {
		err = btf__add_kfunc_decl_tag(btf, BTF_FASTCALL_TAG, btf_fn_id, kfunc->name);
		if (err < 0)
			return err;
	}
	return 0;
}

static int32_t btf_encoder__add_func(struct btf_encoder *encoder,
				     struct btf_encoder_func_state *state)
{
	struct elf_function *func = state->elf;
	int btf_fnproto_id, btf_fn_id, tag_type_id = 0;
	int16_t component_idx = -1;
	const char *name;
	const char *value;
	char tmp_value[KSYM_NAME_LEN];
	uint16_t idx;
	int err;

	btf_fnproto_id = btf_encoder__add_func_proto_for_state(encoder, state);
	name = func->name;
	if (btf_fnproto_id >= 0)
		btf_fn_id = btf_encoder__add_ref_type(encoder, BTF_KIND_FUNC, btf_fnproto_id,
						      name, false);
	if (btf_fnproto_id < 0 || btf_fn_id < 0) {
		printf("error: failed to encode function '%s': invalid %s\n",
		       name, btf_fnproto_id < 0 ? "proto" : "func");
		return -1;
	}

	if (func->kfunc && encoder->tag_kfuncs && !encoder->skip_encoding_decl_tag) {
		err = btf__tag_kfunc(encoder->btf, func, btf_fn_id);
		if (err < 0)
			return err;
	}

	if (state->nr_annots == 0)
		return 0;

	for (idx = 0; idx < state->nr_annots; idx++) {
		struct btf_encoder_func_annot *a = &state->annots[idx];

		value = btf__str_by_offset(encoder->btf, a->value);
		/* adding BTF data may result in a mode of the
		 * value string memory, so make a temporary copy.
		 */
		strncpy(tmp_value, value, sizeof(tmp_value) - 1);
		component_idx = a->component_idx;

		tag_type_id = btf_encoder__add_decl_tag(encoder, tmp_value,
							btf_fn_id, component_idx);
		if (tag_type_id < 0)
			break;
	}
	if (tag_type_id < 0) {
		fprintf(stderr,
			"error: failed to encode tag '%s' to func %s with component_idx %d\n",
			value, name, component_idx);
		return -1;
	}

	return 0;
}

static int elf_function__name_cmp(const void *_a, const void *_b)
{
	const struct elf_function *a = _a;
	const struct elf_function *b = _b;

	return strcmp(a->name, b->name);
}

static int saved_functions_cmp(const void *_a, const void *_b)
{
	const struct btf_encoder_func_state *a = _a;
	const struct btf_encoder_func_state *b = _b;

	return elf_function__name_cmp(a->elf, b->elf);
}

static int saved_functions_combine(struct btf_encoder *encoder,
				   struct btf_encoder_func_state *a,
				   struct btf_encoder_func_state *b)
{
	uint8_t optimized, unexpected, inconsistent, uncertain_parm_loc;

	if (a->elf != b->elf)
		return 1;

	optimized = a->optimized_parms | b->optimized_parms;
	unexpected = a->unexpected_reg | b->unexpected_reg;
	inconsistent = a->inconsistent_proto | b->inconsistent_proto;
	uncertain_parm_loc = a->uncertain_parm_loc | b->uncertain_parm_loc;
	if (!unexpected && !inconsistent && !funcs__match(encoder, a, b))
		inconsistent = 1;
	a->optimized_parms = b->optimized_parms = optimized;
	a->unexpected_reg = b->unexpected_reg = unexpected;
	a->inconsistent_proto = b->inconsistent_proto = inconsistent;
	a->uncertain_parm_loc = b->uncertain_parm_loc = uncertain_parm_loc;

	return 0;
}

static void btf_encoder__delete_saved_funcs(struct btf_encoder *encoder)
{
	struct btf_encoder_func_state *state;

	for (int i = 0; i < encoder->func_states.cnt; i++) {
		state = &encoder->func_states.array[i];
		free(state->parms);
		free(state->annots);
	}

	free(encoder->func_states.array);

	encoder->func_states.array = NULL;
	encoder->func_states.cnt = 0;
	encoder->func_states.cap = 0;
}

static int btf_encoder__add_saved_funcs(struct btf_encoder *encoder, bool skip_encoding_inconsistent_proto)
{
	struct btf_encoder_func_state *saved_fns = encoder->func_states.array;
	int nr_saved_fns = encoder->func_states.cnt;
	int err = 0, i = 0, j;

	if (nr_saved_fns == 0)
		goto out;

	/* Sort the saved_fns so that we can merge multiple states of
	 * the "same" function into one, before adding it to the BTF.
	 */
	qsort(saved_fns, nr_saved_fns, sizeof(*saved_fns), saved_functions_cmp);

	for (i = 0; i < nr_saved_fns; i = j) {
		struct btf_encoder_func_state *state = &saved_fns[i];
		bool add_to_btf = !skip_encoding_inconsistent_proto;

		/* Compare across sorted functions that match by name/prefix;
		 * share inconsistent/unexpected reg state between them.
		 */
		j = i + 1;

		while (j < nr_saved_fns && saved_functions_combine(encoder, &saved_fns[i], &saved_fns[j]) == 0)
			j++;

		/* do not exclude functions with optimized-out parameters; they
		 * may still be _called_ with the right parameter values, they
		 * just do not _use_ them.  Only exclude functions with
		 * unexpected register use, multiple inconsistent prototypes or
		 * uncertain parameters location
		 */
		add_to_btf |= !state->unexpected_reg && !state->inconsistent_proto && !state->uncertain_parm_loc && !state->elf->ambiguous_addr;

		if (state->uncertain_parm_loc)
			btf_encoder__log_func_skip(encoder, saved_fns[i].elf,
					"uncertain parameter location\n",
					0, 0);

		if (add_to_btf) {
			err = btf_encoder__add_func(encoder, state);
			if (err < 0)
				goto out;
		}
	}

out:
	btf_encoder__delete_saved_funcs(encoder);

	return err;
}

static struct elf_functions *btf_encoder__elf_functions(struct btf_encoder *encoder)
{
	struct elf_functions *funcs = NULL;

	if (!encoder->cu || !encoder->cu->elf)
		return NULL;

	funcs = elf_functions__find(encoder->cu->elf, &encoder->elf_functions_list);
	if (!funcs) {
		funcs = elf_functions__new(encoder->cu->elf);
		if (funcs)
			list_add(&funcs->node, &encoder->elf_functions_list);
	}

	return funcs;
}

static struct elf_function *btf_encoder__find_function(const struct btf_encoder *encoder, const char *name)
{
	struct elf_functions *funcs = elf_functions__find(encoder->cu->elf, &encoder->elf_functions_list);
	struct elf_function key = { .name = (char*)name };

	return bsearch(&key, funcs->entries, funcs->cnt, sizeof(key), elf_function__name_cmp);
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

static int tag__check_id_drift(struct btf_encoder *encoder, const struct tag *tag,
			       uint32_t core_id, uint32_t btf_type_id)
{
	if (btf_type_id != (core_id + encoder->type_id_off)) {
		fprintf(stderr,
			"%s: %s id drift, core_id: %u, btf_type_id: %u, type_id_off: %u\n",
			__func__, dwarf_tag_name(tag->tag),
			core_id, btf_type_id, encoder->type_id_off);
		return -1;
	}

	return 0;
}

static int32_t btf_encoder__add_struct_type(struct btf_encoder *encoder, struct tag *tag)
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
		if (btf_encoder__add_field(encoder, name, encoder->type_id_off + pos->tag.type,
					   pos->bitfield_size, pos->bit_offset))
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

static int32_t btf_encoder__add_enum_type(struct btf_encoder *encoder, struct tag *tag,
					  struct conf_load *conf_load)
{
	struct type *etype = tag__type(tag);
	struct enumerator *pos;
	const char *name = type__name(etype);
	int32_t type_id;

	type_id = btf_encoder__add_enum(encoder, name, etype, conf_load);
	if (type_id < 0)
		return type_id;

	type__for_each_enumerator(etype, pos) {
		name = enumerator__name(pos);
		if (btf_encoder__add_enum_val(encoder, name, pos->value, etype, conf_load))
			return -1;
	}

	return type_id;
}

static int btf_encoder__encode_tag(struct btf_encoder *encoder, struct tag *tag,
				   struct conf_load *conf_load)
{
	/* single out type 0 as it represents special type "void" */
	uint32_t ref_type_id = tag->type == 0 ? 0 : encoder->type_id_off + tag->type;
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
	case DW_TAG_LLVM_annotation:
		name = tag__btf_type_tag(tag)->value;
		return btf_encoder__add_ref_type(encoder, BTF_KIND_TYPE_TAG, ref_type_id, name, false);
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
	case DW_TAG_class_type:
		name = namespace__name(tag__namespace(tag));
		if (tag__type(tag)->declaration)
			return btf_encoder__add_ref_type(encoder, BTF_KIND_FWD, 0, name, tag->tag == DW_TAG_union_type);
		else
			return btf_encoder__add_struct_type(encoder, tag);
	case DW_TAG_array_type:
		/* TODO: Encode one dimension at a time. */
		encoder->need_index_type = true;
		return btf_encoder__add_array(encoder, ref_type_id, encoder->array_index_id, array_type__nelems(tag));
	case DW_TAG_enumeration_type:
		return btf_encoder__add_enum_type(encoder, tag, conf_load);
	case DW_TAG_subroutine_type:
		return btf_encoder__add_func_proto_for_ftype(encoder, tag__ftype(tag));
        case DW_TAG_unspecified_type:
		/* Just don't encode this for now, converting anything with this type to void (0) instead.
		 *
		 * If we end up needing to encode this, one possible hack is to do as follows, as "const void".
		 *
		 * Returning zero means we skipped encoding a DWARF type.
		 */
               // btf_encoder__add_ref_type(encoder, BTF_KIND_CONST, 0, NULL, false);
               return 0;
	default:
		fprintf(stderr, "Unsupported DW_TAG_%s(0x%x): type: 0x%x\n",
			dwarf_tag_name(tag->tag), tag->tag, ref_type_id);
		return -1;
	}
}

static int btf_encoder__write_raw_file(struct btf_encoder *encoder)
{
	const char *filename = encoder->filename;
	uint32_t raw_btf_size;
	const void *raw_btf_data;
	int fd, err;

	raw_btf_data = btf__raw_data(encoder->btf, &raw_btf_size);
	if (raw_btf_data == NULL) {
		fprintf(stderr, "%s: btf__raw_data failed!\n", __func__);
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

static int btf_encoder__write_elf(struct btf_encoder *encoder, const struct btf *btf,
				  const char *btf_secname)
{
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
		if (strcmp(secname, btf_secname) == 0) {
			btf_data = elf_getdata(scn, btf_data);
			break;
		}
	}

	raw_btf_data = btf__raw_data(btf, &raw_btf_size);

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

		snprintf(cmd, sizeof(cmd), "%s --add-section %s=%s %s",
			 llvm_objcopy, btf_secname, tmp_fn, filename);
		if (system(cmd)) {
			fprintf(stderr, "%s: failed to add %s section to '%s': %d!\n",
				__func__, btf_secname, filename, errno);
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

/* Returns if `sym` points to a kfunc set */
static int is_sym_kfunc_set(GElf_Sym *sym, const char *name, Elf_Data *idlist, size_t idlist_addr)
{
	void *ptr = idlist->d_buf;
	struct btf_id_set8 *set;
	int off;

	/* kfuncs are only found in BTF_SET8's */
	if (!strstarts(name, BTF_ID_SET8_PFX))
		return false;

	off = sym->st_value - idlist_addr;
	if (off >= idlist->d_size) {
		fprintf(stderr, "%s: symbol '%s' out of bounds\n", __func__, name);
		return false;
	}

	/* Check the set8 flags to see if it was marked as kfunc */
	set = ptr + off;
	return set->flags & BTF_SET8_KFUNCS;
}

/*
 * Parse BTF_ID symbol and return the func name.
 *
 * Returns:
 *	Caller-owned string containing func name if successful.
 *	NULL if !func or on error.
 */
static char *get_func_name(const char *sym)
{
	char *func, *end;

	/* Example input: __BTF_ID__func__vfs_close__1
	 *
	 * The goal is to strip the prefix and suffix such that we only
	 * return vfs_close.
	 */

	if (!strstarts(sym, BTF_ID_FUNC_PFX))
		return NULL;

	/* Strip prefix and handle malformed input such as  __BTF_ID__func___ */
	const char *func_sans_prefix = sym + sizeof(BTF_ID_FUNC_PFX) - 1;
	if (!strstr(func_sans_prefix, "__"))
                return NULL;

	func = strdup(func_sans_prefix);
	if (!func)
		return NULL;

	/* Strip suffix */
	end = strrchr(func, '_');
	if (!end || *(end - 1) != '_') {
		free(func);
		return NULL;
	}
	*(end - 1) = '\0';

	return func;
}

static int btf_encoder__collect_kfuncs(struct btf_encoder *encoder)
{
	const char *filename = encoder->source_filename;
	struct gobuffer btf_kfunc_ranges = {};
	Elf_Data *symbols = NULL;
	Elf_Data *idlist = NULL;
	Elf_Scn *symscn = NULL;
	int symbols_shndx = -1;
	size_t idlist_addr = 0;
	int fd = -1, err = -1;
	int idlist_shndx = -1;
	size_t strtabidx = 0;
	Elf_Scn *scn = NULL;
	Elf *elf = NULL;
	GElf_Shdr shdr;
	size_t strndx;
	char *secname;
	int nr_syms;
	int i = 0;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s\n", filename);
		goto out;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		elf_error("Cannot set libelf version");
		goto out;
	}

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL) {
		elf_error("Cannot update ELF file");
		goto out;
	}

	/* Locate symbol table and .BTF_ids sections */
	if (elf_getshdrstrndx(elf, &strndx) < 0)
		goto out;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		Elf_Data *data;

		i++;
		if (!gelf_getshdr(scn, &shdr)) {
			elf_error("Failed to get ELF section(%d) hdr", i);
			goto out;
		}

		secname = elf_strptr(elf, strndx, shdr.sh_name);
		if (!secname) {
			elf_error("Failed to get ELF section(%d) hdr name", i);
			goto out;
		}

		if (shdr.sh_type == SHT_SYMTAB) {
			data = elf_getdata(scn, 0);
			if (!data) {
				elf_error("Failed to get ELF section(%d) data", i);
				goto out;
			}

			symbols_shndx = i;
			symscn = scn;
			symbols = data;
			strtabidx = shdr.sh_link;
		} else if (!strcmp(secname, BTF_IDS_SECTION)) {
			/* .BTF_ids section consists of uint32_t elements,
			 * and thus might need byte order conversion.
			 * However, it has type PROGBITS, hence elf_getdata()
			 * won't automatically do the conversion.
			 * Use elf_getdata_rawchunk() instead,
			 * ELF_T_WORD tells it to do the necessary conversion.
			 */
			data = elf_getdata_rawchunk(elf, shdr.sh_offset, shdr.sh_size, ELF_T_WORD);
			if (!data) {
				elf_error("Failed to get %s ELF section(%d) data",
					  BTF_IDS_SECTION, i);
				goto out;
			}

			idlist_shndx = i;
			idlist_addr = shdr.sh_addr;
			idlist = data;
		}
	}

	/* Cannot resolve symbol or .BTF_ids sections. Nothing to do. */
	if (symbols_shndx == -1 || idlist_shndx == -1) {
		err = 0;
		goto out;
	}

	if (!gelf_getshdr(symscn, &shdr)) {
		elf_error("Failed to get ELF symbol table header");
		goto out;
	}
	nr_syms = shdr.sh_size / shdr.sh_entsize;

	/* First collect all kfunc set ranges.
	 *
	 * Note we choose not to sort these ranges and accept a linear
	 * search when doing lookups. Reasoning is that the number of
	 * sets is ~O(100) and not worth the additional code to optimize.
	 */
	for (i = 0; i < nr_syms; i++) {
		struct btf_kfunc_set_range range = {};
		const char *name;
		GElf_Sym sym;

		if (!gelf_getsym(symbols, i, &sym)) {
			elf_error("Failed to get ELF symbol(%d)", i);
			goto out;
		}

		if (sym.st_shndx != idlist_shndx)
			continue;

		name = elf_strptr(elf, strtabidx, sym.st_name);
		if (!is_sym_kfunc_set(&sym, name, idlist, idlist_addr))
			continue;

		range.start = sym.st_value;
		range.end = sym.st_value + sym.st_size;
		gobuffer__add(&btf_kfunc_ranges, &range, sizeof(range));
	}

	/* Now inject BTF with kfunc decl tag for detected kfuncs */
	for (i = 0; i < nr_syms; i++) {
		const struct btf_kfunc_set_range *ranges;
		const struct btf_id_and_flag *pair;
		struct elf_function *elf_fn;
		unsigned int ranges_cnt;
		char *func, *name;
		ptrdiff_t off;
		GElf_Sym sym;
		bool found;
		int j;

		if (!gelf_getsym(symbols, i, &sym)) {
			elf_error("Failed to get ELF symbol(%d)", i);
			goto out;
		}

		if (sym.st_shndx != idlist_shndx)
			continue;

		name = elf_strptr(elf, strtabidx, sym.st_name);
		func = get_func_name(name);
		if (!func)
			continue;

		/* Check if function belongs to a kfunc set */
		ranges = gobuffer__entries(&btf_kfunc_ranges);
		ranges_cnt = gobuffer__nr_entries(&btf_kfunc_ranges);
		found = false;
		for (j = 0; j < ranges_cnt; j++) {
			size_t addr = sym.st_value;

			if (ranges[j].start <= addr && addr < ranges[j].end) {
				found = true;
				off = addr - idlist_addr;
				if (off < 0 || off + sizeof(*pair) > idlist->d_size) {
					fprintf(stderr, "%s: kfunc '%s' offset outside section '%s'\n",
						__func__, func, BTF_IDS_SECTION);
					free(func);
					goto out;
				}
				pair = idlist->d_buf + off;
				break;
			}
		}
		if (!found) {
			free(func);
			continue;
		}

		elf_fn = btf_encoder__find_function(encoder, func);
		if (elf_fn) {
			elf_fn->kfunc = true;
			elf_fn->kfunc_flags = pair->flags;
		}
		free(func);
	}

	err = 0;
out:
	__gobuffer__delete(&btf_kfunc_ranges);
	if (elf)
		elf_end(elf);
	if (fd != -1)
		close(fd);
	return err;
}

int btf_encoder__encode(struct btf_encoder *encoder, struct conf_load *conf)
{
	int err;
	size_t shndx;

	err = btf_encoder__add_saved_funcs(encoder, conf->skip_encoding_btf_inconsistent_proto);
	if (err < 0)
		return err;

	for (shndx = 1; shndx < encoder->seccnt; shndx++)
		if (gobuffer__size(&encoder->secinfo[shndx].secinfo))
			btf_encoder__add_datasec(encoder, shndx);

	/* Empty file, nothing to do, so... done! */
	if (btf__type_cnt(encoder->btf) == 1)
		return 0;

	if (btf__dedup(encoder->btf, NULL)) {
		fprintf(stderr, "%s: btf__dedup failed!\n", __func__);
		return -1;
	}
	if (encoder->raw_output) {
		err = btf_encoder__write_raw_file(encoder);
	} else {
		/* non-embedded libbpf may not have btf__distill_base() or a
		 * definition of BTF_BASE_ELF_SEC, so conditionally compile
		 * distillation code.  Like other --btf_features, it will
		 * silently ignore the feature request if libbpf does not
		 * support it.
		 */
		if (encoder->gen_distilled_base) {
			struct btf *btf = NULL, *distilled_base = NULL;

			if (!btf__distill_base) {
				fprintf(stderr, "btf__distill_base is not available, is libbpf < 1.5?\n");
				return -ENOTSUP;
			}

			if (btf__distill_base(encoder->btf, &distilled_base, &btf) < 0) {
				fprintf(stderr, "could not generate distilled base BTF: %s\n",
					strerror(errno));
				return -1;
			}
			err = btf_encoder__write_elf(encoder, btf, BTF_ELF_SEC);
			if (!err)
				err = btf_encoder__write_elf(encoder, distilled_base, BTF_BASE_ELF_SEC);
			btf__free(btf);
			btf__free(distilled_base);
			return err;
		}
		err = btf_encoder__write_elf(encoder, encoder->btf, BTF_ELF_SEC);
	}

	elf_functions_list__clear(&encoder->elf_functions_list);
	return err;
}

static inline int elf_function__push_sym(struct elf_function *func, struct elf_function_sym *sym) {
	struct elf_function_sym *tmp;

	if (func->sym_cnt)
		tmp = realloc(func->syms, (func->sym_cnt + 1) * sizeof(func->syms[0]));
	else
		tmp = calloc(sizeof(func->syms[0]), 1);

	if (!tmp)
		return -ENOMEM;

	func->syms = tmp;
	func->syms[func->sym_cnt] = *sym;
	func->sym_cnt++;

	return 0;
}

static int elf_functions__collect(struct elf_functions *functions)
{
	uint32_t nr_symbols = elf_symtab__nr_symbols(functions->symtab);
	struct elf_function_sym func_sym;
	struct elf_function *func, *tmp;
	const char *sym_name, *suffix;
	Elf32_Word sym_sec_idx;
	int err = 0, i, j;
	uint32_t core_id;
	GElf_Sym sym;

	/* We know that number of functions is less than number of symbols,
	 * so we can overallocate temporarily.
	 */
	functions->entries = calloc(nr_symbols, sizeof(*functions->entries));
	if (!functions->entries) {
		err = -ENOMEM;
		goto out_free;
	}

	/* First, collect an elf_function for each GElf_Sym
	 * Where func->name is without a suffix
	 */
	functions->cnt = 0;
	elf_symtab__for_each_symbol_index(functions->symtab, core_id, sym, sym_sec_idx) {

		if (elf_sym__type(&sym) != STT_FUNC)
			continue;

		sym_name = elf_sym__name(&sym, functions->symtab);
		if (!sym_name)
			continue;

		suffix = strchr(sym_name, '.');
		if (str_contains_non_fn_suffix(sym_name))
			continue;

		func = &functions->entries[functions->cnt];
		if (suffix)
			func->name = strndup(sym_name, suffix - sym_name);
		else
			func->name = strdup(sym_name);

		if (!func->name) {
			err = -ENOMEM;
			goto out_free;
		}

		func_sym.name = sym_name;
		func_sym.addr = sym.st_value;

		err = elf_function__push_sym(func, &func_sym);
		if (err)
			goto out_free;

		functions->cnt++;
	}

	/* At this point functions->entries is an unordered array of elf_function
	 * each having a name (without a suffix) and a single elf_function_sym (maybe with suffix)
	 * Now let's sort this table by name.
	 */
	if (functions->cnt) {
		qsort(functions->entries, functions->cnt, sizeof(*functions->entries), elf_function__name_cmp);
	} else {
		err = 0;
		goto out_free;
	}

	/* Finally dedup by name, transforming { name -> syms[1] } entries into { name -> syms[n] } */
	i = 0;
	j = 1;
	for (j = 1; j < functions->cnt; j++) {
		struct elf_function *a = &functions->entries[i];
		struct elf_function *b = &functions->entries[j];

		if (!strcmp(a->name, b->name)) {
			elf_function__push_sym(a, &b->syms[0]);
			elf_function__clear(b);
		} else {
			// at this point all syms for `a` have been collected
			// check for ambiguous addresses before moving on
			a->ambiguous_addr = elf_function__has_ambiguous_address(a);
			i++;
			if (i != j)
				functions->entries[i] = functions->entries[j];
		}
	}

	functions->cnt = i + 1;

	/* Reallocate to the exact size */
	tmp = realloc(functions->entries, functions->cnt * sizeof(struct elf_function));
	if (tmp) {
		functions->entries = tmp;
	} else {
		fprintf(stderr, "could not reallocate memory for elf_functions table\n");
		err = -ENOMEM;
		goto out_free;
	}

	return 0;

out_free:
	free(functions->entries);
	functions->entries = NULL;
	functions->cnt = 0;
	return err;
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

static size_t get_elf_section(struct btf_encoder *encoder, uint64_t addr)
{
	/* Start at index 1 to ignore initial SHT_NULL section */
	for (size_t i = 1; i < encoder->seccnt; i++) {
		/* Variables are only present in PROGBITS or NOBITS (.bss) */
		if (!(encoder->secinfo[i].type == SHT_PROGBITS ||
		     encoder->secinfo[i].type == SHT_NOBITS))
			continue;

		if (encoder->secinfo[i].addr <= addr &&
		    (addr - encoder->secinfo[i].addr) < encoder->secinfo[i].sz)
			return i;
	}
	return 0;
}

/*
 * Filter out variables / symbol names with common prefixes and no useful
 * values. Prefixes should be added sparingly, and it should be objectively
 * obvious that they are not useful.
 */
static bool filter_variable_name(const char *name)
{
	static const struct { char *s; size_t len; } skip[] = {
		#define X(str) {str, sizeof(str) - 1}
		X("__UNIQUE_ID"),
		X("__tpstrtab_"),
		X("__exitcall_"),
		X("__gendwarfksyms_ptr_"),
		X("__func_stack_frame_non_standard_")
		#undef X
	};
	int i;

	if (*name != '_')
		return false;

	for (i = 0; i < ARRAY_SIZE(skip); i++) {
		if (strncmp(name, skip[i].s, skip[i].len) == 0)
			return true;
	}
	return false;
}

bool variable_in_sec(struct btf_encoder *encoder, const char *name, size_t shndx)
{
	uint32_t sym_sec_idx;
	uint32_t core_id;
	GElf_Sym sym;

	elf_symtab__for_each_symbol_index(encoder->symtab, core_id, sym, sym_sec_idx) {
		const char *sym_name;

		if (sym_sec_idx != shndx || elf_sym__type(&sym) != STT_OBJECT)
			continue;
		sym_name = elf_sym__name(&sym, encoder->symtab);
		if (!sym_name)
			continue;
		if (strcmp(name, sym_name) == 0)
			return true;
	}
	return false;
}

static int btf_encoder__encode_cu_variables(struct btf_encoder *encoder)
{
	struct cu *cu = encoder->cu;
	uint32_t core_id;
	struct tag *pos;
	int err = -1;

	if (!encoder->symtab)
		return 0;

	if (encoder->verbose)
		printf("search cu '%s' for percpu global variables.\n", cu->name);

	cu__for_each_variable(cu, core_id, pos) {
		struct variable *var = tag__variable(pos);
		uint32_t type, linkage;
		const char *name;
		struct llvm_annotation *annot;
		const struct tag *tag;
		size_t shndx, size;
		uint64_t addr;
		int id;

		/* Skip incomplete (non-defining) declarations */
		if (var->declaration && !var->spec)
			continue;

		/*
		 * top_level: indicates that the variable is declared at the top
		 *   level of the CU, and thus it is globally scoped.
		 * artificial: indicates that the variable is a compiler-generated
		 *   "fake" variable that doesn't appear in the source.
		 * scope: set by pahole to indicate the type of storage the
		 *   variable has. GLOBAL indicates it is stored in static
		 *   memory (as opposed to a stack variable or register)
		 *
		 * Some variables are "top_level" but not GLOBAL:
		 *   e.g. current_stack_pointer, which is a register variable,
		 *   despite having global CU-declarations. We don't want that,
		 *   since no code could actually find this variable.
		 * Some variables are GLOBAL but not top_level:
		 *   e.g. function static variables
		 */
		if (!var->top_level || var->artificial || var->scope != VSCOPE_GLOBAL)
			continue;

		/* addr has to be recorded before we follow spec */
		addr = var->ip.addr;

		/* Get the ELF section info for the variable */
		shndx = get_elf_section(encoder, addr);
		if (!shndx || shndx >= encoder->seccnt || !encoder->secinfo[shndx].include)
			continue;

		/* Convert addr to section relative */
		addr -= encoder->secinfo[shndx].addr;

		/* DWARF specification reference should be followed, because
		 * information like the name & type may not be present on var */
		if (var->spec)
			var = var->spec;

		name = variable__name(var);
		if (!name)
			continue;

		if (filter_variable_name(name))
			continue;

		/* A 0 address may be in a "discard" section; DWARF provides
		 * location information with address 0 for such variables.
		 * Ensure the variable really is in this section by checking
		 * the ELF symtab.
		 */
		if (addr == 0 && !variable_in_sec(encoder, name, shndx))
			continue;
		/* Check for invalid BTF names */
		if (!btf_name_valid(name)) {
			dump_invalid_symbol("Found invalid variable name when encoding btf",
					    name, encoder->verbose, encoder->force);
			if (encoder->force)
				continue;
			else
				return -1;
		}

		if (var->ip.tag.type == 0) {
			fprintf(stderr, "error: found variable '%s' in CU '%s' that has void type\n",
				name, cu->name);
			if (encoder->force)
				continue;
			err = -1;
			break;
		}

		tag = cu__type(cu, var->ip.tag.type);
		size = tag__size(tag, cu);
		if (size == 0 || size > UINT32_MAX) {
			if (encoder->verbose)
				fprintf(stderr, "Ignoring %s-sized variable '%s'...\n",
					size == 0 ? "zero" : "over", name);
			continue;
		}
		if (addr > UINT32_MAX) {
			if (encoder->verbose)
				fprintf(stderr, "Ignoring variable '%s' - its offset %zu doesn't fit in a u32\n",
					name, addr);
			continue;
		}

		type = var->ip.tag.type + encoder->type_id_off;
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

		list_for_each_entry(annot, &var->annots, node) {
			int tag_type_id = btf_encoder__add_decl_tag(encoder, annot->value, id, annot->component_idx);
			if (tag_type_id < 0) {
				fprintf(stderr, "error: failed to encode tag '%s' to variable '%s' with component_idx %d\n",
					annot->value, name, annot->component_idx);
				goto out;
			}
		}

		/*
		 * Add the variable to the secinfo for the section it appears in.
		 * Later we will generate a BTF_VAR_DATASEC for all any section with
		 * an encoded variable.
		 */
		id = btf_encoder__add_var_secinfo(encoder, shndx, id, (uint32_t)addr, (uint32_t)size);
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

struct btf_encoder *btf_encoder__new(struct cu *cu, const char *detached_filename, struct btf *base_btf, bool verbose, struct conf_load *conf_load)
{
	struct btf_encoder *encoder = zalloc(sizeof(*encoder));
	struct elf_functions *funcs = NULL;

	if (encoder) {
		encoder->cu = cu;
		encoder->raw_output = detached_filename != NULL;
		encoder->source_filename = strdup(cu->filename);
		encoder->filename = strdup(encoder->raw_output ? detached_filename : cu->filename);
		if (encoder->source_filename == NULL || encoder->filename == NULL)
			goto out_delete;

		encoder->btf = btf__new_empty_split(base_btf);
		if (encoder->btf == NULL)
			goto out_delete;

		encoder->force		 = conf_load->btf_encode_force;
		encoder->gen_floats	 = conf_load->btf_gen_floats;
		encoder->skip_encoding_decl_tag	 = conf_load->skip_encoding_btf_decl_tag;
		encoder->tag_kfuncs	 = conf_load->btf_decl_tag_kfuncs;
		encoder->gen_distilled_base = conf_load->btf_gen_distilled_base;
		encoder->encode_attributes = conf_load->btf_attributes;
		encoder->verbose	 = verbose;
		encoder->has_index_type  = false;
		encoder->need_index_type = false;
		encoder->array_index_id  = 0;
		encoder->encode_vars = 0;

		if (!conf_load->skip_encoding_btf_vars)
			encoder->encode_vars |= BTF_VAR_PERCPU;
		if (conf_load->encode_btf_global_vars)
			encoder->encode_vars |= BTF_VAR_GLOBAL;

		INIT_LIST_HEAD(&encoder->elf_functions_list);
		funcs = btf_encoder__elf_functions(encoder);
		if (!funcs)
			goto out_delete;

		encoder->symtab = funcs->symtab;

		/* Start with funcs->cnt. The array may grow in btf_encoder__alloc_func_state() */
		encoder->func_states.array = zalloc(sizeof(*encoder->func_states.array) * funcs->cnt);
		encoder->func_states.cap = funcs->cnt;
		encoder->func_states.cnt = 0;

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

		/* index the ELF sections for later lookup */

		GElf_Shdr shdr;
		size_t shndx;
		if (elf_getshdrnum(cu->elf, &encoder->seccnt))
			goto out_delete;
		encoder->secinfo = calloc(encoder->seccnt, sizeof(*encoder->secinfo));
		if (!encoder->secinfo) {
			fprintf(stderr, "%s: error allocating memory for %zu ELF sections\n",
				__func__, encoder->seccnt);
			goto out_delete;
		}

		bool found_percpu = false;
		for (shndx = 0; shndx < encoder->seccnt; shndx++) {
			const char *secname = NULL;
			Elf_Scn *sec = elf_section_by_idx(cu->elf, &shdr, shndx, &secname);
			if (!sec)
				goto out_delete;
			encoder->secinfo[shndx].addr = shdr.sh_addr;
			encoder->secinfo[shndx].sz = shdr.sh_size;
			encoder->secinfo[shndx].name = secname;
			encoder->secinfo[shndx].type = shdr.sh_type;

			if (encoder->encode_vars & BTF_VAR_GLOBAL)
				encoder->secinfo[shndx].include = true;

			if (strcmp(secname, PERCPU_SECTION) == 0) {
				found_percpu = true;
				if (encoder->encode_vars & BTF_VAR_PERCPU)
					encoder->secinfo[shndx].include = true;
			}
		}

		if (!found_percpu && encoder->verbose)
			printf("%s: '%s' doesn't have '%s' section\n", __func__, cu->filename, PERCPU_SECTION);

		if (encoder->tag_kfuncs) {
			if (btf_encoder__collect_kfuncs(encoder))
				goto out_delete;
		}

		if (encoder->verbose)
			printf("File %s:\n", cu->filename);
	}

	return encoder;

out_delete:
	btf_encoder__delete(encoder);
	return NULL;
}

void btf_encoder__delete(struct btf_encoder *encoder)
{
	size_t shndx;

	if (encoder == NULL)
		return;

	for (shndx = 0; shndx < encoder->seccnt; shndx++)
		__gobuffer__delete(&encoder->secinfo[shndx].secinfo);
	free(encoder->secinfo);
	zfree(&encoder->filename);
	zfree(&encoder->source_filename);
	btf__free(encoder->btf);
	encoder->btf = NULL;

	elf_functions_list__clear(&encoder->elf_functions_list);

	btf_encoder__delete_saved_funcs(encoder);

	free(encoder);
}

static bool ftype__has_uncertain_arg_loc(struct cu *cu, struct ftype *ftype)
{
	struct parameter *param;
	int param_idx = 0;

	if (ftype->nr_parms < cu->nr_register_params)
		return false;

	ftype__for_each_parameter(ftype, param) {
		if (param_idx++ < cu->nr_register_params)
			continue;

		struct tag *type = cu__type(cu, param->tag.type);

		if (type == NULL || !tag__is_struct(type))
			continue;

		struct type *ctype = tag__type(type);
		if (ctype->namespace.name == 0)
			continue;

		struct class *class = tag__class(type);

		class__infer_packed_attributes(class, cu);

		if (class->is_packed)
			return true;
	}

	return false;
}

int btf_encoder__encode_cu(struct btf_encoder *encoder, struct cu *cu, struct conf_load *conf_load)
{
	struct llvm_annotation *annot;
	int btf_type_id, tag_type_id, skipped_types = 0;
	struct elf_functions *funcs;
	uint32_t core_id;
	struct function *fn;
	struct tag *pos;
	int err = 0;

	encoder->cu = cu;
	funcs = btf_encoder__elf_functions(encoder);
	if (!funcs) {
		err = -1;
		goto out;
	}
	encoder->symtab = funcs->symtab;

	encoder->type_id_off = btf__type_cnt(encoder->btf) - 1;

	if (!encoder->has_index_type) {
		/* cu__find_base_type_by_name() takes "type_id_t *id" */
		type_id_t id;
		if (cu__find_base_type_by_name(cu, "int", &id)) {
			encoder->has_index_type = true;
			encoder->array_index_id = encoder->type_id_off + id;
		} else {
			encoder->has_index_type = false;
			encoder->array_index_id = encoder->type_id_off + cu->types_table.nr_entries;
		}
	}

	cu__for_each_type(cu, core_id, pos) {
		btf_type_id = btf_encoder__encode_tag(encoder, pos, conf_load);

		if (btf_type_id == 0) {
			++skipped_types;
			continue;
		}

		if (btf_type_id < 0 ||
		    tag__check_id_drift(encoder, pos, core_id, btf_type_id + skipped_types)) {
			err = -1;
			goto out;
		}
	}

	if (encoder->need_index_type && !encoder->has_index_type) {
		struct base_type bt = {};

		bt.name = 0;
		bt.bit_size = 32;
		bt.is_signed = true;
		btf_encoder__add_base_type(encoder, &bt, "int");
		encoder->has_index_type = true;
	}

	cu__for_each_type(cu, core_id, pos) {
		struct namespace *ns;
		const char *tag_name;

		switch (pos->tag) {
		case DW_TAG_structure_type:
			tag_name = "struct";
			break;
		case DW_TAG_union_type:
			tag_name = "union";
			break;
		case DW_TAG_typedef:
			tag_name = "typedef";
			break;
		default:
			continue;
		}

		btf_type_id = encoder->type_id_off + core_id;
		ns = tag__namespace(pos);
		list_for_each_entry(annot, &ns->annots, node) {
			tag_type_id = btf_encoder__add_decl_tag(encoder, annot->value, btf_type_id, annot->component_idx);
			if (tag_type_id < 0) {
				fprintf(stderr, "error: failed to encode tag '%s' to %s '%s' with component_idx %d\n",
					annot->value, tag_name, namespace__name(ns), annot->component_idx);
				goto out;
			}
		}
	}

	cu__for_each_function(cu, core_id, fn) {
		struct elf_function *func = NULL;

		/*
		 * Skip functions that:
		 *   - are marked as declarations
		 *   - do not have full argument names
		 *   - have arguments with uncertain locations, e.g packed
		 *   structs passed by value on stack
		 *   - are not in ftrace list (if it's available)
		 *   - are not external (in case ftrace filter is not available)
		 */
		if (fn->declaration)
			continue;
		if (!ftype__has_arg_names(&fn->proto))
			continue;
		if (funcs->cnt) {
			const char *name;

			name = function__name(fn);
			if (!name)
				continue;

			func = btf_encoder__find_function(encoder, name);
			if (!func) {
				if (encoder->verbose)
					printf("could not find function '%s' in the ELF functions table\n", name);
				continue;
			}
		} else {
			if (!fn->external)
				continue;
		}
		if (!func)
			continue;

		if (ftype__has_uncertain_arg_loc(cu, &fn->proto))
			fn->proto.uncertain_parm_loc = 1;

		err = btf_encoder__save_func(encoder, fn, func);
		if (err)
			goto out;
	}

	if (encoder->encode_vars)
		err = btf_encoder__encode_cu_variables(encoder);

	if (!err)
		err = LSK__DELETE;
out:
	encoder->cu = NULL;
	return err;
}
