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

#define BTF_IDS_SECTION		".BTF_ids"
#define BTF_ID_FUNC_PFX		"__BTF_ID__func__"
#define BTF_ID_SET8_PFX		"__BTF_ID__set8__"
#define BTF_SET8_KFUNCS		(1 << 0)
#define BTF_KFUNC_TYPE_TAG	"bpf_kfunc"
#define BTF_FASTCALL_TAG       "bpf_fastcall"
#define KF_FASTCALL            (1 << 12)

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
	uint32_t type_id_off;
	uint16_t nr_parms;
	uint16_t nr_annots;
	uint8_t initialized:1;
	uint8_t optimized_parms:1;
	uint8_t unexpected_reg:1;
	uint8_t inconsistent_proto:1;
	uint8_t processed:1;
	int ret_type_id;
	struct btf_encoder_func_parm *parms;
	struct btf_encoder_func_annot *annots;
};

struct elf_function {
	const char	*name;
	char		*alias;
	bool		 generated;
	size_t		prefixlen;
	struct btf_encoder_func_state state;
};

struct elf_secinfo {
	uint64_t    addr;
	const char *name;
	uint64_t    sz;
	uint32_t    type;
	bool        include;
	struct gobuffer secinfo;
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
			  gen_distilled_base;
	uint32_t	  array_index_id;
	struct elf_secinfo *secinfo;
	size_t             seccnt;
	int                encode_vars;
	struct {
		struct elf_function *entries;
		int		    allocated;
		int		    cnt;
		int		    suffix_cnt; /* number of .isra, .part etc */
	} functions;
};

struct btf_func {
	const char *name;
	int	    type_id;
};

/* Half open interval representing range of addresses containing kfuncs */
struct btf_kfunc_set_range {
	uint64_t start;
	uint64_t end;
};

static LIST_HEAD(encoders);
static pthread_mutex_t encoders__lock = PTHREAD_MUTEX_INITIALIZER;

static int btf_encoder__add_saved_funcs(struct btf_encoder *encoder);

/* mutex only needed for add/delete, as this can happen in multiple encoding
 * threads.  Traversal of the list is currently confined to thread collection.
 */

#define btf_encoders__for_each_encoder(encoder)		\
	list_for_each_entry(encoder, &encoders, node)

static void btf_encoders__add(struct btf_encoder *encoder)
{
	pthread_mutex_lock(&encoders__lock);
	list_add_tail(&encoder->node, &encoders);
	pthread_mutex_unlock(&encoders__lock);
}

static void btf_encoders__delete(struct btf_encoder *encoder)
{
	struct btf_encoder *existing = NULL;

	pthread_mutex_lock(&encoders__lock);
	/* encoder may not have been added to list yet; check. */
	btf_encoders__for_each_encoder(existing) {
		if (encoder == existing)
			break;
	}
	if (encoder == existing)
		list_del(&encoder->node);
	pthread_mutex_unlock(&encoders__lock);
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

#if LIBBPF_MAJOR_VERSION < 1
static inline int libbpf_err(int ret)
{
        if (ret < 0)
                errno = -ret;
        return ret;
}

static
int btf__add_enum64(struct btf *btf __maybe_unused, const char *name __maybe_unused,
		    __u32 byte_sz __maybe_unused, bool is_signed __maybe_unused)
{
	return  libbpf_err(-ENOTSUP);
}

static
int btf__add_enum64_value(struct btf *btf __maybe_unused, const char *name __maybe_unused,
			  __u64 value __maybe_unused)
{
	return  libbpf_err(-ENOTSUP);
}
#endif

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
	else
		id = btf__add_enum64(btf, name, size, etype->is_signed_enum);
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
	else if (etype->size > 32)
		err = btf__add_enum64_value(encoder->btf, name, value);
	else
		err = btf__add_enum_value(encoder->btf, name, value);

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

static int32_t btf_encoder__add_func_proto(struct btf_encoder *encoder, struct ftype *ftype,
					   struct elf_function *func)
{
	struct btf *btf = encoder->btf;
	const struct btf_type *t;
	struct parameter *param;
	uint16_t nr_params, param_idx;
	int32_t id, type_id;
	char tmp_name[KSYM_NAME_LEN];
	const char *name;
	struct btf_encoder_func_state *state;

	assert(ftype != NULL || func != NULL);

	/* add btf_type for func_proto */
	if (ftype) {
		nr_params = ftype->nr_parms + (ftype->unspec_parms ? 1 : 0);
		type_id = btf_encoder__tag_type(encoder, ftype->tag.type);
	} else if (func) {
		state = &func->state;
		nr_params = state->nr_parms;
		type_id = state->ret_type_id;
	} else {
		return 0;
	}

	id = btf__add_func_proto(btf, type_id);
	if (id > 0) {
		t = btf__type_by_id(btf, id);
		btf_encoder__log_type(encoder, t, false, false, "return=%u args=(%s", t->type, !nr_params ? "void)\n" : "");
	} else {
		btf__log_err(btf, BTF_KIND_FUNC_PROTO, NULL, true, id,
			     "return=%u vlen=%u Error emitting BTF type",
			     type_id, nr_params);
		return id;
	}

	/* add parameters */
	param_idx = 0;
	if (ftype) {
		ftype__for_each_parameter(ftype, param) {
			const char *name = parameter__name(param);

			type_id = param->tag.type == 0 ? 0 : encoder->type_id_off + param->tag.type;
			++param_idx;
			if (btf_encoder__add_func_param(encoder, name, type_id,
							param_idx == nr_params))
				return -1;
		}

		++param_idx;
		if (ftype->unspec_parms)
			if (btf_encoder__add_func_param(encoder, NULL, 0,
							param_idx == nr_params))
				return -1;
	} else {
		for (param_idx = 0; param_idx < nr_params; param_idx++) {
			struct btf_encoder_func_parm *p = &state->parms[param_idx];

			name = btf__name_by_offset(btf, p->name_off);

			/* adding BTF data may result in a move of the
			 * name string memory, so make a temporary copy.
			 */
			strncpy(tmp_name, name, sizeof(tmp_name) - 1);

			if (btf_encoder__add_func_param(encoder, tmp_name, p->type_id,
							param_idx == nr_params))
				return -1;
		}
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

int32_t btf_encoder__add_encoder(struct btf_encoder *encoder, struct btf_encoder *other)
{
	size_t shndx;
	if (encoder == other)
		return 0;

	btf_encoder__add_saved_funcs(other);

	for (shndx = 1; shndx < other->seccnt; shndx++) {
		struct gobuffer *var_secinfo_buf = &other->secinfo[shndx].secinfo;
		size_t sz = gobuffer__size(var_secinfo_buf);
		uint16_t nr_var_secinfo = sz / sizeof(struct btf_var_secinfo);
		uint32_t type_id;
		uint32_t next_type_id = btf__type_cnt(encoder->btf);
		int32_t i, id;
		struct btf_var_secinfo *vsi;

		if (strcmp(encoder->secinfo[shndx].name, other->secinfo[shndx].name)) {
			fprintf(stderr, "mismatched ELF sections at index %zu: \"%s\", \"%s\"\n",
				shndx, encoder->secinfo[shndx].name, other->secinfo[shndx].name);
			return -1;
		}

		for (i = 0; i < nr_var_secinfo; i++) {
			vsi = (struct btf_var_secinfo *)var_secinfo_buf->entries + i;
			type_id = next_type_id + vsi->type - 1; /* Type ID starts from 1 */
			id = btf_encoder__add_var_secinfo(encoder, shndx, type_id, vsi->offset, vsi->size);
			if (id < 0)
				return id;
		}
	}

	return btf__add_btf(encoder->btf, other->btf);
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
	printf("%s (%s): skipping BTF encoding of function due to ",
	       func->alias ?: func->name, func->name);
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

static bool funcs__match(struct btf_encoder *encoder, struct elf_function *func,
			 struct btf *btf1, struct btf_encoder_func_state *s1,
			 struct btf *btf2, struct btf_encoder_func_state *s2)
{
	uint8_t i;

	if (s1->nr_parms != s2->nr_parms) {
		btf_encoder__log_func_skip(encoder, func,
					   "param count mismatch; %d params != %d params\n",
					   s1->nr_parms, s2->nr_parms);
		return false;
	}
	if (!types__match(encoder, btf1, s1->ret_type_id, btf2, s2->ret_type_id)) {
		btf_encoder__log_func_skip(encoder, func, "return type mismatch\n");
		return false;
	}
	if (s1->nr_parms == 0)
		return true;

	for (i = 0; i < s1->nr_parms; i++) {
		if (!types__match(encoder, btf1, s1->parms[i].type_id,
				  btf2, s2->parms[i].type_id)) {
			if (encoder->verbose) {
				const char *p1 = btf__name_by_offset(btf1, s1->parms[i].name_off);
				const char *p2 = btf__name_by_offset(btf2, s2->parms[i].name_off);

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

static int32_t btf_encoder__save_func(struct btf_encoder *encoder, struct function *fn, struct elf_function *func)
{
	struct btf_encoder_func_state *existing = &func->state;
	struct btf_encoder_func_state state = { 0 };
	struct ftype *ftype = &fn->proto;
	struct btf *btf = encoder->btf;
	struct llvm_annotation *annot;
	struct parameter *param;
	uint8_t param_idx = 0;
	int str_off, err = 0;

	/* if already skipping this function, no need to proceed. */
	if (existing->unexpected_reg || existing->inconsistent_proto)
		return 0;

	state.nr_parms = ftype->nr_parms + (ftype->unspec_parms ? 1 : 0);
	state.ret_type_id = ftype->tag.type == 0 ? 0 : encoder->type_id_off + ftype->tag.type;
	if (state.nr_parms > 0) {
		state.parms = zalloc(state.nr_parms * sizeof(*state.parms));
		if (!state.parms) {
			err = -ENOMEM;
			goto out;
		}
	}
	state.inconsistent_proto = ftype->inconsistent_proto;
	state.unexpected_reg = ftype->unexpected_reg;
	state.optimized_parms = ftype->optimized_parms;
	ftype__for_each_parameter(ftype, param) {
		const char *name = parameter__name(param) ?: "";

		str_off = btf__add_str(btf, name);
		if (str_off < 0) {
			err = str_off;
			goto out;
		}
		state.parms[param_idx].name_off = str_off;
		state.parms[param_idx].type_id = param->tag.type == 0 ? 0 :
						encoder->type_id_off + param->tag.type;
		param_idx++;
	}
	if (ftype->unspec_parms)
		state.parms[param_idx].type_id = 0;

	list_for_each_entry(annot, &fn->annots, node)
		state.nr_annots++;
	if (state.nr_annots) {
		uint8_t idx = 0;

		state.annots = zalloc(state.nr_annots * sizeof(*state.annots));
		if (!state.annots) {
			err = -ENOMEM;
			goto out;
		}
		list_for_each_entry(annot, &fn->annots, node) {
			str_off = btf__add_str(encoder->btf, annot->value);
			if (str_off < 0) {
				err = str_off;
				goto out;
			}
			state.annots[idx].value = str_off;
			state.annots[idx].component_idx = annot->component_idx;
			idx++;
		}
	}
	state.initialized = 1;

	if (state.unexpected_reg)
		btf_encoder__log_func_skip(encoder, func,
					   "unexpected register used for parameter\n");
	if (!existing->initialized) {
		memcpy(existing, &state, sizeof(*existing));
		return 0;
	}

	/* If saving and we find an existing entry, we want to merge
	 * observations across both functions, checking that the
	 * "seen optimized parameters", "inconsistent prototype"
	 * and "unexpected register" status is reflected in the
	 * func entry.
	 * If the entry is new, record encoder state required
	 * to add the local function later (encoder + type_id_off)
	 * such that we can add the function later.
	 */
	existing->optimized_parms |= state.optimized_parms;
	existing->unexpected_reg |= state.unexpected_reg;
	if (!existing->unexpected_reg &&
	    !funcs__match(encoder, func, encoder->btf, &state,
			   encoder->btf, existing))
		existing->inconsistent_proto = 1;
out:
	zfree(&state.annots);
	zfree(&state.parms);
	return err;
}

static int32_t btf_encoder__add_func(struct btf_encoder *encoder, struct function *fn,
				     struct elf_function *func)
{
	int btf_fnproto_id, btf_fn_id, tag_type_id = 0;
	int16_t component_idx = -1;
	const char *name;
	const char *value;
	char tmp_value[KSYM_NAME_LEN];

	assert(fn != NULL || func != NULL);

	btf_fnproto_id = btf_encoder__add_func_proto(encoder, fn ? &fn->proto : NULL, func);
	name = func->alias ?: func->name;
	if (btf_fnproto_id >= 0)
		btf_fn_id = btf_encoder__add_ref_type(encoder, BTF_KIND_FUNC, btf_fnproto_id,
						      name, false);
	if (btf_fnproto_id < 0 || btf_fn_id < 0) {
		printf("error: failed to encode function '%s': invalid %s\n",
		       name, btf_fnproto_id < 0 ? "proto" : "func");
		return -1;
	}
	if (!fn) {
		struct btf_encoder_func_state *state = &func->state;
		uint16_t idx;

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
	} else {
		struct llvm_annotation *annot;

		list_for_each_entry(annot, &fn->annots, node) {
			value = annot->value;
			component_idx = annot->component_idx;

			tag_type_id = btf_encoder__add_decl_tag(encoder, value, btf_fn_id,
								component_idx);
			if (tag_type_id < 0)
				break;
		}
	}
	if (tag_type_id < 0) {
		fprintf(stderr,
			"error: failed to encode tag '%s' to func %s with component_idx %d\n",
			value, name, component_idx);
		return -1;
	}

	return 0;
}

static int btf_encoder__add_saved_funcs(struct btf_encoder *encoder)
{
	int i;

	for (i = 0; i < encoder->functions.cnt; i++) {
		struct elf_function *func = &encoder->functions.entries[i];
		struct btf_encoder_func_state *state = &func->state;
		struct btf_encoder *other_encoder = NULL;

		if (!state->initialized || state->processed)
			continue;
		/* merge optimized-out status across encoders; since each
		 * encoder has the same elf symbol table we can use the
		 * same index to access the same elf symbol.
		 */
		btf_encoders__for_each_encoder(other_encoder) {
			struct elf_function *other_func;
			struct btf_encoder_func_state *other_state;
			uint8_t optimized, unexpected, inconsistent;

			if (other_encoder == encoder)
				continue;

			other_func = &other_encoder->functions.entries[i];
			other_state = &other_func->state;
			if (!other_state->initialized)
				continue;
			optimized = state->optimized_parms | other_state->optimized_parms;
			unexpected = state->unexpected_reg | other_state->unexpected_reg;
			inconsistent = state->inconsistent_proto | other_state->inconsistent_proto;
			if (!unexpected && !inconsistent &&
			    !funcs__match(encoder, func,
					  encoder->btf, state,
					  other_encoder->btf, other_state))
				inconsistent = 1;
			state->optimized_parms = other_state->optimized_parms = optimized;
			state->unexpected_reg = other_state->unexpected_reg = unexpected;
			state->inconsistent_proto = other_state->inconsistent_proto = inconsistent;

			other_state->processed = 1;
		}
		/* do not exclude functions with optimized-out parameters; they
		 * may still be _called_ with the right parameter values, they
		 * just do not _use_ them.  Only exclude functions with
		 * unexpected register use or multiple inconsistent prototypes.
		 */
		if (!state->unexpected_reg && !state->inconsistent_proto) {
			if (btf_encoder__add_func(encoder, NULL, func))
				return -1;
		}
		state->processed = 1;
	}
	return 0;
}

static int functions_cmp(const void *_a, const void *_b)
{
	const struct elf_function *a = _a;
	const struct elf_function *b = _b;

	/* if search key allows prefix match, verify target has matching
	 * prefix len and prefix matches.
	 */
	if (a->prefixlen && a->prefixlen == b->prefixlen)
		return strncmp(a->name, b->name, b->prefixlen);
	return strcmp(a->name, b->name);
}

#ifndef max
#define max(x, y) ((x) < (y) ? (y) : (x))
#endif

static void *reallocarray_grow(void *ptr, int *nmemb, size_t size)
{
	int new_nmemb = max(1000, *nmemb * 3 / 2);
	void *new = realloc(ptr, new_nmemb * size);

	if (new)
		*nmemb = new_nmemb;
	return new;
}

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
		new = reallocarray_grow(encoder->functions.entries,
					&encoder->functions.allocated,
					sizeof(*encoder->functions.entries));
		if (!new) {
			/*
			 * The cleanup - delete_functions is called
			 * in btf_encoder__encode_cu error path.
			 */
			return -1;
		}
		encoder->functions.entries = new;
	}

	memset(&encoder->functions.entries[encoder->functions.cnt], 0,
	       sizeof(*new));
	encoder->functions.entries[encoder->functions.cnt].name = name;
	if (strchr(name, '.')) {
		const char *suffix = strchr(name, '.');

		encoder->functions.suffix_cnt++;
		encoder->functions.entries[encoder->functions.cnt].prefixlen = suffix - name;
	}
	encoder->functions.cnt++;
	return 0;
}

static struct elf_function *btf_encoder__find_function(const struct btf_encoder *encoder,
						       const char *name, size_t prefixlen)
{
	struct elf_function key = { .name = name, .prefixlen = prefixlen };

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
		return btf_encoder__add_func_proto(encoder, tag__ftype(tag), NULL);
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

static int btf_func_cmp(const void *_a, const void *_b)
{
	const struct btf_func *a = _a;
	const struct btf_func *b = _b;

	return strcmp(a->name, b->name);
}

/*
 * Collects all functions described in BTF.
 * Returns non-zero on error.
 */
static int btf_encoder__collect_btf_funcs(struct btf_encoder *encoder, struct gobuffer *funcs)
{
	struct btf *btf = encoder->btf;
	int nr_types, type_id;
	int err = -1;

	/* First collect all the func entries into an array */
	nr_types = btf__type_cnt(btf);
	for (type_id = 1; type_id < nr_types; type_id++) {
		const struct btf_type *type;
		struct btf_func func = {};
		const char *name;

		type = btf__type_by_id(btf, type_id);
		if (!type) {
			fprintf(stderr, "%s: malformed BTF, can't resolve type for ID %d\n",
				__func__, type_id);
			err = -EINVAL;
			goto out;
		}

		if (!btf_is_func(type))
			continue;

		name = btf__name_by_offset(btf, type->name_off);
		if (!name) {
			fprintf(stderr, "%s: malformed BTF, can't resolve name for ID %d\n",
				__func__, type_id);
			err = -EINVAL;
			goto out;
		}

		func.name = name;
		func.type_id = type_id;
		err = gobuffer__add(funcs, &func, sizeof(func));
		if (err < 0)
			goto out;
	}

	/* Now that we've collected funcs, sort them by name */
	gobuffer__sort(funcs, sizeof(struct btf_func), btf_func_cmp);

	err = 0;
out:
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

static int btf_encoder__tag_kfunc(struct btf_encoder *encoder, struct gobuffer *funcs, const char *kfunc, __u32 flags)
{
	struct btf_func key = { .name = kfunc };
	struct btf *btf = encoder->btf;
	struct btf_func *target;
	const void *base;
	unsigned int cnt;
	int err;

	base = gobuffer__entries(funcs);
	cnt = gobuffer__nr_entries(funcs);
	target = bsearch(&key, base, cnt, sizeof(key), btf_func_cmp);
	if (!target) {
		fprintf(stderr, "%s: failed to find kfunc '%s' in BTF\n", __func__, kfunc);
		return -1;
	}

	/* Note we are unconditionally adding the btf_decl_tag even
	 * though vmlinux may already contain btf_decl_tags for kfuncs.
	 * We are ok to do this b/c we will later btf__dedup() to remove
	 * any duplicates.
	 */
	err = btf__add_kfunc_decl_tag(btf, BTF_KFUNC_TYPE_TAG, target->type_id, kfunc);
	if (err < 0)
		return err;
	if (flags & KF_FASTCALL) {
		err = btf__add_kfunc_decl_tag(btf, BTF_FASTCALL_TAG, target->type_id, kfunc);
		if (err < 0)
			return err;
	}

	return 0;
}

static int btf_encoder__tag_kfuncs(struct btf_encoder *encoder)
{
	const char *filename = encoder->source_filename;
	struct gobuffer btf_kfunc_ranges = {};
	struct gobuffer btf_funcs = {};
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

	elf = elf_begin(fd, ELF_C_READ, NULL);
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

		data = elf_getdata(scn, 0);
		if (!data) {
			elf_error("Failed to get ELF section(%d) data", i);
			goto out;
		}

		if (shdr.sh_type == SHT_SYMTAB) {
			symbols_shndx = i;
			symscn = scn;
			symbols = data;
			strtabidx = shdr.sh_link;
		} else if (!strcmp(secname, BTF_IDS_SECTION)) {
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

	err = btf_encoder__collect_btf_funcs(encoder, &btf_funcs);
	if (err) {
		fprintf(stderr, "%s: failed to collect BTF funcs\n", __func__);
		goto out;
	}

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
		unsigned int ranges_cnt;
		char *func, *name;
		ptrdiff_t off;
		GElf_Sym sym;
		bool found;
		int err;
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

		err = btf_encoder__tag_kfunc(encoder, &btf_funcs, func, pair->flags);
		if (err) {
			fprintf(stderr, "%s: failed to tag kfunc '%s'\n", __func__, func);
			free(func);
			goto out;
		}
		free(func);
	}

	err = 0;
out:
	__gobuffer__delete(&btf_funcs);
	__gobuffer__delete(&btf_kfunc_ranges);
	if (elf)
		elf_end(elf);
	if (fd != -1)
		close(fd);
	return err;
}

int btf_encoder__encode(struct btf_encoder *encoder)
{
	bool should_tag_kfuncs;
	int err;
	size_t shndx;

	/* for single-threaded case, saved funcs are added here */
	btf_encoder__add_saved_funcs(encoder);

	for (shndx = 1; shndx < encoder->seccnt; shndx++)
		if (gobuffer__size(&encoder->secinfo[shndx].secinfo))
			btf_encoder__add_datasec(encoder, shndx);

	/* Empty file, nothing to do, so... done! */
	if (btf__type_cnt(encoder->btf) == 1)
		return 0;

	/* Note vmlinux may already contain btf_decl_tag's for kfuncs. So
	 * take care to call this before btf_dedup().
	 */
	should_tag_kfuncs = encoder->tag_kfuncs && !encoder->skip_encoding_decl_tag;
	if (should_tag_kfuncs && btf_encoder__tag_kfuncs(encoder)) {
		fprintf(stderr, "%s: failed to tag kfuncs!\n", __func__);
		return -1;
	}

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
#if LIBBPF_MAJOR_VERSION >= 1 && LIBBPF_MINOR_VERSION >= 5
		if (encoder->gen_distilled_base) {
			struct btf *btf = NULL, *distilled_base = NULL;

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
#endif
		err = btf_encoder__write_elf(encoder, encoder->btf, BTF_ELF_SEC);
	}
	return err;
}


static int btf_encoder__collect_symbols(struct btf_encoder *encoder)
{
	uint32_t sym_sec_idx;
	uint32_t core_id;
	GElf_Sym sym;

	elf_symtab__for_each_symbol_index(encoder->symtab, core_id, sym, sym_sec_idx) {
		if (btf_encoder__collect_function(encoder, &sym))
			return -1;
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

		/* Check for invalid BTF names */
		if (!btf_name_valid(name)) {
			dump_invalid_symbol("Found invalid variable name when encoding btf",
					    name, encoder->verbose, encoder->force);
			if (encoder->force)
				continue;
			else
				return -1;
		}

		if (filter_variable_name(name))
			continue;

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

	if (encoder) {
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
		encoder->verbose	 = verbose;
		encoder->has_index_type  = false;
		encoder->need_index_type = false;
		encoder->array_index_id  = 0;
		encoder->encode_vars = 0;
		if (!conf_load->skip_encoding_btf_vars)
			encoder->encode_vars |= BTF_VAR_PERCPU;
		if (conf_load->encode_btf_global_vars)
			encoder->encode_vars |= BTF_VAR_GLOBAL;

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

		if (btf_encoder__collect_symbols(encoder))
			goto out_delete;

		if (encoder->verbose)
			printf("File %s:\n", cu->filename);
		btf_encoders__add(encoder);
	}
out:
	return encoder;

out_delete:
	btf_encoder__delete(encoder);
	return NULL;
}

void btf_encoder__delete_func(struct elf_function *func)
{
	free(func->alias);
	zfree(&func->state.annots);
	zfree(&func->state.parms);
}

void btf_encoder__delete(struct btf_encoder *encoder)
{
	int i;
	size_t shndx;

	if (encoder == NULL)
		return;

	btf_encoders__delete(encoder);
	for (shndx = 0; shndx < encoder->seccnt; shndx++)
		__gobuffer__delete(&encoder->secinfo[shndx].secinfo);
	zfree(&encoder->filename);
	zfree(&encoder->source_filename);
	btf__free(encoder->btf);
	encoder->btf = NULL;
	elf_symtab__delete(encoder->symtab);

	for (i = 0; i < encoder->functions.cnt; i++)
		btf_encoder__delete_func(&encoder->functions.entries[i]);
	encoder->functions.allocated = encoder->functions.cnt = 0;
	free(encoder->functions.entries);
	encoder->functions.entries = NULL;

	free(encoder);
}

int btf_encoder__encode_cu(struct btf_encoder *encoder, struct cu *cu, struct conf_load *conf_load)
{
	struct llvm_annotation *annot;
	int btf_type_id, tag_type_id, skipped_types = 0;
	uint32_t core_id;
	struct function *fn;
	struct tag *pos;
	int err = 0;

	encoder->cu = cu;
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
		bool save = false;

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
			const char *name;

			name = function__name(fn);
			if (!name)
				continue;

			/* prefer exact function name match... */
			func = btf_encoder__find_function(encoder, name, 0);
			if (func) {
				if (func->generated)
					continue;
				if (conf_load->skip_encoding_btf_inconsistent_proto)
					save = true;
				else
					func->generated = true;
			} else if (encoder->functions.suffix_cnt &&
				   conf_load->btf_gen_optimized) {
				/* falling back to name.isra.0 match if no exact
				 * match is found; only bother if we found any
				 * .suffix function names.  The function
				 * will be saved and added once we ensure
				 * it does not have optimized-out parameters
				 * in any cu.
				 */
				func = btf_encoder__find_function(encoder, name,
								  strlen(name));
				if (func) {
					save = true;
					if (encoder->verbose)
						printf("matched function '%s' with '%s'%s\n",
						       name, func->name,
						       fn->proto.optimized_parms ?
						       ", has optimized-out parameters" :
						       fn->proto.unexpected_reg ? ", has unexpected register use by params" :
						       "");
					func->alias = strdup(name);
				}
			}
		} else {
			if (!fn->external)
				continue;
		}
		if (!func)
			continue;

		if (save)
			err = btf_encoder__save_func(encoder, fn, func);
		else
			err = btf_encoder__add_func(encoder, fn, func);
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

struct btf *btf_encoder__btf(struct btf_encoder *encoder)
{
	return encoder->btf;
}
