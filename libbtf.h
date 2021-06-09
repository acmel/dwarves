/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook
 */

#ifndef _LIBBTF_H
#define _LIBBTF_H

struct btf;
struct gobuffer;

#include <stdbool.h>
#include <stdint.h>

extern bool btf_gen_floats;

#define PERCPU_SECTION ".data..percpu"

struct btf_encoder;
struct cu;
struct base_type;
struct ftype;

int32_t btf_encoder__add_base_type(struct btf_encoder *encoder, const struct base_type *bt, const char *name);
int32_t btf_encoder__add_ref_type(struct btf_encoder *encoder, uint16_t kind, uint32_t type, const char *name, bool kind_flag);
int btf_encoder__add_field(struct btf_encoder *encoder, const char *name, uint32_t type, uint32_t bitfield_size, uint32_t bit_offset);
int32_t btf_encoder__add_struct(struct btf_encoder *encoder, uint8_t kind, const char *name, uint32_t size);
int32_t btf_encoder__add_array(struct btf_encoder *encoder, uint32_t type, uint32_t index_type, uint32_t nelems);
int32_t btf__encode_enum(struct btf *btf, const char *name, uint32_t size);
int btf__encode_enum_val(struct btf *btf, const char *name, int32_t value);
int32_t btf_encoder__add_func_proto(struct btf_encoder *encoder, struct cu *cu, struct ftype *ftype, uint32_t type_id_off);
int32_t btf__encode_var_type(struct btf *btf, uint32_t type, const char *name, uint32_t linkage);
int32_t btf__encode_var_secinfo(struct gobuffer *buf, uint32_t type, uint32_t offset, uint32_t size);
int32_t btf__encode_datasec_type(struct btf *btf, const char *section_name, struct gobuffer *var_secinfo_buf);

#endif /* _LIBBTF_H */
