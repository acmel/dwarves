/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook
 */

#ifndef _LIBBTF_H
#define _LIBBTF_H

#include "gobuffer.h"

#include <stdbool.h>
#include <stdint.h>
#include "lib/bpf/src/btf.h"

struct btf_elf {
	Elf		  *elf;
	GElf_Ehdr	  ehdr;
	struct gobuffer   percpu_secinfo;
	char		  *filename;
	int		  in_fd;
	struct btf	  *btf;
};

extern uint8_t btf_elf__verbose;
extern uint8_t btf_elf__force;
#define btf_elf__verbose_log(fmt, ...) { if (btf_elf__verbose) printf(fmt, __VA_ARGS__); }
extern bool btf_gen_floats;

#define PERCPU_SECTION ".data..percpu"

struct cu;
struct base_type;
struct ftype;

struct btf_elf *btf_elf__new(const char *filename, Elf *elf, struct btf *base_btf);
void btf_elf__delete(struct btf_elf *btf);

int32_t btf__encode_base_type(struct btf *btf, const struct base_type *bt, const char *name);
int32_t btf__encode_ref_type(struct btf *btf, uint16_t kind, uint32_t type, const char *name, bool kind_flag);
int btf__encode_member(struct btf *btf, const char *name, uint32_t type, uint32_t bitfield_size, uint32_t bit_offset);
int32_t btf__encode_struct(struct btf *btf, uint8_t kind, const char *name, uint32_t size);
int32_t btf__encode_array(struct btf *btf, uint32_t type, uint32_t index_type, uint32_t nelems);
int32_t btf__encode_enum(struct btf *btf, const char *name, uint32_t size);
int btf__encode_enum_val(struct btf *btf, const char *name, int32_t value);
int32_t btf__encode_func_proto(struct btf *btf, struct cu *cu, struct ftype *ftype, uint32_t type_id_off);
int32_t btf__encode_var_type(struct btf *btf, uint32_t type, const char *name, uint32_t linkage);
int32_t btf__encode_var_secinfo(struct gobuffer *buf, uint32_t type, uint32_t offset, uint32_t size);
int32_t btf__encode_datasec_type(struct btf *btf, const char *section_name, struct gobuffer *var_secinfo_buf);
int  btf_elf__encode(struct btf_elf *btf, uint8_t flags);

#endif /* _LIBBTF_H */
