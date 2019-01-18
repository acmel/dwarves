/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook
 */

#ifndef _LIBBTF_H
#define _LIBBTF_H

#include "gobuffer.h"

#include <stdbool.h>
#include <stdint.h>

struct btf {
	union {
		struct btf_header *hdr;
		void		  *data;
	};
	void		  *priv;
	Elf		  *elf;
	GElf_Ehdr	  ehdr;
	struct gobuffer	  types;
	struct gobuffer   *strings;
	char		  *filename;
	size_t		  size;
	int		  swapped;
	int		  in_fd;
	uint8_t		  wordsize;
	bool		  is_big_endian;
	uint32_t	  type_index;
};

extern uint8_t btf_verbose;
#define btf_verbose_log(fmt, ...) { if (btf_verbose) printf(fmt, __VA_ARGS__); }

struct base_type;
struct ftype;

struct btf *btf__new(const char *filename, Elf *elf);
void btf__free(struct btf *btf);

int32_t btf__add_base_type(struct btf *btf, const struct base_type *bt);
int32_t btf__add_ref_type(struct btf *btf, uint16_t kind, uint32_t type,
			  uint32_t name, bool kind_flag);
int btf__add_member(struct btf *btf, uint32_t name, uint32_t type, bool kind_flag,
		    uint32_t bitfield_size, uint32_t bit_offset);
int32_t btf__add_struct(struct btf *btf, uint8_t kind, uint32_t name,
			bool kind_flag, uint32_t size, uint16_t nr_members);
int32_t btf__add_array(struct btf *btf, uint32_t type, uint32_t index_type,
		       uint32_t nelems);
int32_t btf__add_enum(struct btf *btf, uint32_t name, uint32_t size,
		      uint16_t nr_entries);
int btf__add_enum_val(struct btf *btf, uint32_t name, int32_t value);
int32_t btf__add_func_proto(struct btf *btf, struct ftype *ftype,
			    uint32_t type_id_off);
void btf__set_strings(struct btf *btf, struct gobuffer *strings);
int  btf__encode(struct btf *btf, uint8_t flags);

char *btf__string(struct btf *btf, uint32_t ref);
int btf__load(struct btf *btf);

uint32_t btf__get32(struct btf *btf, uint32_t *p);

void *btf__get_buffer(struct btf *btf);

size_t btf__get_size(struct btf *btf);

#endif /* _LIBBTF_H */
