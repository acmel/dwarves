/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook
 */

#ifndef _LIBBTF_H
#define _LIBBTF_H

#include "gobuffer.h"

#include <stdbool.h>
#include <stdint.h>

struct btf_elf {
	union {
		struct btf_header *hdr;
		void		  *data;
	};
	void		  *priv;
	Elf		  *elf;
	GElf_Ehdr	  ehdr;
	struct elf_symtab *symtab;
	struct gobuffer	  types;
	struct gobuffer   *strings;
	struct gobuffer   percpu_secinfo;
	char		  *filename;
	size_t		  size;
	int		  swapped;
	int		  in_fd;
	uint8_t		  wordsize;
	bool		  is_big_endian;
	bool		  raw_btf; // "/sys/kernel/btf/vmlinux"
	uint32_t	  type_index;
	uint32_t	  percpu_shndx;
	uint64_t	  percpu_base_addr;
};

extern uint8_t btf_elf__verbose;
#define btf_elf__verbose_log(fmt, ...) { if (btf_elf__verbose) printf(fmt, __VA_ARGS__); }

#define PERCPU_SECTION ".data..percpu"

struct base_type;
struct ftype;

struct btf_elf *btf_elf__new(const char *filename, Elf *elf);
void btf_elf__delete(struct btf_elf *btf);

int32_t btf_elf__add_base_type(struct btf_elf *btf, const struct base_type *bt);
int32_t btf_elf__add_ref_type(struct btf_elf *btf, uint16_t kind, uint32_t type,
			      uint32_t name, bool kind_flag);
int btf_elf__add_member(struct btf_elf *btf, uint32_t name, uint32_t type, bool kind_flag,
			uint32_t bitfield_size, uint32_t bit_offset);
int32_t btf_elf__add_struct(struct btf_elf *btf, uint8_t kind, uint32_t name,
			    bool kind_flag, uint32_t size, uint16_t nr_members);
int32_t btf_elf__add_array(struct btf_elf *btf, uint32_t type, uint32_t index_type,
			   uint32_t nelems);
int32_t btf_elf__add_enum(struct btf_elf *btf, uint32_t name, uint32_t size,
			  uint16_t nr_entries);
int btf_elf__add_enum_val(struct btf_elf *btf, uint32_t name, int32_t value);
int32_t btf_elf__add_func_proto(struct btf_elf *btf, struct ftype *ftype,
				uint32_t type_id_off);
int32_t btf_elf__add_var_type(struct btf_elf *btfe, uint32_t type, uint32_t name_off,
			      uint32_t linkage);
int32_t btf_elf__add_var_secinfo(struct gobuffer *buf, uint32_t type,
				 uint32_t offset, uint32_t size);
int32_t btf_elf__add_datasec_type(struct btf_elf *btfe, const char *section_name,
				  struct gobuffer *var_secinfo_buf);
void btf_elf__set_strings(struct btf_elf *btf, struct gobuffer *strings);
int  btf_elf__encode(struct btf_elf *btf, uint8_t flags);

char *btf_elf__string(struct btf_elf *btf, uint32_t ref);
int btf_elf__load(struct btf_elf *btf);

uint32_t btf_elf__get32(struct btf_elf *btf, uint32_t *p);

void *btf_elf__get_buffer(struct btf_elf *btf);

size_t btf_elf__get_size(struct btf_elf *btf);

#endif /* _LIBBTF_H */
