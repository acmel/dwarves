#ifndef _BTF_ENCODER_H_
#define _BTF_ENCODER_H_ 1
/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook

  Derived from ctf_encoder.h, which is:
  Copyright (C) Arnaldo Carvalho de Melo <acme@redhat.com>
 */

#include <stdbool.h>
#include <stdint.h>

struct btf;
struct btf_elf;
struct cu;

#define MAX_PERCPU_VAR_CNT 4096

struct var_info {
	uint64_t    addr;
	const char *name;
	uint32_t    sz;
};

struct btf_encoder {
	struct btf_elf *btfe;
	bool	 has_index_type,
	         need_index_type,
		 verbose;
	uint32_t array_index_id;
	struct {
		struct var_info vars[MAX_PERCPU_VAR_CNT];
		int		var_cnt;
		uint32_t	shndx;
		uint64_t	base_addr;
		uint64_t	sec_sz;
	} percpu;
};

struct btf_encoder *btf_encoder__new(struct cu *cu, struct btf *base_btf, bool skip_encoding_vars, bool verbose);
void btf_encoder__delete(struct btf_encoder *encoder);

int btf_encoder__encode(const char *filename);

int cu__encode_btf(struct cu *cu, struct btf *base_btf, int verbose, bool force,
		   bool skip_encoding_vars, const char *detached_btf_filename);

#endif /* _BTF_ENCODER_H_ */
