#ifndef _BTF_ENCODER_H_
#define _BTF_ENCODER_H_ 1
/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook

  Derived from ctf_encoder.h, which is:
  Copyright (C) Arnaldo Carvalho de Melo <acme@redhat.com>
 */

#include <stdbool.h>

struct btf_encoder;
struct btf;
struct cu;

struct btf_encoder *btf_encoder__new(struct cu *cu, struct btf *base_btf, bool skip_encoding_vars, bool force, bool gen_floats, bool verbose);
void btf_encoder__delete(struct btf_encoder *encoder);

int btf_encoder__encode(struct btf_encoder *encoder, const char *detached_filename);

int btf_encoder__encode_cu(struct btf_encoder *encoder, struct cu *cu);

#endif /* _BTF_ENCODER_H_ */
