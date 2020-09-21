#ifndef _BTF_ENCODER_H_
#define _BTF_ENCODER_H_ 1
/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook

  Derived from ctf_encoder.h, which is:
  Copyright (C) Arnaldo Carvalho de Melo <acme@redhat.com>
 */

struct cu;

int btf_encoder__encode();

int cu__encode_btf(struct cu *cu, int verbose, bool force,
		   bool skip_encoding_vars);

#endif /* _BTF_ENCODER_H_ */
