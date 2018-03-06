#ifndef _BTF_ENCODER_H_
#define _BTF_ENCODER_H_ 1

struct cu;

int cu__encode_btf(struct cu *cu, int verbose);

#endif /* _BTF_ENCODER_H_ */
