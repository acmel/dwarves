#ifndef _LIBCTF_H
#define _LIBCTF_H

#include <sys/types.h>

typedef struct Ctf Ctf;

extern Ctf *ctf_begin(void *buf, size_t size);
extern void ctf_end(Ctf *ctf);

extern u_int16_t ctf_get16(Ctf *cp, u_int16_t *p);
extern u_int32_t ctf_get32(Ctf *cp, u_int32_t *p);
extern void ctf_put16(Ctf *cp, u_int16_t *p, u_int16_t val);
extern void ctf_put32(Ctf *cp, u_int32_t *p, u_int32_t val);

extern void *ctf_get_buffer(Ctf *cp);
extern size_t ctf_get_size(Ctf *cp);

#endif /* _LIBCTF_H */
