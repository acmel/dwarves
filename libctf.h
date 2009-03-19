#ifndef _LIBCTF_H
#define _LIBCTF_H

#include <stdint.h>

struct ctf *ctf__new(const char *filename, void *buf, size_t size);
void ctf__delete(struct ctf *ctf);

uint16_t ctf__get16(struct ctf *self, uint16_t *p);
uint32_t ctf__get32(struct ctf *self, uint32_t *p);
void ctf__put16(struct ctf *self, uint16_t *p, uint16_t val);
void ctf__put32(struct ctf *self, uint32_t *p, uint32_t val);

void *ctf__get_buffer(struct ctf *self);
size_t ctf__get_size(struct ctf *self);

#endif /* _LIBCTF_H */
