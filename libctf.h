#ifndef _LIBCTF_H
#define _LIBCTF_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct ctf *ctf__new(const char *filename, void *buf, size_t size);
void ctf__delete(struct ctf *ctf);

uint16_t ctf__get16(struct ctf *self, uint16_t *p);
uint32_t ctf__get32(struct ctf *self, uint32_t *p);
void ctf__put16(struct ctf *self, uint16_t *p, uint16_t val);
void ctf__put32(struct ctf *self, uint32_t *p, uint32_t val);

void *ctf__get_buffer(struct ctf *self);
size_t ctf__get_size(struct ctf *self);

int ctf__add_base_type(struct ctf *self, uint32_t name, uint16_t size);
int ctf__add_fwd_decl(struct ctf *self, uint32_t name);
int ctf__add_short_type(struct ctf *self, uint16_t kind, uint16_t type,
			uint32_t name);
void ctf__add_short_member(struct ctf *self, uint32_t name, uint16_t type,
			   uint16_t offset, int64_t *position);
void ctf__add_full_member(struct ctf *self, uint32_t name, uint16_t type,
			  uint64_t offset, int64_t *position);
int ctf__add_struct(struct ctf *self, uint16_t kind, uint32_t name,
		    uint64_t size, uint16_t nr_members, int64_t *position);
int ctf__add_array(struct ctf *self, uint16_t type, uint16_t index_type,
		   uint32_t nelems);
void ctf__add_parameter(struct ctf *self, uint16_t type, int64_t *position);
int ctf__add_function_type(struct ctf *self, uint16_t type,
			   uint16_t nr_parms, bool varargs, int64_t *position);
int ctf__add_enumeration_type(struct ctf *self, uint32_t name, uint16_t size,
			      uint16_t nr_entries, int64_t *position);
void ctf__add_enumerator(struct ctf *self, uint32_t name, uint32_t value,
			 int64_t *position);

struct gobuffer;

void ctf__set_strings(struct ctf *self, struct gobuffer *strings);
int  ctf__encode(struct ctf *self, uint8_t flags);

#endif /* _LIBCTF_H */
