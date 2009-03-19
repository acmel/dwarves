#include <stdio.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <zlib.h>

#include "libctf.h"
#include "ctf.h"
#include "dutil.h"

struct ctf {
	void	*buf;
	size_t	size;
	int	swapped;
	const char *filename;
};

uint16_t ctf__get16(struct ctf *self, uint16_t *p)
{
	uint16_t val = *p;

	if (self->swapped)
		val = ((val >> 8) | (val << 8));
	return val;
}

uint32_t ctf__get32(struct ctf *self, uint32_t *p)
{
	uint32_t val = *p;

	if (self->swapped)
		val = ((val >> 24) |
		       ((val >> 8) & 0x0000ff00) |
		       ((val << 8) & 0x00ff0000) |
		       (val << 24));
	return val;
}

void ctf__put16(struct ctf *self, uint16_t *p, uint16_t val)
{
	if (self->swapped)
		val = ((val >> 8) | (val << 8));
	*p = val;
}

void ctf__put32(struct ctf *self, uint32_t *p, uint32_t val)
{
	if (self->swapped)
		val = ((val >> 24) |
		       ((val >> 8) & 0x0000ff00) |
		       ((val << 8) & 0x00ff0000) |
		       (val << 24));
	*p = val;
}

static int ctf__decompress(struct ctf *self, void *orig_buf, size_t orig_size)
{
	struct ctf_header *hp = orig_buf;
	const char *err_str;
	z_stream state;
	size_t len;
	void *new;

	len = (ctf__get32(self, &hp->ctf_str_off) +
	       ctf__get32(self, &hp->ctf_str_len));
	new = malloc(len + sizeof(*hp));
	if (!new) {
		fprintf(stderr, "CTF decompression allocation failure.\n");
		return -ENOMEM;
	}
	memcpy(new, hp, sizeof(*hp));

	memset(&state, 0, sizeof(state));
	state.next_in = (Bytef *) (hp + 1);
	state.avail_in = orig_size - sizeof(*hp);
	state.next_out = new + sizeof(*hp);
	state.avail_out = len;

	if (inflateInit(&state) != Z_OK) {
		err_str = "struct ctf decompression inflateInit failure.";
		goto err;
	}

	if (inflate(&state, Z_FINISH) != Z_STREAM_END) {
		err_str = "struct ctf decompression inflate failure.";
		goto err;
	}

	if (inflateEnd(&state) != Z_OK) {
		err_str = "struct ctf decompression inflateEnd failure.";
		goto err;
	}

	if (state.total_out != len) {
		err_str = "struct ctf decompression truncation error.";
		goto err;
	}

	self->buf = new;
	self->size = len + sizeof(*hp);

	return 0;

err:
	fputs(err_str, stderr);
	free(new);
	return -EINVAL;
}

static int ctf__load(struct ctf *self, void *orig_buf, size_t orig_size)
{
	struct ctf_header *hp = orig_buf;
	int err = -ENOTSUP;

	if (hp->ctf_version != CTF_VERSION)
		goto out;

	err = -EINVAL;
	if (hp->ctf_magic == CTF_MAGIC)
		self->swapped = 0;
	else if (hp->ctf_magic == CTF_MAGIC_SWAP)
		self->swapped = 1;
	else
		goto out;

	if (!(hp->ctf_flags & CTF_FLAGS_COMPR)) {
		err = -ENOMEM;
		self->buf = malloc(orig_size);
		if (self->buf != NULL) {
			memcpy(self->buf, orig_buf, orig_size);
			self->size = orig_size;
			err = 0;
		}
	} else
		err = ctf__decompress(self, orig_buf, orig_size);
out:
	return err;
}

struct ctf *ctf__new(const char *filename, void *orig_buf, size_t orig_size)
{
	struct ctf *self = zalloc(sizeof(*self));

	if (self != NULL) {
		self->filename = strdup(filename);
		if (self->filename == NULL ||
		    (orig_buf != NULL &&
		     ctf__load(self, orig_buf, orig_size) != 0)) {
			free(self);
			self = NULL;
		}
	}

	return self;
}

void ctf__delete(struct ctf *self)
{
	free(self->buf);
	free(self);
}

void *ctf__get_buffer(struct ctf *self)
{
	return self->buf;
}

size_t ctf__get_size(struct ctf *self)
{
	return self->size;
}
