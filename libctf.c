#include <stdio.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <zlib.h>

#include "libctf.h"
#include "ctf.h"

struct Ctf {
	void	*buf;
	size_t	size;
	int	swapped;
};

u_int16_t ctf_get16(Ctf *cp, u_int16_t *p)
{
	u_int16_t val = *p;

	if (cp->swapped)
		val = ((val >> 8) | (val << 8));
	return val;
}

u_int32_t ctf_get32(Ctf *cp, u_int32_t *p)
{
	u_int32_t val = *p;

	if (cp->swapped)
		val = ((val >> 24) |
		       ((val >> 8) & 0x0000ff00) |
		       ((val << 8) & 0x00ff0000) |
		       (val << 24));
	return val;
}

void ctf_put16(Ctf *cp, u_int16_t *p, u_int16_t val)
{
	if (cp->swapped)
		val = ((val >> 8) | (val << 8));
	*p = val;
}

void ctf_put32(Ctf *cp, u_int32_t *p, u_int32_t val)
{
	if (cp->swapped)
		val = ((val >> 24) |
		       ((val >> 8) & 0x0000ff00) |
		       ((val << 8) & 0x00ff0000) |
		       (val << 24));
	*p = val;
}

static int decompress_ctf(struct Ctf *cp, void *orig_buf, size_t orig_size)
{
	struct ctf_header *hp = orig_buf;
	const char *err_str;
	z_stream state;
	size_t len;
	void *new;

	len = (ctf_get32(cp, &hp->ctf_str_off) +
	       ctf_get32(cp, &hp->ctf_str_len));
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
		err_str = "Ctf decompression inflateInit failure.";
		goto err;
	}

	if (inflate(&state, Z_FINISH) != Z_STREAM_END) {
		err_str = "Ctf decompression inflate failure.";
		goto err;
	}

	if (inflateEnd(&state) != Z_OK) {
		err_str = "Ctf decompression inflateEnd failure.";
		goto err;
	}

	if (state.total_out != len) {
		err_str = "Ctf decompression truncation error.";
		goto err;
	}

	cp->buf = new;
	cp->size = len + sizeof(*hp);

	return 0;

err:
	fputs(err_str, stderr);
	free(new);
	return -EINVAL;
}

Ctf *ctf_begin(void *orig_buf, size_t orig_size)
{
	struct ctf_header *hp = orig_buf;
	struct Ctf *cp;
	int swapped;

	if (hp->ctf_magic == CTF_MAGIC)
		swapped = 0;
	else if (hp->ctf_magic == CTF_MAGIC_SWAP)
		swapped = 1;
	else {
		fprintf(stderr, "Bad CTF magic %04x.\n", hp->ctf_magic);
		return NULL;
	}

	if (hp->ctf_version != CTF_VERSION) {
		fprintf(stderr, "Bad CTF version %u, expected %u.\n",
			hp->ctf_version, CTF_VERSION);
		return NULL;
	}

	cp = malloc(sizeof(*cp));
	if (!cp) {
		fprintf(stderr, "Ctf allocation failure.\n");
		return NULL;
	}

	memset(cp, 0, sizeof(*cp));
	cp->swapped = swapped;

	if (!(hp->ctf_flags & CTF_FLAGS_COMPR)) {
		cp->buf = malloc(orig_size);
		if (!cp->buf) {
			fprintf(stderr, "Ctf buffer allocation failure.\n");
			free(cp);
			return NULL;
		}
		memcpy(cp->buf, orig_buf, orig_size);
		cp->size = orig_size;

		return cp;
	} else {
		int err = decompress_ctf(cp, orig_buf, orig_size);

		if (err) {
			fprintf(stderr, "Ctf decompression failure.\n");
			free(cp);
			return NULL;
		}
	}

	return cp;
}

void ctf_end(Ctf *cp)
{
	free(cp->buf);
	free(cp);
}

void *ctf_get_buffer(Ctf *cp)
{
	return cp->buf;
}

size_t ctf_get_size(Ctf *cp)
{
	return cp->size;
}
