#include <fcntl.h>
#include <limits.h>
#include <malloc.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "libctf.h"
#include "ctf.h"
#include "dutil.h"
#include "gobuffer.h"

struct ctf {
	void		*buf;
	struct gobuffer types;
	struct gobuffer *strings;
	const char *filename;
	size_t		size;
	int		swapped;
	unsigned int	type_index;
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

void ctf__set_strings(struct ctf *self, struct gobuffer *strings)
{
	self->strings = strings;
}

int ctf__add_base_type(struct ctf *self, uint32_t name, uint16_t size)
{
	struct ctf_full_type t;

	t.base.ctf_name = name;
	t.base.ctf_info = CTF_INFO_ENCODE(CTF_TYPE_KIND_INT, 0, 0);
	t.base.ctf_size = size;
	t.ctf_size_high = CTF_TYPE_INT_ENCODE(0, 0, size);

	gobuffer__add(&self->types, &t, sizeof(t) - sizeof(uint32_t));
	return ++self->type_index;
}

int ctf__add_short_type(struct ctf *self, uint16_t kind, uint16_t type,
			uint32_t name)
{
	struct ctf_short_type t;

	t.ctf_name = name;
	t.ctf_info = CTF_INFO_ENCODE(kind, 0, 0);
	t.ctf_type = type;

	gobuffer__add(&self->types, &t, sizeof(t));
	return ++self->type_index;
}

int ctf__add_fwd_decl(struct ctf *self, uint32_t name)
{
	return ctf__add_short_type(self, CTF_TYPE_KIND_FWD, 0, name);
}

int ctf__add_array(struct ctf *self, uint16_t type, uint16_t index_type,
		   uint32_t nelems)
{
	struct {
		struct ctf_short_type t;
		struct ctf_array a;
	} array;

	array.t.ctf_name = 0;
	array.t.ctf_info = CTF_INFO_ENCODE(CTF_TYPE_KIND_ARR, 0, 0);
	array.t.ctf_size = 0;
	array.a.ctf_array_type	     = type;
	array.a.ctf_array_index_type = index_type;
	array.a.ctf_array_nelems     = nelems;

	gobuffer__add(&self->types, &array, sizeof(array));
	return ++self->type_index;
}

void ctf__add_short_member(struct ctf *self, uint32_t name, uint16_t type,
			   uint16_t offset, int64_t *position)
{
	struct ctf_short_member m = {
		.ctf_member_name   = name,
		.ctf_member_type   = type,
		.ctf_member_offset = offset,
	};

	memcpy(gobuffer__ptr(&self->types, *position), &m, sizeof(m));
	*position += sizeof(m);
}

void ctf__add_full_member(struct ctf *self, uint32_t name, uint16_t type,
			  uint64_t offset, int64_t *position)
{
	struct ctf_full_member m = {
		.ctf_member_name   = name,
		.ctf_member_type   = type,
		.ctf_member_offset_high = offset >> 32,
		.ctf_member_offset_low  = offset & 0xffffffffl,
	};

	memcpy(gobuffer__ptr(&self->types, *position), &m, sizeof(m));
	*position += sizeof(m);
}

int ctf__add_struct(struct ctf *self, uint16_t kind, uint32_t name,
		    uint64_t size, uint16_t nr_members, int64_t *position)
{
	const bool is_short = size < CTF_SHORT_MEMBER_LIMIT;
	uint32_t members_len = ((is_short ? sizeof(struct ctf_short_member) :
					    sizeof(struct ctf_full_member)) *
				nr_members);
	struct ctf_full_type t;
	int len;

	t.base.ctf_name = name;
	t.base.ctf_info = CTF_INFO_ENCODE(kind, nr_members, 0);
	if (size < 0xffff) {
		len = sizeof(t.base);
		t.base.ctf_size = size;
	} else {
		len = sizeof(t);
		t.base.ctf_size	= 0xffff;
		t.ctf_size_high	= size >> 32;
		t.ctf_size_low	= size & 0xffffffff;
	}

	gobuffer__add(&self->types, &t, len);
	*position = gobuffer__allocate(&self->types, members_len);
	return ++self->type_index;
}

void ctf__add_parameter(struct ctf *self, uint16_t type, int64_t *position)
{
	uint16_t *parm = gobuffer__ptr(&self->types, *position);

	*parm = type;
	*position += sizeof(*parm);
}

int ctf__add_function_type(struct ctf *self, uint16_t type, uint16_t nr_parms,
			   int64_t *position)
{
	struct ctf_short_type t;
	int len = sizeof(uint16_t) * nr_parms;

	/*
	 * Round up to next multiple of 4 to maintain 32-bit alignment.
	 */
	if (len & 0x2)
		len += 0x2;

	t.ctf_name = 0;
	t.ctf_info = CTF_INFO_ENCODE(CTF_TYPE_KIND_FUNC, nr_parms, 0);
	t.ctf_type = type;

	gobuffer__add(&self->types, &t, sizeof(t));
	*position = gobuffer__allocate(&self->types, len);
	return ++self->type_index;
}

int ctf__add_enumeration_type(struct ctf *self, uint32_t name,
			      uint16_t nr_entries, int64_t *position)
{
	struct ctf_short_type e;

	e.ctf_name = name;
	e.ctf_info = CTF_INFO_ENCODE(CTF_TYPE_KIND_ENUM, nr_entries, 0);
	e.ctf_size = 0;

	gobuffer__add(&self->types, &e, sizeof(e));
	*position = gobuffer__allocate(&self->types,
				       nr_entries * sizeof(struct ctf_enum));
	return ++self->type_index;
}

void ctf__add_enumerator(struct ctf *self, uint32_t name, uint32_t value,
			 int64_t *position)
{
	struct ctf_enum m = {
		.ctf_enum_name = name,
		.ctf_enum_val  = value,
	};

	memcpy(gobuffer__ptr(&self->types, *position), &m, sizeof(m));
	*position += sizeof(m);
}

static const void *ctf__compress(void *orig_buf, unsigned int *size)
{
	z_stream z = {
		.zalloc	  = Z_NULL,
		.zfree	  = Z_NULL,
		.opaque	  = Z_NULL,
		.avail_in = *size,
		.next_in  = (Bytef *)orig_buf,
	};
	void *bf = NULL;
	unsigned int bf_size = 0;

	if (deflateInit(&z, Z_BEST_COMPRESSION) != Z_OK)
		goto out;

#define _GOBUFFER__ZCHUNK 16384 * 1024

	do {
		const unsigned int new_bf_size = bf_size + _GOBUFFER__ZCHUNK;
		void *nbf = realloc(bf, new_bf_size);

		if (nbf == NULL)
			goto out_close_and_free;

		bf = nbf;
		z.avail_out = _GOBUFFER__ZCHUNK;
		z.next_out  = (Bytef *)bf + bf_size;
		bf_size	    = new_bf_size;
		if (deflate(&z, Z_FULL_FLUSH) == Z_STREAM_ERROR)
			goto out_close_and_free;
		printf("%s: size=%d, bf_size=%d, total_out=%ld, total_in=%ld\n", __func__, *size, bf_size, z.total_out, z.total_in);
	} while (z.total_in != *size);

	if (deflate(&z, Z_FINISH) == Z_STREAM_ERROR)
		goto out_close_and_free;

	deflateEnd(&z);
	*size = z.total_out;
out:
	return bf;

out_close_and_free:
	deflateEnd(&z);
	free(bf);
	bf = NULL;
	goto out;
}

int ctf__encode(struct ctf *self, uint8_t flags)
{
	struct ctf_header *hdr;
	unsigned int size;
	const void *bf;
	int fd;

	size = gobuffer__size(&self->types) + gobuffer__size(self->strings);
	self->size = sizeof(*hdr) + size;
	self->buf = malloc(self->size);

	if (self->buf == NULL) {
		printf("%s: malloc failed!\n", __func__);
		return -ENOMEM;
	}

	hdr = self->buf;
	memset(hdr, 0, sizeof(*hdr));
	hdr->ctf_magic    = CTF_MAGIC;
	hdr->ctf_version  = 2;
	hdr->ctf_flags    = flags;
	hdr->ctf_type_off = 0;
	hdr->ctf_str_off  = gobuffer__size(&self->types);
	hdr->ctf_str_len  = gobuffer__size(self->strings);

	memcpy(self->buf + sizeof(*hdr) + hdr->ctf_type_off,
	       gobuffer__entries(&self->types),
	       gobuffer__size(&self->types));
	memcpy(self->buf + sizeof(*hdr) + hdr->ctf_str_off,
	       gobuffer__entries(self->strings),
	       gobuffer__size(self->strings));

	*(char *)(self->buf + sizeof(*hdr) + hdr->ctf_str_off) = '\0';
	if (flags & CTF_FLAGS_COMPR) {
		bf = ctf__compress(self->buf + sizeof(*hdr), &size);
		if (bf == NULL) {
			printf("%s: ctf__compress failed!\n", __func__);
			return -ENOMEM;
		}
	} else {
		bf   = self->buf;
		size = self->size;
	}

	printf("\n\ntypes:\n entries: %d\n size: %u"
		 "\nstrings:\n entries: %u\n size: %u\ncompressed size: %d\n",
	       self->type_index,
	       gobuffer__size(&self->types),
	       gobuffer__nr_entries(self->strings),
	       gobuffer__size(self->strings), size);

	char pathname[PATH_MAX];
	snprintf(pathname, sizeof(pathname), "%s.SUNW_ctf", self->filename);
	fd = creat(pathname, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		fprintf(stderr, "%s: open(%s) failed!\n", __func__, pathname);
		return -1;
	}
	write(fd, hdr, sizeof(*hdr));
	write(fd, bf, size);
	close(fd);
	return 0;
}
