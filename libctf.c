#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <malloc.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "libctf.h"
#include "ctf.h"
#include "dutil.h"
#include "gobuffer.h"

bool ctf__ignore_symtab_function(const GElf_Sym *sym, const char *sym_name)
{
	return (!elf_sym__is_local_function(sym) ||
		elf_sym__visibility(sym) != STV_DEFAULT ||
		sym->st_size == 0 ||
		memcmp(sym_name, "__libc_csu_",
		       sizeof("__libc_csu_") - 1) == 0);
}

bool ctf__ignore_symtab_object(const GElf_Sym *sym, const char *sym_name)
{
	return (!elf_sym__is_local_object(sym) || sym->st_size == 0 ||
		elf_sym__visibility(sym) != STV_DEFAULT ||
		strchr(sym_name, '.') != NULL);
}

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

int ctf__load(struct ctf *self)
{
	int err = -ENOTSUP;
	GElf_Shdr shdr;
	Elf_Scn *sec = elf_section_by_name(self->elf, &self->ehdr,
					   &shdr, ".SUNW_ctf", NULL);

	if (sec == NULL)
		return -ESRCH;

	Elf_Data *data = elf_getdata(sec, NULL);
	if (data == NULL) {
		fprintf(stderr, "%s: cannot get data of CTF section.\n",
			__func__);
		return -1;
	}

	struct ctf_header *hp = data->d_buf;
	size_t orig_size = data->d_size;

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
			memcpy(self->buf, hp, orig_size);
			self->size = orig_size;
			err = 0;
		}
	} else
		err = ctf__decompress(self, hp, orig_size);
out:
	return err;
}

struct ctf *ctf__new(const char *filename, Elf *elf)
{
	struct ctf *self = zalloc(sizeof(*self));

	if (self != NULL) {
		self->filename = strdup(filename);
		if (self->filename == NULL)
			goto out_delete;

		if (elf != NULL) {
			self->in_fd = -1;
			self->elf = elf;
		} else {

			self->in_fd = open(filename, O_RDONLY);
			if (self->in_fd < 0)
				goto out_delete_filename;

			if (elf_version(EV_CURRENT) == EV_NONE) {
				fprintf(stderr, "%s: cannot set libelf version.\n",
					__func__);
				goto out_close;
			}

			self->elf = elf_begin(self->in_fd, ELF_C_READ_MMAP, NULL);
			if (!self->elf) {
				fprintf(stderr, "%s: cannot read %s ELF file.\n",
					__func__, filename);
				goto out_close;
			}
		}

		if (gelf_getehdr(self->elf, &self->ehdr) == NULL) {
			fprintf(stderr, "%s: cannot get elf header.\n", __func__);
			goto out_elf_end;
		}

		switch (self->ehdr.e_ident[EI_CLASS]) {
		case ELFCLASS32: self->wordsize = 4; break;
		case ELFCLASS64: self->wordsize = 8; break;
		default:	 self->wordsize = 0; break;
		}
	}

	return self;
out_elf_end:
	if (elf == NULL)
		elf_end(self->elf);
out_close:
	if (elf == NULL)
		close(self->in_fd);
out_delete_filename:
	free(self->filename);
out_delete:
	free(self);
	return NULL;
}

void ctf__delete(struct ctf *self)
{
	if (self != NULL) {
		if (self->in_fd != -1) {
			elf_end(self->elf);
			close(self->in_fd);
		}
		__gobuffer__delete(&self->objects);
		__gobuffer__delete(&self->types);
		__gobuffer__delete(&self->funcs);
		elf_symtab__delete(self->symtab);
		free(self->filename);
		free(self->buf);
		free(self);
	}
}

char *ctf__string(struct ctf *self, uint32_t ref)
{
	struct ctf_header *hp = self->buf;
	uint32_t off = CTF_REF_OFFSET(ref);
	char *name;

	if (CTF_REF_TBL_ID(ref) != CTF_STR_TBL_ID_0)
		return "(external ref)";

	if (off >= ctf__get32(self, &hp->ctf_str_len))
		return "(ref out-of-bounds)";

	if ((off + ctf__get32(self, &hp->ctf_str_off)) >= self->size)
		return "(string table truncated)";

	name = ((char *)(hp + 1) + ctf__get32(self, &hp->ctf_str_off) + off);

	return name[0] == '\0' ? NULL : name;
}

void *ctf__get_buffer(struct ctf *self)
{
	return self->buf;
}

size_t ctf__get_size(struct ctf *self)
{
	return self->size;
}

int ctf__load_symtab(struct ctf *self)
{
	self->symtab = elf_symtab__new(".symtab", self->elf, &self->ehdr);
	return self->symtab == NULL ? -1 : 0;
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
			   bool varargs, int64_t *position)
{
	struct ctf_short_type t;
	int len = sizeof(uint16_t) * (nr_parms + !!varargs);

	/*
	 * Round up to next multiple of 4 to maintain 32-bit alignment.
	 */
	if (len & 0x2)
		len += 0x2;

	t.ctf_name = 0;
	t.ctf_info = CTF_INFO_ENCODE(CTF_TYPE_KIND_FUNC,
				     nr_parms + !!varargs, 0);
	t.ctf_type = type;

	gobuffer__add(&self->types, &t, sizeof(t));
	*position = gobuffer__allocate(&self->types, len);
	if (varargs) {
		unsigned int pos = *position + (nr_parms * sizeof(uint16_t));
		uint16_t *end_of_args = gobuffer__ptr(&self->types, pos);
		*end_of_args = 0;
	}

	return ++self->type_index;
}

int ctf__add_enumeration_type(struct ctf *self, uint32_t name, uint16_t size,
			      uint16_t nr_entries, int64_t *position)
{
	struct ctf_short_type e;

	e.ctf_name = name;
	e.ctf_info = CTF_INFO_ENCODE(CTF_TYPE_KIND_ENUM, nr_entries, 0);
	e.ctf_size = size;

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

void ctf__add_function_parameter(struct ctf *self, uint16_t type,
				 int64_t *position)
{
	uint16_t *parm = gobuffer__ptr(&self->funcs, *position);

	*parm = type;
	*position += sizeof(*parm);
}

int ctf__add_function(struct ctf *self, uint16_t type, uint16_t nr_parms,
		      bool varargs, int64_t *position)
{
	struct ctf_short_type func;
	int len = sizeof(uint16_t) * (nr_parms + !!varargs);

	/*
	 * Round up to next multiple of 4 to maintain 32-bit alignment.
	 */
	if (len & 0x2)
		len += 0x2;

	func.ctf_info = CTF_INFO_ENCODE(CTF_TYPE_KIND_FUNC,
					nr_parms + !!varargs, 0);
	func.ctf_type = type;

	/*
	 * We don't store the name for the function, it comes from the
	 * symtab.
	 */
	gobuffer__add(&self->funcs, &func.ctf_info,
		      sizeof(func) - sizeof(func.ctf_name));
	*position = gobuffer__allocate(&self->funcs, len);
	if (varargs) {
		unsigned int pos = *position + (nr_parms * sizeof(uint16_t));
		uint16_t *end_of_args = gobuffer__ptr(&self->funcs, pos);
		*end_of_args = 0;
	}

	return 0;
}

int ctf__add_object(struct ctf *self, uint16_t type)
{
	return gobuffer__add(&self->objects, &type,
			     sizeof(type)) >= 0 ? 0 : -ENOMEM;
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
#if 0
		fprintf(stderr,
			"%s: size=%d, bf_size=%d, total_out=%ld, total_in=%ld\n",
			__func__, *size, bf_size, z.total_out, z.total_in);
#endif
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
	void *bf = NULL;
	int err = -1;

	/* Empty file, nothing to do, so... done! */
	if (gobuffer__size(&self->types) == 0)
		return 0;

	size = (gobuffer__size(&self->types) +
		gobuffer__size(&self->objects) +
		gobuffer__size(&self->funcs) +
		gobuffer__size(self->strings));

	self->size = sizeof(*hdr) + size;
	self->buf = malloc(self->size);

	if (self->buf == NULL) {
		fprintf(stderr, "%s: malloc failed!\n", __func__);
		return -ENOMEM;
	}

	hdr = self->buf;
	memset(hdr, 0, sizeof(*hdr));
	hdr->ctf_magic    = CTF_MAGIC;
	hdr->ctf_version  = 2;
	hdr->ctf_flags    = flags;

	uint32_t offset = 0;
	hdr->ctf_object_off = offset;
	offset += gobuffer__size(&self->objects);
	hdr->ctf_func_off = offset;
	offset += gobuffer__size(&self->funcs);
	hdr->ctf_type_off = offset;
	offset += gobuffer__size(&self->types);
	hdr->ctf_str_off  = offset;
	hdr->ctf_str_len  = gobuffer__size(self->strings);

	void *payload = self->buf + sizeof(*hdr);
	gobuffer__copy(&self->objects, payload + hdr->ctf_object_off);
	gobuffer__copy(&self->funcs, payload + hdr->ctf_func_off);
	gobuffer__copy(&self->types, payload + hdr->ctf_type_off);
	gobuffer__copy(self->strings, payload + hdr->ctf_str_off);

	*(char *)(self->buf + sizeof(*hdr) + hdr->ctf_str_off) = '\0';
	if (flags & CTF_FLAGS_COMPR) {
		bf = (void *)ctf__compress(self->buf + sizeof(*hdr), &size);
		if (bf == NULL) {
			printf("%s: ctf__compress failed!\n", __func__);
			return -ENOMEM;
		}
		void *new_bf = malloc(sizeof(*hdr) + size);
		if (new_bf == NULL)
			return -ENOMEM;
		memcpy(new_bf, hdr, sizeof(*hdr));
		memcpy(new_bf + sizeof(*hdr), bf, size);
		free(bf);
		bf = new_bf;
		size += sizeof(*hdr);
	} else {
		bf   = self->buf;
		size = self->size;
	}
#if 0
	printf("\n\ntypes:\n entries: %d\n size: %u"
		 "\nstrings:\n entries: %u\n size: %u\ncompressed size: %d\n",
	       self->type_index,
	       gobuffer__size(&self->types),
	       gobuffer__nr_entries(self->strings),
	       gobuffer__size(self->strings), size);
#endif
	int fd = open(self->filename, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s\n", self->filename);
		return -1;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "Cannot set libelf version.\n");
		goto out_close;
	}

	Elf *elf = elf_begin(fd, ELF_C_RDWR, NULL);
	if (elf == NULL) {
		fprintf(stderr, "Cannot update ELF file.\n");
		goto out_close;
	}

	elf_flagelf(elf, ELF_C_SET, ELF_F_DIRTY);

	GElf_Ehdr ehdr_mem;
	GElf_Ehdr *ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (ehdr == NULL) {
		fprintf(stderr, "%s: elf_getehdr failed.\n", __func__);
		goto out_close;
	}

	/*
	 * First we look if there was already a .SUNW_ctf section to overwrite.
	 */
	Elf_Data *data = NULL;
	size_t strndx;
	GElf_Shdr shdr_mem;
	GElf_Shdr *shdr;
	Elf_Scn *scn = NULL;

	elf_getshdrstrndx(elf, &strndx);

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		shdr = gelf_getshdr(scn, &shdr_mem);
		if (shdr == NULL)
			continue;
		char *secname = elf_strptr(elf, strndx, shdr->sh_name);
		if (strcmp(secname, ".SUNW_ctf") == 0) {
			data = elf_getdata(scn, data);
			goto out_update;
		}
	}
	/* FIXME
	 * OK, if we have the section, that is ok, we can just replace the
	 * data, if not, I made a mistake on the small amount of boilerplate
	 * below, probably .relA.ted to relocations...
	 */
#if 0
	/* Now we look if the ".SUNW_ctf" string is in the strings table */
	scn = elf_getscn(elf, strndx);
	shdr = gelf_getshdr(scn, &shdr_mem);

	data = elf_getdata(scn, data);

	fprintf(stderr, "Looking for the string\n");
	size_t ctf_name_offset = 1; /* First byte is '\0' */
	while (ctf_name_offset < data->d_size) {
		const char *cur_str = data->d_buf + ctf_name_offset;

		fprintf(stderr, "*-> %s\n", cur_str);
		if (strcmp(cur_str, ".SUNW_ctf") == 0)
			goto found_SUNW_ctf_str;

		ctf_name_offset += strlen(cur_str) + 1;
	}

	/* Add the section name */
	const size_t ctf_name_len = strlen(".SUNW_ctf") + 1;
	char *new_strings_table = malloc(data->d_size + ctf_name_len);
	if (new_strings_table == NULL)
		goto out_close;

	memcpy(new_strings_table, data->d_buf, data->d_size);
	strcpy(new_strings_table + data->d_size, ".SUNW_ctf");
	ctf_name_offset = data->d_size;
	data->d_size += ctf_name_len;
	data->d_buf = new_strings_table;
	elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);

	Elf_Scn *newscn;
found_SUNW_ctf_str:
	newscn = elf_newscn(elf);
	if (newscn == NULL)
		goto out_close;

	data = elf_newdata(newscn);
	if (data == NULL)
		goto out_close;

	shdr = gelf_getshdr(newscn, &shdr_mem);
	shdr->sh_name = ctf_name_offset;
	shdr->sh_type = SHT_PROGBITS;
	gelf_update_shdr(newscn, &shdr_mem);
	elf_flagshdr(newscn, ELF_C_SET, ELF_F_DIRTY);
#else
	char pathname[PATH_MAX];
	snprintf(pathname, sizeof(pathname), "%s.SUNW_ctf", self->filename);
	fd = creat(pathname, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		fprintf(stderr, "%s: open(%s) failed!\n", __func__, pathname);
		goto out_close;
	}
	if (write(fd, bf, size) != size)
		goto out_close;

	if (close(fd) < 0)
		goto out_unlink;

	char cmd[PATH_MAX];
	snprintf(cmd, sizeof(cmd), "objcopy --add-section .SUNW_ctf=%s %s",
		 pathname, self->filename);
	if (system(cmd) == 0)
		err = 0;
out_unlink:
	unlink(pathname);
	return err;
#endif
out_update:
	data->d_buf = bf;
	data->d_size = size;
	elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);

	if (elf_update(elf, ELF_C_NULL) < 0)
		goto out_close;
	if (elf_update(elf, ELF_C_WRITE) < 0)
		goto out_close;

	elf_end(elf);
	err = 0;
out_close:
	if (bf != self->buf)
		free(bf);
	close(fd);
	return err;
}
