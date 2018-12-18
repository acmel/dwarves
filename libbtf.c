#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <malloc.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include "libbtf.h"
#include "btf.h"
#include "dutil.h"
#include "gobuffer.h"
#include "dwarves.h"

#define BTF_INFO_ENCODE(kind, kind_flag, vlen)				\
	((!!(kind_flag) << 31) | ((kind) << 24) | ((vlen) & BTF_MAX_VLEN))
#define BTF_INT_ENCODE(encoding, bits_offset, nr_bits)		\
	((encoding) << 24 | (bits_offset) << 16 | (nr_bits))

struct btf_int_type {
	struct btf_type type;
	uint32_t 	data;
};

struct btf_enum_type {
	struct btf_type type;
	struct btf_enum btf_enum;
};

struct btf_array_type {
	struct btf_type type;
	struct btf_array array;
};

uint8_t btf_verbose;

struct btf *btf__new(const char *filename, Elf *elf)
{
	struct btf *btf = zalloc(sizeof(*btf));

	if (!btf)
		return NULL;

	btf->in_fd = -1;
	btf->filename = strdup(filename);
	if (btf->filename == NULL)
		goto errout;

	if (elf != NULL) {
		btf->elf = elf;
	} else {
		btf->in_fd = open(filename, O_RDONLY);
		if (btf->in_fd < 0)
			goto errout;

		if (elf_version(EV_CURRENT) == EV_NONE) {
			fprintf(stderr, "%s: cannot set libelf version.\n",
				__func__);
			goto errout;
		}

		btf->elf = elf_begin(btf->in_fd, ELF_C_READ_MMAP, NULL);
		if (!btf->elf) {
			fprintf(stderr, "%s: cannot read %s ELF file.\n",
				__func__, filename);
			goto errout;
		}
	}

	if (gelf_getehdr(btf->elf, &btf->ehdr) == NULL) {
		fprintf(stderr, "%s: cannot get elf header.\n", __func__);
		goto errout;
	}

	switch (btf->ehdr.e_ident[EI_DATA]) {
	case ELFDATA2LSB: btf->is_big_endian = false; break;
	case ELFDATA2MSB: btf->is_big_endian = true;  break;
	default:
		fprintf(stderr, "%s: unknown elf endianness.\n", __func__);
		goto errout;
	}

	switch (btf->ehdr.e_ident[EI_CLASS]) {
	case ELFCLASS32: btf->wordsize = 4; break;
	case ELFCLASS64: btf->wordsize = 8; break;
	default:	 btf->wordsize = 0; break;
	}

	return btf;

errout:
	btf__free(btf);
	return NULL;
}

void btf__free(struct btf *btf)
{
	if (!btf)
		return;

	if (btf->in_fd != -1) {
		close(btf->in_fd);
		if (btf->elf)
			elf_end(btf->elf);
	}

	__gobuffer__delete(&btf->types);
	free(btf->filename);
	free(btf->data);
	free(btf);
}

static void *btf__nohdr_data(struct btf *btf)
{
	return btf->hdr + 1;
}

void btf__set_strings(struct btf *btf, struct gobuffer *strings)
{
	btf->strings = strings;
}

#define BITS_PER_BYTE 8
#define BITS_PER_BYTE_MASK (BITS_PER_BYTE - 1)
#define BITS_PER_BYTE_MASKED(bits) ((bits) & BITS_PER_BYTE_MASK)
#define BITS_ROUNDDOWN_BYTES(bits) ((bits) >> 3)
#define BITS_ROUNDUP_BYTES(bits) (BITS_ROUNDDOWN_BYTES(bits) + !!BITS_PER_BYTE_MASKED(bits))

static const char * const btf_kind_str[NR_BTF_KINDS] = {
	[BTF_KIND_UNKN]		= "UNKNOWN",
	[BTF_KIND_INT]		= "INT",
	[BTF_KIND_PTR]		= "PTR",
	[BTF_KIND_ARRAY]	= "ARRAY",
	[BTF_KIND_STRUCT]	= "STRUCT",
	[BTF_KIND_UNION]	= "UNION",
	[BTF_KIND_ENUM]		= "ENUM",
	[BTF_KIND_FWD]		= "FWD",
	[BTF_KIND_TYPEDEF]	= "TYPEDEF",
	[BTF_KIND_VOLATILE]	= "VOLATILE",
	[BTF_KIND_CONST]	= "CONST",
	[BTF_KIND_RESTRICT]	= "RESTRICT",
};

static const char *btf__name_in_gobuf(const struct btf *btf,
				      uint32_t offset)
{
	if (!offset)
		return "(anon)";
	else
		return &btf->strings->entries[offset];
}

static const char * btf__int_encoding_str(uint8_t encoding)
{
	if (encoding == 0)
		return "(none)";
	else if (encoding == BTF_INT_SIGNED)
		return "SIGNED";
	else if (encoding == BTF_INT_CHAR)
		return "CHAR";
	else if (encoding == BTF_INT_BOOL)
		return "BOOL";
	else
		return "UNKN";
}

__attribute ((format (printf, 4, 5)))
static void btf__log_type(const struct btf *btf, const struct btf_type *t,
			  bool err, const char *fmt, ...)
{
	uint8_t kind;
	FILE *out;

	if (!btf_verbose && !err)
		return;

	kind = BTF_INFO_KIND(t->info);
	out = err ? stderr : stdout;

	fprintf(out, "[%u] %s %s",
		btf->type_index, btf_kind_str[kind],
		btf__name_in_gobuf(btf, t->name_off));

	if (fmt && *fmt) {
		va_list ap;

		fprintf(out, " ");
		va_start(ap, fmt);
		vfprintf(out, fmt, ap);
		va_end(ap);
	}

	fprintf(out, "\n");
}

__attribute ((format (printf, 5, 6)))
static void btf_log_member(const struct btf *btf,
			   const struct btf_member *member,
			   bool kind_flag, bool err, const char *fmt, ...)
{
	FILE *out;

	if (!btf_verbose && !err)
		return;

	out = err ? stderr : stdout;

	if (kind_flag)
		fprintf(out, "\t%s type_id=%u bitfield_size=%u bits_offset=%u",
			btf__name_in_gobuf(btf, member->name_off),
			member->type,
			BTF_MEMBER_BITFIELD_SIZE(member->offset),
			BTF_MEMBER_BIT_OFFSET(member->offset));
	else
		fprintf(out, "\t%s type_id=%u bits_offset=%u",
			btf__name_in_gobuf(btf, member->name_off),
			member->type,
			member->offset);

	if (fmt && *fmt) {
		va_list ap;

		fprintf(out, " ");
		va_start(ap, fmt);
		vfprintf(out, fmt, ap);
		va_end(ap);
	}

	fprintf(out, "\n");
}

int32_t btf__add_base_type(struct btf *btf, const struct base_type *bt)
{
	struct btf_int_type int_type;
	struct btf_type *t = &int_type.type;
	uint8_t encoding = 0;

	t->name_off = bt->name;
	t->info = BTF_INFO_ENCODE(BTF_KIND_INT, 0, 0);
	t->size = BITS_ROUNDUP_BYTES(bt->bit_size);
	if (bt->is_signed) {
		encoding = BTF_INT_SIGNED;
	} else if (bt->is_bool) {
		encoding = BTF_INT_BOOL;
	} else if (bt->float_type) {
		fprintf(stderr, "float_type is not supported\n");
		return -1;
	}
	int_type.data = BTF_INT_ENCODE(encoding, 0, bt->bit_size);

	++btf->type_index;
	if (gobuffer__add(&btf->types, &int_type, sizeof(int_type)) >= 0) {
		btf__log_type(btf, t, false,
			      "size=%u bit_offset=%u nr_bits=%u encoding=%s",
			      t->size, BTF_INT_OFFSET(int_type.data),
			      BTF_INT_BITS(int_type.data),
			      btf__int_encoding_str(BTF_INT_ENCODING(int_type.data)));
		return btf->type_index;
	} else {
		btf__log_type(btf, t, true,
			      "size=%u bit_offset=%u nr_bits=%u encoding=%s Error in adding gobuffer",
			      t->size, BTF_INT_OFFSET(int_type.data),
			      BTF_INT_BITS(int_type.data),
			      btf__int_encoding_str(BTF_INT_ENCODING(int_type.data)));
		return -1;
	}
}

int32_t btf__add_ref_type(struct btf *btf, uint16_t kind, uint32_t type,
			  uint32_t name, bool kind_flag)
{
	struct btf_type t;

	t.name_off = name;
	t.info = BTF_INFO_ENCODE(kind, kind_flag, 0);
	t.type = type;

	++btf->type_index;
	if (gobuffer__add(&btf->types, &t, sizeof(t)) >= 0) {
		if (kind == BTF_KIND_FWD)
			btf__log_type(btf, &t, false, "%s",
				      kind_flag ? "union" : "struct");
		else
			btf__log_type(btf, &t, false, "type_id=%u", t.type);
		return btf->type_index;
	} else {
		btf__log_type(btf, &t, true,
			      "kind_flag=%d type_id=%u Error in adding gobuffer",
			      kind_flag, t.type);
		return -1;
	}
}

int32_t btf__add_array(struct btf *btf, uint32_t type, uint32_t index_type,
		       uint32_t nelems)
{
	struct btf_array_type array_type;
	struct btf_type *t = &array_type.type;
	struct btf_array *array = &array_type.array;

	t->name_off = 0;
	t->info = BTF_INFO_ENCODE(BTF_KIND_ARRAY, 0, 0);
	t->size = 0;

	array->type = type;
	array->index_type = index_type;
	array->nelems = nelems;

	++btf->type_index;
	if (gobuffer__add(&btf->types, &array_type, sizeof(array_type)) >= 0) {
		btf__log_type(btf, t, false,
			      "type_id=%u index_type_id=%u nr_elems=%u",
			      array->type, array->index_type, array->nelems);
		return btf->type_index;
	} else {
		btf__log_type(btf, t, true,
			      "type_id=%u index_type_id=%u nr_elems=%u Error in adding gobuffer",
			      array->type, array->index_type, array->nelems);
		return -1;
	}
}

int btf__add_member(struct btf *btf, uint32_t name, uint32_t type, bool kind_flag,
		    uint32_t bitfield_size, uint32_t offset)
{
	struct btf_member member = {
		.name_off   = name,
		.type   = type,
		.offset = kind_flag ? (bitfield_size << 24 | offset) : offset,
	};

	if (gobuffer__add(&btf->types, &member, sizeof(member)) >= 0) {
		btf_log_member(btf, &member, kind_flag, false, NULL);
		return 0;
	} else {
		btf_log_member(btf, &member, kind_flag, true, "Error in adding gobuffer");
		return -1;
	}
}

int32_t btf__add_struct(struct btf *btf, uint8_t kind, uint32_t name,
			bool kind_flag, uint32_t size, uint16_t nr_members)
{
	struct btf_type t;

	t.name_off = name;
	t.info = BTF_INFO_ENCODE(kind, kind_flag, nr_members);
	t.size = size;

	++btf->type_index;
	if (gobuffer__add(&btf->types, &t, sizeof(t)) >= 0) {
		btf__log_type(btf, &t, false, "kind_flag=%d size=%u vlen=%u",
			      kind_flag, t.size, BTF_INFO_VLEN(t.info));
		return btf->type_index;
	} else {
		btf__log_type(btf, &t, true,
			      "kind_flag=%d size=%u vlen=%u Error in adding gobuffer",
			      kind_flag, t.size, BTF_INFO_VLEN(t.info));
		return -1;
	}
}

int32_t btf__add_enum(struct btf *btf, uint32_t name, uint32_t bit_size,
		      uint16_t nr_entries)
{
	struct btf_type t;

	t.name_off = name;
	t.info = BTF_INFO_ENCODE(BTF_KIND_ENUM, 0, nr_entries);
	t.size = BITS_ROUNDUP_BYTES(bit_size);

	++btf->type_index;
	if (gobuffer__add(&btf->types, &t, sizeof(t)) >= 0) {
		btf__log_type(btf, &t, false, "size=%u vlen=%u",
			      t.size, BTF_INFO_VLEN(t.info));
		return btf->type_index;
	} else {
		btf__log_type(btf, &t, true,
			      "size=%u vlen=%u Error in adding gobuffer",
			      t.size, BTF_INFO_VLEN(t.info));
		return -1;
	}
}

int btf__add_enum_val(struct btf *btf, uint32_t name, int32_t value)
{
	struct btf_enum e = {
		.name_off = name,
		.val  = value,
	};

	if (gobuffer__add(&btf->types, &e, sizeof(e)) < 0) {
		fprintf(stderr, "\t%s val=%d Error in adding gobuffer\n",
			btf__name_in_gobuf(btf, e.name_off), e.val);
		return -1;
	} else if (btf_verbose)
		printf("\t%s val=%d\n", btf__name_in_gobuf(btf, e.name_off),
		       e.val);

	return 0;
}

static int btf__write_elf(struct btf *btf)
{
	GElf_Shdr shdr_mem, *shdr;
	GElf_Ehdr ehdr_mem, *ehdr;
	Elf_Data *btf_elf = NULL;
	Elf_Scn *scn = NULL;
	Elf *elf = NULL;
	int fd, err = -1;
	size_t strndx;

	fd = open(btf->filename, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s\n", btf->filename);
		return -1;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "Cannot set libelf version.\n");
		goto out;
	}

	elf = elf_begin(fd, ELF_C_RDWR, NULL);
	if (elf == NULL) {
		fprintf(stderr, "Cannot update ELF file.\n");
		goto out;
	}

	elf_flagelf(elf, ELF_C_SET, ELF_F_DIRTY);

	ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (ehdr == NULL) {
		fprintf(stderr, "%s: elf_getehdr failed.\n", __func__);
		goto out;
	}

	/*
	 * First we look if there was already a .BTF section to overwrite.
	 */

	elf_getshdrstrndx(elf, &strndx);
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		shdr = gelf_getshdr(scn, &shdr_mem);
		if (shdr == NULL)
			continue;
		char *secname = elf_strptr(elf, strndx, shdr->sh_name);
		if (strcmp(secname, ".BTF") == 0) {
			btf_elf = elf_getdata(scn, btf_elf);
			break;
		}
	}

	if (btf_elf) {
		/* Exisiting .BTF section found */
		btf_elf->d_buf = btf->data;
		btf_elf->d_size = btf->size;
		elf_flagdata(btf_elf, ELF_C_SET, ELF_F_DIRTY);

		if (elf_update(elf, ELF_C_NULL) >= 0 &&
		    elf_update(elf, ELF_C_WRITE) >= 0)
			err = 0;
	} else {
		const char *llvm_objcopy;
		char tmp_fn[PATH_MAX];
		char cmd[PATH_MAX];

		llvm_objcopy = getenv("LLVM_OBJCOPY");
		if (!llvm_objcopy)
			llvm_objcopy = "llvm-objcopy";

		/* Use objcopy to add a .BTF section */
		snprintf(tmp_fn, sizeof(tmp_fn), "%s.btf", btf->filename);
		close(fd);
		fd = creat(tmp_fn, S_IRUSR | S_IWUSR);
		if (fd == -1) {
			fprintf(stderr, "%s: open(%s) failed!\n", __func__,
				tmp_fn);
			goto out;
		}

		snprintf(cmd, sizeof(cmd), "%s --add-section .BTF=%s %s",
			 llvm_objcopy, tmp_fn, btf->filename);

		if (write(fd, btf->data, btf->size) == btf->size &&
		    !system(cmd))
			err = 0;

		unlink(tmp_fn);
	}

out:
	if (fd != -1)
		close(fd);
	if (elf)
		elf_end(elf);
	return err;
}

int btf__encode(struct btf *btf, uint8_t flags)
{
	struct btf_header *hdr;

	/* Empty file, nothing to do, so... done! */
	if (gobuffer__size(&btf->types) == 0)
		return 0;

	btf->size = sizeof(*hdr) +
		(gobuffer__size(&btf->types) +
		 gobuffer__size(btf->strings));
	btf->data = zalloc(btf->size);

	if (btf->data == NULL) {
		fprintf(stderr, "%s: malloc failed!\n", __func__);
		return -1;
	}

	hdr = btf->hdr;
	hdr->magic = BTF_MAGIC;
	hdr->version = 1;
	hdr->flags = flags;
	hdr->hdr_len = sizeof(*hdr);

	hdr->type_off = 0;
	hdr->type_len = gobuffer__size(&btf->types);
	hdr->str_off  = hdr->type_len;
	hdr->str_len  = gobuffer__size(btf->strings);

	gobuffer__copy(&btf->types, btf__nohdr_data(btf) + hdr->type_off);
	gobuffer__copy(btf->strings, btf__nohdr_data(btf) + hdr->str_off);

	*(char *)(btf__nohdr_data(btf) + hdr->str_off) = '\0';

	return btf__write_elf(btf);
}
