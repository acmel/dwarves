/* 
  Copyright (C) 2000,2002,2004,2005 Silicon Graphics, Inc.  All Rights Reserved.

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it would be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

  Further, this software is distributed without any warranty that it is
  free of the rightful claim of any third person regarding infringement
  or the like.  Any license provided herein, whether implied or
  otherwise, applies only to this software file.  Patent licenses, if
  any, provided herein do not apply to combinations of this program with
  other software, or any other product whatsoever.

  You should have received a copy of the GNU General Public License along
  with this program; if not, write the Free Software Foundation, Inc., 59
  Temple Place - Suite 330, Boston MA 02111-1307, USA.

  Contact information:  Silicon Graphics, Inc., 1500 Crittenden Lane,
  Mountain View, CA 94043, or:

  http://www.sgi.com

  For further information regarding this notice, see:

  http://oss.sgi.com/projects/GenInfo/NoticeExplan
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <dwarf.h>
#include <libdwarf.h>

#include "list.h"

static char bf[4096];

static current_compile_unit;

static void *zalloc(const size_t size)
{
	void *s = malloc(size);
	if (s != NULL)
		memset(s, 0, size);
	return s;
}

static LIST_HEAD(classes);

struct cu_info {
	unsigned int	 cu;
	unsigned int	 offset;
};

struct class {
	struct list_head node;
	struct list_head members;
	char		 name[32];
	unsigned long	 size;
	unsigned int	 cu_offset;
	unsigned int	 type;
	unsigned int	 tag;		/* struct, union, base type, etc */
	unsigned int	 nr_entries;	/* For arrays */
};

const char *tag_name(const unsigned int tag)
{
	switch (tag) {
	case DW_TAG_structure_type:	return "struct ";
	case DW_TAG_union_type:		return "union ";
	case DW_TAG_pointer_type:	return " *";
	}

	return "";
}

struct class *find_class_by_name(const char *name)
{
	struct class *pos;

	list_for_each_entry(pos, &classes, node)
		if (strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

struct class *find_class_by_type(const unsigned int type)
{
	struct class *pos;

	list_for_each_entry(pos, &classes, node)
		if (pos->cu_offset == type)
			return pos;

	return NULL;
}

const unsigned long class__size(struct class *self)
{
	unsigned long size = self->size;

	if (self->tag != DW_TAG_pointer_type && self->type != 0) {
		struct class *class = find_class_by_type(self->type);
		
		if (class != NULL)
			size = class__size(class);
	}

	if (self->tag == DW_TAG_array_type)
		size *= self->nr_entries;

	return size;
}

const char *class__name(struct class *self, char *bf, size_t len)
{
	if (self->tag == DW_TAG_pointer_type) {
		struct class *ptr_class = find_class_by_type(self->type);

		if (ptr_class != NULL) {
			char ptr_class_name[128];
			snprintf(bf, len, "%s *",
				 class__name(ptr_class,
					     ptr_class_name,
					     sizeof(ptr_class_name)));
		}
	} else if (self->tag == DW_TAG_array_type) {
		struct class *ptr_class = find_class_by_type(self->type);

		if (ptr_class != NULL)
			return class__name(ptr_class, bf, len);
	} else
		snprintf(bf, len, "%s%s", tag_name(self->tag), self->name);
	return bf;
}

struct class_member {
	struct list_head node;
	char		 name[32];
	unsigned int	 type;
	unsigned int	 offset;
	unsigned int	 bit_size;
	unsigned int	 bit_offset;
};

struct class_member *class_member__new(void)
{
	return zalloc(sizeof(struct class_member));
}

void class_member__set_name(struct class_member *self, const char *name)
{
	snprintf(self->name, sizeof(self->name), "%s", name);
}

unsigned long class_member__print(struct class_member *self)
{
	struct class *class = find_class_by_type(self->type);
	const char *class_name = bf;
	char class_name_bf[128];
	char member_name_bf[128];
	unsigned long size = -1;

	snprintf(member_name_bf, sizeof(member_name_bf),
		 "%s;", self->name);

	if (class == NULL)
		snprintf(bf, sizeof(bf), "<%d>", self->type);
	else {
		size = class__size(class);

		/* Is it a function pointer? */
		if (class->tag == DW_TAG_pointer_type) {
			struct class *ptr_class = find_class_by_type(class->type);

			if (ptr_class != NULL &&
			    ptr_class->tag == DW_TAG_subroutine_type) {
				/* function has no return value (void) */
				if (ptr_class->type == 0)
					strcpy(bf, "void");
				else {
					struct class *ret_class = find_class_by_type(ptr_class->type);

					if (ret_class != NULL)
						class_name = class__name(ret_class,
									 class_name_bf,
									 sizeof(class_name_bf));
				}
				snprintf(member_name_bf, sizeof(member_name_bf),
					 "(*%s)();", self->name);
				goto out;
			}
		}

		class_name = class__name(class, class_name_bf, sizeof(class_name_bf));
		if (class->tag == DW_TAG_array_type)
			snprintf(member_name_bf, sizeof(member_name_bf),
				 "%s[%d];", self->name, class->nr_entries);
		else if (self->bit_size != 0)
			snprintf(member_name_bf, sizeof(member_name_bf),
				 "%s:%d;", self->name, self->bit_size);
	}
out:
	printf("        %-20s %-20s /* %5d %5lu */\n",
	       class_name, member_name_bf, self->offset, size);
	return size;
}

struct class *class__new(const unsigned int tag, unsigned int cu_offset)
{
	struct class *self = malloc(sizeof(*self));

	if (self != NULL) {
		INIT_LIST_HEAD(&self->members);
		self->tag	= tag;
		self->cu_offset = cu_offset;
		self->type	= 0;
		self->size	= 0;
	}

	return self;
}

void class__set_name(struct class *self, const char *name)
{
	snprintf(self->name, sizeof(self->name), "%s", name);
}

void class__add_member(struct class *self, struct class_member *member)
{
	list_add_tail(&member->node, &self->members);
}

void class__print(struct class *self)
{
	unsigned long sum = 0;
	unsigned long sum_holes = 0;
	struct class_member *pos;
	char name[128];
	size_t last_size = 0;
	int last_offset = -1;

	printf("%49.49s /* offset size */\n", "");
	printf("%s {\n", class__name(self, name, sizeof(name)));
	list_for_each_entry(pos, &self->members, node) {
		 if (sum > 0) {
			 const size_t cc_last_size = pos->offset - last_offset;

			 /*
			  * If the offset is the same this better
			  * be a bitfield or an empty struct (see
			  * rwlock_t in the Linux kernel sources when
			  * compiled for UP) or...
			  */
			 if (cc_last_size > 0) {
				 const size_t hole = cc_last_size - last_size;

				 if (hole > 0) {
					 printf("\n        /* XXX %d bytes hole, "
						"try to pack */\n\n", hole);
					 sum_holes += hole;
				}
			 } else if (pos->bit_size == 0 && last_size != 0)
				printf("\n/* BRAIN FART ALERT! not a bitfield "
					" and the offset hasn't changed. */\n\n",
				       self->size, sum, sum_holes);
		 }

		 last_size = class_member__print(pos);
		 /*
		  * check for bitfields, accounting only the first
		  * field.
		  */
		 if (pos->bit_size == 0 || pos->bit_offset == 0)
			 sum += last_size;
		 last_offset = pos->offset;
	}

	if (last_offset + last_size != self->size) {
		const size_t hole = self->size - (last_offset + last_size);

		printf("  /* %d bytes hole, try to pack */\n", hole);
		sum_holes += hole;
	}

	printf("}; /* sizeof struct: %d, sum sizeof members: %lu */\n",
	       self->size, sum);

	if (sum + sum_holes != self->size)
		printf("\n/* BRAIN FART ALERT! %d != %d + %d(holes) */\n\n",
		       self->size, sum, sum_holes);
	putchar('\n');
}

void add_class(struct class *class)
{
	list_add_tail(&class->node, &classes);
}

void print_classes(void)
{
	struct class *pos;

	list_for_each_entry(pos, &classes, node)
		if (pos->tag == DW_TAG_structure_type && pos->name[0] != '\0')
			class__print(pos);
}

static struct class *current_class;

static int indent_level;

typedef char *(*encoding_type_func) (Dwarf_Debug dbg, Dwarf_Half val);

static char *program_name;

void print_error(Dwarf_Debug dbg, char *msg, int dwarf_code, Dwarf_Error err)
{
	if (dwarf_code == DW_DLV_ERROR) {
		char *errmsg = dwarf_errmsg(err);
		Dwarf_Unsigned myerr = dwarf_errno(err);

		fprintf(stderr, "%s ERROR:  %s:  %s (%lu)\n",
			program_name, msg, errmsg, (unsigned long) myerr);
	} else if (dwarf_code == DW_DLV_NO_ENTRY) {
		fprintf(stderr, "%s NO ENTRY:  %s: \n", program_name, msg);
	} else if (dwarf_code == DW_DLV_OK) {
		fprintf(stderr, "%s:  %s \n", program_name, msg);
	} else {
		fprintf(stderr, "%s InternalError:  %s:  code %d\n",
			program_name, msg, dwarf_code);
	}

	exit(EXIT_FAILURE);
}

static int _dwarf_print_one_locdesc(Dwarf_Debug dbg, Dwarf_Locdesc * llbuf,
				    char *string_out)
{

    Dwarf_Locdesc *locd;
    Dwarf_Half no_of_ops = 0;
    int i;
    char small_buf[100];

    locd = llbuf;
    no_of_ops = llbuf->ld_cents;
    for (i = 0; i < no_of_ops; i++) {
	Dwarf_Small op;
	Dwarf_Unsigned opd1, opd2;

	/* local_space_needed is intended to be 'more than big enough'
	   for a short group of loclist entries.  */
	char small_buf[100];

	if (i > 0)
	    strcat(string_out, " ");

	op = locd->ld_s[i].lr_atom;
	if (op > DW_OP_nop) {
	    print_error(dbg, "dwarf_op unexpected value", DW_DLV_OK,
			0);
	    return DW_DLV_ERROR;
	}

	opd1 = locd->ld_s[i].lr_number;
	if (op >= DW_OP_breg0 && op <= DW_OP_breg31) {
	    snprintf(small_buf, sizeof(small_buf),
		     "%+lld", (Dwarf_Signed) opd1);
	    strcat(string_out, small_buf);
	} else {
	    switch (op) {
	    case DW_OP_addr:
		snprintf(small_buf, sizeof(small_buf), " %#llx", opd1);
		strcat(string_out, small_buf);
		break;
	    case DW_OP_const1s:
	    case DW_OP_const2s:
	    case DW_OP_const4s:
	    case DW_OP_const8s:
	    case DW_OP_consts:
	    case DW_OP_skip:
	    case DW_OP_bra:
	    case DW_OP_fbreg:
		snprintf(small_buf, sizeof(small_buf),
			 " %lld", (Dwarf_Signed) opd1);
		strcat(string_out, small_buf);
		break;
	    case DW_OP_const1u:
	    case DW_OP_const2u:
	    case DW_OP_const4u:
	    case DW_OP_const8u:
	    case DW_OP_constu:
	    case DW_OP_pick:
	    case DW_OP_plus_uconst:
	    case DW_OP_regx:
	    case DW_OP_piece:
	    case DW_OP_deref_size:
	    case DW_OP_xderef_size:
		snprintf(small_buf, sizeof(small_buf), " %llu", opd1);
		strcat(string_out, small_buf);
		break;
	    case DW_OP_bregx:
		snprintf(small_buf, sizeof(small_buf), "%llu", opd1);
		strcat(string_out, small_buf);



		opd2 = locd->ld_s[i].lr_number2;
		snprintf(small_buf, sizeof(small_buf),
			 "%+lld", (Dwarf_Signed) opd2);
		strcat(string_out, small_buf);

		break;
	    default:
		break;
	    }
	}
    }

    return DW_DLV_OK;
}

static void get_location_list(Dwarf_Debug dbg, Dwarf_Die die,
			      Dwarf_Attribute attr, char *s)
{
	Dwarf_Locdesc *llbuf = NULL;
	Dwarf_Locdesc **llbufarray = NULL;
	Dwarf_Signed no_of_elements;
	Dwarf_Error err;
	int i;
	int lres = 0;
	int llent = 0;

	lres = dwarf_loclist_n(attr, &llbufarray, &no_of_elements, &err);
	if (lres == DW_DLV_ERROR)
		print_error(dbg, "dwarf_loclist", lres, err);

	if (lres == DW_DLV_NO_ENTRY)
		return;

	for (llent = 0; llent < no_of_elements; ++llent) {
		char small_buf[100];

		llbuf = llbufarray[llent];

		if (llbuf->ld_from_loclist) {
			if (llent == 0) {
				snprintf(small_buf, sizeof(small_buf),
					"<loclist with %ld entries follows>",
					(long) no_of_elements);
				strcat(s, small_buf);
			}
			strcat(s, "\n\t\t\t");
			snprintf(small_buf, sizeof(small_buf), "[%2d]", llent);
			strcat(s, small_buf);
		}
		lres = _dwarf_print_one_locdesc(dbg, llbuf, s);
		if (lres == DW_DLV_ERROR)
			return;
		else {
			/* DW_DLV_OK so we add follow-on at end, else is
			   DW_DLV_NO_ENTRY (which is impossible, treat like
			   DW_DLV_OK). */
		}
	}

	for (i = 0; i < no_of_elements; ++i) {
		dwarf_dealloc(dbg, llbufarray[i]->ld_s, DW_DLA_LOC_BLOCK);
		dwarf_dealloc(dbg, llbufarray[i], DW_DLA_LOCDESC);
	}
	dwarf_dealloc(dbg, llbufarray, DW_DLA_LIST);
}

static char *get_FORM_name(Dwarf_Debug dbg, Dwarf_Half val)
{
	switch (val) {
	case DW_FORM_addr:
		return "DW_FORM_addr";
	case DW_FORM_block2:
		return "DW_FORM_block2";
	case DW_FORM_block4:
		return "DW_FORM_block4";
	case DW_FORM_data2:
		return "DW_FORM_data2";
	case DW_FORM_data4:
		return "DW_FORM_data4";
	case DW_FORM_data8:
		return "DW_FORM_data8";
	case DW_FORM_string:
		return "DW_FORM_string";
	case DW_FORM_block:
		return "DW_FORM_block";
	case DW_FORM_block1:
		return "DW_FORM_block1";
	case DW_FORM_data1:
		return "DW_FORM_data1";
	case DW_FORM_flag:
		return "DW_FORM_flag";
	case DW_FORM_sdata:
		return "DW_FORM_sdata";
	case DW_FORM_strp:
		return "DW_FORM_strp";
	case DW_FORM_udata:
		return "DW_FORM_udata";
	case DW_FORM_ref_addr:
		return "DW_FORM_ref_addr";
	case DW_FORM_ref1:
		return "DW_FORM_ref1";
	case DW_FORM_ref2:
		return "DW_FORM_ref2";
	case DW_FORM_ref4:
		return "DW_FORM_ref4";
	case DW_FORM_ref8:
		return "DW_FORM_ref8";
	case DW_FORM_ref_udata:
		return "DW_FORM_ref_udata";
	case DW_FORM_indirect:
		return "DW_FORM_indirect";
	default:
		{ 
		    char buf[100]; 
		    char *n; 
		    snprintf(buf,sizeof(buf),"<Unknown FORM value 0x%x>",(int)val);
		 fprintf(stderr,"FORM of %d (0x%x) is unknown to dwarfdump. " 
 		 "Continuing. \n",(int)val,(int)val );  
		    n = strdup(buf);
		    return n; 
		} 
	}
/*NOTREACHED*/
}

static void formx_unsigned(Dwarf_Unsigned u, char *s)
{
     char small_buf[40];
     snprintf(small_buf, sizeof(small_buf), "%llu", (unsigned long long)u);
     strcat(s, small_buf);

}

static void formx_signed(Dwarf_Signed u, char *s)
{
     char small_buf[40];
     snprintf(small_buf, sizeof(small_buf), "%lld", (long long)u);
     strcat(s, small_buf);
}

/* We think this is an integer. Figure out how to print it.
   In case the signedness is ambiguous (such as on 
   DW_FORM_data1 (ie, unknown signedness) print two ways.
*/
static int formxdata_print_value(Dwarf_Attribute attrib, char *s,
				 Dwarf_Error *err)
{
    Dwarf_Signed tempsd = 0;
    Dwarf_Unsigned tempud = 0;
    int sres = 0;
    int ures = 0;
    Dwarf_Error serr = 0;
    ures = dwarf_formudata(attrib, &tempud, err);
    sres = dwarf_formsdata(attrib, &tempsd, &serr);
    if(ures == DW_DLV_OK) {
      if(sres == DW_DLV_OK) {
	if(tempud == tempsd) {
	   /* Data is the same value, so makes no difference which
		we print. */
	   formx_unsigned(tempud, s);
	} else {
	   formx_unsigned(tempud, s);
	   strcat(s, "(as signed = ");
	   formx_signed(tempsd, s);
	   strcat(s, ")");
        }
      } else if (sres == DW_DLV_NO_ENTRY) {
	formx_unsigned(tempud, s);
      } else /* DW_DLV_ERROR */{
	formx_unsigned(tempud, s);
      }
      return DW_DLV_OK;
    } else  if (ures == DW_DLV_NO_ENTRY) {
      if(sres == DW_DLV_OK) {
	formx_signed(tempsd, s);
	return sres;
      } else if (sres == DW_DLV_NO_ENTRY) {
	return sres;
      } else /* DW_DLV_ERROR */{
	*err = serr;
        return sres;
      }
    } 
    /* else ures ==  DW_DLV_ERROR */ 
    if(sres == DW_DLV_OK) {
	formx_signed(tempsd, s);
    } else if (sres == DW_DLV_NO_ENTRY) {
	return ures;
    } 
    /* DW_DLV_ERROR */
    return ures;
}

/* Fill buffer with attribute value.
   We pass in tag so we can try to do the right thing with
   broken compiler DW_TAG_enumerator 
*/
static void get_attr_value(Dwarf_Debug dbg, Dwarf_Half tag,
			   Dwarf_Attribute attrib, char **srcfiles,
			   Dwarf_Signed cnt, char *s)
{
    Dwarf_Half theform;
    char *temps;
    Dwarf_Block *tempb;
    Dwarf_Signed tempsd = 0;
    Dwarf_Unsigned tempud = 0;
    int i;
    Dwarf_Half attr;
    Dwarf_Off off;
    Dwarf_Die die_for_check;
    Dwarf_Half tag_for_check;
    Dwarf_Bool tempbool;
    Dwarf_Error err;
    Dwarf_Addr addr = 0;
    int fres;
    int bres;
    int wres;
    int dres;
    Dwarf_Half direct_form = 0;
    char small_buf[100];

    fres = dwarf_whatform(attrib, &theform, &err);
    /* depending on the form and the attribute, process the form */
    if (fres == DW_DLV_ERROR) {
	print_error(dbg, "dwarf_whatform cannot find attr form", fres,
		    err);
    } else if (fres == DW_DLV_NO_ENTRY) {
	return;
    }

    dwarf_whatform_direct(attrib, &direct_form, &err);
    /* ignore errors in dwarf_whatform_direct() */


    switch (theform) {
    case DW_FORM_addr:
	bres = dwarf_formaddr(attrib, &addr, &err);
	if (bres == DW_DLV_OK) {
	    snprintf(small_buf, sizeof(small_buf), "%#llx",
		     (unsigned long long) addr);
	    strcat(s, small_buf);
	} else {
	    print_error(dbg, "addr formwith no addr?!", bres, err);
	}
	break;
    case DW_FORM_ref_addr:
	/* DW_FORM_ref_addr is not accessed thru formref: ** it is an
	   address (global section offset) in ** the .debug_info
	   section. */
	bres = dwarf_global_formref(attrib, &off, &err);
	if (bres == DW_DLV_OK) {
	    snprintf(small_buf, sizeof(small_buf),
		     "<global die offset %llu>",
		     (unsigned long long) off);
	    strcat(s, small_buf);
	} else {
	    print_error(dbg,
			"DW_FORM_ref_addr form with no reference?!",
			bres, err);
	}
	break;
    case DW_FORM_ref1:
    case DW_FORM_ref2:
    case DW_FORM_ref4:
    case DW_FORM_ref8:
    case DW_FORM_ref_udata:
	bres = dwarf_formref(attrib, &off, &err);
	if (bres != DW_DLV_OK) {
	    print_error(dbg, "ref formwith no ref?!", bres, err);
	}
	snprintf(small_buf, sizeof(small_buf), "<%llu>", off);
	strcat(s, small_buf);
	break;
    case DW_FORM_block:
    case DW_FORM_block1:
    case DW_FORM_block2:
    case DW_FORM_block4:
	fres = dwarf_formblock(attrib, &tempb, &err);
	if (fres == DW_DLV_OK) {
	    for (i = 0; i < tempb->bl_len; i++) {
		snprintf(small_buf, sizeof(small_buf), "%02x",
			 *(i + (unsigned char *) tempb->bl_data));
		strcat(s, small_buf);
	    }
	    dwarf_dealloc(dbg, tempb, DW_DLA_BLOCK);
	} else {
	    print_error(dbg, "DW_FORM_blockn cannot get block\n", fres,
			err);
	}
	break;
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
	fres = dwarf_whatattr(attrib, &attr, &err);
	if (fres == DW_DLV_ERROR) {
	    print_error(dbg, "FORM_datan cannot get attr", fres, err);
	} else if (fres == DW_DLV_NO_ENTRY) {
	    print_error(dbg, "FORM_datan cannot get attr", fres, err);
	} else {
	    switch (attr) {
	    case DW_AT_ordering:
	    case DW_AT_byte_size:
	    case DW_AT_bit_offset:
	    case DW_AT_bit_size:
	    case DW_AT_inline:
	    case DW_AT_language:
	    case DW_AT_visibility:
	    case DW_AT_virtuality:
	    case DW_AT_accessibility:
	    case DW_AT_address_class:
	    case DW_AT_calling_convention:
	    case DW_AT_discr_list:	/* DWARF3 */
	    case DW_AT_encoding:
	    case DW_AT_identifier_case:
	    case DW_AT_MIPS_loop_unroll_factor:
	    case DW_AT_MIPS_software_pipeline_depth:
	    case DW_AT_decl_column:
	    case DW_AT_decl_file:
	    case DW_AT_decl_line:
	    case DW_AT_start_scope:
	    case DW_AT_byte_stride:
	    case DW_AT_bit_stride:
	    case DW_AT_count:
	    case DW_AT_stmt_list:
	    case DW_AT_MIPS_fde:
		wres = get_small_encoding_integer_and_name(dbg,
							   attrib,
							   &tempud,
							   /* attrname */
		    (char *) NULL,
							   /* err_string 
							    */ 
							   (char **)
							   NULL,
							   (encoding_type_func) 0,
							   &err);

		if (wres == DW_DLV_OK) {
		    snprintf(small_buf, sizeof(small_buf), "%llu",
			     tempud);
		    strcat(s, small_buf);
		    if (attr == DW_AT_decl_file) {
			if (srcfiles && tempud > 0 && tempud <= cnt) {
			    /* added by user request */
			    /* srcfiles is indexed starting at 0, but
			       DW_AT_decl_file defines that 0 means no
			       file, so tempud 1 means the 0th entry in
			       srcfiles, thus tempud-1 is the correct
			       index into srcfiles.  */
			    char *fname = srcfiles[tempud - 1];

			    strcat(s, " ");
			    strcat(s, fname);
			}
		    }
		} else {
		    print_error(dbg, "Cannot get encoding attribute ..",
				wres, err);
		}
		break;
	    case DW_AT_const_value:
		wres = formxdata_print_value(attrib, s, &err);
		if(wres == DW_DLV_OK){
		    /* String appended already. */
		} else if (wres == DW_DLV_NO_ENTRY) {
		    /* nothing? */
		} else {
		   print_error(dbg,"Cannot get DW_AT_const_value ",wres,err);
		}
  
		
		break;
	    case DW_AT_upper_bound:
	    case DW_AT_lower_bound:
	    default:
		wres = formxdata_print_value(attrib, s, &err);
		if (wres == DW_DLV_OK) {
		    /* String appended already. */
		} else if (wres == DW_DLV_NO_ENTRY) {
		    /* nothing? */
		} else {
		    print_error(dbg, "Cannot get formsdata..", wres,
				err);
		}
		break;
	    }
	}
	break;
    case DW_FORM_sdata:
	wres = dwarf_formsdata(attrib, &tempsd, &err);
	if (wres == DW_DLV_OK) {
	    snprintf(small_buf, sizeof(small_buf), "%lld", tempsd);
	    strcat(s, small_buf);
	} else if (wres == DW_DLV_NO_ENTRY) {
	    /* nothing? */
	} else {
	    print_error(dbg, "Cannot get formsdata..", wres, err);
	}
	break;
    case DW_FORM_udata:
	wres = dwarf_formudata(attrib, &tempud, &err);
	if (wres == DW_DLV_OK) {
	    snprintf(small_buf, sizeof(small_buf), "%llu", tempud);
	    strcat(s, small_buf);
	} else if (wres == DW_DLV_NO_ENTRY) {
	    /* nothing? */
	} else {
	    print_error(dbg, "Cannot get formudata....", wres, err);
	}
	break;
    case DW_FORM_string:
    case DW_FORM_strp:
	wres = dwarf_formstring(attrib, &temps, &err);
	if (wres == DW_DLV_OK) {
	    strcat(s, temps);
	} else if (wres == DW_DLV_NO_ENTRY) {
	    /* nothing? */
	} else {
	    print_error(dbg, "Cannot get formstr/p....", wres, err);
	}

	break;
    case DW_FORM_flag:
	wres = dwarf_formflag(attrib, &tempbool, &err);
	if (wres == DW_DLV_OK) {
	    if (tempbool) {
		snprintf(small_buf, sizeof(small_buf), "yes(%d)",
			 tempbool);
		strcat(s, small_buf);
	    } else {
		snprintf(small_buf, sizeof(small_buf), "no");
		strcat(s, small_buf);
	    }
	} else if (wres == DW_DLV_NO_ENTRY) {
	    /* nothing? */
	} else {
	    print_error(dbg, "Cannot get formflag/p....", wres, err);
	}
	break;
    case DW_FORM_indirect:
	/* We should not ever get here, since the true form was
	   determined and direct_form has the DW_FORM_indirect if it is
	   used here in this attr. */
	strcat(s, get_FORM_name(dbg, theform));
	break;
    default:
	print_error(dbg, "dwarf_whatform unexpected value", DW_DLV_OK,
		    err);
    }
}

static void print_attribute(Dwarf_Debug dbg, Dwarf_Die die, Dwarf_Half attr,
			    Dwarf_Attribute attr_in, char **srcfiles,
			    Dwarf_Signed cnt, struct class *class,
			    struct class_member *member)
{
	Dwarf_Attribute attrib = 0;
	Dwarf_Unsigned uval = 0;
	char *atname = NULL;
	char *valname = NULL;
	int tres = 0;
	Dwarf_Error err;
	Dwarf_Half tag = 0;

	/* the following gets the real attribute, even in the ** face of an 
	   incorrect doubling, or worse, of attributes */
	attrib = attr_in;
	/* do not get attr via dwarf_attr: if there are (erroneously) **
	   multiple of an attr in a DIE, dwarf_attr will ** not get the
	   second, erroneous one and dwarfdump ** will print the first one
	   multiple times. Oops. */

	tres = dwarf_tag(die, &tag, &err);
	if (tres == DW_DLV_ERROR)
		tag = 0;
	else if (tres == DW_DLV_NO_ENTRY)
		tag = 0;

	switch (attr) {
	case DW_AT_language:
	case DW_AT_accessibility:
	case DW_AT_visibility:
	case DW_AT_virtuality:
	case DW_AT_identifier_case:
	case DW_AT_inline:
	case DW_AT_encoding:
	case DW_AT_ordering:
	case DW_AT_calling_convention:
	case DW_AT_discr_list:	/* DWARF3 */
	/* Unsupported attributes, not needed for our purposes -acme */
	break;
	case DW_AT_location:
	case DW_AT_data_member_location:
	case DW_AT_vtable_elem_location:
	case DW_AT_string_length:
	case DW_AT_return_addr:
	case DW_AT_use_location:
	case DW_AT_static_link:
	case DW_AT_frame_base:
		/* value is a location description or location list */
		bf[0] = '\0';
		get_location_list(dbg, die, attrib, bf);
		valname = bf;
		break;
	default:
		bf[0] = '\0';
		get_attr_value(dbg, tag, attrib, srcfiles, cnt, bf);
		valname = bf;
		break;
	}

	switch (attr) {
	case DW_AT_name:
		if (class != NULL)
			class__set_name(class, valname);
		else if (member != NULL)
			class_member__set_name(member, valname);
		break;
	case DW_AT_byte_size:
		if (class != NULL)
			class->size = atoi(valname);
		break;
	case DW_AT_bit_size:
		if (member != NULL)
			member->bit_size = atoi(valname);
		break;
	case DW_AT_bit_offset:
		if (member != NULL)
			member->bit_offset = atoi(valname);
		break;
	case DW_AT_upper_bound:
		if (class != NULL)
			class->nr_entries = atoi(valname) + 1;
		break;
	case DW_AT_data_member_location:
		if (member != NULL)
			member->offset = atoi(valname);
		break;
	case DW_AT_type: {
		unsigned int type;

		valname[strlen(valname) - 1] = '\0';
		type = atoi(valname + 1);
		if (class != NULL) {
			if (class->type == 0)
				class->type = type;
		} else if (member != NULL)
			member->type = type;
	}
		break;
    }
}

/* print info about die */
void print_one_die(Dwarf_Debug dbg, Dwarf_Die die, char **srcfiles,
		   Dwarf_Signed cnt)
{
	Dwarf_Signed i;
	Dwarf_Half tag;
	Dwarf_Signed atcnt;
	Dwarf_Off offset;
	Dwarf_Error err;
	Dwarf_Attribute *atlist;
	int tres;
	int ores;
	int atres;
	struct class *class = NULL;
	struct class_member *member = NULL;

	tres = dwarf_tag(die, &tag, &err);
	if (tres != DW_DLV_OK)
		print_error(dbg, "accessing tag of die!", tres, err);

	ores = dwarf_die_CU_offset(die, &offset, &err);
	if (ores != DW_DLV_OK)
		print_error(dbg, "dwarf_die_CU_offset", ores, err);

	if (tag == DW_TAG_member) {
		member = class_member__new();
		if (member == NULL)
			print_error(dbg, "class_member__new", ores, err);
		class__add_member(current_class, member);
	} else if (tag == DW_TAG_subrange_type) {
		/* Do nothing, its relevant to the previous class */
		class = current_class;
	} else {
		if (current_class != NULL)
			add_class(current_class);
	    
		class = current_class = class__new(tag, offset);
		if (current_class == NULL)
			print_error(dbg, "class__new", ores, err);
	}

    atres = dwarf_attrlist(die, &atlist, &atcnt, &err);
    if (atres == DW_DLV_ERROR) {
	print_error(dbg, "dwarf_attrlist", atres, err);
    } else if (atres == DW_DLV_NO_ENTRY) {
	/* indicates there are no attrs.  It is not an error. */
	atcnt = 0;
    }

    for (i = 0; i < atcnt; i++) {
	Dwarf_Half attr;
	int ares;

	ares = dwarf_whatattr(atlist[i], &attr, &err);
	if (ares == DW_DLV_OK) {
	    print_attribute(dbg, die, attr,
			    atlist[i],
			    srcfiles, cnt, class, member);
	} else {
	    print_error(dbg, "dwarf_whatattr entry missing", ares, err);
	}
    }

    for (i = 0; i < atcnt; i++)
	dwarf_dealloc(dbg, atlist[i], DW_DLA_ATTR);

    if (atres == DW_DLV_OK)
	dwarf_dealloc(dbg, atlist, DW_DLA_LIST);
}

#define DIE_STACK_SIZE 50
static Dwarf_Die die_stack[DIE_STACK_SIZE];

#define PUSH_DIE_STACK(x) { die_stack[indent_level] = x; }
#define POP_DIE_STACK { die_stack[indent_level] = 0; }

/* recursively follow the die tree */
extern void
print_die_and_children(Dwarf_Debug dbg, Dwarf_Die in_die_in,
		       char **srcfiles, Dwarf_Signed cnt)
{
    Dwarf_Die child;
    Dwarf_Die sibling;
    Dwarf_Error err;
    int tres;
    int cdres;
    Dwarf_Die in_die = in_die_in;

    for (;;) {
	PUSH_DIE_STACK(in_die);

	/* here to pre-descent processing of the die */
	print_one_die(dbg, in_die, srcfiles, cnt);

	cdres = dwarf_child(in_die, &child, &err);
	/* child first: we are doing depth-first walk */
	if (cdres == DW_DLV_OK) {
	    indent_level++;
	    print_die_and_children(dbg, child, srcfiles, cnt);
	    indent_level--;
	    dwarf_dealloc(dbg, child, DW_DLA_DIE);
	} else if (cdres == DW_DLV_ERROR) {
	    print_error(dbg, "dwarf_child", cdres, err);
	}

	cdres = dwarf_siblingof(dbg, in_die, &sibling, &err);
	if (cdres == DW_DLV_OK) {
	    /* print_die_and_children(dbg, sibling, srcfiles, cnt); We
	       loop around to actually print this, rather than
	       recursing. Recursing is horribly wasteful of stack
	       space. */
	} else if (cdres == DW_DLV_ERROR) {
	    print_error(dbg, "dwarf_siblingof", cdres, err);
	}

	/* Here do any post-descent (ie post-dwarf_child) processing of 
	   the in_die. */

	POP_DIE_STACK;
	if (in_die != in_die_in) {
	    /* Dealloc our in_die, but not the argument die, it belongs 
	       to our caller. Whether the siblingof call worked or not. 
	     */
	    dwarf_dealloc(dbg, in_die, DW_DLA_DIE);
	}
	if (cdres == DW_DLV_OK) {
	    /* Set to process the sibling, loop again. */
	    in_die = sibling;
	} else {
	    /* We are done, no more siblings at this level. */

	    break;
	}
    }				/* end for loop on siblings */
    return;
}

/* Encodings have undefined signedness. Accept either
   signedness.  The values are small (they are defined
   in the DWARF specification), so the
   form the compiler uses (as long as it is
   a constant value) is a non-issue.

   If string_out is non-NULL, construct a string output, either
   an error message or the name of the encoding.
   The function pointer passed in is to code generated
   by a script at dwarfdump build time. The code for
   the val_as_string function is generated
   from dwarf.h.  See <build dir>/dwarf_names.c

   If string_out is non-NULL then attr_name and val_as_string
   must also be non-NULL.

*/
int
get_small_encoding_integer_and_name(Dwarf_Debug dbg,
				    Dwarf_Attribute attrib,
				    Dwarf_Unsigned * uval_out,
				    char *attr_name,
				    char ** string_out,
				    encoding_type_func val_as_string,
				    Dwarf_Error * err)
{
    Dwarf_Unsigned uval = 0;
    char buf[100];		/* The strings are small. */
    int vres = dwarf_formudata(attrib, &uval, err);

    if (vres != DW_DLV_OK) {
	Dwarf_Signed sval = 0;

	vres = dwarf_formsdata(attrib, &sval, err);
	if (vres != DW_DLV_OK) {
	    if (string_out != 0) {
		snprintf(buf, sizeof(buf),
			 "%s has a bad form.", attr_name);
		*string_out = strdup(buf);
	    }
	    return vres;
	}
	*uval_out = (Dwarf_Unsigned) sval;
    } else {
	*uval_out = uval;
    }
    if (string_out)
	*string_out = val_as_string(dbg, (Dwarf_Half) uval);

    return DW_DLV_OK;

}
extern char *optarg;

#define BYTES_PER_INSTRUCTION 4

static void print_infos(Dwarf_Debug dbg);

int check_error = 0;

/* defined in print_sections.c, die for the current compile unit, 
   used in get_fde_proc_name() */
extern Dwarf_Die current_cu_die_for_print_frames;

/* These configure items are for the 
   frame data.
*/

char cu_name[BUFSIZ];
Dwarf_Unsigned cu_offset = 0;

Dwarf_Error err;

#define PRINT_CHECK_RESULT(str,result)  {\
    fprintf(stderr, "%-24s%8d%8d\n", str, result.checks, result.errors); \
}

/*
  Given a file which we know is an elf file, process
  the dwarf data.
*/
static int process_one_file(Elf *elf, char *file_name, int archive)
{
	Dwarf_Debug dbg;
	int dres = dwarf_elf_init(elf, DW_DLC_READ, NULL, NULL, &dbg, &err);

	if (dres == DW_DLV_NO_ENTRY) {
		printf("No DWARF information present in %s\n", file_name);
		return 0;
	}

	if (dres != DW_DLV_OK)
		print_error(dbg, "dwarf_elf_init", dres, err);

	if (archive) {
		Elf_Arhdr *mem_header = elf_getarhdr(elf);

		printf("\narchive member \t%s\n",
		       mem_header ? mem_header->ar_name : "");
	}

	print_infos(dbg);

	dres = dwarf_finish(dbg, &err);
	if (dres != DW_DLV_OK)
		print_error(dbg, "dwarf_finish", dres, err);

	return 0;
}

/* process each compilation unit in .debug_info */
static void print_infos(Dwarf_Debug dbg)
{
	Dwarf_Unsigned cu_header_length = 0;
	Dwarf_Unsigned abbrev_offset = 0;
	Dwarf_Half version_stamp = 0;
	Dwarf_Half address_size = 0;
	Dwarf_Die cu_die = 0;
	Dwarf_Unsigned next_cu_offset = 0;
	int nres = DW_DLV_OK;

	/* Loop until it fails.  */
	while ((nres = dwarf_next_cu_header(dbg, &cu_header_length,
					    &version_stamp, &abbrev_offset,
					    &address_size, &next_cu_offset,
					    &err)) == DW_DLV_OK) {
		/* process a single compilation unit in .debug_info. */
		int sres = dwarf_siblingof(dbg, NULL, &cu_die, &err);

		if (sres == DW_DLV_OK) {
			Dwarf_Signed cnt = 0;
			char **srcfiles = NULL;
			int srcf = dwarf_srcfiles(cu_die, &srcfiles,
						  &cnt, &err);

			if (srcf != DW_DLV_OK) {
				srcfiles = NULL;
				cnt = 0;
			}

			print_die_and_children(dbg, cu_die, srcfiles, cnt);
			if (srcf == DW_DLV_OK) {
				int si;

				for (si = 0; si < cnt; ++si)
					dwarf_dealloc(dbg, srcfiles[si],
						      DW_DLA_STRING);

				dwarf_dealloc(dbg, srcfiles, DW_DLA_LIST);
			}
			dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
		} else if (sres != DW_DLV_NO_ENTRY)
			print_error(dbg, "Regetting cu_die", sres, err);

		cu_offset = next_cu_offset;
	}

	if (nres == DW_DLV_ERROR) {
		char *errmsg = dwarf_errmsg(err);
		Dwarf_Unsigned myerr = dwarf_errno(err);

		fprintf(stderr, "%s ERROR:  %s:  %s (%lu)\n",
			program_name, "attempting to print .debug_info",
			errmsg, (unsigned long) myerr);
		fprintf(stderr, "attempting to continue.\n");
	}
}

int main(int argc, char *argv[])
{
	char *file_name;
	int f;
	Elf_Cmd cmd;
	Elf *arf, *elf;
	int archive = 0;

	elf_version(EV_NONE);
	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "dwarfdump: libelf.a out of date.\n");
		exit(EXIT_FAILURE);
	}

	file_name = argv[1];
	f = open(file_name, O_RDONLY);
	if (f == -1) {
		fprintf(stderr, "%s ERROR:  can't open %s\n", program_name,
			file_name);
		return EXIT_FAILURE;
	}

	cmd = ELF_C_READ;
	arf = elf_begin(f, cmd, (Elf *) 0);
	if (elf_kind(arf) == ELF_K_AR)
		archive = 1;

	while ((elf = elf_begin(f, cmd, arf)) != 0) {
		Elf32_Ehdr *eh32 = elf32_getehdr(elf);

		if (eh32 == NULL) {
		/* not a 32-bit obj */
			Elf64_Ehdr *eh64 = elf64_getehdr(elf);
			if (eh64 != NULL)
				process_one_file(elf, file_name, archive);
		} else
			process_one_file(elf, file_name, archive);
		cmd = elf_next(elf);
		elf_end(elf);
	}

	elf_end(arf);
	if (argc == 2)
		print_classes();
	else {
		struct class *class = find_class_by_name(argv[2]);
		if (class != NULL)
			class__print(class);
		else
			printf("struct %s not found!\n", argv[2]);
	}
	return 0;
}
