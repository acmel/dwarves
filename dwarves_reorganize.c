/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Red Hat Inc.
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
*/

#include "list.h"
#include "dwarves_reorganize.h"
#include "dwarves.h"

static void class__recalc_holes(struct class *class)
{
	class->holes_searched = 0;
	class__find_holes(class);
}

void class__subtract_offsets_from(struct class *class,
				  struct class_member *from,
				  const uint16_t size)
{
	struct class_member *member;

	class__for_each_member_continue(class, from, member) {
		member->byte_offset -= size;
		member->bit_offset  -= size * 8;
	}

	if (class->padding != 0) {
		struct class_member *last_member =
					type__last_member(&class->type);
		const ssize_t new_padding = (class__size(class) -
					     (last_member->byte_offset +
					      last_member->byte_size));
		if (new_padding > 0)
			class->padding = new_padding;
		else
			class->padding = 0;
	}
}

void class__add_offsets_from(struct class *class, struct class_member *from,
			     const uint16_t size)
{
	struct class_member *member;

	class__for_each_member_continue(class, from, member) {
		member->byte_offset += size;
		member->bit_offset  += size * 8;
	}
}

/*
 * XXX: Check this more thoroughly. Right now it is used because I was
 * to lazy to do class__remove_member properly, adjusting alignments and
 * holes as we go removing fields. Ditto for class__add_offsets_from.
 */
void class__fixup_alignment(struct class *class, const struct cu *cu)
{
	struct class_member *pos, *last_member = NULL;
	size_t power2;

	type__for_each_data_member(&class->type, pos) {
		if (last_member == NULL && pos->byte_offset != 0) { /* paranoid! */
			class__subtract_offsets_from(class, pos,
						     (pos->byte_offset -
						      pos->byte_size));
			pos->byte_offset = 0;
			pos->bit_offset = 0;
		} else if (last_member != NULL &&
			   last_member->hole >= cu->addr_size) {
			size_t dec = (last_member->hole / cu->addr_size) *
				     cu->addr_size;

			last_member->hole -= dec;
			if (last_member->hole == 0)
				--class->nr_holes;
			pos->byte_offset -= dec;
			pos->bit_offset -= dec * 8;
			class->type.size -= dec;
			class__subtract_offsets_from(class, pos, dec);
		} else for (power2 = cu->addr_size; power2 >= 2; power2 /= 2) {
			const size_t remainder = pos->byte_offset % power2;

			if (pos->byte_size == power2) {
				if (remainder == 0) /* perfectly aligned */
					break;
				if (last_member->hole >= remainder) {
					last_member->hole -= remainder;
					if (last_member->hole == 0)
						--class->nr_holes;
					pos->byte_offset -= remainder;
					pos->bit_offset -= remainder * 8;
					class__subtract_offsets_from(class, pos, remainder);
				} else {
					const size_t inc = power2 - remainder;

					if (last_member->hole == 0)
						++class->nr_holes;
					last_member->hole += inc;
					pos->byte_offset += inc;
					pos->bit_offset += inc * 8;
					class->type.size += inc;
					class__add_offsets_from(class, pos, inc);
				}
			}
		}

		last_member = pos;
	}

	if (last_member != NULL) {
		struct class_member *m =
		 type__find_first_biggest_size_base_type_member(&class->type, cu);
		size_t unpadded_size = last_member->byte_offset + last_member->byte_size;
		size_t m_size = m->byte_size, remainder;

		/* google for struct zone_padding in the linux kernel for an example */
		if (m_size == 0)
			return;

		remainder = unpadded_size % m_size;
		if (remainder != 0) {
			class->padding = m_size - remainder;
			class->type.size = unpadded_size + class->padding;
		}
	}
}

static struct class_member *
	class__find_next_hole_of_size(struct class *class,
				      struct class_member *from, size_t size)
{
	struct class_member *bitfield_head = NULL;
	struct class_member *member;

	class__for_each_member_continue(class, from, member) {
		if (member->bitfield_size != 0) {
			if (bitfield_head == NULL)
				bitfield_head = member;
		} else
			bitfield_head = NULL;
		if (member->hole != 0) {
			if (member->byte_size != 0 && member->byte_size <= size)
				return bitfield_head ? : member;
		}
	}

	return NULL;
}

static struct class_member *
	class__find_last_member_of_size(struct class *class,
					struct class_member *to, size_t size)
{
	struct class_member *member;

	class__for_each_member_reverse(class, member) {
		if (member->tag.tag != DW_TAG_member)
			continue;

		if (member == to)
			break;
		/*
		 * Check if this is the first member of a bitfield.  It either
		 * has another member before it that is not part of the current
		 * bitfield or it is the first member of the struct.
		 */
		if (member->bitfield_size != 0 && member->byte_offset != 0) {
			struct class_member *prev =
					list_entry(member->tag.node.prev,
						   struct class_member,
						   tag.node);
			if (prev->bitfield_size != 0)
				continue;

		}

		if (member->byte_size != 0 && member->byte_size <= size)
			return member;
	}

	return NULL;
}

static bool class__move_member(struct class *class, struct class_member *dest,
			      struct class_member *from, const struct cu *cu,
			      int from_padding, const int verbose, FILE *fp)
{
	const size_t from_size = from->byte_size;
	const size_t dest_size = dest->byte_size;

#ifndef BITFIELD_REORG_ALGORITHMS_ENABLED
	/*
	 * For now refuse to move a bitfield, we need to first fixup some BRAIN FARTs
	 */
	if (from->bitfield_size != 0)
		return false;
#endif
	const bool from_was_last = from->tag.node.next == class__tags(class);
	struct class_member *tail_from = from;
	struct class_member *from_prev = list_entry(from->tag.node.prev,
						    struct class_member,
						    tag.node);
	uint16_t orig_tail_from_hole = tail_from->hole;
	const uint16_t orig_from_offset = from->byte_offset;
	/*
	 * Align 'from' after 'dest':
	 */
	const uint16_t offset = dest->hole % (from_size > cu->addr_size ?
						cu->addr_size : from_size);
	/*
	 * Set new 'from' offset, after 'dest->byte_offset', aligned
	 */
	const uint16_t new_from_offset = dest->byte_offset + dest_size + offset;

	if (verbose)
		fputs("/* Moving", fp);

	if (from->bitfield_size != 0) {
		struct class_member *pos, *tmp;
		LIST_HEAD(from_list);

		if (verbose)
			fprintf(fp, " bitfield('%s' ... ",
				class_member__name(from));
		class__for_each_member_safe_from(class, from, pos, tmp) {
			/*
			 * Have we reached the end of the bitfield?
			 */
			if (pos->byte_offset != orig_from_offset)
				break;
			tail_from = pos;
			orig_tail_from_hole = tail_from->hole;
			pos->byte_offset = new_from_offset;
			pos->bit_offset = new_from_offset * 8 + pos->bitfield_offset;
			list_move_tail(&pos->tag.node, &from_list);
		}
		list_splice(&from_list, &dest->tag.node);
		if (verbose)
			fprintf(fp, "'%s')",
				class_member__name(tail_from));
	} else {
		if (verbose)
			fprintf(fp, " '%s'", class_member__name(from));
		/*
		 *  Remove 'from' from the list
		 */
		list_del(&from->tag.node);
		/*
		 * Add 'from' after 'dest':
		 */
		__list_add(&from->tag.node, &dest->tag.node,
			   dest->tag.node.next);
		from->byte_offset = new_from_offset;
		from->bit_offset = new_from_offset * 8 + from->bitfield_offset;
	}

	if (verbose)
		fprintf(fp, " from after '%s' to after '%s' */\n",
		        class_member__name(from_prev),
			class_member__name(dest));

	if (from_padding) {
		/*
		 * Check if we're eliminating the need for padding:
		 */
		if (orig_from_offset % cu->addr_size == 0) {
			/*
			 * Good, no need for padding anymore:
			 */
			class->type.size -= from_size + class->padding;
		} else {
			/*
			 * No, so just add from_size to the padding:
			 */
			if (verbose)
				fprintf(fp, "/* adding %zd bytes from %s to "
					"the padding */\n",
					from_size, class_member__name(from));
		}
	} else if (from_was_last) {
		class->type.size -= from_size + class->padding;
	} else {
		/*
		 * See if we are adding a new hole that is bigger than
		 * sizeof(long), this may have problems with explicit alignment
		 * made by the programmer, perhaps we need A switch that allows
		 * us to avoid realignment, just using existing holes but
		 * keeping the existing alignment, anyway the programmer has to
		 * check the resulting rerganization before using it, and for
		 * automatic stuff such as the one that will be used for struct
		 * "views" in tools such as ctracer we are more interested in
		 * packing the subset as tightly as possible.
		 */
		if (orig_tail_from_hole + from_size >= cu->addr_size) {
			class->type.size -= cu->addr_size;
			class__subtract_offsets_from(class, from_prev,
						     cu->addr_size);
		}
	}

	class__recalc_holes(class);

	if (verbose > 1) {
		class__fprintf(class, cu, fp);
		fputc('\n', fp);
	}

	return true;
}

#ifdef BITFIELD_REORG_ALGORITHMS_ENABLED
static struct class_member *
	class__find_next_bit_hole_of_size(struct class *class,
					  struct class_member *from,
					  size_t size)
{
	struct class_member *member;

	class__for_each_member_continue(class, from, member) {
		if (member->tag.tag != DW_TAG_member)
			continue;
		if (member->bit_hole != 0 &&
		    member->bitfield_size <= size)
		    return member;
	}
#if 0
	/*
	 * FIXME: Handle the case where the bit padding is on the same bitfield
	 * that we're looking, i.e. we can't combine a bitfield with itclass,
	 * perhaps we should tag bitfields with a sequential, clearly marking
	 * each of the bitfields in advance, so that all the algoriths that
	 * have to deal with bitfields, moving them around, demoting, etc, can
	 * be simplified.
	 */
	/*
	 * Now look if the last member is a one member bitfield,
	 * i.e. if we have bit_padding
	 */
	if (class->bit_padding != 0)
		return type__last_member(&class->type);
#endif
	return NULL;
}

static void class__move_bit_member(struct class *class, const struct cu *cu,
				   struct class_member *dest,
				   struct class_member *from,
				   const int verbose, FILE *fp)
{
	struct class_member *from_prev = list_entry(from->tag.node.prev,
						    struct class_member,
						    tag.node);

	if (verbose)
		fprintf(fp, "/* Moving '%s:%u' from after '%s' to "
			"after '%s:%u' */\n",
			class_member__name(from), from->bitfield_size,
			class_member__name(from_prev),
			class_member__name(dest), dest->bitfield_size);
	/*
	 *  Remove 'from' from the list
	 */
	list_del(&from->tag.node);
	/*
	 * Add from after dest:
	 */
	__list_add(&from->tag.node,
		   &dest->tag.node,
		   dest->tag.node.next);

	/* Check if this was the last entry in the bitfield */
	if (from_prev->bitfield_size == 0) {
		size_t from_size = from->byte_size;
		/*
		 * Are we shrinking the struct?
		 */
		if (from_size + from->hole >= cu->addr_size) {
			class->type.size -= from_size + from->hole;
			class__subtract_offsets_from(class, from_prev,
						     from_size + from->hole);
		}
	}
	/*
	 * Tricky, what are the rules for bitfield layouts on this arch?
	 * Assume its IA32
	 */
	from->bitfield_offset = dest->bitfield_offset + dest->bitfield_size;
	/*
	 * Now both have the same offset:
	 */
	from->byte_offset = dest->byte_offset;
	from->bit_offset = dest->byte_offset * 8 + from->bitfield_offset;

	class__recalc_holes(class);

	if (verbose > 1) {
		class__fprintf(class, cu, fp);
		fputc('\n', fp);
	}
}

static void class__demote_bitfield_members(struct class *class,
					   struct class_member *from,
					   struct class_member *to,
					   const struct base_type *old_type,
					   const struct base_type *new_type,
					   type_id_t new_type_id)
{
	struct class_member *member;

	class__for_each_member_from(class, from, member) {
		member->byte_size = new_type->bit_size / 8;
		member->tag.type = new_type_id;
		if (member == to)
			break;
	}
}

static struct tag *cu__find_base_type_of_size(const struct cu *cu,
					      const size_t size, type_id_t *id)
{
	const char *type_name, *type_name_alt = NULL;

	switch (size) {
	case sizeof(unsigned char):
		type_name = "unsigned char"; break;
	case sizeof(unsigned short int):
		type_name = "short unsigned int";
		type_name_alt = "unsigned short"; break;
	case sizeof(unsigned int):
		type_name = "unsigned int";
		type_name_alt = "unsigned"; break;
	case sizeof(unsigned long long):
		if (cu->addr_size == 8) {
			type_name = "long unsigned int";
			type_name_alt = "unsigned long";
		} else {
			type_name = "long long unsigned int";
			type_name_alt = "unsigned long long";
		}
		break;
	default:
		return NULL;
	}

	struct tag *ret = cu__find_base_type_by_name(cu, type_name, id);
	return ret ?: cu__find_base_type_by_name(cu, type_name_alt, id);
}

static int class__demote_bitfields(struct class *class, const struct cu *cu,
				   const int verbose, FILE *fp)
{
	struct class_member *member;
	struct class_member *bitfield_head = NULL;
	const struct tag *old_type_tag, *new_type_tag;
	size_t current_bitfield_size = 0, size, bytes_needed;
	int some_was_demoted = 0;

	type__for_each_data_member(&class->type, member) {
		/*
		 * Check if we are moving away from a bitfield
		 */
		if (member->bitfield_size == 0) {
			current_bitfield_size = 0;
			bitfield_head = NULL;
		} else {
			if (bitfield_head == NULL) {
				bitfield_head = member;
				current_bitfield_size = member->bitfield_size;
			} else if (bitfield_head->byte_offset != member->byte_offset) {
				/*
				 * We moved from one bitfield to another, for
				 * now don't handle this case, just move on to
				 * the next bitfield, we may well move it to
				 * another place and then the first bitfield will
				 * be isolated and will be handled in the next
				 * pass.
				 */
				bitfield_head = member;
				current_bitfield_size = member->bitfield_size;
			} else
				current_bitfield_size += member->bitfield_size;
		}

		/*
		 * Have we got to the end of a bitfield with holes?
		 */
		if (member->bit_hole == 0)
			continue;

		size = member->byte_size;
	    	bytes_needed = (current_bitfield_size + 7) / 8;
		bytes_needed = roundup_pow_of_two(bytes_needed);
		if (bytes_needed == size)
			continue;

		type_id_t new_type_id;
		old_type_tag = cu__type(cu, member->tag.type);
		new_type_tag = cu__find_base_type_of_size(cu, bytes_needed,
							  &new_type_id);

		if (new_type_tag == NULL) {
			fprintf(fp, "/* BRAIN FART ALERT! couldn't find a "
				    "%zd bytes base type */\n\n", bytes_needed);
			continue;
		}
		if (verbose) {
			char old_bf[64], new_bf[64];
			fprintf(fp, "/* Demoting bitfield ('%s' ... '%s') "
				"from '%s' to '%s' */\n",
				class_member__name(bitfield_head),
				class_member__name(member),
				base_type__name(tag__base_type(old_type_tag),
						old_bf, sizeof(old_bf)),
				base_type__name(tag__base_type(new_type_tag),
						new_bf, sizeof(new_bf)));
		}

		class__demote_bitfield_members(class,
					       bitfield_head, member,
					       tag__base_type(old_type_tag),
					       tag__base_type(new_type_tag),
					       new_type_id);
		class__recalc_holes(class);
		some_was_demoted = 1;

		if (verbose > 1) {
			class__fprintf(class, cu, fp);
			fputc('\n', fp);
		}
	}
	/*
	 * Now look if we have bit padding, i.e. if the the last member
	 * is a bitfield and its the sole member in this bitfield, i.e.
	 * if it wasn't already demoted as part of a bitfield of more than
	 * one member:
	 */
	member = type__last_member(&class->type);
	if (class->bit_padding != 0 && bitfield_head == member) {
		size = member->byte_size;
		bytes_needed = (member->bitfield_size + 7) / 8;
		if (bytes_needed < size) {
			old_type_tag = cu__type(cu, member->tag.type);
			type_id_t new_type_id;
			new_type_tag =
				cu__find_base_type_of_size(cu, bytes_needed,
							   &new_type_id);

			tag__assert_search_result(old_type_tag);
			tag__assert_search_result(new_type_tag);

			if (verbose) {
				char old_bf[64], new_bf[64];
				fprintf(fp, "/* Demoting bitfield ('%s') "
					"from '%s' to '%s' */\n",
					class_member__name(member),
					base_type__name(tag__base_type(old_type_tag),
							old_bf, sizeof(old_bf)),
					base_type__name(tag__base_type(new_type_tag),
							new_bf, sizeof(new_bf)));
			}
			class__demote_bitfield_members(class,
						       member, member,
						       tag__base_type(old_type_tag),
						       tag__base_type(new_type_tag),
						       new_type_id);
			class__recalc_holes(class);
			some_was_demoted = 1;

			if (verbose > 1) {
				class__fprintf(class, cu, fp);
				fputc('\n', fp);
			}
		}
	}

	return some_was_demoted;
}

static void class__reorganize_bitfields(struct class *class,
					const struct cu *cu,
					const int verbose, FILE *fp)
{
	struct class_member *member, *brother;
restart:
	type__for_each_data_member(&class->type, member) {
		/* See if we have a hole after this member */
		if (member->bit_hole != 0) {
			/*
			 * OK, try to find a member that has a bit hole after
			 * it and that has a size that fits the current hole:
			*/
			brother =
			   class__find_next_bit_hole_of_size(class, member,
							     member->bit_hole);
			if (brother != NULL) {
				class__move_bit_member(class, cu,
						       member, brother,
						       verbose, fp);
				goto restart;
			}
		}
	}
}

static void class__fixup_bitfield_types(struct class *class,
					struct class_member *from,
					struct class_member *to_before,
					type_id_t type)
{
	struct class_member *member;

	class__for_each_member_from(class, from, member) {
		if (member == to_before)
			break;
		member->tag.type = type;
	}
}

/*
 * Think about this pahole output a bit:
 *
 * [filo examples]$ pahole swiss_cheese cheese
 * / * <11b> /home/acme/git/pahole/examples/swiss_cheese.c:3 * /
 * struct cheese {
 * <SNIP>
 *       int         bitfield1:1;   / * 64 4 * /
 *       int         bitfield2:1;   / * 64 4 * /
 *
 *       / * XXX 14 bits hole, try to pack * /
 *       / * Bitfield WARNING: DWARF size=4, real size=2 * /
 *
 *       short int   d;             / * 66 2 * /
 * <SNIP>
 *
 * The compiler (gcc 4.1.1 20070105 (Red Hat 4.1.1-51) in the above example),
 * Decided to combine what was declared as an int (4 bytes) bitfield but doesn't
 * uses even one byte with the next field, that is a short int (2 bytes),
 * without demoting the type of the bitfield to short int (2 bytes), so in terms
 * of alignment the real size is 2, not 4, to make things easier for the rest of
 * the reorganizing routines we just do the demotion ourselves, fixing up the
 * sizes.
*/
static void class__fixup_member_types(struct class *class, const struct cu *cu,
				      const uint8_t verbose, FILE *fp)
{
	struct class_member *pos, *bitfield_head = NULL;
	uint8_t fixup_was_done = 0;

	type__for_each_data_member(&class->type, pos) {
		/*
		 * Is this bitfield member?
		 */
		if (pos->bitfield_size != 0) {
			/*
			 * The first entry in a bitfield?
			 */
			if (bitfield_head == NULL)
				bitfield_head = pos;
			continue;
		}
		/*
		 * OK, not a bitfield member, but have we just passed
		 * by a bitfield?
		 */
		if (bitfield_head != NULL) {
			const uint16_t real_size = (pos->byte_offset -
						  bitfield_head->byte_offset);
			const size_t size = bitfield_head->byte_size;
			/*
			 * Another case:
struct irq_cfg {
	struct irq_pin_list *      irq_2_pin;            / *     0     8 * /
	cpumask_var_t              domain;               / *     8    16 * /
	cpumask_var_t              old_domain;           / *    24    16 * /
	u8                         vector;               / *    40     1 * /
	u8                         move_in_progress:1;   / *    41: 7  1 * /
	u8                         remapped:1;           / *    41: 6  1 * /

	/ * XXX 6 bits hole, try to pack * /
	/ * XXX 6 bytes hole, try to pack * /

	union {
		struct irq_2_iommu irq_2_iommu;          / *          16 * /
		struct irq_2_irte  irq_2_irte;           / *           4 * /
	};                                               / *    48    16 * /
	/ *  --- cacheline 1 boundary (64 bytes) --- * /

			 * So just fix it up if the byte_size of the bitfield is
			 * greater than what it really uses.
			 */
			if (real_size < size) {
				type_id_t new_type_id;
				struct tag *new_type_tag =
					cu__find_base_type_of_size(cu,
								   real_size,
								   &new_type_id);
				if (new_type_tag == NULL) {
					fprintf(stderr, "%s: couldn't find"
						" a base_type of %d bytes!\n",
						__func__, real_size);
					continue;
				}
				class__fixup_bitfield_types(class,
							    bitfield_head, pos,
							    new_type_id);
				fixup_was_done = 1;
			}
		}
		bitfield_head = NULL;
	}
	if (fixup_was_done) {
		class__recalc_holes(class);
	}
	if (verbose && fixup_was_done) {
		fprintf(fp, "/* bitfield types were fixed */\n");
		if (verbose > 1) {
			class__fprintf(class, cu, fp);
			fputc('\n', fp);
		}
	}
}
#endif // BITFIELD_REORG_ALGORITHMS_ENABLED

void class__reorganize(struct class *class, const struct cu *cu,
		       const int verbose, FILE *fp)
{
	struct class_member *member, *brother, *last_member;
	size_t alignment_size;

	class__find_holes(class);
#ifdef BITFIELD_REORG_ALGORITHMS_ENABLED
	class__fixup_member_types(class, cu, verbose, fp);
	while (class__demote_bitfields(class, cu, verbose, fp))
		class__reorganize_bitfields(class, cu, verbose, fp);
#endif
	/* Now try to combine holes */
restart:
	alignment_size = 0;
	/*
	 * It can be NULL if this class doesn't have any data members,
	 * just inheritance entries
	 */
	last_member = type__last_member(&class->type);
	if (last_member == NULL)
		return;

	type__for_each_data_member(&class->type, member) {
		const size_t aligned_size = member->byte_size + member->hole;
		if (aligned_size <= cu->addr_size &&
		    aligned_size > alignment_size)
			alignment_size = aligned_size;
	}

	if (alignment_size != 0) {
		size_t modulo;
		uint16_t new_padding;

		if (alignment_size > 1)
			alignment_size = roundup(alignment_size, 2);
		modulo = (last_member->byte_offset +
			  last_member->byte_size) % alignment_size;
		if (modulo != 0)
			new_padding = cu->addr_size - modulo;
		else
			new_padding = 0;

		if (new_padding != class->padding) {
			class->padding	= new_padding;
			class->type.size = (last_member->byte_offset +
					   last_member->byte_size + new_padding);
		}
	}

	type__for_each_data_member(&class->type, member) {
		/* See if we have a hole after this member */
		if (member->hole != 0) {
			/*
			 * OK, try to find a member that has a hole after it
			 * and that has a size that fits the current hole:
			*/
			brother = class__find_next_hole_of_size(class, member,
								member->hole);
			if (brother != NULL) {
				struct class_member *brother_prev =
					    list_entry(brother->tag.node.prev,
						       struct class_member,
						       tag.node);
				/*
				 * If it the next member, avoid moving it closer,
				 * it could be a explicit alignment rule, like
				 * ____cacheline_aligned_in_smp in the Linux
				 * kernel.
				 */
				if (brother_prev != member) {
					if (class__move_member(class, member, brother, cu, 0, verbose, fp))
						goto restart;
				}
			}
			/*
			 * OK, but is there padding? If so the last member
			 * has a hole, if we are not at the last member and
			 * it has a size that is smaller than the current hole
			 * we can move it after the current member, reducing
			 * the padding or eliminating it altogether.
			 */
			if (class->padding > 0 &&
			    member != last_member &&
			    last_member->byte_size != 0 &&
			    last_member->byte_size <= member->hole) {
				if (class__move_member(class, member, last_member, cu, 1, verbose, fp))
					goto restart;
			}
		}
	}

	/* Now try to move members at the tail to after holes */
	if (class->nr_holes == 0)
		return;

	type__for_each_data_member(&class->type, member) {
		/* See if we have a hole after this member */
		if (member->hole != 0) {
			brother = class__find_last_member_of_size(class, member,
								  member->hole);
			if (brother != NULL) {
				struct class_member *brother_prev =
					    list_entry(brother->tag.node.prev,
						       struct class_member,
						       tag.node);
				/*
				 * If it the next member, avoid moving it closer,
				 * it could be a explicit alignment rule, like
				 * ____cacheline_aligned_in_smp in the Linux
				 * kernel.
				 */
				if (brother_prev != member) {
					if (class__move_member(class, member, brother, cu, 0, verbose, fp))
						goto restart;
				}
			}
		}
	}
}
