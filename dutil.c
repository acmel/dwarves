/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
*/


#include "dutil.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *zalloc(size_t size)
{
        return calloc(1, size);
}

void __zfree(void **ptr)
{
        free(*ptr);
        *ptr = NULL;
}

struct str_node *str_node__new(const char *s, bool dupstr)
{
	struct str_node *snode = malloc(sizeof(*snode));

	if (snode != NULL){
		if (dupstr) {
			s = strdup(s);
			if (s == NULL)
				goto out_delete;
		}
		snode->s = s;
	}

	return snode;

out_delete:
	free(snode);
	return NULL;
}

static void str_node__delete(struct str_node *snode, bool dupstr)
{
	if (snode == NULL)
		return;

	if (dupstr)
		zfree(&snode->s);
	free(snode);
}

int __strlist__add(struct strlist *slist, const char *new_entry, void *priv)
{
        struct rb_node **p = &slist->entries.rb_node;
        struct rb_node *parent = NULL;
	struct str_node *sn;

        while (*p != NULL) {
		int rc;

                parent = *p;
                sn = rb_entry(parent, struct str_node, rb_node);
		rc = strcmp(sn->s, new_entry);

		if (rc > 0)
                        p = &(*p)->rb_left;
                else if (rc < 0)
                        p = &(*p)->rb_right;
		else
			return -EEXIST;
        }

	sn = str_node__new(new_entry, slist->dupstr);
	if (sn == NULL)
		return -ENOMEM;

        rb_link_node(&sn->rb_node, parent, p);
        rb_insert_color(&sn->rb_node, &slist->entries);

	sn->priv = priv;

	list_add_tail(&sn->node, &slist->list_entries);

	return 0;
}

int strlist__add(struct strlist *slist, const char *new_entry)
{
	return __strlist__add(slist, new_entry, NULL);
}

int strlist__load(struct strlist *slist, const char *filename)
{
	char entry[1024];
	int err = -1;
	FILE *fp = fopen(filename, "r");

	if (fp == NULL)
		return -1;

	while (fgets(entry, sizeof(entry), fp) != NULL) {
		const size_t len = strlen(entry);

		if (len == 0)
			continue;
		entry[len - 1] = '\0';

		if (strlist__add(slist, entry) != 0)
			goto out;
	}

	err = 0;
out:
	fclose(fp);
	return err;
}

struct strlist *strlist__new(bool dupstr)
{
	struct strlist *slist = malloc(sizeof(*slist));

	if (slist != NULL) {
		slist->entries = RB_ROOT;
		INIT_LIST_HEAD(&slist->list_entries);
		slist->dupstr = dupstr;
	}

	return slist;
}

void strlist__delete(struct strlist *slist)
{
	if (slist != NULL) {
		struct str_node *pos;
		struct rb_node *next = rb_first(&slist->entries);

		while (next) {
			pos = rb_entry(next, struct str_node, rb_node);
			next = rb_next(&pos->rb_node);
			strlist__remove(slist, pos);
		}
		slist->entries = RB_ROOT;
		free(slist);
	}
}

void strlist__remove(struct strlist *slist, struct str_node *sn)
{
	rb_erase(&sn->rb_node, &slist->entries);
	list_del_init(&sn->node);
	str_node__delete(sn, slist->dupstr);
}

bool strlist__has_entry(struct strlist *slist, const char *entry)
{
        struct rb_node **p = &slist->entries.rb_node;
        struct rb_node *parent = NULL;

        while (*p != NULL) {
		struct str_node *sn;
		int rc;

                parent = *p;
                sn = rb_entry(parent, struct str_node, rb_node);
		rc = strcmp(sn->s, entry);

		if (rc > 0)
                        p = &(*p)->rb_left;
                else if (rc < 0)
                        p = &(*p)->rb_right;
		else
			return true;
        }

	return false;
}

Elf_Scn *elf_section_by_name(Elf *elf, GElf_Shdr *shp, const char *name, size_t *index)
{
	Elf_Scn *sec = NULL;
	size_t cnt = 1;
	size_t str_idx;

	if (elf_getshdrstrndx(elf, &str_idx))
		return NULL;

	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *str;

		gelf_getshdr(sec, shp);
		str = elf_strptr(elf, str_idx, shp->sh_name);
		if (!str)
			return NULL;
		if (!strcmp(name, str)) {
			if (index)
				*index = cnt;
			break;
		}
		++cnt;
	}

	return sec;
}

Elf_Scn *elf_section_by_idx(Elf *elf, GElf_Shdr *shp, int idx)
{
	Elf_Scn *sec;

	sec = elf_getscn(elf, idx);
	if (sec)
		gelf_getshdr(sec, shp);
	return sec;
}

char *strlwr(char *s)
{
	int len = strlen(s), i;

	for (i = 0; i < len; ++i)
		s[i] = tolower(s[i]);

	return s;
}
