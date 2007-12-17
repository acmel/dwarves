/* 
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/percpu.h>
#include <linux/relay.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/module.h>
#include "ctracer_relay.h"

static struct rchan *ctracer__rchan;

static int ctracer__subbuf_start_callback(struct rchan_buf *buf, void *subbuf,
					  void *prev_subbuf,
					  size_t prev_padding)
{
	static int warned;
	if (!relay_buf_full(buf))
		return 1;
	if (!warned) {
		warned = 1;
		printk("relay_buf_full!\n");
	}
	return 0;
}

static struct dentry *ctracer__create_buf_file_callback(const char *filename,
							struct dentry *parent,
							int mode,
							struct rchan_buf *buf,
							int *is_global)
{
	return debugfs_create_file(filename, mode, parent, buf,
				   &relay_file_operations);
}

static int ctracer__remove_buf_file_callback(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}

static struct rchan_callbacks ctracer__relay_callbacks = {
	.subbuf_start	 = ctracer__subbuf_start_callback,
	.create_buf_file = ctracer__create_buf_file_callback,
	.remove_buf_file = ctracer__remove_buf_file_callback,
};

extern void ctracer__class_state(const void *from, void *to);

void ctracer__method_hook(const unsigned long long now,
			  const int probe_type,
			  const unsigned long long function_id,
			  const void *object, const int state_len)
{
	if (object != NULL) {
		void *t = relay_reserve(ctracer__rchan,
					sizeof(struct trace_entry) + state_len);

		if (t != NULL) {
			struct trace_entry *entry = t;
			
			entry->nsec	   = now;
			entry->probe_type  = probe_type;
			entry->object	   = object;
			entry->function_id = function_id;
			ctracer__class_state(object, t + sizeof(*entry));
		}
	}
}

EXPORT_SYMBOL_GPL(ctracer__method_hook);

static int __init ctracer__relay_init(void)
{
	ctracer__rchan = relay_open("ctracer", NULL, 512 * 1024, 64,
				    &ctracer__relay_callbacks, NULL);
	if (ctracer__rchan == NULL) {
		pr_info("ctracer: couldn't create the relay\n");
		return -1;
	}
	return 0;
}

module_init(ctracer__relay_init);

static void __exit ctracer__relay_exit(void)
{
	relay_close(ctracer__rchan);
}

module_exit(ctracer__relay_exit);

MODULE_LICENSE("GPL");
