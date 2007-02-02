#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/percpu.h>
#include <linux/relay.h>
#include <linux/sched.h>
#include <linux/string.h>

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

struct trace_entry {
	unsigned int	   sec;
	unsigned int	   usec:31;
	unsigned int	   probe_type:1; /* Entry or exit */
	const void	   *object;
	unsigned long long function_id;
};

extern void ctracer__class_state(const void *from, void *to);

void ctracer__method_entry(const unsigned long long function_id,
			   const void *object, const int state_len)
{
	struct timeval now;

	do_gettimeofday(&now);
{
	unsigned long flags;
	void *t;

	local_irq_save(flags);
	t = relay_reserve(ctracer__rchan,
			  sizeof(struct trace_entry) + state_len);

	if (t != NULL) {
		struct trace_entry *entry = t;

		entry->sec	   = now.tv_sec;
		entry->usec	   = now.tv_usec;
		entry->probe_type  = 0;
		entry->object	   = object;
		entry->function_id = function_id;
		ctracer__class_state(object, t + sizeof(*entry));
	}
	local_irq_restore(flags);
}
}

void ctracer__method_exit(unsigned long long function_id)
{
	struct timeval now;

	do_gettimeofday(&now);
{
	unsigned long flags;
	void *t;

	local_irq_save(flags);
	t = relay_reserve(ctracer__rchan, sizeof(struct trace_entry));

	if (t != NULL) {
		struct trace_entry *entry = t;

		entry->sec	   = now.tv_sec;
		entry->usec	   = now.tv_usec;
		entry->probe_type  = 1;
		entry->object	   = NULL; /* need to find a way to get this */
		entry->function_id = function_id;
	}
	local_irq_restore(flags);
}
}

int ctracer__relay_init(void)
{
	ctracer__rchan = relay_open("ctracer", NULL, 256 * 1024, 64,
				    &ctracer__relay_callbacks);
	if (ctracer__rchan == NULL) {
		pr_info("ctracer: couldn't create the relay\n");
		return -1;
	}
	return 0;
}

void ctracer__relay_exit(void)
{
	relay_close(ctracer__rchan);
}
