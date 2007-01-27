#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/stddef.h>

extern struct jprobe	*ctracer__jprobes[];
extern struct kretprobe *ctracer__kretprobes[];

static int __init ctracer__jprobe_init(void)
{
	int i = 0, nj = 0, nr = 0;

	while (ctracer__jprobes[i] != NULL) {
		int err = register_jprobe(ctracer__jprobes[i]);
		if (err != 0)
			pr_info("ctracer: register_jprobe(%s) failed, err=%d\n",
				ctracer__jprobes[i]->kp.symbol_name, err);
		else
			++nj;
		ctracer__kretprobes[i]->maxactive = 64;
		err = register_kretprobe(ctracer__kretprobes[i]);
		if (err != 0)
			pr_info("ctracer: register_kretprobe(%s) failed,"
				" err=%d\n",
			        ctracer__kretprobes[i]->kp.symbol_name, err);
		else
			++nr;
		++i;
		if ((i % 5) == 0)
			yield();
	}

	pr_info("ctracer: registered %u entry probes\n", nj);
	pr_info("ctracer: registered %u exit probes\n", nr);

        return 0;
}

module_init(ctracer__jprobe_init);

static void __exit ctracer__jprobe_exit(void)
{
	int i = 0;

	while (ctracer__jprobes[i] != NULL) {
		if (ctracer__jprobes[i]->kp.nmissed != 0)
			pr_info("ctracer: entry: missed %lu %s\n",
				ctracer__jprobes[i]->kp.nmissed,
				ctracer__jprobes[i]->kp.symbol_name);
		unregister_jprobe(ctracer__jprobes[i]);
		if (ctracer__kretprobes[i]->nmissed != 0)
			pr_info("ctracer: exit: missed %d %s\n",
				ctracer__kretprobes[i]->nmissed,
				ctracer__kretprobes[i]->kp.symbol_name);
		unregister_kretprobe(ctracer__kretprobes[i]);
		++i;
		if ((i % 5) == 0)
			yield();
	}

}

module_exit(ctracer__jprobe_exit);

MODULE_LICENSE("GPL");
