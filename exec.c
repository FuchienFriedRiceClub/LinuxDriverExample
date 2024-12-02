#include "lde.h"
#include "kallsyms.h"
#include <linux/binfmts.h>
#include <linux/list.h>

void exec_formats_dump(void)
{
	struct list_head* my_exec_formats;
	struct linux_binfmt* my_fmt;
	rwlock_t* my_exec_formats_lock;
	int i;

	my_fmt = (struct linux_binfmt*)LDE_KLN_PTR("elf_format");
	my_exec_formats = &(my_fmt->lh);
	my_exec_formats_lock = (rwlock_t*)LDE_KLN_PTR("binfmt_lock");
	if (!my_exec_formats || !my_exec_formats_lock) {
		printk(KERN_ERR "unable to find symbol by [kallsyms_lookup_name], will exit ...\n");
		return;
	}
	else {
		printk(KERN_INFO "found symbol, formats: 0x%px, binfmt_lock: %px\n", my_exec_formats, my_exec_formats_lock);
	}

	i = 0;
	read_lock(my_exec_formats_lock);
	list_for_each_entry(my_fmt, my_exec_formats, lh) {
		printk(KERN_INFO
			"exec fmts num: %04d, name: %s, load_binary: 0x%ps\n",
			i, my_fmt->module->name, my_fmt->load_binary
		);

		i++;
	}
	read_unlock(my_exec_formats_lock);
}
