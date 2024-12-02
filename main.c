#include "lde.h" 
#include "procfs.h"
#include "syscall.h"
#include "kallsyms.h"
#include "kprobes.h"

static int __init lde_init(void)
{
	int ret;

	dump_stack();
	printk(KERN_INFO "starting from 0x%px ...\n", lde_init);

	ret = lde_proc_create();
	if (ret != SUCCEED) {
		printk(KERN_ERR "%s cannot create proc, will return\n", __func__);
		goto TAG_RETURN;
	}

	lde_kln_ptr_set();

TAG_RETURN:
	return ret;
}

static void __exit lde_exit(void)
{
	printk(KERN_INFO "exiting from 0x%px ...\n", lde_exit);

	lde_proc_remove();
	lde_syscall_revert();
	lde_kprobes_unregister();
}

module_init(lde_init);
module_exit(lde_exit);

MODULE_LICENSE(DRIVER_LICENSE);
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESCRIPTION);
