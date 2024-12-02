#include "lde.h"
#include "kallsyms.h"
#include "kprobes.h"

kallsyms_lookup_name_t kallsyms_lookup_name_ptr;

void lde_kln_ptr_set(void)
{
	struct kprobe kp_kln = {
		.symbol_name = "kallsyms_lookup_name",
	};

#ifndef KALLSYMS_EXIST
	printk(KERN_INFO "get [kallsyms_lookup_name] address by [kprobes]\n");
	kallsyms_lookup_name_ptr = (kallsyms_lookup_name_t)lde_sym_addr_get_by_kprobes(&kp_kln);
#else
	printk(KERN_INFO "[kallsyms_lookup_name] has benn exported\n");
#endif
}

void kln_syms_addr_prt(syms_list* syms_info, int count)
{
	int i;
	unsigned long addr;

	for (i = 0; i < count; i++) {
		addr = (unsigned long)LDE_KLN_PTR(syms_info[i].sym_name);
		if (!addr) {
			printk(KERN_ERR "unable to find symbol [%s] by [kallsyms_lookup_name]\n",
				syms_info[i].sym_name);
			continue;
		}
		else {
			printk(KERN_INFO "found symbol [%s], address: 0x%lx\n",
				syms_info[i].sym_name, addr);
		}
	}
}
