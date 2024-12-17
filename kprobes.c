#include "lde.h"
#include "kprobes.h"

struct kprobe lde_kp_info[KPROBE_END_TAG];
struct kretprobe lde_kretp_info[KPROBE_END_TAG];

// echo -n "xxxx" | sudo tee -a /sys/module/lde/parameters/kp_sym
char kp_sym[KSYM_NAME_LEN] = "x64_sys_call";
module_param_string(kp_sym, kp_sym, KSYM_NAME_LEN, 0644);

// echo xxxx | sudo tee -a /sys/module/lde/parameters/kp_sym_offset
int kp_sym_offset = 0x0;
module_param(kp_sym_offset, int, 0644);

void lde_kprobe_register(struct kprobe* kp_info)
{
	int ret;

	ret = register_kprobe(kp_info);
	printk(KERN_INFO "register kprobe for [%s], at 0x%px, with return num: %d\n",
		kp_info->symbol_name, kp_info->addr, ret);
}

void lde_kretprobe_register(struct kretprobe* krp_info)
{
	int ret;

	ret = register_kretprobe(krp_info);
	printk(KERN_INFO "register kretprobe for [%s], at 0x%px, with return num: %d\n",
		krp_info->kp.symbol_name, krp_info->kp.addr, ret);
}

unsigned long* lde_sym_addr_get_by_kprobes(struct kprobe* kp_info)
{
	unsigned long* sym_addr;

	lde_kprobe_register(kp_info);

	sym_addr = (unsigned long*)kp_info->addr;
	unregister_kprobe(kp_info);

	return sym_addr;
}

void lde_kprobes_unregister(void)
{
	kprobe_index kpidx;

	kpidx = STACK_KPROBE_INFO;
	do {
		if (lde_kp_info[kpidx].addr) {
			printk(KERN_INFO "will unregister kprobe [%s]\n", lde_kp_info[kpidx].symbol_name);

			unregister_kprobe(&lde_kp_info[kpidx]);
			lde_kp_info[kpidx].addr = NULL;
		}

		if (lde_kretp_info[kpidx].kp.addr) {
			printk(KERN_INFO "will unregister kretprobe [%s]\n", lde_kretp_info[kpidx].kp.symbol_name);

			unregister_kretprobe(&lde_kretp_info[kpidx]);
			lde_kretp_info[kpidx].kp.addr = NULL;
		}

		kpidx++;
	} while(kpidx < KPROBE_END_TAG);
}
