#include "lde.h"
#include "syscall.h"
#include "kallsyms.h"
#include <linux/unistd.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <asm/msr.h>
#include <uapi/asm/vsyscall.h>

#define SYSCALL_HAS_CHANGED		1
#define CR0_WP_BIT				16

// echo xxxx | sudo tee -a /sys/module/lde/parameters/syscall_swap_id
int syscall_swap_id = __NR_perf_event_open;
module_param(syscall_swap_id, int, 0644);

static unsigned long* lde_sys_call_table;
static int (*syscall_orig)(void);

static unsigned long raw_data_orig[2];

static int lde_my_syscall(void)
{
	dump_stack();
	printk(KERN_INFO "enter %s\n", __func__);

	return SUCCEED;
}

static unsigned long cr0_get(void)
{
	unsigned long cr0_val;

	asm volatile ("movq %%cr0, %%rax" : "=a"(cr0_val));
	printk(KERN_INFO "current cr0 value: 0x%lx\n", cr0_val);

	return cr0_val;
}

static void cr0_set(unsigned long val)
{
	printk(KERN_INFO "cr0 set to: 0x%lx\n", val);
	asm volatile ("movq %%rax, %%cr0" :: "a"(val));

	cr0_get();

	return;
}

static unsigned long cr0_bit_disable(int bit)
{
	unsigned long cr0_val, cr0_bak;

	cr0_val = cr0_get();
	cr0_bak = cr0_val;

	cr0_val &= ~(1UL << bit);
	cr0_set(cr0_val);

	return cr0_bak;
}

static int syscall_check(void)
{
	printk(KERN_INFO "my table address: 0x%lx, target element address: 0x%lx\n",
		(unsigned long)lde_sys_call_table, (unsigned long)syscall_orig);

	if ((lde_sys_call_table != NULL) && ((int(*)(void))lde_sys_call_table[syscall_swap_id]) != syscall_orig) {
		return SYSCALL_HAS_CHANGED;
	}
	else {
		return SUCCEED;
	}
}

void lde_syscall_revert(void)
{
	int ret;
	unsigned long cr0_orig;

	ret = syscall_check();
	if (ret == SUCCEED) {
		goto TAG_NO_CHANGE;
	}

	printk(KERN_INFO "will revert syscall\n");

	cr0_orig = cr0_bit_disable(CR0_WP_BIT);

	lde_sys_call_table[syscall_swap_id] = (unsigned long)syscall_orig;
	*(unsigned long*)syscall_orig = raw_data_orig[0];
	*(unsigned long*)(syscall_orig + 8) = raw_data_orig[1];

	cr0_set(cr0_orig);

	return;

TAG_NO_CHANGE:
	printk(KERN_INFO "lde_sys_call_table not modified by lde, nothing to do ...\n");

}

static void msr_syscall_read(void)
{
	unsigned long msr_star_val, msr_lstar_val;

	rdmsrl(MSR_STAR, msr_star_val);
	rdmsrl(MSR_LSTAR, msr_lstar_val);
	printk(KERN_INFO "MSR_STAR: 0x%lx, MSR_LSTAR: 0x%lx\n", msr_star_val, msr_lstar_val);
}

void lde_syscall_hack(void)
{
	int ret;
	unsigned long cr0_orig;
	unsigned int cmd[3];
	char offset[8];

	ret = syscall_check();
	if (ret == SYSCALL_HAS_CHANGED) {
		printk(KERN_INFO "syscall table already changed\n");
		return;
	}

	printk(KERN_INFO "will swap syscall\n");

	lde_sys_call_table = (unsigned long*)LDE_KLN_PTR("sys_call_table");
	if (!lde_sys_call_table) {
		printk(KERN_ERR "unable to find symbol by [kallsyms_lookup_name], will exit ...\n");
		return;
	}
	else {
		printk(KERN_INFO "found symbol at 0x%px\n", lde_sys_call_table);
	}

	msr_syscall_read();
	cr0_orig = cr0_bit_disable(CR0_WP_BIT);

	syscall_orig = (int(*)(void))(lde_sys_call_table[syscall_swap_id]);
	printk(KERN_INFO "current lde_sys_call_table[%04d], [0x%px %pS]\n",
		syscall_swap_id, (int*)lde_sys_call_table[syscall_swap_id], (int*)lde_sys_call_table[syscall_swap_id]);
	lde_sys_call_table[syscall_swap_id] = (unsigned long)&lde_my_syscall;
	printk(KERN_INFO "current lde_sys_call_table[%04d] (after swap), [0x%px %pS]\n",
		syscall_swap_id, (int*)lde_sys_call_table[syscall_swap_id], (int*)lde_sys_call_table[syscall_swap_id]);

	raw_data_orig[0] = *(unsigned long*)(syscall_orig);
	raw_data_orig[1] = *(unsigned long*)(syscall_orig + 8);
	*(unsigned long*)offset = (unsigned long)&lde_my_syscall;
	cmd[0] = offset[6] | (offset[7] << 8) | (0xFF << 16) | (0xE0 << 24);
	cmd[1] = offset[2] | (offset[3] << 8) | (offset[4] << 16) | (offset[5] << 24);
	cmd[2] = 0x48 | (0xB8 << 8) | (offset[0] << 16) | (offset[1] << 24);

	*(unsigned int*)syscall_orig = cmd[2];
	*(unsigned int*)(syscall_orig + 4) = cmd[1];
	*(unsigned int*)(syscall_orig + 8) = cmd[0];

	cr0_set(cr0_orig);
}

void vsyscall_info_show(void)
{
	struct vm_area_struct* vsyscall_info;
	int* vsyscall_mode;
	const char* vsc_mode_str[] = {
		"EMULATE",
		"XONLY",
		"NONE"
	};

	vsyscall_info = (struct vm_area_struct*)LDE_KLN_PTR("gate_vma");
	vsyscall_mode = (int*)LDE_KLN_PTR("vsyscall_mode");
	if (!vsyscall_info || !vsyscall_mode) {
		printk(KERN_ERR "unable to find symbol by [kallsyms_lookup_name], will exit ...\n");
		return;
	}
	else {
		printk(KERN_INFO "found symbol, vma at 0x%px, mode: %s\n",
			vsyscall_info, vsc_mode_str[*vsyscall_mode]);
	}

	printk(KERN_INFO "VSYSCALL_ADDR: %lx, %s %lx - %lx\n", VSYSCALL_ADDR,
		vsyscall_info->vm_ops->name(NULL), vsyscall_info->vm_start, vsyscall_info->vm_end);
}

typedef enum _vdso_syms_id {
	LINUX_TASK_SIZE = 0,
	LINUX_TASK_SIZE_64BIT,
	UM_VDSO_ADDR,
	ALIGN_VDSO_ADDR,
	UM_VDSO,
	VDSO_START,
	VDSO_UPDATE_BEGIN,
	VDSO_END,
	VDSO_UPDATE_END,
	VDSOP,
	VDSO_MAPPING,
	VDSO_END_TAG,
} vdso_syms_id;

static const char* vdso_syms_name[] = {
	"task_size",
	"task_size_64bit",
	"um_vdso_addr",
	"align_vdso_addr",
	"um_vdso",
	"vdso_start",
	"vdso_update_begin",
	"vdso_end",
	"vdso_update_end",
	"vdsop",
	"vdso_mapping",
};

void vdso_info_show(void)
{
	syms_list syms_info[VDSO_END_TAG];

	vdso_syms_id vs_inx;

	vs_inx = LINUX_TASK_SIZE;
	do {
		syms_info[vs_inx].id = vs_inx;
		syms_info[vs_inx].sym_name = vdso_syms_name[vs_inx];

		vs_inx++;
	} while(vs_inx < VDSO_END_TAG);

	kln_syms_addr_prt(syms_info, sizeof(syms_info) / sizeof(syms_list));
}
