#include "lde.h"
#include "procfs.h"
#include "tasks.h"
#include "kallsyms.h"
#include "kprobes.h"

#define COMM_MAX_LEN		15

// echo xxxx | sudo tee -a /sys/module/lde/parameters/current_bt_times
int current_bt_times = 0;
module_param(current_bt_times, int, 0644);

// echo xxxx | sudo tee -a /sys/module/lde/parameters/max_times
int max_times = 5;
module_param(max_times, int, 0644);

typedef enum _kp_dump_mode {
	CANNOT = 0,
	CAN_DUMP_REGS,
	CAN_DUMP_ALL
} kp_dump_mode;

struct func_time {
	ktime_t enter_stamp;
};
static char cur_sym[KSYM_NAME_LEN];

static bool excepted_proc_check(void)
{
	if ((expected_pid == current->pid)
	|| (strncmp(expected_pname, current->comm, COMM_MAX_LEN) == 0)) {
		return true;
	}

	return false;
}

static kp_dump_mode bt_need(void)
{
	if (current_bt_times > max_times || max_times < 0) {
		printk(KERN_INFO "stop stack dump\n");
		return CAN_DUMP_REGS;
	}

	current_bt_times++;

	return CAN_DUMP_ALL;
}

static kp_dump_mode bt_check(void)
{
	kp_dump_mode ret;

	if (excepted_proc_check()) {
		ret = bt_need();
		return ret;
	}

	return CANNOT;
}

static void all_regs_print(struct pt_regs* args)
{
	printk(KERN_INFO
		"callee used ->\n"
		"r15 = 0x%016lx ; r14 = 0x%016lx ; r13 = 0x%016lx ; r12 = 0x%016lx ;\n"
		"bp  = 0x%016lx ; bx  = 0x%016lx ;\n"
		"caller used ->\n"
		"r11 = 0x%016lx ; r10 = 0x%016lx ; r9  = 0x%016lx ; r8  = 0x%016lx ;\n"
		"ax  = 0x%016lx ; cx  = 0x%016lx ; dx  = 0x%016lx ; si  = 0x%016lx ;\n"
		"di  = 0x%016lx ;\n"
		"syscall && error code && IRQ num ->\n"
		"ax  = 0x%016lx ;\n"
		"return frame for [iretq] ->\n"
		"ip  = 0x%016lx ; cs  = 0x%016lx ; sp  = 0x%016lx ; ss  = 0x%016lx ;\n"
		"flags = 0x%016lx ;\n",
		args->r15, args->r14, args->r13, args->r12,
		args->bp, args->bx,
		args->r11, args->r10, args->r9, args->r8,
		args->ax, args->cx, args->dx, args->si,
		args->di,
		args->orig_ax,
		args->ip, args->cs, args->sp, args->ss,
		args->flags
	);
}

static __kprobes int stack_dump_by_kprobe_pre(struct kprobe* kp_info, struct pt_regs* args)
{
	kp_dump_mode ret;

	ret = bt_check();
	switch (ret) {
	case CAN_DUMP_ALL:
		all_regs_print(args);
		task_simple_info_show(current);
		all_signal_simple_info_print(current);
		dump_stack();
		break;
	case CAN_DUMP_REGS:
		all_regs_print(args);
		break;
	default:
		return 0;
	}

	printk(KERN_INFO "leave %s\n", __func__);

	return 0;
}

static __kprobes void stack_dump_by_kprobe_post(struct kprobe* kp_info, struct pt_regs* args, unsigned long flags)
{
	kp_dump_mode ret;

	ret = bt_check();
	switch (ret) {
	case CAN_DUMP_ALL:
	case CAN_DUMP_REGS:
		all_regs_print(args);
		break;
	default:
		return;
	}

	printk(KERN_INFO "leave %s\n", __func__);
}

static int func_entry_handler(struct kretprobe_instance* krpi, struct pt_regs* regs)
{
	kp_dump_mode ret;
	struct func_time* data;

	// skip kernel threads
	if (!current->mm)
		return 1;

	ret = bt_check();
	switch (ret) {
	case CAN_DUMP_ALL:
	case CAN_DUMP_REGS:
		data = (struct func_time*)krpi->data;
		data->enter_stamp = ktime_get();
		printk(KERN_INFO "enter %s at %lld\n", kp_sym, (long long)data->enter_stamp);
		break;
	default:
		break;
	}

	return 0;
}

static int func_ret_handler(struct kretprobe_instance* krpi, struct pt_regs* regs)
{
	kp_dump_mode ret;
	unsigned long retval;
	struct func_time *data;
	s64 delta;
	ktime_t now;

	ret = bt_check();

	switch (ret) {
	case CAN_DUMP_ALL:
	case CAN_DUMP_REGS:
		now = ktime_get();
		retval = regs_return_value(regs);
		data = (struct func_time*)krpi->data;
		delta = ktime_to_ns(ktime_sub(now, data->enter_stamp));
		printk(KERN_INFO "%s returned 0x%lx and took %lld ns to execute\n"
			"\treturn to address 0x%lx, frame = 0x%lx\n",
			kp_sym, retval, (long long)delta,
			(unsigned long)(krpi->node.ret_addr),
			(unsigned long)(krpi->node.frame));
		break;
	default:
		break;
	}

	return 0;
}

void specified_func2stack_dump(void)
{
	lde_kprobes_unregister();

	strncpy(cur_sym, kp_sym, KSYM_NAME_LEN);
	current_bt_times = 0;

	lde_kp_info[STACK_KPROBE_INFO].symbol_name = cur_sym;
	lde_kp_info[STACK_KPROBE_INFO].offset = kp_sym_offset;
	lde_kp_info[STACK_KPROBE_INFO].pre_handler = stack_dump_by_kprobe_pre;
	lde_kp_info[STACK_KPROBE_INFO].post_handler = stack_dump_by_kprobe_post;

	lde_kretp_info[STACK_KPROBE_INFO].kp.symbol_name = cur_sym;
	lde_kretp_info[STACK_KPROBE_INFO].handler = func_ret_handler;
	lde_kretp_info[STACK_KPROBE_INFO].entry_handler = func_entry_handler;
	lde_kretp_info[STACK_KPROBE_INFO].data_size = sizeof(struct func_time);
	lde_kretp_info[STACK_KPROBE_INFO].maxactive = max_times;

	lde_kprobe_register(&lde_kp_info[STACK_KPROBE_INFO]);
	lde_kretprobe_register(&lde_kretp_info[STACK_KPROBE_INFO]);
}
