#include "lde.h"
#include "procfs.h"
#include "syscall.h"
#include "idt.h"
#include "init_sections.h"
#include "tasks.h"
#include "stack.h"
#include "kallsyms.h"
#include "fs.h"
#include "exec.h"
#include "kernel.h"
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#define PROC_OPS_EXITS
#endif

#define MAX_CMDS_BUFFER_LEN			256
#define MAX_SYSINFO_BUFFER_LEN		256
#define MAX_RECEIVE_BUFFER_LEN		256

typedef enum _cmds_index {
	SYSCALL_HACK = 0,
	SYSCALL_REVERT,
	VSYSCALL_INFO_SHOW,
	VDSO_INFO_SHOW,
	IDT_INFO_SHOW,
	INIT_SECTIONS_INFO_SHOW,
	TASKS_LIST_SHOW,
	TASK_MAX_SIZE_SHOW,
	STACK_DUMP_SHOW,
	FILE_SYSTEMS_INFO_DUMP,
	EXEC_FORMATS_INFO_DUMP,
	CMD_END,
} cmds_index;
typedef void cmd_run_func(void);
typedef struct _lde_cmd_support_info {
	const char* name;
	const char* desc;
	const char* usage;
	cmd_run_func* func;
} lde_cmd_support_info;

static struct proc_dir_entry* lde_proc_entry = NULL;
static lde_cmd_support_info* my_cmds_support_info = NULL;
static char* lde_proc_msg = NULL;
char** global_lde_argv = NULL;

static const char* cmds_list[] = {
	"sc_hack",
	"sc_revert",
	"vsyscall",
	"vdso",
	"idt",
	"init_secs",
	"tasks",
	"task_size",
	"bt",
	"fs",
	"exec_fmts",
};
static const char* cmds_desc[] = {
	"system call replacement [default -> __NR_perf_event_open]",
	"system call restoration",
	"vsyscall info view",
	"vdso info view",
	"idt info view",
	"init sections info view",
	"all tasks view",
	"task max size view",
	"specify a function and a process to dump stack [function default -> x64_sys_call]",
	"file systems info view",
	"executable file formats info view",
};
static const char* lde_sysfs = {
	"syscall_swap_id: specifying syscall id\n"
	"expected_pid: specifying process id\n"
	"expected_pname: specifying process name\n"
	"current_bt_times: specifying current stack dump times\n"
	"stack_dump_max_times: specifying stack dump max times\n"
	"kp_sym: specifying kprobe used symbol\n"
};
static cmd_run_func* funcs_list[] = {
	lde_syscall_hack,
	lde_syscall_revert,
	vsyscall_info_show,
	vdso_info_show,
	idt_info_show,
	init_sections_info_show,
	tasks_list_show,
	task_max_size_get,
	specified_func2stack_dump,
	file_systems_info_dump,
	exec_formats_dump,
};

static void lde_proc_support_info_init(void) {
	cmds_index cmd_idx;

	if (my_cmds_support_info != NULL) {
		printk(KERN_INFO "lde driver proc support has been init!\n");
		return;
	}

	my_cmds_support_info = (lde_cmd_support_info*)kmalloc(
		sizeof(lde_cmd_support_info) * CMD_END, GFP_KERNEL);
	if (!my_cmds_support_info) {
		printk(KERN_ERR "malloc failed\n");
		return;
	}

	cmd_idx = SYSCALL_HACK;
	do {
		my_cmds_support_info[cmd_idx].name = cmds_list[cmd_idx];
		my_cmds_support_info[cmd_idx].desc = cmds_desc[cmd_idx];
		my_cmds_support_info[cmd_idx].func = funcs_list[cmd_idx];

		cmd_idx++;
	} while (cmd_idx < CMD_END);
}

static void lde_proc_read_info_init(void)
{
	int i;
	cmds_index cmd_idx;
	unsigned long cpus_cnt, kb_addr;
	struct task_struct** tasks_list;
	lde_dump_cpu_task lde_cpu_task_dump;

	if (lde_proc_msg != NULL) {
		printk(KERN_INFO "lde driver proc read info has been init!\n");
		return;
	}

	lde_proc_msg = (char*)kmalloc(
		MAX_CMDS_BUFFER_LEN + MAX_SYSINFO_BUFFER_LEN,
		GFP_KERNEL
	);
	if (!lde_proc_msg) {
		printk(KERN_ERR "malloc failed\n");
		return;
	}

	cmd_idx = SYSCALL_HACK;
	do {
		printk(KERN_INFO "add message num: %d - %d\n", cmd_idx, CMD_END - 1);

		snprintf(lde_proc_msg, MAX_CMDS_BUFFER_LEN,
			"%s"
			"%s: %s\n",
			cmd_idx == SYSCALL_HACK ? "lde driver cmds list ->\n" : lde_proc_msg,
			my_cmds_support_info[cmd_idx].name, my_cmds_support_info[cmd_idx].desc
		);

		cmd_idx++;
	} while (cmd_idx < CMD_END);

	snprintf(lde_proc_msg, MAX_CMDS_BUFFER_LEN,
			"%s"
			"\nsysfs info ->\n"
			"%s",
			lde_proc_msg, lde_sysfs
	);

	cpus_cnt = online_cpus_cnt_get();
	snprintf(lde_proc_msg, MAX_CMDS_BUFFER_LEN + MAX_SYSINFO_BUFFER_LEN,
		"%s"
		"\ncpus && tasks info ->\n"
		"total cpus count: %ld\n"
		"current: task_struct = 0x%px ; cpu = %d ; pid = %d ; comm = %s ;\n",
		lde_proc_msg,
		cpus_cnt,
		current, task_cpu(current), current->pid, current->comm
	);

	lde_cpu_task_dump = (lde_dump_cpu_task)LDE_KLN_PTR("dump_cpu_task");
	if (lde_cpu_task_dump) {
		snprintf(lde_proc_msg, MAX_CMDS_BUFFER_LEN + MAX_SYSINFO_BUFFER_LEN,
			"%s"
			"you can view cpu task dump info by [dump_cpu_task]\n",
			lde_proc_msg
		);
	}
	tasks_list = all_cpus_cur_task_get(tasks_list, cpus_cnt);
	if (!tasks_list) {
		snprintf(lde_proc_msg, MAX_CMDS_BUFFER_LEN + MAX_SYSINFO_BUFFER_LEN,
			"%s"
			"\nper cpu simple info cannot get\n",
			lde_proc_msg
		);
	}

	i = 0;
	do {
		if (tasks_list) {
			snprintf(lde_proc_msg, MAX_CMDS_BUFFER_LEN + MAX_SYSINFO_BUFFER_LEN,
				"%s"
				"task_struct = 0x%px ; cpu = %d ; pid = %d ; comm = %s\n",
				lde_proc_msg,
				tasks_list[i], task_cpu(tasks_list[i]),
				tasks_list[i]->pid, tasks_list[i]->comm
			);
		}

		i++;
	} while(i < cpus_cnt);

	kb_addr = kernel_base_addr_get();
	snprintf(lde_proc_msg, MAX_CMDS_BUFFER_LEN + MAX_SYSINFO_BUFFER_LEN,
		"%s"
		"\nkernel info ->\n"
		"base address = 0x%lx\n",
		lde_proc_msg, kb_addr
	);

	kfree(tasks_list);
}

static void lde_proc_support_info_check(void)
{
	if (!my_cmds_support_info) {
		printk(KERN_INFO "proc support info is empty, will init!\n");
		lde_proc_support_info_init();
	}
}

static void lde_proc_msg_get(void)
{
	lde_proc_support_info_check();

	if (!lde_proc_msg) {
		printk(KERN_INFO "proc message is empty, will init!\n");
		lde_proc_read_info_init();
	}
}

static ssize_t lde_proc_read(struct file* file, char __user* ubuf, size_t count, loff_t* offp) 
{
	int ret;
	ssize_t buf_len;

	printk(KERN_INFO "%s called file 0x%px, buffer 0x%px count 0x%lx off 0x%llx\n",
		__func__, file, ubuf, count, *offp);

	ret = 0;
	if (*offp > 0) {
		goto TAG_RETURN;
	}

	lde_proc_msg_get();
	if (!lde_proc_msg) {
		goto TAG_RETURN;
	}
	buf_len = strnlen(lde_proc_msg, MAX_CMDS_BUFFER_LEN + MAX_SYSINFO_BUFFER_LEN) + 1;

	printk(KERN_INFO "will send message to proc file\n");
	ret = copy_to_user(ubuf, lde_proc_msg, buf_len);
	*offp = buf_len;
	ret = buf_len;

TAG_RETURN:
	return ret;
}

static ssize_t lde_proc_write(struct file* file, const char __user* ubuf, size_t count, loff_t* offp) 
{
	ssize_t ret;
	char data[MAX_RECEIVE_BUFFER_LEN];
	cmds_index cmd_idx;

	printk(KERN_INFO "%s called legnth 0x%lx, 0x%px\n",
		__func__, count, ubuf);

	ret = count;
	global_lde_argv = NULL;
	if (count < 1) {
		printk(KERN_ERR "number of messages received is less than 1\n");
		ret = -EBADMSG;
		goto TAG_RETURN;
	}

	if (count > sizeof(data)) {
		printk(KERN_ERR "number of messages is too big\n");
		ret = -EFBIG;
		goto TAG_RETURN;
	}

	if (copy_from_user(data, ubuf, count)) {
		printk(KERN_ERR "cannot copy buffer from user\n");
		ret = -EFAULT;
		goto TAG_RETURN;
	}

	lde_proc_support_info_check();

	cmd_idx = SYSCALL_HACK;
	do {
		if (strncmp(data, my_cmds_support_info[cmd_idx].name, MAX_RECEIVE_BUFFER_LEN) == 0) {
			printk(KERN_INFO "match cmd [%s]\n", my_cmds_support_info[cmd_idx].name);

			my_cmds_support_info[cmd_idx].func();
			goto TAG_RETURN;
		}

		cmd_idx++;
	} while (cmd_idx < CMD_END);
	printk(KERN_WARNING "unknow cmd [%s]!\n", data);

TAG_RETURN:
	return ret;
}

#ifdef PROC_OPS_EXITS
static struct proc_ops lde_proc_ops = {
	.proc_read = lde_proc_read,
	.proc_write = lde_proc_write,
};
#else
static const struct file_operations lde_proc_ops = {
 .owner = THIS_MODULE,
 .read = lde_proc_read,
 .write = lde_proc_write,
};
#endif

int lde_proc_create(void)
{
	int ret;

	ret = SUCCEED;

	lde_proc_entry = proc_create("lde_proc", 0666, NULL, &lde_proc_ops);
	if (!lde_proc_entry) {
		printk(KERN_ERR "%s create proc entry failed\n", __func__);

		ret = PROC_CREATE_FAILED;
	}

	return ret;
}

void lde_proc_remove(void)
{
	if (lde_proc_entry == NULL) {
		printk(KERN_INFO "%s proc not exists\n", __func__);
		goto TAG_RETURN;
	}
	else {
		printk(KERN_INFO "%s proc will remove\n", __func__);
	}

	if (my_cmds_support_info != NULL) {
		kfree(&my_cmds_support_info);
	}

	if (lde_proc_msg != NULL) {
		kfree(lde_proc_msg);
	}

	proc_remove(lde_proc_entry);

TAG_RETURN:
	return;
}
