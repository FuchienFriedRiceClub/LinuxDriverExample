#include "lde.h"
#include "tasks.h"
#include "kallsyms.h"
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/auxvec.h>
#include <asm/page_64.h>
#include <asm/signal.h>

#define FIRST_AUV_ID			0
#define FIRST_AUV_VAL			1
#define SIGSET_WIDTH			(1024 / (8 * sizeof (unsigned long int)))

// echo xxxx | sudo tee -a /sys/module/lde/parameters/expected_pid
int expected_pid = -1;
module_param(expected_pid, int, 0644);

// echo -n "xxxx" | sudo tee -a /sys/module/lde/parameters/expected_pname
char expected_pname[PROCESS_NAME_MAX_LEN] = "wula!\0";
module_param_string(expected_pname, expected_pname, PROCESS_NAME_MAX_LEN, 0644);

lde_curr_task_get lde_curr_task = NULL;
unsigned long cpus_cnt = 0;

unsigned long online_cpus_cnt_get(void)
{
	cpus_cnt = 0;
	for_each_online_cpu(cpus_cnt);
	cpus_cnt = num_online_cpus();
	printk(KERN_INFO "online cpus count: %ld\n", cpus_cnt);

	return cpus_cnt;
}

void cpus_cur_task_get(void)
{
	if (!lde_curr_task) {
		lde_curr_task = (lde_curr_task_get)LDE_KLN_PTR("cpu_curr_snapshot");
	}
}

struct task_struct** all_cpus_cur_task_get(struct task_struct** tasks_list, int cpu_cnt)
{
	int i;
	
	cpus_cur_task_get();
	tasks_list = (struct task_struct**)kmalloc(
		sizeof(struct task_struct*) * cpu_cnt, GFP_KERNEL);
	if (!lde_curr_task || !tasks_list) {
		return NULL;
	}
	i = 0;
	do {
		tasks_list[i] = lde_curr_task(i);

		i++;
	} while (i < cpu_cnt);

	return tasks_list;
}

void task_max_size_get(void)
{
	unsigned long addr_max, addr_base;

	addr_max = TASK_SIZE_MAX;
	addr_base = ELF_ET_DYN_BASE;
	printk(KERN_INFO "task max size: 0x%lx ; base address: 0x%lx\n", addr_max, addr_base);
}

static void signal_simple_info_print(struct sigpending* signal_pending)
{
	int i;
	struct sigqueue* signal_info;

	i = 0;
	list_for_each_entry(signal_info, &signal_pending->list, list) {
		printk(KERN_INFO
			"\t\t%08d - signal num = %d ;\n",
			i, signal_info->info.si_signo
		);

		i++;
	}
}

void all_signal_simple_info_print(struct task_struct* task)
{
	printk(KERN_INFO "\tpending signal ->\n");
	signal_simple_info_print(&task->pending);
	printk(KERN_INFO "\tshared pending signal ->\n");
	signal_simple_info_print(&task->signal->shared_pending);
}

void task_simple_info_show(struct task_struct* task)
{
	printk(KERN_INFO
		"pid = %08d, name = %s: \n"
		"\tcanary: 0x%016lx, start_stack: 0x%016lx, vdso: 0x%016lx, \n"
		"\targ_start: 0x%016lx, arg_end: 0x%016lx, \n"
		"\tenv_start: 0x%016lx, env_end: 0x%016lx, \n"
		"\tauv id: 0x%04lx, auv value: 0x%016lx, \n"
		"\tstart_code: 0x%016lx, end_code: 0x%016lx. \n",
		task->pid, task->comm, task->stack_canary,
		task->mm ? task->mm->start_stack : 0x0,
		task->mm ? (unsigned long)task->mm->context.vdso : 0x0,
		task->mm ? task->mm->arg_start : 0x0, task->mm ? task->mm->arg_end : 0x0,
		task->mm ? task->mm->env_start : 0x0, task->mm ? task->mm->env_end : 0x0,
		task->mm ? task->mm->saved_auxv[FIRST_AUV_ID] : 0x0,
		task->mm ? task->mm->saved_auxv[FIRST_AUV_VAL] : 0x0,
		task->mm ? task->mm->start_code : 0x0,
		task->mm ? task->mm->end_code : 0x0
	);
}

static void task_cred_info_dump(struct task_struct* task)
{
	const struct cred* my_cred = my_cred = get_task_cred(task);
	printk(KERN_INFO
		"\tuid: %04d ; gid: %04d ; suid: %04d ; sgid: %04d ;\n"
		"\teuid: %04d ; egid %04d ; fsuid: %04d ; fsgid: %04d. \n",
		my_cred->uid.val, my_cred->gid.val,
		my_cred->suid.val, my_cred->sgid.val,
		my_cred->euid.val, my_cred->egid.val,
		my_cred->fsuid.val, my_cred->fsgid.val
	);
}

void tasks_list_show(void)
{
	struct list_head* task_site;
	struct task_struct* task;

	task_site = init_task.tasks.next;
	while (task_site != NULL && task_site != &init_task.tasks) {
		task = list_entry(task_site, struct task_struct, tasks);
		
		task_simple_info_show(task);
		all_signal_simple_info_print(task);
		task_cred_info_dump(task);

		task_site = task_site->next;
	}
}
