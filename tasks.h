#ifndef __LDE_TASKS_H__

#define __LDE_TASKS_H__

#define PROCESS_NAME_MAX_LEN	0x100

typedef void (*lde_dump_cpu_task)(int cpu);
typedef struct task_struct* (*lde_curr_task_get)(int cpu);

extern pid_t expected_pid;
extern char expected_pname[PROCESS_NAME_MAX_LEN];
extern lde_curr_task_get lde_curr_task;
extern unsigned long cpus_cnt;

void tasks_list_show(void);
void task_max_size_get(void);
unsigned long online_cpus_cnt_get(void);
void task_simple_info_show(struct task_struct* task);
void all_signal_simple_info_print(struct task_struct* task);
struct task_struct** all_cpus_cur_task_get(struct task_struct** tasks_list, int cpu_cnt);
void cpus_cur_task_get(void);

#endif // __LDE_TASKS_H__
