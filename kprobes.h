#ifndef __LDE_KPROBES_H__

#define __LDE_KPROBES_H__

#include <linux/kprobes.h>

extern char kp_sym[KSYM_NAME_LEN];
extern char retkp_sym[KSYM_NAME_LEN];
extern int kp_sym_offset;

typedef enum _kprobe_index {
	STACK_KPROBE_INFO = 0,
	KPROBE_END_TAG,
} kprobe_index;

extern struct kprobe lde_kp_info[KPROBE_END_TAG];
extern struct kretprobe lde_kretp_info[KPROBE_END_TAG];

unsigned long* lde_sym_addr_get_by_kprobes(struct kprobe* kp_info);
void lde_kprobe_register(struct kprobe* kp_info);
void lde_kretprobe_register(struct kretprobe* krp_info);
void lde_kprobes_unregister(void);

#endif // __LDE_KPROBES_H__
