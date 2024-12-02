#ifndef __LDE_KALLSYMS_H__

#define __LDE_KALLSYMS_H__

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
#define KALLSYMS_EXIST
#include <linux/kallsyms.h>
#endif

#ifdef KALLSYMS_EXIST
#define LDE_KLN_PTR				kallsyms_lookup_name
#else
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
extern kallsyms_lookup_name_t	kallsyms_lookup_name_ptr;
#define LDE_KLN_PTR				kallsyms_lookup_name_ptr
#endif

typedef struct _syms_list {
	int id;
	const char* sym_name;
} syms_list;

void lde_kln_ptr_set(void);
void kln_syms_addr_prt(syms_list* syms_info, int count);

#endif // __LDE_KALLSYMS_H__
