#ifndef _LDE_SYSTEM_CALL_H__

#define _LDE_SYSTEM_CALL_H__

void lde_syscall_hack(void);
void lde_syscall_revert(void);
void vsyscall_info_show(void);
void vdso_info_show(void);

#endif // _LDE_SYSTEM_CALL_H__
