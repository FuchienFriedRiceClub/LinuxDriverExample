#include "lde.h"
#include "init_sections.h"
#include "kallsyms.h"
#include <linux/init.h>
#include <asm/init.h>

typedef enum _init_sections_id {
	INIT_SETUP_START = 0,
	INIT_SETUP_END,
	INIT_CALL_START,
	INIT_CALL_0_START,
	INIT_CALL_1_START,
	INIT_CALL_2_START,
	INIT_CALL_3_START,
	INIT_CALL_4_START,
	INIT_CALL_5_START,
	INIT_CALL_6_START,
	INIT_CALL_7_START,
	INIT_CALL_END,
	INIT_SECTIONS_END,
} init_sections_id;

static const char* init_sections_name[] = {
	"__setup_start",
	"__setup_end",
	"__initcall_start",
	"__initcall0_start",
	"__initcall1_start",
	"__initcall2_start",
	"__initcall3_start",
	"__initcall4_start",
	"__initcall5_start",
	"__initcall6_start",
	"__initcall7_start",
	"__initcall_end",
};

void init_sections_info_show(void)
{
	init_sections_id initsec_idx;
	syms_list syms_info[INIT_SECTIONS_END];

	initsec_idx = INIT_SETUP_START;
	do {
		syms_info[initsec_idx].id = initsec_idx;
		syms_info[initsec_idx].sym_name = init_sections_name[initsec_idx];

		initsec_idx++;
	} while(initsec_idx < INIT_SECTIONS_END);

	kln_syms_addr_prt(syms_info, sizeof(syms_info) / sizeof(syms_list));

	printk(KERN_INFO ".init.xxx section already free\n");
}
