#include "lde.h"
#include "idt.h"
#include "kallsyms.h"
#include <asm/desc_defs.h>

static struct gate_struct* idt_table[IDT_ENTRIES];

void idt_info_show(void)
{
	int i;
	struct desc_ptr* idt_desc;
	unsigned long sym_addr;

	idt_desc = (struct desc_ptr*)LDE_KLN_PTR("idt_descr");
	*idt_table = (struct gate_struct*)LDE_KLN_PTR("idt_table");
	if (!idt_desc || !*idt_table) {
		printk(KERN_ERR "unable to find symbol by [kallsyms_lookup_name], will exit ...\n");
		return;
	}
	else {
		printk(KERN_INFO "found symbol, idt_desc: 0x%px, idt_table: 0x%px\n", idt_desc, *idt_table);
	}

	for (i = 0; i < IDT_ENTRIES; i++) {
		sym_addr = (*idt_table)[i].offset_low | ((*idt_table)[i].offset_middle << 16) | ((unsigned long)(*idt_table)[i].offset_high << 32);
		printk(KERN_INFO "%02x: 0x%04x:0x%04x 0x%02x:0x%02x:0x%02x:0x%02x:0x%02x 0x%lx %pS\n",
			i, (*idt_table)[i].segment, (*idt_table)[i].offset_low,
			(*idt_table)[i].bits.ist, (*idt_table)[i].bits.zero, (*idt_table)[i].bits.type,
			(*idt_table)[i].bits.dpl, (*idt_table)[i].bits.p, sym_addr, (unsigned long*)sym_addr);
	}
}
