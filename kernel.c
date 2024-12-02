#include "lde.h"
#include "kallsyms.h"

unsigned long kernel_base_addr_get(void)
{
	return LDE_KLN_PTR(
#ifdef CONFIG_X86
	"_text"
#else
	"_stext"
#endif
	);
}
