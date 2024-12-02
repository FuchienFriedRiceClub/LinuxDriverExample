WFLAGS := -Wall
LDFLAGS = -Map /var/tmp/lde_map.txt
EXTRA_CFLAGS := $(WFLAGS)
EXTRA_CFLAGS += -D_DEBUG

MODULE = lde
$(MODULE)-objs := main.o procfs.o syscall.o \
					idt.o kprobes.o kallsyms.o \
					init_sections.o tasks.o stack.o \
					fs.o exec.o kernel.o
obj-m := $(MODULE).o

all: MoudleBuild

MoudleBuild:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
