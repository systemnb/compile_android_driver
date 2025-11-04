obj-m := android-paradise.o

android-paradise-objs += entry.o

ifeq ($(KDIR),)
$(error KDIR is not set. Please run 'make KDIR=<path-to-kernel-source>')
endif

MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function -Wno-unused-variable

all:
	$(MAKE) -C $(KDIR) M=$(MDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(MDIR) clean