ifeq ($(KERNELRELEASE), )
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: build clean

build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
else
$(info Building with KERNELRELEASE = ${KERNELRELEASE})
obj-m := isecfirewall.o
isecfirewall-objs := isecfw.o isecfw_proc.o isecfw_dev.o isecfw_netfilter.o isecfw_rule.o 

endif
