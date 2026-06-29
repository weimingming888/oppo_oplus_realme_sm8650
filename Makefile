obj-m += hello.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# 编译选项：关闭未使用变量警告
ccflags-y += -Wno-unused-variable

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean