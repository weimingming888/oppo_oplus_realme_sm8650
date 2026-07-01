obj-m += hello.o

# Android 内核构建路径（从你的错误日志中看到的）
KDIR := /home/runner/work/oppo_oplus_realme_sm8650/oppo_oplus_realme_sm8650/kernel_workspace/common/out

PWD := $(shell pwd)

# 编译选项：关闭未使用变量警告
ccflags-y += -Wno-unused-variable
ccflags-y += -Wno-error=unused-variable

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean