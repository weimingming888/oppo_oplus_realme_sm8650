obj-m := hello.o

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

ccflags-y := -DDEBUG -Wall

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

install:
	@echo "========================================="
	@echo "Loading hide_mount module..."
	@echo "========================================="
	sudo insmod hello.ko
	@echo ""
	@echo "Checking module status:"
	@lsmod | grep hello
	@echo ""
	@echo "Recent kernel messages:"
	@dmesg | tail -15
	@echo ""
	@echo "Testing if mounts are hidden:"
	@echo "--- /proc/self/mountinfo (should be empty) ---"
	@cat /proc/self/mountinfo | wc -l
	@echo "--- /proc/mounts (should be empty) ---"
	@cat /proc/mounts | wc -l

remove:
	@echo "Removing hide_mount module..."
	sudo rmmod hello
	@dmesg | tail -5

test:
	@echo "========================================="
	@echo "Testing hide_mount module"
	@echo "========================================="
	@echo ""
	@echo "1. Before loading module:"
	@echo "   mountinfo count: $$(cat /proc/self/mountinfo | wc -l)"
	@echo "   mounts count:    $$(cat /proc/mounts | wc -l)"
	@echo ""
	@echo "2. Loading module..."
	@sudo insmod hello.ko
	@echo ""
	@echo "3. After loading module:"
	@echo "   mountinfo count: $$(cat /proc/self/mountinfo | wc -l)"
	@echo "   mounts count:    $$(cat /proc/mounts | wc -l)"
	@echo ""
	@echo "4. Checking dmesg:"
	@dmesg | tail -10
	@echo ""
	@echo "5. Removing module..."
	@sudo rmmod hello
	@echo ""
	@echo "6. After removal:"
	@echo "   mountinfo count: $$(cat /proc/self/mountinfo | wc -l)"
	@echo "   mounts count:    $$(cat /proc/mounts | wc -l)"
	@echo "========================================="

debug:
	@echo "=== Debug Information ==="
	@echo "Kernel version: $(shell uname -r)"
	@echo ""
	@echo "Mount-related symbols:"
	@sudo cat /proc/kallsyms | grep -E 'mount.*show|show.*mount' | grep -v iio | head -20
	@echo ""
	@echo "Module info:"
	@modinfo hello.ko 2>/dev/null || echo "Module not built"

.PHONY: all clean install remove test debug