obj-m += hello.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=arm64 LLVM=1 LLVM_IAS=1 modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
