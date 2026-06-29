#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>

static int __init init(void)
{
    unsigned long addr = (unsigned long)module_kallsyms_lookup_name("_printk");
    if (!addr) return -ENOENT;
    
    ((int (*)(const char *fmt, ...))addr)("成功找到地址: 0x%lx\n", addr);
    return 0;
}

static void __exit exit(void) {}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");