#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");

/* ---------- 你提供的地址 ---------- */
#define KALLSYMS_LOOKUP_NAME_ADDR 0xffffffdbb6bc1164

/* 声明函数指针类型 */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

/* ---------- 初始化 ---------- */
static int __init test_init(void)
{
    kallsyms_lookup_name_t my_kallsyms_lookup_name;
    unsigned long addr;
    
    /* 将地址转换为函数指针 */
    my_kallsyms_lookup_name = (kallsyms_lookup_name_t)KALLSYMS_LOOKUP_NAME_ADDR;
    
    printk(KERN_INFO "Testing kallsyms_lookup_name at 0x%lx\n", 
           KALLSYMS_LOOKUP_NAME_ADDR);
    
    /* 测试查找一个已知符号（比如 filp_open） */
    addr = my_kallsyms_lookup_name("filp_open");
    if (addr) {
        printk(KERN_INFO "SUCCESS! filp_open = 0x%lx\n", addr);
    } else {
        printk(KERN_ERR "FAILED! kallsyms_lookup_name returned 0\n");
        return -EINVAL;
    }
    
    /* 再测试查找另一个符号 */
    addr = my_kallsyms_lookup_name("do_sys_open");
    if (addr) {
        printk(KERN_INFO "do_sys_open = 0x%lx\n", addr);
    } else {
        printk(KERN_WARNING "do_sys_open not found (可能不存在或未导出)\n");
    }
    
    /* 测试查找不存在的符号（应返回 0） */
    addr = my_kallsyms_lookup_name("nonexistent_symbol_xyz");
    if (addr == 0) {
        printk(KERN_INFO "Correctly returned 0 for nonexistent symbol\n");
    }
    
    return 0;
}

/* ---------- 退出 ---------- */
static void __exit test_exit(void)
{
    printk(KERN_INFO "Test module unloaded\n");
}

module_init(test_init);
module_exit(test_exit);