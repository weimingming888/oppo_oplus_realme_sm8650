#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kprobe Symbol Resolver");
MODULE_DESCRIPTION("Resolve common kernel symbols via kprobe");

/* ---------- 要解析的符号列表 ---------- */
static const char *symbols[] = {
    /* 挂载相关 */
    "show_vfsmnt",
    "show_mountinfo",
    "m_show",
    "mounts_show",
    "mountinfo_show",
    
    /* seq_file 相关 */
    "seq_read",
    "seq_printf",
    "seq_puts",
    "seq_putc",
    "proc_reg_read",
    "proc_reg_write",
    "proc_reg_open",
    "proc_reg_release",
    
    /* 文件操作相关 */
    "filp_open",
    "do_sys_open",
    "vfs_read",
    "vfs_write",
    "vfs_open",
    "filp_close",
    
    /* kallsyms 相关 */
    "kallsyms_lookup_name",
    "kallsyms_on_each_symbol",
    "kallsyms_lookup",
    
    /* 系统调用相关 */
    "sys_open",
    "sys_read",
    "sys_write",
    "sys_close",
    "sys_mount",
    "sys_umount",
    
    /* kprobe 相关 */
    "register_kprobe",
    "unregister_kprobe",
    
    /* 进程/任务相关 */
    "do_exit",
    "do_fork",
    "kernel_thread",
    
    /* 内存相关 */
    "kmalloc",
    "kfree",
    "vmalloc",
    "vfree",
    "__get_free_pages",
    "free_pages",
    
    /* 调度相关 */
    "schedule",
    "schedule_timeout",
    
    /* 中断相关 */
    "request_irq",
    "free_irq",
    "enable_irq",
    "disable_irq",
    
    /* 时间相关 */
    "jiffies",
    "do_gettimeofday",
    "ktime_get",
    
    /* 其它常用 */
    "printk",
    "sprintf",
    "snprintf",
    "strcmp",
    "strcpy",
    "strlen",
    "memcpy",
    "memset",
    "memcmp",
    
    NULL  /* 结束标记 */
};

/* ---------- 获取符号地址 ---------- */
static unsigned long get_symbol_addr(const char *name)
{
    struct kprobe kp;
    unsigned long addr = 0;
    int ret;
    
    memset(&kp, 0, sizeof(struct kprobe));
    kp.symbol_name = name;
    kp.pre_handler = NULL;
    kp.post_handler = NULL;
    
    ret = register_kprobe(&kp);
    if (ret == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    
    return addr;
}

/* ---------- 打印结果（带对齐） ---------- */
static void print_symbol(const char *name, unsigned long addr)
{
    if (addr) {
        printk(KERN_INFO "  ✅ %-30s = 0x%lx\n", name, addr);
    } else {
        printk(KERN_INFO "  ❌ %-30s = NOT FOUND\n", name);
    }
}

/* ---------- 模块初始化 ---------- */
static int __init resolver_init(void)
{
    int i;
    unsigned long addr;
    int found = 0;
    int not_found = 0;
    
    printk(KERN_INFO "\n");
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "Kernel Symbol Resolver via Kprobe\n");
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "\n");
    printk(KERN_INFO "Resolving %d symbols...\n", 
           sizeof(symbols) / sizeof(symbols[0]) - 1);
    printk(KERN_INFO "\n");
    
    /* 遍历所有符号 */
    for (i = 0; symbols[i] != NULL; i++) {
        addr = get_symbol_addr(symbols[i]);
        print_symbol(symbols[i], addr);
        
        if (addr)
            found++;
        else
            not_found++;
    }
    
    printk(KERN_INFO "\n");
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "Summary: %d found, %d not found\n", found, not_found);
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "\n");
    
    return 0;
}

/* ---------- 模块退出 ---------- */
static void __exit resolver_exit(void)
{
    printk(KERN_INFO "Symbol resolver module unloaded\n");
}

module_init(resolver_init);
module_exit(resolver_exit);