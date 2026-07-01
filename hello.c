#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Symbol Export Tester");
MODULE_DESCRIPTION("Test if kallsyms_on_each_symbol is exported");

/* 回调函数：遍历符号时被调用 */
static int symbol_callback(void *data, const char *symname, 
                           struct module *mod, unsigned long addr)
{
    /* 只打印前 5 个符号，避免刷屏 */
    static int count = 0;
    if (count++ < 5) {
        printk(KERN_INFO "  Symbol: %s at 0x%lx\n", symname, addr);
    }
    return 0;
}

/* ---------- 模块初始化 ---------- */
static int __init test_init(void)
{
    int ret;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "Testing kallsyms_on_each_symbol\n");
    printk(KERN_INFO "========================================\n");
    
    /* 尝试调用 kallsyms_on_each_symbol */
    ret = kallsyms_on_each_symbol(symbol_callback, NULL);
    
    if (ret == 0) {
        printk(KERN_INFO "✅ SUCCESS! kallsyms_on_each_symbol is EXPORTED\n");
        printk(KERN_INFO "   The function works and returned 0\n");
        printk(KERN_INFO "========================================\n");
        return 0;
    } else {
        printk(KERN_INFO "⚠️  kallsyms_on_each_symbol returned: %d\n", ret);
        printk(KERN_INFO "   (May still be exported but returned error)\n");
        printk(KERN_INFO "========================================\n");
        return 0;
    }
}

/* ---------- 模块退出 ---------- */
static void __exit test_exit(void)
{
    printk(KERN_INFO "Test module unloaded\n");
}

module_init(test_init);
module_exit(test_exit);