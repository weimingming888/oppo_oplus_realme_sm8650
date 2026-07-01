#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kprobe Address Finder");
MODULE_DESCRIPTION("Get kallsyms_lookup_name address via kprobe");

/* ---------- kprobe 结构 ---------- */
static struct kprobe kp_kallsyms_lookup_name;

/* ---------- 空 handler（不需要做任何事） ---------- */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

/* ---------- 模块初始化 ---------- */
static int __init finder_init(void)
{
    int ret;
    unsigned long addr;

    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "Getting kallsyms_lookup_name address\n");
    printk(KERN_INFO "via kprobe\n");
    printk(KERN_INFO "========================================\n");

    /* 清空 kprobe 结构 */
    memset(&kp_kallsyms_lookup_name, 0, sizeof(struct kprobe));

    /* 设置要查找的符号名 */
    kp_kallsyms_lookup_name.symbol_name = "kallsyms_lookup_name";
    kp_kallsyms_lookup_name.pre_handler = handler_pre;

    /* 注册 kprobe */
    ret = register_kprobe(&kp_kallsyms_lookup_name);
    if (ret < 0) {
        printk(KERN_ERR "❌ Failed to register kprobe: %d\n", ret);
        printk(KERN_ERR "   Symbol 'kallsyms_lookup_name' not found\n");
        return ret;
    }

    /* 获取地址 */
    addr = (unsigned long)kp_kallsyms_lookup_name.addr;

    printk(KERN_INFO "✅ SUCCESS!\n");
    printk(KERN_INFO "   kallsyms_lookup_name = 0x%lx\n", addr);
    printk(KERN_INFO "========================================\n");

    return 0;
}

/* ---------- 模块退出 ---------- */
static void __exit finder_exit(void)
{
    unregister_kprobe(&kp_kallsyms_lookup_name);
    printk(KERN_INFO "Finder module unloaded\n");
}

module_init(finder_init);
module_exit(finder_exit);