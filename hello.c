#include <linux/module.h>
#include <linux/kprobes.h>

static struct kprobe kp;

/* 直接清空 mountinfo */
static int pre_show_mountinfo(struct kprobe *p, struct pt_regs *regs)
{
    return 1;  /* 跳过原函数，输出为空 */
}

static int __init init(void)
{
    kp.pre_handler = pre_show_mountinfo;
    kp.symbol_name = "show_mountinfo";
    
    if (register_kprobe(&kp) == 0) {
        pr_info("✅ /proc/self/mountinfo 已清空\n");
        return 0;
    }
    
    pr_err("注册失败\n");
    return -ENOENT;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    pr_info("✅ /proc/self/mountinfo 已恢复\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");