#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>

static struct kprobe kp;

/* 直接清空，不做任何判断 */
static int pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    
#ifdef CONFIG_ARM64
    m = (struct seq_file *)regs->regs[0];
#else
    m = (struct seq_file *)regs->di;
#endif

    if (!m || !m->buf) return 0;
    
    /* 直接清空 */
    m->buf[0] = '\0';
    m->count = 0;
    
    return 0;
}

static int __init init(void)
{
    kp.pre_handler = pre_handler;
    kp.symbol_name = "show_mountinfo";
    
    if (register_kprobe(&kp) == 0) {
        pr_info("✅ mountinfo 已清空\n");
        return 0;
    }
    
    pr_err("注册失败\n");
    return -ENOENT;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    pr_info("✅ 已恢复\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");