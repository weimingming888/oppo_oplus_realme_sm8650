#include <linux/module.h>
#include <linux/kprobes.h>

static struct kprobe kp;

static int pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    pr_info("🔍 拦截到: %s\n", p->symbol_name);
    return 0;
}

static int __init init(void)
{
    const char *symbols[] = {
        "show_mountinfo",
        "mounts_show",
        "seq_show_mounts",
        "show_mounts",
        "mountinfo_show",
        "proc_mounts_show",
        "show_vfsmnt",
        "seq_show",
        NULL
    };
    
    int i;
    for (i = 0; symbols[i] != NULL; i++) {
        kp.pre_handler = pre_handler;
        kp.symbol_name = symbols[i];
        
        if (register_kprobe(&kp) == 0) {
            pr_info("✅ 拦截: %s\n", symbols[i]);
            return 0;
        }
    }
    
    pr_err("没有找到可拦截的函数\n");
    return -ENOENT;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");