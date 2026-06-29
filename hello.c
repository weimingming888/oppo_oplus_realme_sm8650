#include <linux/module.h>
#include <linux/kprobes.h>

static struct kprobe kp;

/* 拦截挂载表显示函数，返回空 */
static int pre_show(struct kprobe *p, struct pt_regs *regs)
{
    /* 跳过原函数，输出为空 */
    return 1;
}

static int __init init(void)
{
    /* 尝试多个可能的函数名 */
    const char *symbols[] = {
        "show_mountinfo",      // /proc/self/mountinfo
        "mounts_show",         // /proc/mounts
        "seq_show_mounts",     // 通用
        "show_mounts",
        "mountinfo_show",
        NULL
    };
    
    for (int i = 0; symbols[i] != NULL; i++) {
        kp.pre_handler = pre_show;
        kp.symbol_name = symbols[i];
        
        if (register_kprobe(&kp) == 0) {
            pr_info("✅ 隐藏: %s\n", symbols[i]);
            return 0;
        }
    }
    
    pr_err("找不到挂载表显示函数\n");
    return -ENOENT;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    pr_info("✅ 挂载表已恢复\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");