#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>

#define MAX_HOOKS 5

static struct kprobe kp[MAX_HOOKS];
static int hook_count = 0;

/* 每次读取都清空 */
static int clear_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    
#ifdef CONFIG_ARM64
    m = (struct seq_file *)regs->regs[0];
#else
    m = (struct seq_file *)regs->di;
#endif

    if (!m || !m->buf) return 0;
    
    /* 每次调用都清空 */
    m->buf[0] = '\0';
    m->count = 0;
    
    return 0;
}

static int register_hooks(void)
{
    const char *symbols[] = {
        "show_mountinfo",   // /proc/self/mountinfo
        "mounts_show",      // /proc/mounts
        "seq_show_mounts",  // 备选
        NULL
    };
    
    int i;
    int success = 0;
    
    for (i = 0; symbols[i] != NULL && hook_count < MAX_HOOKS; i++) {
        kp[hook_count].pre_handler = clear_handler;
        kp[hook_count].symbol_name = symbols[i];
        
        if (register_kprobe(&kp[hook_count]) == 0) {
            pr_info("✅ %s 已清空\n", symbols[i]);
            hook_count++;
            success++;
        }
    }
    
    return success;
}

static int __init init(void)
{
    pr_info("=== 挂载表实时清空 ===\n");
    pr_info("⚠️  所有挂载表读取都将返回空\n");
    
    if (register_hooks() > 0) {
        pr_info("✅ 已启用 (%d 个钩子)\n", hook_count);
        return 0;
    }
    
    pr_err("注册失败\n");
    return -ENOENT;
}

static void __exit exit(void)
{
    int i;
    for (i = 0; i < hook_count; i++) {
        unregister_kprobe(&kp[i]);
    }
    pr_info("✅ 已恢复\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");