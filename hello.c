#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");

static struct kprobe kp;

/* pre_handler: 返回 1 表示跳过原函数 */
static int pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    
    (void)p;
    
#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#else
    m = NULL;
#endif
    
    if (!m)
        return 0;
    
    /* 清空 buffer */
    m->count = 0;
    if (m->buf && m->size > 0) {
        memset(m->buf, 0, m->size);
    }
    
    /* 返回 1 跳过原函数，直接返回用户空间 */
    return 1;
}

static int __init init(void)
{
    int ret;
    const char *symbols[] = {
        "show_map_vma",
        "proc_pid_maps_show",
        "seq_show_map_vma",
        "maps_show",
        "show_map",
        NULL
    };
    int i;
    
    for (i = 0; symbols[i] != NULL; i++) {
        memset(&kp, 0, sizeof(struct kprobe));
        kp.symbol_name = symbols[i];
        kp.pre_handler = pre_handler;
        
        ret = register_kprobe(&kp);
        if (ret == 0) {
            printk(KERN_INFO "[MAPS] ✅ Hooked: %s\n", symbols[i]);
            printk(KERN_INFO "[MAPS] Skipping original function, returning empty\n");
            return 0;
        }
    }
    
    printk(KERN_ERR "[MAPS] ❌ Failed to register kprobe\n");
    return -1;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "[MAPS] Unloaded\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");