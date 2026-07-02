#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");

static struct kprobe kp;

static void post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct seq_file *m;
    
    (void)p;
    (void)flags;
    
#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#else
    m = NULL;
#endif
    
    if (!m || !m->buf || m->count == 0)
        return;
    
    /* 直接打印整个 buffer */
    printk(KERN_INFO "[MAPS] ========================================\n");
    printk(KERN_INFO "[MAPS] Buffer size: %lu bytes\n", m->count);
    printk(KERN_INFO "[MAPS] PID: %d (%s)\n", current->pid, current->comm);
    printk(KERN_INFO "[MAPS] ========================================\n");
    printk(KERN_INFO "[MAPS]\n%s", m->buf);
    printk(KERN_INFO "[MAPS] ========================================\n");
}

static int __init init(void)
{
    int ret;
    
    memset(&kp, 0, sizeof(struct kprobe));
    kp.symbol_name = "show_map";
    kp.post_handler = post_handler;
    
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "[MAPS] ❌ Failed to hook show_map\n");
        return ret;
    }
    
    printk(KERN_INFO "[MAPS] ✅ Hooked: show_map at %p\n", kp.addr);
    printk(KERN_INFO "[MAPS] Printing entire buffer\n");
    return 0;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "[MAPS] Unloaded\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");