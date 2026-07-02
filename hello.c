#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");

static struct kprobe kp_show;
static struct kprobe kp_stop;
static int stop_printed = 0;

/* map_seq_show: 每个 VMA 调用一次，只记录不打印 */
static void show_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
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
    
    /* 不打印，静默记录 */
}

/* map_seq_stop: 遍历结束，打印完整 buffer */
static void stop_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
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
    
    /* 只打印一次（避免多次读取时重复） */
    if (stop_printed)
        return;
    
    stop_printed = 1;
    
    printk(KERN_INFO "[MAPS] ========================================\n");
    printk(KERN_INFO "[MAPS] map_seq_stop called!\n");
    printk(KERN_INFO "[MAPS] Full buffer size: %lu bytes\n", m->count);
    printk(KERN_INFO "[MAPS] PID: %d (%s)\n", current->pid, current->comm);
    printk(KERN_INFO "[MAPS] ========================================\n");
    printk(KERN_INFO "[MAPS]\n%s", m->buf);
    printk(KERN_INFO "[MAPS] ========================================\n");
}

static int __init init(void)
{
    int ret;
    
    stop_printed = 0;
    
    /* Hook map_seq_show */
    memset(&kp_show, 0, sizeof(struct kprobe));
    kp_show.symbol_name = "map_seq_show";
    kp_show.post_handler = show_post_handler;
    
    ret = register_kprobe(&kp_show);
    if (ret < 0) {
        printk(KERN_ERR "[MAPS] ❌ Failed to hook map_seq_show\n");
        return ret;
    }
    printk(KERN_INFO "[MAPS] ✅ Hooked: map_seq_show\n");
    
    /* Hook map_seq_stop (关键！) */
    memset(&kp_stop, 0, sizeof(struct kprobe));
    kp_stop.symbol_name = "map_seq_stop";
    kp_stop.post_handler = stop_post_handler;
    
    ret = register_kprobe(&kp_stop);
    if (ret < 0) {
        printk(KERN_ERR "[MAPS] ❌ Failed to hook map_seq_stop\n");
        unregister_kprobe(&kp_show);
        return ret;
    }
    printk(KERN_INFO "[MAPS] ✅ Hooked: map_seq_stop\n");
    
    printk(KERN_INFO "[MAPS] ========================================\n");
    printk(KERN_INFO "[MAPS] Ready! Run: cat /proc/self/maps\n");
    printk(KERN_INFO "[MAPS] Full buffer will print at map_seq_stop\n");
    printk(KERN_INFO "[MAPS] ========================================\n");
    return 0;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp_show);
    unregister_kprobe(&kp_stop);
    printk(KERN_INFO "[MAPS] Unloaded\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");