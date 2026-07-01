#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");

static struct kprobe kp;

/* post_handler: 在 show_map_vma 执行后调用 */
static void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct seq_file *m;
    
    (void)p;
    (void)flags;
    
    /* ARM64: 第一个参数在 x0 */
#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#else
    m = NULL;
#endif
    
    if (!m || !m->buf || m->count == 0)
        return;
    
    /* 直接打印 buffer 内容 */
    printk(KERN_INFO "[MAPS] %.*s", (int)m->count, m->buf);
}

static int __init init(void)
{
    int ret;
    
    kp.symbol_name = "show_map_vma";
    kp.post_handler = handler_post;
    
    ret = register_kprobe(&kp);
    if (ret < 0) {
        /* 试试其他符号名 */
        kp.symbol_name = "proc_pid_maps_show";
        ret = register_kprobe(&kp);
    }
    if (ret < 0) {
        kp.symbol_name = "seq_show_map_vma";
        ret = register_kprobe(&kp);
    }
    if (ret < 0) {
        printk(KERN_ERR "[MAPS] Failed to register kprobe\n");
        return ret;
    }
    
    printk(KERN_INFO "[MAPS] Loaded, hook at %p\n", kp.addr);
    return 0;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "[MAPS] Unloaded\n");
}

module_init(init);
module_exit(exit);