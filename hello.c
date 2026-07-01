#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");

static struct kprobe kp;

static void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct seq_file *m;
    char *line_start, *line_end;
    char line[256];
    int len;
    
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
    
    /* 只取第一行（maps 格式） */
    line_end = memchr(m->buf, '\n', m->count);
    if (!line_end)
        return;
    
    len = (int)(line_end - m->buf);
    if (len > 255)
        len = 255;
    
    memcpy(line, m->buf, len);
    line[len] = '\0';
    
    printk(KERN_INFO "[MAPS] %s\n", line);
}

static int __init init(void)
{
    int ret;
    
    kp.symbol_name = "show_map_vma";
    kp.post_handler = handler_post;
    
    ret = register_kprobe(&kp);
    if (ret < 0) {
        kp.symbol_name = "proc_pid_maps_show";
        ret = register_kprobe(&kp);
    }
    if (ret < 0) {
        kp.symbol_name = "seq_show_map_vma";
        ret = register_kprobe(&kp);
    }
    if (ret < 0) {
        printk(KERN_ERR "[MAPS] register failed\n");
        return ret;
    }
    
    printk(KERN_INFO "[MAPS] Loaded\n");
    return 0;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "[MAPS] Unloaded\n");
}

module_init(init);
module_exit(exit);