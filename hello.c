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
    char *buf;
    unsigned long count;
    char line[256];
    char *line_start, *line_end;
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
    
    buf = m->buf;
    count = m->count;
    
    /* ====== 打印 buffer 内容 ====== */
    printk(KERN_INFO "[MAPS] ========================================\n");
    printk(KERN_INFO "[MAPS] Buffer size: %lu bytes\n", count);
    printk(KERN_INFO "[MAPS] PID: %d (%s)\n", current->pid, current->comm);
    printk(KERN_INFO "[MAPS] ========================================\n");
    
    /* 逐行打印 */
    unsigned long pos = 0;
    int line_num = 0;
    
    while (pos < count) {
        line_end = memchr(buf + pos, '\n', count - pos);
        if (!line_end)
            break;
        
        line_start = buf + pos;
        pos = (unsigned long)(line_end - buf) + 1;
        
        len = (int)(pos - (unsigned long)(line_start - buf));
        if (len > 255)
            len = 255;
        
        memcpy(line, line_start, len);
        line[len] = '\0';
        if (len > 0 && line[len-1] == '\n')
            line[len-1] = '\0';
        
        line_num++;
        printk(KERN_INFO "[MAPS] %d: %s\n", line_num, line);
    }
    
    printk(KERN_INFO "[MAPS] ========================================\n");
    printk(KERN_INFO "[MAPS] Total lines: %d\n", line_num);
    printk(KERN_INFO "[MAPS] ========================================\n");
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
        kp.post_handler = post_handler;
        
        ret = register_kprobe(&kp);
        if (ret == 0) {
            printk(KERN_INFO "[MAPS] ✅ Hooked: %s\n", symbols[i]);
            printk(KERN_INFO "[MAPS] Printing buffer content\n");
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