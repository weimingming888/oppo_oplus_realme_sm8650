#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");

static struct kprobe kp;

static void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct seq_file *m;
    char *line_start, *line_end;
    char *p_anon;
    char line[512];
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
    
    /* 只取第一行 */
    line_end = memchr(m->buf, '\n', m->count);
    if (!line_end)
        return;
    
    len = (int)(line_end - m->buf);
    if (len > 511)
        len = 511;
    
    memcpy(line, m->buf, len);
    line[len] = '\0';
    
    /* 检查是否为匿名映射（地址范围后面没有文件路径） */
    p_anon = strstr(line, "00:00 0");
    
    if (p_anon) {
        /* 检查权限：r-xp 或 rwxp */
        if (strstr(line, "r-xp") || strstr(line, "rwxp")) {
            printk(KERN_INFO "[MAPS] %s\n", line);
        }
    }
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
        printk(KERN_ERR "[MAPS] Failed to register kprobe\n");
        return ret;
    }
    
    printk(KERN_INFO "[MAPS] Loaded, hook at %p\n", kp.addr);
    printk(KERN_INFO "[MAPS] Filter: anonymous r-xp and rwxp only\n");
    return 0;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "[MAPS] Unloaded\n");
}

module_init(init);
module_exit(exit);