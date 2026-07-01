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
    char line[512];
    int len;
    char *p_anon;
    int has_text = 0;
    int i;
    
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
    
    /* 检查是否为匿名映射：偏移量为 00000000，设备为 00:00，inode 为 0 */
    p_anon = strstr(line, "00:00 0");
    if (!p_anon)
        return;
    
    /* 检查权限：r-xp 或 rwxp */
    if (!strstr(line, "r-xp") && !strstr(line, "rwxp"))
        return;
    
    /* 检查行末尾是否有文字（非空格非制表符） */
    for (i = strlen(line) - 1; i >= 0; i--) {
        if (line[i] == ' ' || line[i] == '\t')
            continue;
        if (line[i] != '\0') {
            has_text = 1;  /* 末尾有文字 */
            break;
        }
    }
    
    /* 如果末尾有文字，放行（不打印） */
    if (has_text)
        return;
    
    /* 匿名 r-xp 或 rwxp，过滤掉并打印 */
    printk(KERN_INFO "[FILTERED] %s\n", line);
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
    printk(KERN_INFO "[MAPS] Rule: Filter anonymous r-xp/rwxp with no trailing text\n");
    return 0;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "[MAPS] Unloaded\n");
}

module_init(init);
module_exit(exit);