#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/dcache.h>

static struct kprobe kp_show_map_vma;
static int line_count = 0;

static void post_show_map_vma(struct kprobe *kp, struct pt_regs *regs, 
                               unsigned long flags)
{
    struct seq_file *m = NULL;
    char *buf;
    char *line_start, *line_end;
    unsigned long count, pos;
    char line[512];
    int len;
    
    (void)kp;
    (void)flags;
    
#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#elif defined(CONFIG_ARM)
    m = (struct seq_file *)regs->ARM_r0;
#else
    m = NULL;
#endif
    
    if (!m || !m->buf || m->count == 0)
        return;
    
    buf = m->buf;
    count = m->count;
    pos = 0;
    
    /* 逐行打印所有内容 */
    while (pos < count) {
        line_end = memchr(buf + pos, '\n', count - pos);
        if (!line_end)
            break;
            
        line_start = buf + pos;
        pos = (unsigned long)(line_end - buf) + 1;
        
        len = (int)(pos - (unsigned long)(line_start - buf));
        if (len > 511) 
            len = 511;
            
        memcpy(line, line_start, len);
        line[len] = '\0';
        
        if (len > 0 && line[len-1] == '\n')
            line[len-1] = '\0';
        
        line_count++;
        printk(KERN_INFO "[MAP_DBG] %s\n", line);
    }
}

static int mapdbg_init(void)
{
    int ret;
    const char *symbols[] = {
        "show_map_vma",
        "seq_show_map_vma",
        "proc_pid_maps_show",
        "show_map",
        NULL
    };
    int i;

    printk(KERN_INFO "[MAP_DBG] ========================================\n");
    printk(KERN_INFO "[MAP_DBG] VMA Debug Module Loaded\n");
    printk(KERN_INFO "[MAP_DBG] Output all /proc/pid/maps content\n");
    printk(KERN_INFO "[MAP_DBG] ========================================\n");

    memset(&kp_show_map_vma, 0, sizeof(struct kprobe));
    kp_show_map_vma.post_handler = post_show_map_vma;

    for (i = 0; symbols[i] != NULL; i++) {
        kp_show_map_vma.symbol_name = symbols[i];
        ret = register_kprobe(&kp_show_map_vma);
        if (ret == 0) {
            printk(KERN_INFO "[MAP_DBG] ✅ Hooked: %s at %p\n", 
                   symbols[i], kp_show_map_vma.addr);
            printk(KERN_INFO "[MAP_DBG] ========================================\n");
            printk(KERN_INFO "[MAP_DBG] Run: dmesg -w | grep '[MAP_DBG]'\n");
            printk(KERN_INFO "[MAP_DBG] Or: cat /proc/self/maps to trigger\n");
            printk(KERN_INFO "[MAP_DBG] ========================================\n");
            return 0;
        }
    }

    printk(KERN_ERR "[MAP_DBG] ❌ Failed to register kprobe\n");
    return -ENOENT;
}

static void mapdbg_exit(void)
{
    unregister_kprobe(&kp_show_map_vma);
    printk(KERN_INFO "[MAP_DBG] ========================================\n");
    printk(KERN_INFO "[MAP_DBG] Module unloaded\n");
    printk(KERN_INFO "[MAP_DBG] Total lines printed: %d\n", line_count);
    printk(KERN_INFO "[MAP_DBG] ========================================\n");
}

module_init(mapdbg_init);
module_exit(mapdbg_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Print all /proc/pid/maps content");