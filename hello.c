#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");

static struct kprobe kp_show_map;
static unsigned long g_show_map_addr;

/* ---------- 获取符号地址 ---------- */
static unsigned long get_symbol_addr(const char *name)
{
    struct kprobe kp;
    unsigned long addr = 0;
    int ret;
    
    memset(&kp, 0, sizeof(struct kprobe));
    kp.symbol_name = name;
    
    ret = register_kprobe(&kp);
    if (ret == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
        printk(KERN_INFO "[Filter] ✅ %s = 0x%lx\n", name, addr);
    }
    return addr;
}

/* ---------- show_map post_handler ---------- */
static void show_map_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct seq_file *m;
    char *buf, *src, *dst, *line_start, *line_end;
    unsigned long count, src_pos, dst_pos, remaining, line_len;
    int hidden = 0;
    int line_num = 0;
    char line_copy[256];
    int copy_len;
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
    
    if (!m || !m->buf || m->count == 0) return;
    
    printk(KERN_INFO "[Filter] ========== MAPS DUMP START ==========\n");
    printk(KERN_INFO "[Filter] PID=%d (%s), count=%lu\n", 
           current->pid, current->comm, m->count);
    
    buf = m->buf;
    count = m->count;
    src = buf;
    dst = buf;
    src_pos = 0;
    dst_pos = 0;
    
    while (src_pos < count) {
        remaining = count - src_pos;
        line_end = memchr(src + src_pos, '\n', remaining);
        
        if (!line_end) {
            line_start = src + src_pos;
            line_len = remaining;
            line_num++;
            
            copy_len = (line_len < 255) ? line_len : 255;
            for (i = 0; i < copy_len; i++) {
                line_copy[i] = line_start[i];
            }
            line_copy[copy_len] = '\0';
            
            printk(KERN_INFO "[Filter] LINE %d: %s\n", line_num, line_copy);
            
            if (strstr(line_start, "[vdso]") != NULL) {
                printk(KERN_INFO "[Filter] ✅ KEEP (vdso)\n");
                if (dst_pos != src_pos) memmove(dst + dst_pos, line_start, line_len);
                dst_pos += line_len;
                src_pos = count;
                break;
            }
            
            if (strstr(line_start, "rwxp") != NULL) {
                hidden++;
                printk(KERN_INFO "[Filter] ❌ HIDE (rwxp)\n");
            } else {
                printk(KERN_INFO "[Filter] ✅ KEEP\n");
                if (dst_pos != src_pos) memmove(dst + dst_pos, line_start, line_len);
                dst_pos += line_len;
            }
            src_pos = count;
            break;
        }
        
        line_start = src + src_pos;
        line_len = (unsigned long)(line_end - line_start) + 1;
        line_num++;
        
        copy_len = (line_len < 255) ? line_len : 255;
        for (i = 0; i < copy_len; i++) {
            line_copy[i] = line_start[i];
        }
        line_copy[copy_len] = '\0';
        
        printk(KERN_INFO "[Filter] LINE %d: %s\n", line_num, line_copy);
        
        if (strstr(line_start, "[vdso]") != NULL) {
            printk(KERN_INFO "[Filter] ✅ KEEP (vdso)\n");
            if (dst_pos != src_pos) memmove(dst + dst_pos, line_start, line_len);
            dst_pos += line_len;
            src_pos += line_len;
            continue;
        }
        
        if (strstr(line_start, "rwxp") != NULL) {
            hidden++;
            printk(KERN_INFO "[Filter] ❌ HIDE (rwxp)\n");
        } else {
            printk(KERN_INFO "[Filter] ✅ KEEP\n");
            if (dst_pos != src_pos) memmove(dst + dst_pos, line_start, line_len);
            dst_pos += line_len;
        }
        src_pos += line_len;
    }
    
    printk(KERN_INFO "[Filter] Total lines: %d, Hidden: %d\n", line_num, hidden);
    printk(KERN_INFO "[Filter] ========== MAPS DUMP END ==========\n");
    
    m->count = dst_pos;
    if (m->count < m->size) {
        m->buf[m->count] = '\0';
    }
}

/* ---------- 模块初始化 ---------- */
static int __init filter_init(void)
{
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] DEBUG: rwxp filter with line dump\n");
    printk(KERN_INFO "========================================\n");
    
    g_show_map_addr = get_symbol_addr("show_map");
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("show_map_vma");
    }
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("proc_pid_maps_show");
    }
    
    if (!g_show_map_addr) {
        printk(KERN_ERR "[Filter] ❌ show_map not found!\n");
        return -ENOENT;
    }
    
    memset(&kp_show_map, 0, sizeof(struct kprobe));
    kp_show_map.addr = (void *)g_show_map_addr;
    kp_show_map.post_handler = show_map_post_handler;
    
    if (register_kprobe(&kp_show_map) == 0) {
        printk(KERN_INFO "[Filter] ✅ Hook registered\n");
        printk(KERN_INFO "[Filter] Open any app to see maps dump\n");
        return 0;
    }
    
    return -EINVAL;
}

/* ---------- 模块退出 ---------- */
static void __exit filter_exit(void)
{
    unregister_kprobe(&kp_show_map);
    printk(KERN_INFO "[Filter] Unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);