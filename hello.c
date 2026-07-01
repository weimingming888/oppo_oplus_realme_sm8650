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

static unsigned long get_symbol_addr(const char *name)
{
    struct kprobe kp;
    unsigned long addr = 0;
    int ret;
    
    memset(&kp, 0, sizeof(struct kprobe));
    kp.symbol_name = name;
    kp.pre_handler = NULL;
    kp.post_handler = NULL;
    
    ret = register_kprobe(&kp);
    if (ret == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
        printk(KERN_INFO "[Filter] ✅ %s = 0x%lx\n", name, addr);
    } else {
        printk(KERN_WARNING "[Filter] ❌ %s NOT FOUND (err=%d)\n", name, ret);
    }
    return addr;
}

static int is_target_process(void)
{
    struct task_struct *task = current;
    if (!task) return 0;
    
    if (strstr(task->comm, "duckdetector") ||
        strstr(task->comm, "eltavine") ||
        strstr(task->comm, "DefaultDispatch") ||
        strstr(task->comm, "DuckDetector")) {
        return 1;
    }
    return 0;
}

static int should_hide_line(const char *line, unsigned long len)
{
    (void)len;
    
    if (strstr(line, "r-xp 00000000") == NULL) {
        return 0;
    }
    
    if (strstr(line, "[vdso]") != NULL) {
        return 0;
    }
    
    if (strstr(line, "/") != NULL) {
        return 0;
    }
    
    return 1;
}

static void filter_maps_lines(struct seq_file *m)
{
    char *buf, *src, *dst, *line_start, *line_end;
    unsigned long count, src_pos, dst_pos, remaining, line_len;
    int hidden_count = 0;
    
    if (!m || !m->buf || m->count == 0) return;
    
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
            
            if (!should_hide_line(line_start, line_len)) {
                if (dst_pos != src_pos) {
                    memmove(dst + dst_pos, line_start, line_len);
                }
                dst_pos += line_len;
            } else {
                hidden_count++;
            }
            src_pos = count;
            break;
        }
        
        line_start = src + src_pos;
        line_len = (unsigned long)(line_end - line_start) + 1;
        
        if (!should_hide_line(line_start, line_len)) {
            if (dst_pos != src_pos) {
                memmove(dst + dst_pos, line_start, line_len);
            }
            dst_pos += line_len;
        } else {
            hidden_count++;
        }
        src_pos += line_len;
    }
    
    if (hidden_count > 0) {
        printk(KERN_INFO "[Filter] 🧹 Hidden %d lines for PID=%d (%s)\n",
               hidden_count, current->pid, current->comm);
    }
    
    m->count = dst_pos;
    if (m->count < m->size) {
        m->buf[m->count] = '\0';
    }
}

/* ---------- show_map post_handler ---------- */
static void show_map_post_handler(struct kprobe *p, struct pt_regs *regs,
                                  unsigned long flags)
{
    struct seq_file *m;
    
    (void)p;
    (void)flags;
    
    if (!is_target_process()) {
        return;
    }
    
#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#else
    m = NULL;
#endif
    
    if (!m) {
        return;
    }
    
    filter_maps_lines(m);
}

static int __init filter_init(void)
{
    int ret;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] DuckDetector maps filter\n");
    printk(KERN_INFO "[Filter] Hooking: show_map (not seq_read)\n");
    printk(KERN_INFO "========================================\n");
    
    /* 获取 show_map 地址 */
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
    
    ret = register_kprobe(&kp_show_map);
    if (ret == 0) {
        printk(KERN_INFO "[Filter] ✅ Hook registered!\n");
        printk(KERN_INFO "========================================\n");
        printk(KERN_INFO "[Filter] ✅ r-xp 00000000 lines will be hidden\n");
        printk(KERN_INFO "[Filter] ✅ [vdso] preserved\n");
        printk(KERN_INFO "========================================\n");
        return 0;
    }
    
    printk(KERN_ERR "[Filter] ❌ Failed: %d\n", ret);
    return ret;
}

static void __exit filter_exit(void)
{
    unregister_kprobe(&kp_show_map);
    printk(KERN_INFO "[Filter] Unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);