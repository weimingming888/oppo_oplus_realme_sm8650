#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Multi Hook Filter");
MODULE_DESCRIPTION("Filter r-xp 00000000 via multiple hooks");

static struct kprobe kp_show_map;
static struct kprobe kp_seq_read;
static unsigned long g_show_map_addr;
static unsigned long g_seq_read_addr;

/* ---------- 通过 kprobe 获取符号地址 ---------- */
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

/* ---------- 检查是否应该隐藏 ---------- */
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

/* ---------- 过滤 maps ---------- */
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
    
#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#else
    m = NULL;
#endif
    
    if (!m) return;
    filter_maps_lines(m);
}

/* ---------- seq_read post_handler ---------- */
static void seq_read_post_handler(struct kprobe *p, struct pt_regs *regs,
                                  unsigned long flags)
{
    struct file *file;
    struct seq_file *m;
    ssize_t ret;
    const char *name;
    
    (void)p;
    (void)flags;
    
#if defined(CONFIG_ARM64)
    file = (struct file *)regs->regs[0];
    ret = (ssize_t)regs->regs[0];
#elif defined(CONFIG_X86_64)
    file = (struct file *)regs->di;
    ret = (ssize_t)regs->ax;
#else
    file = NULL;
    ret = 0;
#endif
    
    if (!file || ret <= 0) return;
    
    if (!file->f_path.dentry) return;
    name = file->f_path.dentry->d_name.name;
    if (!name) return;
    
    if (strcmp(name, "maps") != 0 && strcmp(name, "smaps") != 0) {
        return;
    }
    
    m = (struct seq_file *)file->private_data;
    if (!m) return;
    
    filter_maps_lines(m);
}

/* ---------- 模块初始化 ---------- */
static int __init filter_init(void)
{
    int ret;
    int hooks = 0;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] MULTI HOOK filter\n");
    printk(KERN_INFO "[Filter] Hooking: show_map + seq_read\n");
    printk(KERN_INFO "========================================\n");
    
    g_show_map_addr = get_symbol_addr("show_map");
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("show_map_vma");
    }
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("proc_pid_maps_show");
    }
    
    if (g_show_map_addr) {
        memset(&kp_show_map, 0, sizeof(struct kprobe));
        kp_show_map.addr = (void *)g_show_map_addr;
        kp_show_map.post_handler = show_map_post_handler;
        ret = register_kprobe(&kp_show_map);
        if (ret == 0) {
            hooks++;
            printk(KERN_INFO "[Filter] ✅ show_map hook registered\n");
        }
    }
    
    g_seq_read_addr = get_symbol_addr("seq_read");
    if (!g_seq_read_addr) {
        g_seq_read_addr = get_symbol_addr("proc_reg_read");
    }
    
    if (g_seq_read_addr) {
        memset(&kp_seq_read, 0, sizeof(struct kprobe));
        kp_seq_read.addr = (void *)g_seq_read_addr;
        kp_seq_read.post_handler = seq_read_post_handler;
        ret = register_kprobe(&kp_seq_read);
        if (ret == 0) {
            hooks++;
            printk(KERN_INFO "[Filter] ✅ seq_read hook registered\n");
        }
    }
    
    if (hooks == 0) {
        printk(KERN_ERR "[Filter] ❌ No hooks registered!\n");
        return -ENOENT;
    }
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] ✅ %d hook(s) registered\n", hooks);
    printk(KERN_INFO "[Filter] ✅ r-xp 00000000 hidden (ALL paths)\n");
    printk(KERN_INFO "========================================\n");
    return 0;
}

/* ---------- 模块退出 ---------- */
static void __exit filter_exit(void)
{
    unregister_kprobe(&kp_show_map);
    unregister_kprobe(&kp_seq_read);
    printk(KERN_INFO "[Filter] Unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);