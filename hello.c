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
static struct kprobe kp_seq_read;
static struct kprobe kp_proc_reg_read;
static struct kprobe kp_show_map_vma;
static unsigned long g_show_map_addr;
static unsigned long g_seq_read_addr;
static unsigned long g_proc_reg_read_addr;
static unsigned long g_show_map_vma_addr;

static int hook_count = 0;
static int filter_count = 0;

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
    } else {
        printk(KERN_WARNING "[Filter] ❌ %s NOT FOUND (err=%d)\n", name, ret);
    }
    return addr;
}

/* ---------- 检查是否应该隐藏 ---------- */
static int should_hide_line(const char *line, unsigned long len)
{
    (void)len;
    
    /* 调试：打印前几行看格式 */
    static int debug_count = 0;
    if (debug_count < 3) {
        printk(KERN_INFO "[Filter] DEBUG line: %s\n", line);
        debug_count++;
    }
    
    /* 隐藏 r-xp 00000000 或 rwxp 00000000 的匿名映射 */
    if ((strstr(line, "r-xp 00000000") != NULL || 
         strstr(line, "rwxp 00000000") != NULL) &&
        strstr(line, "/") == NULL) {
        return 1;
    }
    
    /* 隐藏所有 libart.so */
    if (strstr(line, "libart.so") != NULL) {
        return 1;
    }
    
    return 0;
}

/* ---------- 过滤 maps ---------- */
static void filter_maps_lines(struct seq_file *m, const char *hook_name)
{
    char *buf, *src, *dst, *line_start, *line_end;
    unsigned long count, src_pos, dst_pos, remaining, line_len;
    int hidden = 0;
    
    if (!m || !m->buf || m->count == 0) return;
    
    filter_count++;
    if (filter_count % 10 == 0) {
        printk(KERN_INFO "[Filter] %s called, count=%d\n", hook_name, filter_count);
    }
    
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
                if (dst_pos != src_pos) memmove(dst + dst_pos, line_start, line_len);
                dst_pos += line_len;
            } else {
                hidden++;
            }
            src_pos = count;
            break;
        }
        
        line_start = src + src_pos;
        line_len = (unsigned long)(line_end - line_start) + 1;
        
        if (!should_hide_line(line_start, line_len)) {
            if (dst_pos != src_pos) memmove(dst + dst_pos, line_start, line_len);
            dst_pos += line_len;
        } else {
            hidden++;
        }
        src_pos += line_len;
    }
    
    if (hidden > 0) {
        printk(KERN_INFO "[Filter] 🧹 %s hidden %d lines for PID=%d (%s)\n",
               hook_name, hidden, current->pid, current->comm);
    }
    
    m->count = dst_pos;
    if (m->count < m->size) m->buf[m->count] = '\0';
}

/* ---------- 各 hook handler ---------- */
static void show_map_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct seq_file *m;
    (void)p; (void)flags;
#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#else
    m = (struct seq_file *)regs->di;
#endif
    if (m) filter_maps_lines(m, "show_map");
}

static void seq_read_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct file *file;
    struct seq_file *m;
    ssize_t ret;
    (void)p; (void)flags;
#if defined(CONFIG_ARM64)
    file = (struct file *)regs->regs[0];
    ret = (ssize_t)regs->regs[0];
#else
    file = (struct file *)regs->di;
    ret = (ssize_t)regs->ax;
#endif
    if (!file || ret <= 0) return;
    if (!file->f_path.dentry) return;
    const char *name = file->f_path.dentry->d_name.name;
    if (!name) return;
    if (strcmp(name, "maps") != 0 && strcmp(name, "smaps") != 0) return;
    m = (struct seq_file *)file->private_data;
    if (m) filter_maps_lines(m, "seq_read");
}

static void proc_reg_read_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct file *file;
    struct seq_file *m;
    ssize_t ret;
    (void)p; (void)flags;
#if defined(CONFIG_ARM64)
    file = (struct file *)regs->regs[0];
    ret = (ssize_t)regs->regs[0];
#else
    file = (struct file *)regs->di;
    ret = (ssize_t)regs->ax;
#endif
    if (!file || ret <= 0) return;
    if (!file->f_path.dentry) return;
    const char *name = file->f_path.dentry->d_name.name;
    if (!name) return;
    if (strcmp(name, "maps") != 0 && strcmp(name, "smaps") != 0) return;
    m = (struct seq_file *)file->private_data;
    if (m) filter_maps_lines(m, "proc_reg_read");
}

/* ---------- 注册 hook ---------- */
static int register_hook(const char *name, unsigned long addr, struct kprobe *kp, void *handler)
{
    if (!addr) return 0;
    memset(kp, 0, sizeof(struct kprobe));
    kp->addr = (void *)addr;
    kp->post_handler = handler;
    if (register_kprobe(kp) == 0) {
        hook_count++;
        printk(KERN_INFO "[Filter] ✅ %s hook registered\n", name);
        return 1;
    }
    return 0;
}

/* ---------- 模块初始化 ---------- */
static int __init filter_init(void)
{
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] ENHANCED FILTER (Debug)\n");
    printk(KERN_INFO "[Filter] Hooking ALL possible functions\n");
    printk(KERN_INFO "========================================\n");
    
    g_show_map_addr = get_symbol_addr("show_map");
    if (!g_show_map_addr) g_show_map_addr = get_symbol_addr("show_map_vma");
    if (!g_show_map_addr) g_show_map_addr = get_symbol_addr("proc_pid_maps_show");
    
    g_seq_read_addr = get_symbol_addr("seq_read");
    g_proc_reg_read_addr = get_symbol_addr("proc_reg_read");
    
    register_hook("show_map", g_show_map_addr, &kp_show_map, show_map_post_handler);
    register_hook("seq_read", g_seq_read_addr, &kp_seq_read, seq_read_post_handler);
    register_hook("proc_reg_read", g_proc_reg_read_addr, &kp_proc_reg_read, proc_reg_read_post_handler);
    
    if (hook_count == 0) {
        printk(KERN_ERR "[Filter] ❌ No hooks registered!\n");
        return -ENOENT;
    }
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] ✅ %d hook(s) registered\n", hook_count);
    printk(KERN_INFO "[Filter] Filter rules:\n");
    printk(KERN_INFO "  - r-xp/rwxp 00000000 [anonymous] -> HIDE\n");
    printk(KERN_INFO "  - libart.so -> HIDE\n");
    printk(KERN_INFO "========================================\n");
    return 0;
}

/* ---------- 模块退出 ---------- */
static void __exit filter_exit(void)
{
    unregister_kprobe(&kp_show_map);
    unregister_kprobe(&kp_seq_read);
    unregister_kprobe(&kp_proc_reg_read);
    printk(KERN_INFO "[Filter] Unloaded, total filter calls: %d\n", filter_count);
}

module_init(filter_init);
module_exit(filter_exit);