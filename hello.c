#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonymous Exec Filter");
MODULE_DESCRIPTION("Filter anonymous executable memory mappings globally");

static struct kprobe kp_seq_read;
static unsigned long g_seq_read_addr;

/* ---------- 通过 kprobe 获取符号地址 ---------- */
static unsigned long get_symbol_addr(const char *name)
{
    struct kprobe kp;
    unsigned long addr;
    int ret;
    
    addr = 0;
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

/* ---------- 检查是否为 maps 文件 ---------- */
static int is_maps_file(struct file *file)
{
    struct dentry *dentry;
    const char *name;
    
    if (!file) {
        return 0;
    }
    
    dentry = file->f_path.dentry;
    if (!dentry) {
        return 0;
    }
    
    name = dentry->d_name.name;
    if (!name) {
        return 0;
    }
    
    if (strcmp(name, "maps") == 0 ||
        strcmp(name, "smaps") == 0 ||
        strstr(name, "maps") == name) {
        return 1;
    }
    
    return 0;
}

/* ---------- 检查一行是否是匿名可执行内存 ---------- */
static int is_anonymous_executable(const char *line, unsigned long len)
{
    char lower[256];
    int i;
    
    if (!line || len == 0) {
        return 0;
    }
    
    for (i = 0; i < len && i < 255; i++) {
        lower[i] = (line[i] >= 'A' && line[i] <= 'Z') ?
                   line[i] + 0x20 : line[i];
    }
    lower[i < 255 ? i : 255] = '\0';
    
    /* 检查是否有 'x' 权限（可执行） */
    if (!strstr(lower, "x")) {
        return 0;
    }
    
    /* 检查是否是匿名映射（没有文件路径） */
    if (strstr(lower, "[anonymous]") ||
        strstr(lower, "[anon:") ||
        strstr(lower, " 00:00 0 ")) {
        return 1;
    }
    
    return 0;
}

/* ---------- 过滤 maps 内容 ---------- */
static void filter_maps_lines(struct seq_file *m)
{
    char *buf, *src, *dst, *line_start, *line_end;
    unsigned long count, src_pos, dst_pos, remaining, line_len;
    int hidden_count;
    
    if (!m || !m->buf || m->count == 0) {
        return;
    }
    
    hidden_count = 0;
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
            
            if (!is_anonymous_executable(line_start, line_len)) {
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
        
        if (!is_anonymous_executable(line_start, line_len)) {
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
        printk(KERN_INFO "[Filter] 🧹 Filtered %d anonymous executable lines for PID=%d\n",
               hidden_count, current->pid);
    }
    
    m->count = dst_pos;
    if (m->count < m->size) {
        m->buf[m->count] = '\0';
    }
}

/* ---------- seq_read post_handler ---------- */
static void seq_read_post_handler(struct kprobe *p, struct pt_regs *regs,
                                  unsigned long flags)
{
    struct file *file;
    struct seq_file *m;
    ssize_t ret;
    
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
    
    if (!file || ret <= 0) {
        return;
    }
    
    if (!is_maps_file(file)) {
        return;
    }
    
    m = (struct seq_file *)file->private_data;
    if (!m) {
        return;
    }
    
    filter_maps_lines(m);
}

/* ---------- 模块初始化 ---------- */
static int __init filter_init(void)
{
    int ret;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] Anonymous Executable Memory Filter\n");
    printk(KERN_INFO "[Filter] Global - all processes\n");
    printk(KERN_INFO "========================================\n");
    
    g_seq_read_addr = get_symbol_addr("seq_read");
    if (!g_seq_read_addr) {
        g_seq_read_addr = get_symbol_addr("proc_reg_read");
    }
    
    if (!g_seq_read_addr) {
        printk(KERN_ERR "[Filter] ❌ seq_read not found!\n");
        return -ENOENT;
    }
    
    memset(&kp_seq_read, 0, sizeof(struct kprobe));
    kp_seq_read.addr = (void *)g_seq_read_addr;
    kp_seq_read.post_handler = seq_read_post_handler;
    
    ret = register_kprobe(&kp_seq_read);
    if (ret == 0) {
        printk(KERN_INFO "[Filter] ✅ Hook registered!\n");
        printk(KERN_INFO "========================================\n");
        printk(KERN_INFO "[Filter] 🧹 Anonymous executable lines will be hidden\n");
        printk(KERN_INFO "[Filter] Other maps (stack, heap, libraries) remain\n");
        printk(KERN_INFO "========================================\n");
        return 0;
    } else {
        printk(KERN_ERR "[Filter] ❌ Failed to register: %d\n", ret);
        return ret;
    }
}

/* ---------- 模块退出 ---------- */
static void __exit filter_exit(void)
{
    unregister_kprobe(&kp_seq_read);
    printk(KERN_INFO "[Filter] Unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);