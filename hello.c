#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");

static struct kprobe kp_seq_read;
static unsigned long g_seq_read_addr;

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

static int is_maps_file(struct file *file)
{
    struct dentry *dentry;
    const char *name;
    
    if (!file) return 0;
    dentry = file->f_path.dentry;
    if (!dentry) return 0;
    name = dentry->d_name.name;
    if (!name) return 0;
    
    if (strcmp(name, "maps") == 0 ||
        strcmp(name, "smaps") == 0 ||
        strstr(name, "maps") == name) {
        return 1;
    }
    return 0;
}

static int should_hide_line(const char *line, unsigned long len)
{
    (void)len;
    
    /* 必须包含 r-xp 00000000 */
    if (strstr(line, "r-xp 00000000") == NULL) {
        return 0;
    }
    
    /* [vdso] 是系统组件，不隐藏 */
    if (strstr(line, "[vdso]") != NULL) {
        return 0;
    }
    
    /* 有文件路径的也不隐藏（如 .so） */
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
        printk(KERN_INFO "[Filter] 🧹 Hidden %d lines for PID=%d\n",
               hidden_count, current->pid);
    }
    
    m->count = dst_pos;
    if (m->count < m->size) {
        m->buf[m->count] = '\0';
    }
}

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
    
    if (!file || ret <= 0 || !is_maps_file(file)) {
        return;
    }
    
    if (!is_target_process()) {
        return;
    }
    
    m = (struct seq_file *)file->private_data;
    if (!m) return;
    
    filter_maps_lines(m);
}

static int __init filter_init(void)
{
    int ret;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] DuckDetector maps filter\n");
    printk(KERN_INFO "[Filter] Hiding: r-xp 00000000 (except [vdso])\n");
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
        printk(KERN_INFO "[Filter] ✅ LSPosed lines hidden\n");
        printk(KERN_INFO "[Filter] ✅ [vdso] preserved\n");
        printk(KERN_INFO "========================================\n");
        return 0;
    }
    
    printk(KERN_ERR "[Filter] ❌ Failed: %d\n", ret);
    return ret;
}

static void __exit filter_exit(void)
{
    unregister_kprobe(&kp_seq_read);
    printk(KERN_INFO "[Filter] Unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);