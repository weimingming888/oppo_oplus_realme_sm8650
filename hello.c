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
static unsigned long g_show_map_addr;
static unsigned long g_seq_read_addr;

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
    int result = 0;
    (void)len;
    
    /* 隐藏 r-xp 00000000 或 rwxp 00000000 的匿名映射 */
    if ((strstr(line, "r-xp 00000000") != NULL || 
         strstr(line, "rwxp 00000000") != NULL) &&
        strstr(line, "/") == NULL &&
        strstr(line, "[vdso]") == NULL) {
        result = 1;
    }
    
    /* 隐藏所有 libart.so */
    if (strstr(line, "libart.so") != NULL) {
        result = 1;
    }
    
    return result;
}

/* ---------- 过滤 maps ---------- */
static void filter_maps_lines(struct seq_file *m)
{
    char *buf, *src, *dst, *line_start, *line_end;
    unsigned long count, src_pos, dst_pos, remaining, line_len;
    int hidden = 0;
    
    if (!m || !m->buf || m->count == 0) return;
    
    filter_count++;
    if (filter_count % 10 == 0) {
        printk(KERN_INFO "[Filter] filter called %d times\n", filter_count);
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
                if (dst_pos != src_pos) {
                    memmove(dst + dst_pos, line_start, line_len);
                }
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
            if (dst_pos != src_pos) {
                memmove(dst + dst_pos, line_start, line_len);
            }
            dst_pos += line_len;
        } else {
            hidden++;
        }
        src_pos += line_len;
    }
    
    if (hidden > 0) {
        printk(KERN_INFO "[Filter] 🧹 Hidden %d lines for PID=%d (%s)\n",
               hidden, current->pid, current->comm);
    }
    
    m->count = dst_pos;
    if (m->count < m->size) {
        m->buf[m->count] = '\0';
    }
}

/* ---------- show_map post_handler ---------- */
static void show_map_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct seq_file *m;
    
    (void)p;
    (void)flags;
    
    /* show_map 的函数签名: int show_map(struct seq_file *m, void *v) */
    /* 第一个参数在 x0 寄存器 */
#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#else
    m = NULL;
#endif
    
    if (m) {
        filter_maps_lines(m);
    }
}

/* ---------- seq_read post_handler ---------- */
static void seq_read_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct file *file;
    struct seq_file *m;
    ssize_t ret;
    const char *name;
    
    (void)p;
    (void)flags;
    
    /* ============================================================
     * ARM64:
     *   seq_read 函数执行后，x0 是返回值
     *   但第一个参数 file 在函数执行后可能被覆盖了
     *   正确的做法：从 file->private_data 获取 seq_file
     * ============================================================ */
    
    /* 在 post_handler 中，x0 是返回值（ssize_t） */
#if defined(CONFIG_ARM64)
    ret = (ssize_t)regs->regs[0];
    /* 没有办法获取 file 参数了，因为 x0 已经被返回值覆盖 */
    /* 但我们可以从 current 的 fd 表中找？太复杂了 */
    /* 更好的方案：使用 pre_handler 保存 file 指针 */
#elif defined(CONFIG_X86_64)
    file = (struct file *)regs->di;
    ret = (ssize_t)regs->ax;
#else
    file = NULL;
    ret = 0;
#endif
    
    /* 暂时只支持 x86_64，ARM64 使用 show_map 就够了 */
}

/* ---------- 模块初始化 ---------- */
static int __init filter_init(void)
{
    int ret;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] ENHANCED FILTER\n");
    printk(KERN_INFO "[Filter] Fixed ARM64 register handling\n");
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
            hook_count++;
            printk(KERN_INFO "[Filter] ✅ show_map hook registered\n");
        }
    }
    
    if (hook_count == 0) {
        printk(KERN_ERR "[Filter] ❌ No hooks registered!\n");
        return -ENOENT;
    }
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] ✅ %d hook(s) registered\n", hook_count);
    printk(KERN_INFO "[Filter] ✅ r-xp/rwxp 00000000 [anonymous] -> HIDE\n");
    printk(KERN_INFO "[Filter] ✅ libart.so -> HIDE\n");
    printk(KERN_INFO "========================================\n");
    return 0;
}

/* ---------- 模块退出 ---------- */
static void __exit filter_exit(void)
{
    unregister_kprobe(&kp_show_map);
    printk(KERN_INFO "[Filter] Unloaded, total filter calls: %d\n", filter_count);
}

module_init(filter_init);
module_exit(filter_exit);