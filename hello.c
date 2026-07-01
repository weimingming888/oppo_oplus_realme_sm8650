#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/uidgid.h>

MODULE_LICENSE("GPL");

static struct kprobe kp_show_map;
static unsigned long g_show_map_addr;

/* ---------- 文件写入相关 ---------- */
static struct file *log_file = NULL;
static DEFINE_MUTEX(log_mutex);

/* 向文件写入内容 - 内核 6.1 兼容版本 */
static void write_to_log(const char *buf, size_t len)
{
    loff_t pos;
    int ret;
    
    if (!log_file || !buf || len == 0)
        return;
    
    mutex_lock(&log_mutex);
    
    /* 移动到文件末尾 */
    pos = vfs_llseek(log_file, 0, SEEK_END);
    if (pos >= 0) {
        /* 内核 6.1 使用 kernel_write，需要传递 loff_t 指针 */
        ret = kernel_write(log_file, buf, len, &pos);
        if (ret < 0) {
            printk(KERN_ERR "[Filter] Failed to write log: %d\n", ret);
        }
    }
    
    mutex_unlock(&log_mutex);
}

/* 在内核中打开文件 */
static struct file *open_log_file(const char *path, int flags)
{
    struct file *filp;
    
    /* 内核 6.1 直接使用 filp_open，无需 set_fs */
    filp = filp_open(path, flags, 0644);
    if (IS_ERR(filp)) {
        printk(KERN_ERR "[Filter] filp_open failed: %ld\n", PTR_ERR(filp));
        return NULL;
    }
    
    return filp;
}

/* 关闭日志文件 */
static void close_log_file(void)
{
    if (log_file) {
        filp_close(log_file, NULL);
        log_file = NULL;
    }
}

/* ---------- 写入完整 maps 内容 ---------- */
static void write_maps_content(struct seq_file *m)
{
    char *buf;
    unsigned long count;
    char header[256];
    
    if (!m || !m->buf || m->count == 0)
        return;
    
    /* 分配临时缓冲区（多加一个字节用于终止符） */
    buf = kmalloc(m->count + 1, GFP_KERNEL);
    if (!buf) {
        printk(KERN_ERR "[Filter] Failed to allocate buffer\n");
        return;
    }
    
    /* 复制数据 */
    memcpy(buf, m->buf, m->count);
    buf[m->count] = '\0';
    
    /* 写入标题头 */
    snprintf(header, sizeof(header), 
             "\n========== MAPS DUMP: PID=%d (%s) Time=%lu ==========\n",
             current->pid, current->comm, jiffies);
    write_to_log(header, strlen(header));
    
    /* 写入完整内容 */
    write_to_log(buf, m->count);
    
    /* 写入结束标记 */
    snprintf(header, sizeof(header), 
             "========== END OF MAPS (Total: %lu bytes) ==========\n\n",
             m->count);
    write_to_log(header, strlen(header));
    
    kfree(buf);
}

/* ---------- 精确检查是否为 rwxp 权限 ---------- */
static int is_rwxp_permission(const char *line_start, unsigned long line_len)
{
    const char *p = line_start;
    
    /* 跳过地址段和权限字段之前的空格 */
    /* 格式: start-end perm offset major:minor inode pathname */
    
    /* 跳过开头的空格 */
    while (p - line_start < line_len && *p == ' ') p++;
    
    /* 跳过第一个地址 (start) */
    while (p - line_start < line_len && *p != ' ') p++;
    while (p - line_start < line_len && *p == ' ') p++;
    
    /* 跳过第二个地址 (end) */
    while (p - line_start < line_len && *p != ' ') p++;
    while (p - line_start < line_len && *p == ' ') p++;
    
    /* 现在 p 指向权限字段 (如 rwxp, r-xp, r--p 等) */
    if (p - line_start + 4 <= line_len) {
        return (p[0] == 'r' && p[1] == 'w' && p[2] == 'x' && p[3] == 'p');
    }
    return 0;
}

/* ---------- 复制一行内容到临时缓冲区 ---------- */
static void copy_line_to_buffer(const char *src, char *dst, size_t len)
{
    size_t copy_len = (len < 255) ? len : 255;
    size_t i;
    
    for (i = 0; i < copy_len; i++) {
        dst[i] = src[i];
    }
    dst[copy_len] = '\0';
    
    /* 移除换行符以便打印 */
    if (copy_len > 0 && dst[copy_len - 1] == '\n') {
        dst[copy_len - 1] = '\0';
    }
}

/* ---------- show_map post_handler ---------- */
static void show_map_post_handler(struct kprobe *p, struct pt_regs *regs, 
                                   unsigned long flags)
{
    struct seq_file *m;
    char *buf, *src, *dst, *line_start, *line_end;
    unsigned long count, src_pos, dst_pos, remaining, line_len;
    int hidden = 0;
    int line_num = 0;
    char line_copy[256];
    
    (void)p;
    (void)flags;
    
    /* 获取 seq_file 指针 */
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
    
    printk(KERN_INFO "[Filter] ========== MAPS DUMP START ==========\n");
    printk(KERN_INFO "[Filter] PID=%d (%s), count=%lu\n", 
           current->pid, current->comm, m->count);
    
    /* 首先，将完整内容写入 sdcard */
    write_maps_content(m);
    
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
            /* 处理最后一行（没有换行符） */
            line_start = src + src_pos;
            line_len = remaining;
            line_num++;
            
            copy_line_to_buffer(line_start, line_copy, line_len);
            printk(KERN_INFO "[Filter] LINE %d: %s\n", line_num, line_copy);
            
            /* 检查是否为 rwxp */
            if (is_rwxp_permission(line_start, line_len)) {
                hidden++;
                printk(KERN_INFO "[Filter] ❌ HIDE (rwxp)\n");
            } else {
                printk(KERN_INFO "[Filter] ✅ KEEP\n");
                if (dst_pos != src_pos) 
                    memmove(dst + dst_pos, line_start, line_len);
                dst_pos += line_len;
            }
            src_pos = count;
            break;
        }
        
        /* 处理完整的行（包含换行符） */
        line_start = src + src_pos;
        line_len = (unsigned long)(line_end - line_start) + 1;  /* 包含换行符 */
        line_num++;
        
        copy_line_to_buffer(line_start, line_copy, line_len);
        printk(KERN_INFO "[Filter] LINE %d: %s\n", line_num, line_copy);
        
        /* 检查是否为 rwxp */
        if (is_rwxp_permission(line_start, line_len)) {
            hidden++;
            printk(KERN_INFO "[Filter] ❌ HIDE (rwxp)\n");
        } else {
            printk(KERN_INFO "[Filter] ✅ KEEP\n");
            if (dst_pos != src_pos) 
                memmove(dst + dst_pos, line_start, line_len);
            dst_pos += line_len;
        }
        src_pos += line_len;
    }
    
    printk(KERN_INFO "[Filter] Total lines: %d, Hidden: %d\n", line_num, hidden);
    printk(KERN_INFO "[Filter] ========== MAPS DUMP END ==========\n");
    
    /* 更新 seq_file 的 count */
    m->count = dst_pos;
    if (m->count < m->size) {
        m->buf[m->count] = '\0';
    }
}

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
        printk(KERN_INFO "[Filter] ❌ %s not found (err=%d)\n", name, ret);
    }
    return addr;
}

/* ---------- 模块初始化 ---------- */
static int __init filter_init(void)
{
    const char *log_path = "/sdcard/test.txt";
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] rwxp filter with file logging\n");
    printk(KERN_INFO "[Filter] Kernel version: %d.%d.%d\n",
           LINUX_VERSION_CODE >> 16,
           (LINUX_VERSION_CODE >> 8) & 0xFF,
           LINUX_VERSION_CODE & 0xFF);
    printk(KERN_INFO "========================================\n");
    
    /* 打开日志文件（如果不存在则创建） */
    log_file = open_log_file(log_path, O_CREAT | O_WRONLY | O_APPEND);
    if (!log_file) {
        printk(KERN_ERR "[Filter] ❌ Failed to open %s\n", log_path);
        /* 继续执行，不因为文件打开失败而终止 */
    } else {
        printk(KERN_INFO "[Filter] ✅ Log file opened: %s\n", log_path);
        /* 写入启动标记 */
        write_to_log("\n=== FILTER MODULE LOADED ===\n", 28);
        write_to_log("=== Kernel 6.1 compatible ===\n", 30);
    }
    
    /* 尝试多个可能的符号名 */
    g_show_map_addr = get_symbol_addr("show_map");
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("show_map_vma");
    }
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("proc_pid_maps_show");
    }
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("seq_show_map");
    }
    
    if (!g_show_map_addr) {
        printk(KERN_ERR "[Filter] ❌ show_map not found!\n");
        close_log_file();
        return -ENOENT;
    }
    
    memset(&kp_show_map, 0, sizeof(struct kprobe));
    kp_show_map.addr = (void *)g_show_map_addr;
    kp_show_map.post_handler = show_map_post_handler;
    
    if (register_kprobe(&kp_show_map) == 0) {
        printk(KERN_INFO "[Filter] ✅ Hook registered at 0x%lx\n", g_show_map_addr);
        printk(KERN_INFO "[Filter] Open any app to see maps dump\n");
        return 0;
    }
    
    printk(KERN_ERR "[Filter] ❌ Failed to register kprobe\n");
    close_log_file();
    return -EINVAL;
}

/* ---------- 模块退出 ---------- */
static void __exit filter_exit(void)
{
    unregister_kprobe(&kp_show_map);
    
    if (log_file) {
        write_to_log("\n=== FILTER MODULE UNLOADED ===\n", 28);
        close_log_file();
        printk(KERN_INFO "[Filter] Log file closed\n");
    }
    
    printk(KERN_INFO "[Filter] Unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);