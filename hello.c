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

MODULE_LICENSE("GPL");

static struct kprobe kp_show_map;
static unsigned long g_show_map_addr;

/* ---------- 文件写入相关 ---------- */
static struct file *log_file = NULL;
static DEFINE_MUTEX(log_mutex);

/* 在内核中打开文件 */
static struct file *open_log_file(const char *path, int flags)
{
    struct file *filp;
    mm_segment_t old_fs;
    
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    
    filp = filp_open(path, flags, 0644);
    
    set_fs(old_fs);
    return filp;
}

/* 向文件写入内容 */
static void write_to_log(const char *buf, size_t len)
{
    loff_t pos;
    mm_segment_t old_fs;
    
    if (!log_file || !buf || len == 0)
        return;
    
    mutex_lock(&log_mutex);
    
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    
    /* 移动到文件末尾 */
    pos = vfs_llseek(log_file, 0, SEEK_END);
    if (pos >= 0) {
        vfs_write(log_file, buf, len, &pos);
    }
    
    set_fs(old_fs);
    
    mutex_unlock(&log_mutex);
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
    int ret;
    
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
    buf[m->count] = '\0';  /* 确保字符串终止 */
    
    /* 写入标题头 */
    snprintf(header, sizeof(header), 
             "\n========== MAPS DUMP: PID=%d (%s) ==========\n",
             current->pid, current->comm);
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
            line_start = src + src_pos;
            line_len = remaining;
            line_num++;
            
            copy_len = (line_len < 255) ? line_len : 255;
            for (i = 0; i < copy_len; i++) {
                line_copy[i] = line_start[i];
            }
            line_copy[copy_len] = '\0';
            
            printk(KERN_INFO "[Filter] LINE %d: %s\n", line_num, line_copy);
            
            /* 精确匹配权限字段 */
            if (line_len >= 4) {
                char perm[5] = {0};
                /* 跳过地址段，获取权限字段 */
                const char *p = line_start;
                int skip = 0;
                
                /* 跳过第一个地址段（到空格） */
                while (p - line_start < line_len && *p != ' ') p++;
                while (p - line_start < line_len && *p == ' ') p++;
                /* 跳过第二个地址段（到空格） */
                while (p - line_start < line_len && *p != ' ') p++;
                while (p - line_start < line_len && *p == ' ') p++;
                /* 现在 p 指向权限字段 */
                if (p - line_start + 4 <= line_len) {
                    perm[0] = p[0];
                    perm[1] = p[1];
                    perm[2] = p[2];
                    perm[3] = p[3];
                    perm[4] = '\0';
                }
                
                if (strcmp(perm, "rwxp") == 0) {
                    hidden++;
                    printk(KERN_INFO "[Filter] ❌ HIDE (rwxp)\n");
                } else {
                    printk(KERN_INFO "[Filter] ✅ KEEP\n");
                    if (dst_pos != src_pos) 
                        memmove(dst + dst_pos, line_start, line_len);
                    dst_pos += line_len;
                }
            } else {
                /* 行太短，直接保留 */
                if (dst_pos != src_pos) 
                    memmove(dst + dst_pos, line_start, line_len);
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
        
        /* 精确匹配权限字段 */
        if (line_len >= 4) {
            char perm[5] = {0};
            const char *p = line_start;
            int skip = 0;
            
            /* 跳过地址段，获取权限字段 */
            while (p - line_start < line_len && *p != ' ') p++;
            while (p - line_start < line_len && *p == ' ') p++;
            while (p - line_start < line_len && *p != ' ') p++;
            while (p - line_start < line_len && *p == ' ') p++;
            
            if (p - line_start + 4 <= line_len) {
                perm[0] = p[0];
                perm[1] = p[1];
                perm[2] = p[2];
                perm[3] = p[3];
                perm[4] = '\0';
            }
            
            if (strcmp(perm, "rwxp") == 0) {
                hidden++;
                printk(KERN_INFO "[Filter] ❌ HIDE (rwxp)\n");
            } else {
                printk(KERN_INFO "[Filter] ✅ KEEP\n");
                if (dst_pos != src_pos) 
                    memmove(dst + dst_pos, line_start, line_len);
                dst_pos += line_len;
            }
        } else {
            /* 行太短，直接保留 */
            if (dst_pos != src_pos) 
                memmove(dst + dst_pos, line_start, line_len);
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

/* ---------- 模块初始化 ---------- */
static int __init filter_init(void)
{
    const char *log_path = "/sdcard/test.txt";
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] DEBUG: rwxp filter with file logging\n");
    printk(KERN_INFO "========================================\n");
    
    /* 打开日志文件（如果不存在则创建） */
    log_file = open_log_file(log_path, O_CREAT | O_WRONLY | O_APPEND);
    if (!log_file || IS_ERR(log_file)) {
        printk(KERN_ERR "[Filter] ❌ Failed to open %s (err=%ld)\n", 
               log_path, PTR_ERR(log_file));
        log_file = NULL;
        /* 继续执行，不因为文件打开失败而终止 */
    } else {
        printk(KERN_INFO "[Filter] ✅ Log file opened: %s\n", log_path);
        /* 写入启动标记 */
        write_to_log("\n=== FILTER MODULE LOADED ===\n", 28);
    }
    
    g_show_map_addr = get_symbol_addr("show_map");
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("show_map_vma");
    }
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("proc_pid_maps_show");
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
        printk(KERN_INFO "[Filter] ✅ Hook registered\n");
        printk(KERN_INFO "[Filter] Open any app to see maps dump\n");
        return 0;
    }
    
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