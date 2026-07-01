#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/file.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DuckDetector Bypass");
MODULE_DESCRIPTION("Hide LSPosed traces from com.eltavine.duckdetector with debug");

/* ---------- 全局变量 ---------- */
static struct kprobe kp_seq_read;
static struct kprobe kp_proc_reg_read;
static unsigned long target_pid = 0;
static int hidden_count = 0;
static int total_lines = 0;

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
    }
    
    return addr;
}

/* ---------- 检查当前进程是否是 DuckDetector ---------- */
static int is_duckdetector(void)
{
    struct task_struct *task = current;
    char *cmdline;
    static pid_t cached_pid = 0;
    
    if (!task)
        return 0;
    
    /* 检查进程名 */
    if (strstr(task->comm, "duckdetector") ||
        strstr(task->comm, "eltavine")) {
        if (cached_pid != task->pid) {
            cached_pid = task->pid;
            printk(KERN_INFO "[DuckDetector] ✅ Found target! PID=%d, COMM=%s\n", 
                   task->pid, task->comm);
        }
        return 1;
    }
    
    /* 检查命令行（更准确） */
    if (task->mm && task->mm->arg_start) {
        char buf[128];
        unsigned long arg_start = task->mm->arg_start;
        unsigned long arg_end = task->mm->arg_end;
        unsigned long len = arg_end - arg_start;
        
        if (len > 0 && len < 127) {
            if (strncpy_from_user(buf, (void *)arg_start, len) > 0) {
                buf[len] = '\0';
                if (strstr(buf, "duckdetector") ||
                    strstr(buf, "eltavine")) {
                    if (cached_pid != task->pid) {
                        cached_pid = task->pid;
                        printk(KERN_INFO "[DuckDetector] ✅ Found target via cmdline! PID=%d\n", 
                               task->pid);
                    }
                    return 1;
                }
            }
        }
    }
    
    return 0;
}

/* ---------- 获取隐藏原因的描述 ---------- */
static const char *get_hide_reason(const char *line, unsigned long len)
{
    char lower[256];
    int i;
    
    if (!line || len == 0)
        return "unknown";
    
    for (i = 0; i < len && i < 255; i++) {
        lower[i] = (line[i] >= 'A' && line[i] <= 'Z') ? 
                   line[i] + 0x20 : line[i];
    }
    lower[i < 255 ? i : 255] = '\0';
    
    if (strstr(lower, "anonymous") && strstr(lower, "x")) {
        return "anonymous executable (LSPosed code)";
    }
    
    if (strstr(lower, "rwx")) {
        return "RWX permission (dangerous)";
    }
    
    if (strstr(lower, "libart.so") && 
        (strstr(lower, "shared-dirty") || strstr(lower, "private-dirty"))) {
        return "libart.so dirty pages (hooked)";
    }
    
    if (strstr(lower, "lsposed") ||
        strstr(lower, "lspatch") ||
        strstr(lower, "riru") ||
        strstr(lower, "zygisk") ||
        strstr(lower, "xposed") ||
        strstr(lower, "edxposed") ||
        strstr(lower, "liblsp")) {
        return "LSPosed related file";
    }
    
    if (strstr(lower, "anonymous") && 
        (strstr(lower, "---p") == NULL) &&
        (strstr(lower, "rw-p") == NULL) &&
        (strstr(lower, "r--p") == NULL)) {
        return "suspicious anonymous mapping";
    }
    
    return "unknown reason";
}

/* ---------- 提取行首地址（用于日志） ---------- */
static void extract_line_preview(const char *line, unsigned long len, char *buf, int buf_len)
{
    int i;
    int copied = 0;
    
    for (i = 0; i < len && i < 80 && copied < buf_len - 1; i++) {
        if (line[i] == '\n' || line[i] == '\r')
            break;
        if (line[i] >= 0x20 && line[i] < 0x7F) {
            buf[copied++] = line[i];
        }
    }
    buf[copied] = '\0';
}

/* ---------- 检查一行是否应该被隐藏 ---------- */
static int should_hide_line(const char *line, unsigned long len, char *reason_out, int reason_len)
{
    char lower[256];
    int i;
    const char *reason = NULL;
    
    if (!line || len == 0)
        return 0;
    
    for (i = 0; i < len && i < 255; i++) {
        lower[i] = (line[i] >= 'A' && line[i] <= 'Z') ? 
                   line[i] + 0x20 : line[i];
    }
    lower[i < 255 ? i : 255] = '\0';
    
    /* 1. 隐藏匿名可执行映射（LSPosed 注入代码） */
    if (strstr(lower, "anonymous") && strstr(lower, "x")) {
        reason = "anonymous executable (LSPosed code)";
        goto hide;
    }
    
    /* 2. 隐藏 RWX 映射 */
    if (strstr(lower, "rwx")) {
        reason = "RWX permission (dangerous)";
        goto hide;
    }
    
    /* 3. 隐藏 libart.so 脏页 */
    if (strstr(lower, "libart.so") && 
        (strstr(lower, "shared-dirty") || strstr(lower, "private-dirty"))) {
        reason = "libart.so dirty pages (hooked)";
        goto hide;
    }
    
    /* 4. 隐藏 LSPosed 相关 */
    if (strstr(lower, "lsposed") ||
        strstr(lower, "lspatch") ||
        strstr(lower, "riru") ||
        strstr(lower, "zygisk") ||
        strstr(lower, "xposed") ||
        strstr(lower, "edxposed") ||
        strstr(lower, "liblsp")) {
        reason = "LSPosed related file";
        goto hide;
    }
    
    /* 5. 隐藏任何可执行的匿名映射 */
    if (strstr(lower, "anonymous") && 
        (strstr(lower, "---p") == NULL) &&
        (strstr(lower, "rw-p") == NULL) &&
        (strstr(lower, "r--p") == NULL)) {
        reason = "suspicious anonymous mapping";
        goto hide;
    }
    
    return 0;

hide:
    if (reason_out && reason_len > 0) {
        strncpy(reason_out, reason, reason_len - 1);
        reason_out[reason_len - 1] = '\0';
    }
    return 1;
}

/* ---------- 过滤 maps 内容 ---------- */
static void filter_maps_lines(struct seq_file *m)
{
    char *buf, *src, *dst, *line_start, *line_end;
    unsigned long count, src_pos, dst_pos, remaining, line_len;
    char line_preview[128];
    char reason[64];
    int hidden_this_time = 0;
    
    if (!m || !m->buf || m->count == 0)
        return;
    
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
            
            extract_line_preview(line_start, line_len, line_preview, sizeof(line_preview));
            
            if (should_hide_line(line_start, line_len, reason, sizeof(reason))) {
                hidden_this_time++;
                hidden_count++;
                printk(KERN_INFO "[DuckDetector] 🚫 HIDDEN: %s | Reason: %s\n", 
                       line_preview, reason);
            } else {
                if (dst_pos != src_pos)
                    memmove(dst + dst_pos, line_start, line_len);
                dst_pos += line_len;
            }
            src_pos = count;
            break;
        }
        
        line_start = src + src_pos;
        line_len = (unsigned long)(line_end - line_start) + 1;
        
        extract_line_preview(line_start, line_len, line_preview, sizeof(line_preview));
        total_lines++;
        
        if (should_hide_line(line_start, line_len, reason, sizeof(reason))) {
            hidden_this_time++;
            hidden_count++;
            printk(KERN_INFO "[DuckDetector] 🚫 HIDDEN: %s | Reason: %s\n", 
                   line_preview, reason);
        } else {
            if (dst_pos != src_pos)
                memmove(dst + dst_pos, line_start, line_len);
            dst_pos += line_len;
        }
        src_pos += line_len;
    }
    
    if (hidden_this_time > 0) {
        printk(KERN_INFO "[DuckDetector] 📊 This read: %d hidden, %d shown (total hidden: %d)\n", 
               hidden_this_time, total_lines - hidden_this_time, hidden_count);
    }
    
    m->count = dst_pos;
    if (m->count < m->size)
        m->buf[m->count] = '\0';
}

/* ---------- 判断是否为 maps 文件 ---------- */
static int is_maps_file(struct file *file)
{
    struct dentry *dentry;
    const char *name;
    
    if (!file)
        return 0;
    
    dentry = file->f_path.dentry;
    if (!dentry)
        return 0;
    
    name = dentry->d_name.name;
    if (!name)
        return 0;
    
    if (strcmp(name, "maps") == 0 || 
        strcmp(name, "smaps") == 0 ||
        strcmp(name, "status") == 0 ||
        strstr(name, "maps") == name) {
        return 1;
    }
    
    return 0;
}

/* ---------- seq_read post_handler ---------- */
static void seq_read_post_handler(struct kprobe *p, struct pt_regs *regs,
                                  unsigned long flags)
{
    struct file *file;
    struct seq_file *m;
    ssize_t ret;
    struct task_struct *task = current;
    
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
    
    if (!file || !is_maps_file(file))
        return;
    
    /* 只保护 DuckDetector */
    if (!is_duckdetector())
        return;
    
    if (ret <= 0)
        return;
    
    m = (struct seq_file *)file->private_data;
    if (!m)
        return;
    
    printk(KERN_INFO "[DuckDetector] 🔍 PID=%d reading %s, count=%ld\n", 
           task->pid, file->f_path.dentry->d_name.name, ret);
    
    filter_maps_lines(m);
}

/* ---------- 模块初始化 ---------- */
static int __init duck_bypass_init(void)
{
    unsigned long addr;
    int ret;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "🐤 DuckDetector Bypass (Debug Mode)\n");
    printk(KERN_INFO "Target: com.eltavine.duckdetector\n");
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[DuckDetector] Waiting for target app...\n");
    
    /* 获取 seq_read 地址 */
    addr = get_symbol_addr("seq_read");
    if (!addr) {
        addr = get_symbol_addr("proc_reg_read");
        if (!addr) {
            printk(KERN_ERR "[DuckDetector] ❌ No suitable symbol found\n");
            return -ENOENT;
        }
    }
    
    printk(KERN_INFO "[DuckDetector] ✅ Hook target at 0x%lx\n", addr);
    
    /* 注册 kprobe */
    memset(&kp_seq_read, 0, sizeof(struct kprobe));
    kp_seq_read.addr = (void *)addr;
    kp_seq_read.post_handler = seq_read_post_handler;
    
    ret = register_kprobe(&kp_seq_read);
    if (ret == 0) {
        printk(KERN_INFO "[DuckDetector] ✅ Hooked successfully!\n");
        printk(KERN_INFO "========================================\n");
        printk(KERN_INFO "🐤 DuckDetector is now blind to LSPosed\n");
        printk(KERN_INFO "📊 Debug logs will show hidden entries\n");
        printk(KERN_INFO "========================================\n");
        return 0;
    } else {
        printk(KERN_ERR "[DuckDetector] ❌ Failed to hook: %d\n", ret);
        return ret;
    }
}

/* ---------- 模块退出 ---------- */
static void __exit duck_bypass_exit(void)
{
    unregister_kprobe(&kp_seq_read);
    unregister_kprobe(&kp_proc_reg_read);
    printk(KERN_INFO "[DuckDetector] 📊 Total hidden entries: %d\n", hidden_count);
    printk(KERN_INFO "[DuckDetector] Bypass unloaded\n");
}

module_init(duck_bypass_init);
module_exit(duck_bypass_exit);