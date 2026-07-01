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
MODULE_DESCRIPTION("Hide LSPosed traces with full symbol validation");

/* ---------- 全局变量 ---------- */
static struct kprobe kp_seq_read;
static struct kprobe kp_proc_reg_read;
static int hidden_count = 0;
static int total_lines = 0;

/* 记录获取到的符号地址 */
static unsigned long g_seq_read_addr = 0;
static unsigned long g_proc_reg_read_addr = 0;
static unsigned long g_find_task_by_vpid_addr = 0;

/* ---------- 通过 kprobe 获取符号地址（带校验） ---------- */
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
        printk(KERN_INFO "[Validator] ✅ %s = 0x%lx\n", name, addr);
    } else {
        printk(KERN_WARNING "[Validator] ❌ %s NOT FOUND (err=%d)\n", name, ret);
    }
    
    return addr;
}

/* ---------- 校验所有需要的符号 ---------- */
static int validate_all_symbols(void)
{
    int success = 0;
    
    printk(KERN_INFO "[Validator] ========================================\n");
    printk(KERN_INFO "[Validator] Validating required symbols...\n");
    printk(KERN_INFO "[Validator] ========================================\n");
    
    /* 1. 获取 seq_read */
    g_seq_read_addr = get_symbol_addr("seq_read");
    if (g_seq_read_addr) {
        success++;
    }
    
    /* 2. 获取 proc_reg_read（备选） */
    g_proc_reg_read_addr = get_symbol_addr("proc_reg_read");
    if (g_proc_reg_read_addr) {
        success++;
    }
    
    /* 3. 获取 find_task_by_vpid（调试用） */
    g_find_task_by_vpid_addr = get_symbol_addr("find_task_by_vpid");
    if (g_find_task_by_vpid_addr) {
        success++;
    }
    
    printk(KERN_INFO "[Validator] ========================================\n");
    printk(KERN_INFO "[Validator] Symbols found: %d/3\n", success);
    printk(KERN_INFO "[Validator] ========================================\n");
    
    /* 至少要有一个可用 */
    if (g_seq_read_addr == 0 && g_proc_reg_read_addr == 0) {
        printk(KERN_ERR "[Validator] ❌ FATAL: No read function available!\n");
        return -ENOENT;
    }
    
    return 0;
}

/* ---------- 检查当前进程是否是 DuckDetector ---------- */
static int is_duckdetector(void)
{
    struct task_struct *task = current;
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
    
    return 0;
}

/* ---------- 获取隐藏原因 ---------- */
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
    
    if (strstr(lower, "anonymous") && strstr(lower, "x"))
        return "anonymous executable (LSPosed code)";
    
    if (strstr(lower, "rwx"))
        return "RWX permission (dangerous)";
    
    if (strstr(lower, "libart.so") && 
        (strstr(lower, "shared-dirty") || strstr(lower, "private-dirty")))
        return "libart.so dirty pages (hooked)";
    
    if (strstr(lower, "lsposed") || strstr(lower, "lspatch") ||
        strstr(lower, "riru") || strstr(lower, "zygisk") ||
        strstr(lower, "xposed") || strstr(lower, "edxposed") ||
        strstr(lower, "liblsp"))
        return "LSPosed related file";
    
    return "suspicious mapping";
}

/* ---------- 提取行预览 ---------- */
static void extract_line_preview(const char *line, unsigned long len, char *buf, int buf_len)
{
    int i, copied = 0;
    
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
static int should_hide_line(const char *line, unsigned long len)
{
    char lower[256];
    int i;
    
    if (!line || len == 0)
        return 0;
    
    for (i = 0; i < len && i < 255; i++) {
        lower[i] = (line[i] >= 'A' && line[i] <= 'Z') ? 
                   line[i] + 0x20 : line[i];
    }
    lower[i < 255 ? i : 255] = '\0';
    
    if (strstr(lower, "anonymous") && strstr(lower, "x"))
        return 1;
    
    if (strstr(lower, "rwx"))
        return 1;
    
    if (strstr(lower, "libart.so") && 
        (strstr(lower, "shared-dirty") || strstr(lower, "private-dirty")))
        return 1;
    
    if (strstr(lower, "lsposed") || strstr(lower, "lspatch") ||
        strstr(lower, "riru") || strstr(lower, "zygisk") ||
        strstr(lower, "xposed") || strstr(lower, "edxposed") ||
        strstr(lower, "liblsp"))
        return 1;
    
    return 0;
}

/* ---------- 过滤 maps ---------- */
static void filter_maps_lines(struct seq_file *m)
{
    char *buf, *src, *dst, *line_start, *line_end;
    unsigned long count, src_pos, dst_pos, remaining, line_len;
    char line_preview[128];
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
            
            if (should_hide_line(line_start, line_len)) {
                hidden_this_time++;
                hidden_count++;
                printk(KERN_INFO "[DuckDetector] 🚫 HIDDEN: %s | Reason: %s\n", 
                       line_preview, get_hide_reason(line_start, line_len));
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
        
        if (should_hide_line(line_start, line_len)) {
            hidden_this_time++;
            hidden_count++;
            printk(KERN_INFO "[DuckDetector] 🚫 HIDDEN: %s | Reason: %s\n", 
                   line_preview, get_hide_reason(line_start, line_len));
        } else {
            if (dst_pos != src_pos)
                memmove(dst + dst_pos, line_start, line_len);
            dst_pos += line_len;
        }
        src_pos += line_len;
    }
    
    if (hidden_this_time > 0) {
        printk(KERN_INFO "[DuckDetector] 📊 This read: %d hidden (total: %d)\n", 
               hidden_this_time, hidden_count);
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
    
    if (!is_duckdetector())
        return;
    
    if (ret <= 0)
        return;
    
    m = (struct seq_file *)file->private_data;
    if (!m)
        return;
    
    printk(KERN_INFO "[DuckDetector] 🔍 PID=%d reading %s\n", 
           task->pid, file->f_path.dentry->d_name.name);
    
    filter_maps_lines(m);
}

/* ---------- proc_reg_read post_handler ---------- */
static void proc_reg_read_post_handler(struct kprobe *p, struct pt_regs *regs,
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
    
    if (!is_duckdetector())
        return;
    
    if (ret <= 0)
        return;
    
    m = (struct seq_file *)file->private_data;
    if (!m)
        return;
    
    printk(KERN_INFO "[DuckDetector] 🔍 PID=%d reading %s (via proc_reg_read)\n", 
           task->pid, file->f_path.dentry->d_name.name);
    
    filter_maps_lines(m);
}

/* ---------- 模块初始化 ---------- */
static int __init duck_bypass_init(void)
{
    int ret;
    int hooks_registered = 0;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "🐤 DuckDetector Bypass (Full Validation)\n");
    printk(KERN_INFO "Target: com.eltavine.duckdetector\n");
    printk(KERN_INFO "========================================\n");
    
    /* 1. 校验所有符号 */
    ret = validate_all_symbols();
    if (ret < 0) {
        printk(KERN_ERR "[DuckDetector] ❌ Symbol validation failed!\n");
        return ret;
    }
    
    /* 2. 注册 seq_read hook */
    if (g_seq_read_addr) {
        memset(&kp_seq_read, 0, sizeof(struct kprobe));
        kp_seq_read.addr = (void *)g_seq_read_addr;
        kp_seq_read.post_handler = seq_read_post_handler;
        
        ret = register_kprobe(&kp_seq_read);
        if (ret == 0) {
            hooks_registered++;
            printk(KERN_INFO "[DuckDetector] ✅ seq_read hook registered\n");
        } else {
            printk(KERN_WARNING "[DuckDetector] ⚠️ seq_read hook failed (err=%d)\n", ret);
        }
    }
    
    /* 3. 注册 proc_reg_read hook（备选） */
    if (g_proc_reg_read_addr) {
        memset(&kp_proc_reg_read, 0, sizeof(struct kprobe));
        kp_proc_reg_read.addr = (void *)g_proc_reg_read_addr;
        kp_proc_reg_read.post_handler = proc_reg_read_post_handler;
        
        ret = register_kprobe(&kp_proc_reg_read);
        if (ret == 0) {
            hooks_registered++;
            printk(KERN_INFO "[DuckDetector] ✅ proc_reg_read hook registered\n");
        } else {
            printk(KERN_WARNING "[DuckDetector] ⚠️ proc_reg_read hook failed (err=%d)\n", ret);
        }
    }
    
    /* 4. 检查是否有任何 hook 成功 */
    if (hooks_registered == 0) {
        printk(KERN_ERR "[DuckDetector] ❌ No hooks registered!\n");
        return -ENOENT;
    }
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "🐤 DuckDetector bypass ACTIVE\n");
    printk(KERN_INFO "📊 %d hook(s) registered\n", hooks_registered);
    printk(KERN_INFO "========================================\n");
    
    return 0;
}

/* ---------- 模块退出 ---------- */
static void __exit duck_bypass_exit(void)
{
    unregister_kprobe(&kp_seq_read);
    unregister_kprobe(&kp_proc_reg_read);
    printk(KERN_INFO "[DuckDetector] 📊 Total hidden: %d entries\n", hidden_count);
    printk(KERN_INFO "[DuckDetector] Bypass unloaded\n");
}

module_init(duck_bypass_init);
module_exit(duck_bypass_exit);