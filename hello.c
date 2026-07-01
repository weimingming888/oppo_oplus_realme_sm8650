#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Global Memory Map Hider");
MODULE_DESCRIPTION("Hide anonymous executable mappings globally");

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

/* ---------- 检查当前进程是否为第三方 App ---------- */
static int is_third_party_app(void)
{
    struct task_struct *task = current;
    const char *comm;
    
    if (!task)
        return 0;
    
    comm = task->comm;
    
    /* 排除系统进程（PID < 1000 或名称包含系统关键字） */
    if (task->pid < 1000)
        return 0;
    
    /* 排除系统进程名关键字 */
    if (strstr(comm, "system") ||
        strstr(comm, "server") ||
        strstr(comm, "zygote") ||
        strstr(comm, "init") ||
        strstr(comm, "kernel") ||
        strstr(comm, "rcu") ||
        strstr(comm, "kworker") ||
        strstr(comm, "ksoftirqd") ||
        strstr(comm, "kthreadd") ||
        strstr(comm, "watchdog") ||
        strstr(comm, "migration") ||
        strstr(comm, "irq") ||
        strstr(comm, "binder") ||
        strstr(comm, "logd") ||
        strstr(comm, "vold") ||
        strstr(comm, "netd") ||
        strstr(comm, "surfaceflinger") ||
        strstr(comm, "android") ||
        strstr(comm, "audioserver") ||
        strstr(comm, "cameraserver") ||
        strstr(comm, "drm") ||
        strstr(comm, "gatekeeper") ||
        strstr(comm, "healthd") ||
        strstr(comm, "lmkd") ||
        strstr(comm, "mediaserver") ||
        strstr(comm, "perfd")) {
        return 0;
    }
    
    /* 排除系统 App（包名以 com.android. 开头） */
    if (strstr(comm, "com.android."))
        return 0;
    
    /* 排除 Google 服务 */
    if (strstr(comm, "com.google."))
        return 0;
    
    return 1;  /* 是第三方 App */
}

/* ---------- 检查一行 maps 是否应该被隐藏 ---------- */
static int should_hide_map_line(const char *line, unsigned long len)
{
    char lower_line[256];
    int i;
    
    if (!line || len == 0)
        return 0;
    
    /* 复制并转小写 */
    for (i = 0; i < len && i < 255; i++) {
        lower_line[i] = (line[i] >= 'A' && line[i] <= 'Z') ? 
                         line[i] + 0x20 : line[i];
    }
    lower_line[i < 255 ? i : 255] = '\0';
    
    /* 1. 隐藏匿名可执行映射（LSPosed 注入代码） */
    if (strstr(lower_line, "anonymous") && strstr(lower_line, "x")) {
        return 1;
    }
    
    /* 2. 隐藏 RWX 映射（危险权限） */
    if (strstr(lower_line, "rwxp") || strstr(lower_line, "rwx")) {
        return 1;
    }
    
    /* 3. 隐藏 libart.so 的脏页（被 hook 的痕迹） */
    if (strstr(lower_line, "libart.so") && 
        (strstr(lower_line, "shared-dirty") || 
         strstr(lower_line, "private-dirty"))) {
        return 1;
    }
    
    /* 4. 隐藏只有执行权限的匿名映射 */
    if (strstr(lower_line, "anonymous") && 
        strstr(lower_line, "---p") == NULL &&
        strstr(lower_line, "rw-p") == NULL &&
        strstr(lower_line, "r--p") == NULL) {
        return 1;
    }
    
    /* 5. 隐藏 liblspd 相关库（如果有） */
    if (strstr(lower_line, "liblsp") ||
        strstr(lower_line, "lspatch") ||
        strstr(lower_line, "riru") ||
        strstr(lower_line, "zygisk")) {
        return 1;
    }
    
    return 0;
}

/* ---------- 过滤 maps 内容 ---------- */
static void filter_maps_lines(struct seq_file *m)
{
    char *buf, *src, *dst, *line_start, *line_end;
    unsigned long count, src_pos, dst_pos, remaining, line_len;
    
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
            if (!should_hide_map_line(line_start, line_len)) {
                if (dst_pos != src_pos)
                    memmove(dst + dst_pos, line_start, line_len);
                dst_pos += line_len;
            }
            src_pos = count;
            break;
        }
        
        line_start = src + src_pos;
        line_len = (unsigned long)(line_end - line_start) + 1;
        
        if (!should_hide_map_line(line_start, line_len)) {
            if (dst_pos != src_pos)
                memmove(dst + dst_pos, line_start, line_len);
            dst_pos += line_len;
        }
        src_pos += line_len;
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
        strstr(name, "maps") == name) {
        return 1;
    }
    
    return 0;
}

/* ---------- seq_read post_handler ---------- */
static struct kprobe kp_seq_read;

static void seq_read_post_handler(struct kprobe *p, struct pt_regs *regs,
                                  unsigned long flags)
{
    struct file *file;
    struct seq_file *m;
    ssize_t ret;
    
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
    
    /* 全局模式：只检查当前进程是否是第三方 App */
    if (!is_third_party_app())
        return;
    
    if (ret <= 0)
        return;
    
    m = (struct seq_file *)file->private_data;
    if (!m)
        return;
    
    filter_maps_lines(m);
}

/* ---------- 模块初始化 ---------- */
static int __init memory_hide_init(void)
{
    unsigned long addr;
    int ret;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "Global Memory Map Hider\n");
    printk(KERN_INFO "Protecting ALL third-party apps\n");
    printk(KERN_INFO "========================================\n");
    
    /* 获取 seq_read 地址 */
    addr = get_symbol_addr("seq_read");
    if (!addr) {
        addr = get_symbol_addr("proc_reg_read");
        if (!addr) {
            printk(KERN_ERR "❌ No suitable symbol found\n");
            return -ENOENT;
        }
    }
    
    printk(KERN_INFO "✅ Hook target at 0x%lx\n", addr);
    
    /* 注册 kprobe */
    memset(&kp_seq_read, 0, sizeof(struct kprobe));
    kp_seq_read.addr = (void *)addr;
    kp_seq_read.post_handler = seq_read_post_handler;
    
    ret = register_kprobe(&kp_seq_read);
    if (ret == 0) {
        printk(KERN_INFO "✅ Hooked successfully!\n");
        printk(KERN_INFO "========================================\n");
        printk(KERN_INFO "All third-party apps are now protected\n");
        printk(KERN_INFO "Anonymous executable maps will be hidden\n");
        printk(KERN_INFO "========================================\n");
        return 0;
    } else {
        printk(KERN_ERR "❌ Failed to hook: %d\n", ret);
        return ret;
    }
}

/* ---------- 模块退出 ---------- */
static void __exit memory_hide_exit(void)
{
    unregister_kprobe(&kp_seq_read);
    printk(KERN_INFO "Global Memory Map Hider unloaded\n");
}

module_init(memory_hide_init);
module_exit(memory_hide_exit);