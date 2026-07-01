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
MODULE_AUTHOR("Debug Hook");
MODULE_DESCRIPTION("Debug: find which function reads /proc/maps");

/* ---------- 全局变量 ---------- */
static struct kprobe kp_seq_read;
static struct kprobe kp_proc_reg_read;
static struct kprobe kp_show_map;
static struct kprobe kp_vfs_read;

static unsigned long g_seq_read_addr;
static unsigned long g_proc_reg_read_addr;
static unsigned long g_show_map_addr;
static unsigned long g_vfs_read_addr;

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
        printk(KERN_INFO "[DEBUG] ✅ %s = 0x%lx\n", name, addr);
    } else {
        printk(KERN_WARNING "[DEBUG] ❌ %s NOT FOUND (err=%d)\n", name, ret);
    }
    
    return addr;
}

/* ---------- 检查文件名是否是 maps ---------- */
static int is_maps_file(struct file *file)
{
    struct dentry *dentry;
    const char *name;
    int result;
    
    result = 0;
    
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
        result = 1;
    }
    
    return result;
}

/* ---------- 打印进程信息 ---------- */
static void log_access(const char *hook_name, struct file *file, ssize_t ret)
{
    struct task_struct *task;
    char comm[32];
    const char *filename;
    struct dentry *dentry;
    int i;
    
    task = current;
    if (!task) {
        return;
    }
    
    for (i = 0; i < 31 && i < sizeof(task->comm); i++) {
        comm[i] = task->comm[i];
        if (comm[i] == '\0') {
            break;
        }
    }
    comm[31] = '\0';
    
    filename = "unknown";
    if (file && file->f_path.dentry) {
        dentry = file->f_path.dentry;
        if (dentry->d_name.name) {
            filename = dentry->d_name.name;
        }
    }
    
    printk(KERN_INFO "[DEBUG] 🔍 %s: PID=%d (%s) file=%s ret=%ld\n",
           hook_name, task->pid, comm, filename, (long)ret);
}

/* ---------- seq_read post_handler ---------- */
static void seq_read_post_handler(struct kprobe *p, struct pt_regs *regs,
                                  unsigned long flags)
{
    struct file *file;
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
    
    log_access("seq_read", file, ret);
}

/* ---------- proc_reg_read post_handler ---------- */
static void proc_reg_read_post_handler(struct kprobe *p, struct pt_regs *regs,
                                       unsigned long flags)
{
    struct file *file;
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
    
    log_access("proc_reg_read", file, ret);
}

/* ---------- show_map post_handler ---------- */
static void show_map_post_handler(struct kprobe *p, struct pt_regs *regs,
                                  unsigned long flags)
{
    struct seq_file *m;
    struct file *file;
    
    (void)p;
    (void)flags;
    
#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#else
    m = NULL;
#endif
    
    if (!m) {
        return;
    }
    
    file = (struct file *)m->file;
    if (!file) {
        return;
    }
    
    if (!is_maps_file(file)) {
        return;
    }
    
    log_access("show_map", file, 0);
}

/* ---------- vfs_read post_handler ---------- */
static void vfs_read_post_handler(struct kprobe *p, struct pt_regs *regs,
                                  unsigned long flags)
{
    struct file *file;
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
    
    log_access("vfs_read", file, ret);
}

/* ---------- 注册所有钩子 ---------- */
static int register_all_hooks(void)
{
    int ret;
    int registered;
    
    registered = 0;
    
    if (g_seq_read_addr) {
        memset(&kp_seq_read, 0, sizeof(struct kprobe));
        kp_seq_read.addr = (void *)g_seq_read_addr;
        kp_seq_read.post_handler = seq_read_post_handler;
        ret = register_kprobe(&kp_seq_read);
        if (ret == 0) {
            registered++;
            printk(KERN_INFO "[DEBUG] ✅ seq_read hook registered\n");
        }
    }
    
    if (g_proc_reg_read_addr) {
        memset(&kp_proc_reg_read, 0, sizeof(struct kprobe));
        kp_proc_reg_read.addr = (void *)g_proc_reg_read_addr;
        kp_proc_reg_read.post_handler = proc_reg_read_post_handler;
        ret = register_kprobe(&kp_proc_reg_read);
        if (ret == 0) {
            registered++;
            printk(KERN_INFO "[DEBUG] ✅ proc_reg_read hook registered\n");
        }
    }
    
    if (g_show_map_addr) {
        memset(&kp_show_map, 0, sizeof(struct kprobe));
        kp_show_map.addr = (void *)g_show_map_addr;
        kp_show_map.post_handler = show_map_post_handler;
        ret = register_kprobe(&kp_show_map);
        if (ret == 0) {
            registered++;
            printk(KERN_INFO "[DEBUG] ✅ show_map hook registered\n");
        }
    }
    
    if (g_vfs_read_addr) {
        memset(&kp_vfs_read, 0, sizeof(struct kprobe));
        kp_vfs_read.addr = (void *)g_vfs_read_addr;
        kp_vfs_read.post_handler = vfs_read_post_handler;
        ret = register_kprobe(&kp_vfs_read);
        if (ret == 0) {
            registered++;
            printk(KERN_INFO "[DEBUG] ✅ vfs_read hook registered\n");
        }
    }
    
    return registered;
}

/* ---------- 模块初始化 ---------- */
static int __init debug_init(void)
{
    int registered;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[DEBUG] Finding all possible read functions\n");
    printk(KERN_INFO "========================================\n");
    
    g_seq_read_addr = get_symbol_addr("seq_read");
    g_proc_reg_read_addr = get_symbol_addr("proc_reg_read");
    g_show_map_addr = get_symbol_addr("show_map");
    
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("show_map_vma");
    }
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("proc_pid_maps_show");
    }
    
    g_vfs_read_addr = get_symbol_addr("vfs_read");
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[DEBUG] Registering hooks...\n");
    printk(KERN_INFO "========================================\n");
    
    registered = register_all_hooks();
    
    if (registered == 0) {
        printk(KERN_ERR "[DEBUG] ❌ No hooks registered!\n");
        return -ENOENT;
    }
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[DEBUG] %d hook(s) registered\n", registered);
    printk(KERN_INFO "[DEBUG] Now open DuckDetector and check dmesg\n");
    printk(KERN_INFO "========================================\n");
    
    return 0;
}

/* ---------- 模块退出 ---------- */
static void __exit debug_exit(void)
{
    unregister_kprobe(&kp_seq_read);
    unregister_kprobe(&kp_proc_reg_read);
    unregister_kprobe(&kp_show_map);
    unregister_kprobe(&kp_vfs_read);
    printk(KERN_INFO "[DEBUG] Debug hooks unloaded\n");
}

module_init(debug_init);
module_exit(debug_exit);