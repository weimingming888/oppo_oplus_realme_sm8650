#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Global Seq Cleaner");
MODULE_DESCRIPTION("Clear ALL /proc/pid/maps at seq_read level");

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
        printk(KERN_INFO "[Cleaner] ✅ %s = 0x%lx\n", name, addr);
    } else {
        printk(KERN_WARNING "[Cleaner] ❌ %s NOT FOUND (err=%d)\n", name, ret);
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

/* ---------- seq_read post_handler：在最终输出前清空 ---------- */
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
    
    /* 清空所有内容 */
    m->count = 0;
    if (m->buf) {
        m->buf[0] = '\0';
    }
    
    printk(KERN_INFO "[Cleaner] 🧹 seq_read cleared maps for PID=%d (%s)\n",
           current->pid, current->comm);
}

/* ---------- 模块初始化 ---------- */
static int __init cleaner_init(void)
{
    int ret;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Cleaner] GLOBAL Seq Read Cleaner\n");
    printk(KERN_INFO "[Cleaner] Will clear ALL /proc/pid/maps\n");
    printk(KERN_INFO "========================================\n");
    
    g_seq_read_addr = get_symbol_addr("seq_read");
    if (!g_seq_read_addr) {
        g_seq_read_addr = get_symbol_addr("proc_reg_read");
    }
    
    if (!g_seq_read_addr) {
        printk(KERN_ERR "[Cleaner] ❌ seq_read not found!\n");
        return -ENOENT;
    }
    
    printk(KERN_INFO "[Cleaner] ✅ seq_read = 0x%lx\n", g_seq_read_addr);
    
    memset(&kp_seq_read, 0, sizeof(struct kprobe));
    kp_seq_read.addr = (void *)g_seq_read_addr;
    kp_seq_read.post_handler = seq_read_post_handler;
    
    ret = register_kprobe(&kp_seq_read);
    if (ret == 0) {
        printk(KERN_INFO "[Cleaner] ✅ Hook registered!\n");
        printk(KERN_INFO "========================================\n");
        printk(KERN_INFO "[Cleaner] 🧹 ALL /proc/pid/maps are now EMPTY\n");
        printk(KERN_INFO "========================================\n");
        return 0;
    } else {
        printk(KERN_ERR "[Cleaner] ❌ Failed to register: %d\n", ret);
        return ret;
    }
}

/* ---------- 模块退出 ---------- */
static void __exit cleaner_exit(void)
{
    unregister_kprobe(&kp_seq_read);
    printk(KERN_INFO "[Cleaner] Unloaded - maps restored\n");
}

module_init(cleaner_init);
module_exit(cleaner_exit);