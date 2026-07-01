#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShowMap Filter");
MODULE_DESCRIPTION("Filter r-xp 00000000 via show_map");

static struct kprobe kp_show_map;
static unsigned long g_show_map_addr;

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

/* ---------- 检查当前进程是否是 DuckDetector ---------- */
static int is_target_process(void)
{
    struct task_struct *task;
    const char *comm;
    
    task = current;
    if (!task) return 0;
    
    comm = task->comm;
    
    if (strstr(comm, "duckdetector") ||
        strstr(comm, "eltavine") ||
        strstr(comm, "DefaultDispatch") ||
        strstr(comm, "DuckDetector")) {
        return 1;
    }
    return 0;
}

/* ---------- show_map pre_handler ---------- */
static int show_map_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    
    (void)p;
    
    if (!is_target_process()) {
        return 0;
    }
    
#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#else
    m = NULL;
#endif
    
    if (!m || !m->buf) {
        return 0;
    }
    
    return 0;
}

/* ---------- show_map post_handler：过滤 ---------- */
static void show_map_post_handler(struct kprobe *p, struct pt_regs *regs,
                                  unsigned long flags)
{
    struct seq_file *m;
    
    (void)p;
    (void)flags;
    
    if (!is_target_process()) {
        return;
    }
    
#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#else
    m = NULL;
#endif
    
    if (!m || !m->buf || m->count == 0) {
        return;
    }
    
    if (strstr(m->buf, "r-xp 00000000")) {
        m->count = 0;
        m->buf[0] = '\0';
        printk(KERN_INFO "[Filter] 🧹 Filtered r-xp 00000000 for PID=%d\n",
               current->pid);
    }
}

/* ---------- 模块初始化 ---------- */
static int __init filter_init(void)
{
    int ret;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] show_map filter\n");
    printk(KERN_INFO "Target: DuckDetector\n");
    printk(KERN_INFO "========================================\n");
    
    g_show_map_addr = get_symbol_addr("show_map");
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("show_map_vma");
    }
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("proc_pid_maps_show");
    }
    
    if (!g_show_map_addr) {
        printk(KERN_ERR "[Filter] ❌ show_map not found!\n");
        return -ENOENT;
    }
    
    memset(&kp_show_map, 0, sizeof(struct kprobe));
    kp_show_map.addr = (void *)g_show_map_addr;
    kp_show_map.pre_handler = show_map_pre_handler;
    kp_show_map.post_handler = show_map_post_handler;
    
    ret = register_kprobe(&kp_show_map);
    if (ret == 0) {
        printk(KERN_INFO "[Filter] ✅ Hook registered!\n");
        printk(KERN_INFO "========================================\n");
        printk(KERN_INFO "[Filter] 🧹 r-xp 00000000 hidden for DuckDetector\n");
        printk(KERN_INFO "========================================\n");
        return 0;
    }
    
    printk(KERN_ERR "[Filter] ❌ Failed: %d\n", ret);
    return ret;
}

/* ---------- 模块退出 ---------- */
static void __exit filter_exit(void)
{
    unregister_kprobe(&kp_show_map);
    printk(KERN_INFO "[Filter] Unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);