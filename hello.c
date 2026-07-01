#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Global Maps Cleaner");
MODULE_DESCRIPTION("Clear ALL /proc/pid/maps for entire system");

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
        printk(KERN_INFO "[Cleaner] ✅ %s = 0x%lx\n", name, addr);
    } else {
        printk(KERN_WARNING "[Cleaner] ❌ %s NOT FOUND (err=%d)\n", name, ret);
    }
    
    return addr;
}

/* ---------- show_map post_handler：清空所有进程的 maps ---------- */
static void show_map_post_handler(struct kprobe *p, struct pt_regs *regs,
                                  unsigned long flags)
{
    struct seq_file *m;
    
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
    
    /* 直接清空缓冲区，让 maps 变成空的 */
    m->count = 0;
    if (m->buf) {
        m->buf[0] = '\0';
    }
    
    printk(KERN_INFO "[Cleaner] 🧹 Cleared maps for PID=%d (%s)\n",
           current->pid, current->comm);
}

/* ---------- 模块初始化 ---------- */
static int __init cleaner_init(void)
{
    int ret;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Cleaner] GLOBAL Maps Table Cleaner\n");
    printk(KERN_INFO "[Cleaner] Will clear ALL /proc/pid/maps\n");
    printk(KERN_INFO "========================================\n");
    
    g_show_map_addr = get_symbol_addr("show_map");
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("show_map_vma");
    }
    if (!g_show_map_addr) {
        g_show_map_addr = get_symbol_addr("proc_pid_maps_show");
    }
    
    if (!g_show_map_addr) {
        printk(KERN_ERR "[Cleaner] ❌ show_map not found!\n");
        return -ENOENT;
    }
    
    printk(KERN_INFO "[Cleaner] ✅ show_map = 0x%lx\n", g_show_map_addr);
    
    memset(&kp_show_map, 0, sizeof(struct kprobe));
    kp_show_map.addr = (void *)g_show_map_addr;
    kp_show_map.post_handler = show_map_post_handler;
    
    ret = register_kprobe(&kp_show_map);
    if (ret == 0) {
        printk(KERN_INFO "[Cleaner] ✅ Hook registered!\n");
        printk(KERN_INFO "========================================\n");
        printk(KERN_INFO "[Cleaner] 🧹 ALL /proc/pid/maps are now EMPTY\n");
        printk(KERN_INFO "[Cleaner] ⚠️  This may affect system stability\n");
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
    unregister_kprobe(&kp_show_map);
    printk(KERN_INFO "[Cleaner] Unloaded - maps restored\n");
}

module_init(cleaner_init);
module_exit(cleaner_exit);