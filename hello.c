#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Selective Mount Hider");
MODULE_DESCRIPTION("Hide mount points containing '图标' (improved)");

/* 两个kprobe结构 */
static struct kprobe kp_show_vfsmnt;
static struct kprobe kp_show_mountinfo;

/* 各自的前置计数 */
static unsigned long pre_count_vfsmnt;
static unsigned long pre_count_mountinfo;

/* ---------- 公用pre_handler（直接记录计数） ---------- */
static int mount_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;

#if defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#elif defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#else
    m = NULL;
#endif

    if (!m)
        return 0;

    /* 根据kprobe指针决定使用哪个全局变量 */
    if (p == &kp_show_vfsmnt) {
        pre_count_vfsmnt = m->count;
    } else if (p == &kp_show_mountinfo) {
        pre_count_mountinfo = m->count;
    }
    return 0;
}

/* ---------- 公用post_handler（检查并回退） ---------- */
static void mount_post_handler(struct kprobe *p, struct pt_regs *regs,
                               unsigned long flags)
{
    struct seq_file *m;
    unsigned long pre_count = 0;

#if defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#elif defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#else
    m = NULL;
#endif

    if (!m)
        return;

    /* 获取对应的pre_count */
    if (p == &kp_show_vfsmnt) {
        pre_count = pre_count_vfsmnt;
    } else if (p == &kp_show_mountinfo) {
        pre_count = pre_count_mountinfo;
    } else {
        return;
    }

    if (m->count <= pre_count)
        return;

    /* 检查新写入的内容是否包含"图标" */
    if (m->buf && strstr(m->buf + pre_count, "图标")) {
        m->count = pre_count;   /* 回退缓冲区 */
    }
}

/* ---------- 注册辅助 ---------- */
static int register_hook(const char *symbol, struct kprobe *kp)
{
    int ret;
    memset(kp, 0, sizeof(struct kprobe));
    kp->symbol_name = symbol;
    kp->pre_handler = mount_pre_handler;
    kp->post_handler = mount_post_handler;

    ret = register_kprobe(kp);
    if (ret == 0) {
        printk(KERN_INFO "mount_hide: Hooked %s\n", symbol);
    } else {
        printk(KERN_WARNING "mount_hide: Failed to hook %s (err=%d)\n", symbol, ret);
    }
    return ret;
}

/* ---------- 初始化 ---------- */
static int __init mount_hide_init(void)
{
    int ret = 0;

    pre_count_vfsmnt = 0;
    pre_count_mountinfo = 0;

    ret = register_hook("show_vfsmnt", &kp_show_vfsmnt);
    if (ret)
        goto out;

    ret = register_hook("show_mountinfo", &kp_show_mountinfo);
    if (ret)
        goto unreg_vfsmnt;

    printk(KERN_INFO "mount_hide: Active (filter: '图标')\n");
    return 0;

unreg_vfsmnt:
    unregister_kprobe(&kp_show_vfsmnt);
out:
    printk(KERN_ERR "mount_hide: Init failed\n");
    return ret;
}

/* ---------- 退出 ---------- */
static void __exit mount_hide_exit(void)
{
    unregister_kprobe(&kp_show_vfsmnt);
    unregister_kprobe(&kp_show_mountinfo);
    printk(KERN_INFO "mount_hide: Unloaded\n");
}

module_init(mount_hide_init);
module_exit(mount_hide_exit);