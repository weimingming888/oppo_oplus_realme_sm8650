#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/string.h>

/* ========== C89标准：所有变量声明在函数开头 ========== */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Selective Mount Hider");
MODULE_DESCRIPTION("Hide mount points containing '图标'");

/* ========== 1. 全局kprobe结构 ========== */
static struct kprobe kp_show_vfsmnt;
static struct kprobe kp_show_mountinfo;

/* ========== 2. 保存每个show函数调用前的缓冲区长度 ========== */
static unsigned long pre_count_vfsmnt;
static unsigned long pre_count_mountinfo;

/* ========== 3. kprobe 前置处理：保存当前缓冲区结束位置 ========== */
static int mount_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    unsigned long *pre_ptr;

#if defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#elif defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#else
    m = NULL;
#endif

    if (!m)
        return 0;

    /* 只处理 /proc/mounts 和 /proc/self/mountinfo */
    if (m->file && m->file->f_path.dentry) {
        const char *name = m->file->f_path.dentry->d_name.name;
        if (strcmp(name, "mounts") != 0 && strcmp(name, "mountinfo") != 0) {
            return 0;
        }
    } else {
        return 0;
    }

    /* 保存当前缓冲区的有效数据长度 */
    pre_ptr = (unsigned long *)p->data;
    if (pre_ptr) {
        *pre_ptr = m->count;
    }
    return 0;
}

/* ========== 4. kprobe 后置处理：检查新增内容是否包含"图标"，是则回退 ========== */
static void mount_post_handler(struct kprobe *p, struct pt_regs *regs,
                               unsigned long flags)
{
    struct seq_file *m;
    unsigned long pre_count;

#if defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#elif defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#else
    m = NULL;
#endif

    if (!m)
        return;

    pre_count = *(unsigned long *)p->data;
    if (m->count <= pre_count)
        return;

    if (m->buf && strstr(m->buf + pre_count, "图标")) {
        /* 回退缓冲区，丢弃这一行 */
        m->count = pre_count;
    }
}

/* ========== 5. 注册kprobe的辅助函数 ========== */
static int register_hook(const char *symbol, struct kprobe *kp,
                         unsigned long *data_ptr)
{
    int ret;

    memset(kp, 0, sizeof(struct kprobe));
    kp->symbol_name = symbol;          /* 内核自动解析，无需kallsyms_lookup_name */
    kp->pre_handler = mount_pre_handler;
    kp->post_handler = mount_post_handler;
    kp->data = (void *)data_ptr;       /* 传入计数变量的地址 */

    ret = register_kprobe(kp);
    if (ret == 0) {
        printk(KERN_INFO "mount_hide: Hooked %s successfully\n", symbol);
    } else {
        printk(KERN_WARNING "mount_hide: Failed to hook %s (err=%d)\n",
               symbol, ret);
    }
    return ret;
}

/* ========== 6. 模块初始化 ========== */
static int __init mount_hide_init(void)
{
    int ret = 0;

    pre_count_vfsmnt = 0;
    pre_count_mountinfo = 0;

    ret = register_hook("show_vfsmnt", &kp_show_vfsmnt, &pre_count_vfsmnt);
    if (ret)
        goto out;

    ret = register_hook("show_mountinfo", &kp_show_mountinfo,
                        &pre_count_mountinfo);
    if (ret)
        goto unreg_vfsmnt;

    printk(KERN_INFO "mount_hide: Selective hiding active (filter: '图标')\n");
    return 0;

unreg_vfsmnt:
    unregister_kprobe(&kp_show_vfsmnt);
out:
    printk(KERN_ERR "mount_hide: Initialization failed\n");
    return ret;
}

/* ========== 7. 模块退出 ========== */
static void __exit mount_hide_exit(void)
{
    unregister_kprobe(&kp_show_vfsmnt);
    unregister_kprobe(&kp_show_mountinfo);
    printk(KERN_INFO "mount_hide: Module unloaded, filtering removed\n");
}

module_init(mount_hide_init);
module_exit(mount_hide_exit);