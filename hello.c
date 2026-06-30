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

/* ========== 2. 分别保存两个文件的缓冲区长度 ========== */
static unsigned long pre_count_vfsmnt;
static unsigned long pre_count_mountinfo;

/* ========== 3. kprobe 前置处理：保存当前缓冲区结束位置 ========== */
static int mount_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    unsigned long *pre_ptr = NULL;
    int is_mounts = 0;
    int is_mountinfo = 0;

#if defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#elif defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#else
    m = NULL;
#endif

    if (!m)
        return 0;

    /* 通过文件dentry名称判断是哪个proc文件 */
    if (m->file && m->file->f_path.dentry) {
        const char *name = m->file->f_path.dentry->d_name.name;
        if (strcmp(name, "mounts") == 0)
            is_mounts = 1;
        else if (strcmp(name, "mountinfo") == 0)
            is_mountinfo = 1;
    }

    if (!is_mounts && !is_mountinfo)
        return 0;

    /* 选择对应的计数变量 */
    if (is_mounts)
        pre_ptr = &pre_count_vfsmnt;
    else if (is_mountinfo)
        pre_ptr = &pre_count_mountinfo;

    if (pre_ptr)
        *pre_ptr = m->count;

    return 0;
}

/* ========== 4. kprobe 后置处理：检查新增内容是否包含"图标"，是则回退 ========== */
static void mount_post_handler(struct kprobe *p, struct pt_regs *regs,
                               unsigned long flags)
{
    struct seq_file *m;
    unsigned long pre_count = 0;
    int is_mounts = 0;
    int is_mountinfo = 0;

#if defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#elif defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#else
    m = NULL;
#endif

    if (!m)
        return;

    /* 判断文件类型 */
    if (m->file && m->file->f_path.dentry) {
        const char *name = m->file->f_path.dentry->d_name.name;
        if (strcmp(name, "mounts") == 0)
            is_mounts = 1;
        else if (strcmp(name, "mountinfo") == 0)
            is_mountinfo = 1;
    }

    if (!is_mounts && !is_mountinfo)
        return;

    /* 获取对应的pre_count */
    if (is_mounts)
        pre_count = pre_count_vfsmnt;
    else if (is_mountinfo)
        pre_count = pre_count_mountinfo;

    if (m->count <= pre_count)
        return;

    if (m->buf && strstr(m->buf + pre_count, "图标")) {
        /* 回退缓冲区，丢弃这一行 */
        m->count = pre_count;
    }
}

/* ========== 5. 注册kprobe的辅助函数（不再使用data字段） ========== */
static int register_hook(const char *symbol, struct kprobe *kp)
{
    int ret;

    memset(kp, 0, sizeof(struct kprobe));
    kp->symbol_name = symbol;          /* 内核自动解析，无需kallsyms_lookup_name */
    kp->pre_handler = mount_pre_handler;
    kp->post_handler = mount_post_handler;
    /* 注意：不再设置 kp->data，因为内核6.1已无此字段 */

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

    ret = register_hook("show_vfsmnt", &kp_show_vfsmnt);
    if (ret)
        goto out;

    ret = register_hook("show_mountinfo", &kp_show_mountinfo);
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