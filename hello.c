#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");

/* ============================================================
 * kallsyms_lookup_name 地址（已通过 kprobe 验证）
 * ============================================================ */
#define KALLSYMS_LOOKUP_NAME_ADDR 0xffffffdbb6bc1164

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name = NULL;
static struct kprobe kp_seq_read;

/* ---------- 检测 "图标" ---------- */
static int contains_icon(const char *buf, unsigned long len)
{
    const unsigned char *p = (const unsigned char *)buf;
    const unsigned char *end = p + len;
    while (p + 6 <= end) {
        if (p[0] == 0xE5 && p[1] == 0x9B && p[2] == 0xBE &&
            p[3] == 0xE6 && p[4] == 0xA0 && p[5] == 0x87)
            return 1;
        p++;
    }
    return 0;
}

/* ---------- 过滤 seq_file 缓冲区 ---------- */
static void filter_seq_lines(struct seq_file *m)
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
            if (!contains_icon(line_start, line_len)) {
                if (dst_pos != src_pos)
                    memmove(dst + dst_pos, line_start, line_len);
                dst_pos += line_len;
            }
            src_pos = count;
            break;
        }

        line_start = src + src_pos;
        line_len = (unsigned long)(line_end - line_start) + 1;

        if (!contains_icon(line_start, line_len)) {
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

/* ---------- 判断是否为目标文件 ---------- */
static int is_target_file(struct file *file)
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

    if (strcmp(name, "mounts") == 0 || strcmp(name, "mountinfo") == 0)
        return 1;
    return 0;
}

/* ---------- seq_read post_handler ---------- */
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

    if (!file || !is_target_file(file))
        return;

    if (ret <= 0)
        return;

    m = (struct seq_file *)file->private_data;
    if (!m)
        return;

    filter_seq_lines(m);
}

/* ---------- 注册钩子 ---------- */
static int register_hook(const char *symbol, struct kprobe *kp)
{
    void *addr;
    int ret;

    if (!my_kallsyms_lookup_name)
        return -ENOENT;

    addr = (void *)my_kallsyms_lookup_name(symbol);
    if (!addr) {
        printk(KERN_WARNING "mount_hide: %s not found\n", symbol);
        return -ENOENT;
    }

    memset(kp, 0, sizeof(struct kprobe));
    kp->addr = addr;
    kp->post_handler = seq_read_post_handler;

    ret = register_kprobe(kp);
    if (ret == 0) {
        printk(KERN_INFO "mount_hide: Hooked %s at 0x%px\n", symbol, addr);
        return 0;
    } else {
        printk(KERN_WARNING "mount_hide: Failed to hook %s (err=%d)\n", symbol, ret);
        return ret;
    }
}

/* ---------- 初始化 ---------- */
static int __init mount_hide_init(void)
{
    void *addr;
    int ret;

    printk(KERN_INFO "mount_hide: Loading module...\n");

    /* 1. 使用硬编码地址 */
    my_kallsyms_lookup_name = (kallsyms_lookup_name_t)KALLSYMS_LOOKUP_NAME_ADDR;
    printk(KERN_INFO "mount_hide: kallsyms_lookup_name = 0x%lx\n",
           KALLSYMS_LOOKUP_NAME_ADDR);

    /* 2. 验证地址是否有效 */
    addr = (void *)my_kallsyms_lookup_name("filp_open");
    if (!addr) {
        printk(KERN_ERR "mount_hide: kallsyms_lookup_name verification failed!\n");
        return -EINVAL;
    }
    printk(KERN_INFO "mount_hide: Verified! filp_open = 0x%px\n", addr);

    /* 3. 尝试钩住 seq_read */
    ret = register_hook("seq_read", &kp_seq_read);
    if (ret != 0) {
        ret = register_hook("proc_reg_read", &kp_seq_read);
        if (ret != 0) {
            printk(KERN_ERR "mount_hide: No suitable hook found\n");
            return -ENOENT;
        }
    }

    printk(KERN_INFO "mount_hide: Active! Filtering lines with '图标'\n");
    return 0;
}

/* ---------- 退出 ---------- */
static void __exit mount_hide_exit(void)
{
    unregister_kprobe(&kp_seq_read);
    printk(KERN_INFO "mount_hide: Unloaded\n");
}

module_init(mount_hide_init);
module_exit(mount_hide_exit);