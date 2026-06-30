#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Selective Mount Hider");
MODULE_DESCRIPTION("Hide mount points containing '图标' (line-level filter)");

/* ---------- 三个 kprobe ---------- */
static struct kprobe kp_show_vfsmnt;
static struct kprobe kp_show_mountinfo;
static struct kprobe kp_m_show;

/* ---------- 检查一段内存是否包含"图标" (UTF-8: E5 9B BE E6 A0 87) ---------- */
static int contains_icon(const char *buf, unsigned long len)
{
    const unsigned char *p = (const unsigned char *)buf;
    const unsigned char *end = p + len;

    while (p + 6 <= end) {
        if (p[0] == 0xE5 && p[1] == 0x9B && p[2] == 0xBE &&
            p[3] == 0xE6 && p[4] == 0xA0 && p[5] == 0x87) {
            return 1;
        }
        p++;
    }
    return 0;
}

/* ---------- 过滤 seq_file 缓冲区中的行 ---------- */
static void filter_seq_lines(struct seq_file *m)
{
    char *buf = m->buf;
    unsigned long count = m->count;
    char *src = buf;
    char *dst = buf;
    unsigned long src_pos = 0;
    unsigned long dst_pos = 0;
    char *line_end;
    unsigned long remaining;

    while (src_pos < count) {
        remaining = count - src_pos;
        line_end = memchr(src + src_pos, '\n', remaining);
        if (!line_end)
            break;

        unsigned long line_len = (line_end - (src + src_pos)) + 1;
        char *line_start = src + src_pos;

        /* 检查这一行是否包含"图标" */
        if (!contains_icon(line_start, line_len)) {
            /* 保留这一行，必要时移动 */
            if (dst_pos != src_pos) {
                memmove(dst + dst_pos, line_start, line_len);
            }
            dst_pos += line_len;
        }
        /* 否则跳过该行（不复制） */

        src_pos += line_len;
    }

    m->count = dst_pos;
    if (m->count < m->size)
        m->buf[m->count] = '\0';
}

/* ---------- post_handler：钩子触发后过滤缓冲区 ---------- */
static void mount_post_handler(struct kprobe *p, struct pt_regs *regs,
                               unsigned long flags)
{
    struct seq_file *m;

#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#else
    m = NULL;
#endif

    if (!m || !m->buf || m->count == 0)
        return;

    filter_seq_lines(m);
}

/* ---------- 注册辅助 ---------- */
static int register_hook(const char *symbol, struct kprobe *kp)
{
    int ret;

    memset(kp, 0, sizeof(struct kprobe));
    kp->symbol_name = symbol;
    kp->post_handler = mount_post_handler;
    /* 不需要 pre_handler */

    ret = register_kprobe(kp);
    if (ret == 0) {
        printk(KERN_INFO "mount_hide: Hooked %s\n", symbol);
    } else {
        printk(KERN_WARNING "mount_hide: Failed to hook %s (err=%d)\n",
               symbol, ret);
    }
    return ret;
}

/* ---------- 初始化 ---------- */
static int __init mount_hide_init(void)
{
    int ret1, ret2, ret3;
    int success = 0;

    ret1 = register_hook("show_vfsmnt", &kp_show_vfsmnt);
    if (ret1 == 0) success++;

    ret2 = register_hook("show_mountinfo", &kp_show_mountinfo);
    if (ret2 == 0) success++;

    ret3 = register_hook("m_show", &kp_m_show);
    if (ret3 == 0) success++;

    if (success == 0) {
        printk(KERN_ERR "mount_hide: No symbols hooked\n");
        return -ENOENT;
    }

    printk(KERN_INFO "mount_hide: Active, %d hook(s) (filter lines with '图标')\n",
           success);
    return 0;
}

/* ---------- 退出 ---------- */
static void __exit mount_hide_exit(void)
{
    unregister_kprobe(&kp_show_vfsmnt);
    unregister_kprobe(&kp_show_mountinfo);
    unregister_kprobe(&kp_m_show);
    printk(KERN_INFO "mount_hide: Unloaded\n");
}

module_init(mount_hide_init);
module_exit(mount_hide_exit);