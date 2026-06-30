#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Selective Mount Hider");
MODULE_DESCRIPTION("Hide mount points containing '图标' via seq_read");

static struct kprobe kp_seq_read;

/* ---------- 检查 "图标" (UTF-8) ---------- */
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

/* ---------- 过滤 seq_file 缓冲区中的行 ---------- */
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
        if (!line_end)
            break;
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

/* ---------- 判断文件路径是否为 /proc/mounts 或 /proc/self/mountinfo ---------- */
static int is_target_file(struct file *file)
{
    char *path_buf;
    char *path_str;
    struct path p;
    int is_target;

    if (!file)
        return 0;

    p = file->f_path;
    path_buf = (char *)__get_free_page(GFP_KERNEL);
    if (!path_buf)
        return 0;

    path_str = dentry_path_raw(p.dentry, path_buf, PAGE_SIZE);
    is_target = 0;
    if (!IS_ERR(path_str)) {
        if (strstr(path_str, "mounts") || strstr(path_str, "mountinfo"))
            is_target = 1;
    }
    free_page((unsigned long)path_buf);
    return is_target;
}

/* ---------- seq_read 的 post_handler ---------- */
static void seq_read_post_handler(struct kprobe *p, struct pt_regs *regs,
                                  unsigned long flags)
{
    struct file *file;
    struct seq_file *m;
    ssize_t ret;

#if defined(CONFIG_ARM64)
    file = (struct file *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    file = (struct file *)regs->di;
#else
    file = NULL;
#endif

    if (!file)
        return;

    if (!is_target_file(file))
        return;

    m = (struct seq_file *)file->private_data;
    if (!m)
        return;

    /* 获取返回值（读取的字节数） */
#if defined(CONFIG_ARM64)
    ret = (ssize_t)regs->regs[0];
#elif defined(CONFIG_X86_64)
    ret = (ssize_t)regs->ax;
#else
    ret = 0;
#endif

    if (ret <= 0)
        return;

    filter_seq_lines(m);
}

/* ---------- 模块初始化 ---------- */
static int __init mount_hide_init(void)
{
    int ret;
    memset(&kp_seq_read, 0, sizeof(struct kprobe));
    kp_seq_read.symbol_name = "seq_read";
    kp_seq_read.post_handler = seq_read_post_handler;

    ret = register_kprobe(&kp_seq_read);
    if (ret == 0) {
        printk(KERN_INFO "mount_hide: Hooked seq_read successfully\n");
        return 0;
    } else {
        printk(KERN_ERR "mount_hide: Failed to hook seq_read (err=%d)\n", ret);
        return ret;
    }
}

/* ---------- 模块退出 ---------- */
static void __exit mount_hide_exit(void)
{
    unregister_kprobe(&kp_seq_read);
    printk(KERN_INFO "mount_hide: Unloaded\n");
}

module_init(mount_hide_init);
module_exit(mount_hide_exit);