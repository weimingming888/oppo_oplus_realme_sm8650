#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>

static const char *hide_keywords[] = {
    "/sdcard",
    "/storage",
    "cpu",
    "/usb",
    
    NULL
};

/* 在函数使用前先声明 */
static int should_hide(const char *line);

/* 检查是否应该隐藏 */
static int should_hide(const char *line)
{
    int i;
    
    if (!line) return 0;
    
    for (i = 0; hide_keywords[i] != NULL; i++) {
        if (strstr(line, hide_keywords[i])) {
            return 1;
        }
    }
    return 0;
}

/* 通用过滤函数 */
static int filter_mountinfo(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    char *buf;
    char *new_buf;
    char *p_buf;
    char *end;
    char line[512];
    int len;
    int total_len;
    
#ifdef CONFIG_ARM64
    m = (struct seq_file *)regs->regs[0];
#else
    m = (struct seq_file *)regs->di;
#endif

    if (!m || !m->buf || !m->count) return 0;
    
    buf = m->buf;
    
    new_buf = kmalloc(65536, GFP_ATOMIC);
    if (!new_buf) return 0;
    new_buf[0] = '\0';
    total_len = 0;
    
    p_buf = buf;
    while (p_buf && *p_buf) {
        end = strchr(p_buf, '\n');
        if (end) {
            len = end - p_buf;
            if (len < 512) {
                strncpy(line, p_buf, len);
                line[len] = '\0';
                
                if (!should_hide(line)) {
                    strcat(new_buf, line);
                    strcat(new_buf, "\n");
                    total_len += len + 1;
                }
            }
            p_buf = end + 1;
        } else {
            break;
        }
    }
    
    if (total_len > 0) {
        memcpy(buf, new_buf, total_len + 1);
        m->count = total_len;
    } else {
        buf[0] = '\0';
        m->count = 0;
    }
    
    kfree(new_buf);
    return 0;
}

static struct kprobe kp;

static int __init init(void)
{
    int i;
    
    pr_info("=== 挂载点过滤器 ===\n");
    pr_info("隐藏关键词:\n");
    for (i = 0; hide_keywords[i] != NULL; i++) {
        pr_info("  - %s\n", hide_keywords[i]);
    }
    
    kp.pre_handler = filter_mountinfo;
    kp.symbol_name = "show_mountinfo";
    
    if (register_kprobe(&kp) == 0) {
        pr_info("✅ show_mountinfo 已拦截\n");
        return 0;
    }
    
    /* 尝试其他名字 */
    kp.symbol_name = "mounts_show";
    if (register_kprobe(&kp) == 0) {
        pr_info("✅ mounts_show 已拦截\n");
        return 0;
    }
    
    kp.symbol_name = "seq_show_mounts";
    if (register_kprobe(&kp) == 0) {
        pr_info("✅ seq_show_mounts 已拦截\n");
        return 0;
    }
    
    pr_err("所有钩子注册失败\n");
    return -ENOENT;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    pr_info("✅ 过滤器已禁用\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");