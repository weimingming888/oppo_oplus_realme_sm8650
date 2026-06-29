#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>

static struct kprobe kp;

static const char *hide_keywords[] = {
    "/sdcard",
    "/storage",
    "/mnt",
    "/usb",
    NULL
};

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

static int __init init(void)
{
    pr_info("=== 挂载点过滤器 ===\n");
    
    /* 拦截显示函数，不是 do_mount！ */
    kp.pre_handler = filter_mountinfo;
    kp.symbol_name = "show_mountinfo";  // ← 显示挂载表
    
    if (register_kprobe(&kp) == 0) {
        pr_info("✅ show_mountinfo 已拦截\n");
        return 0;
    }
    
    /* 尝试其他显示函数 */
    kp.symbol_name = "mounts_show";
    if (register_kprobe(&kp) == 0) {
        pr_info("✅ mounts_show 已拦截\n");
        return 0;
    }
    
    pr_err("找不到挂载显示函数\n");
    return -ENOENT;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    pr_info("✅ 已恢复\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");