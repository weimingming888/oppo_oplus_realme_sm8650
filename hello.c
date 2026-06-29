#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>

static struct kprobe kp;

static const char *hide_keywords[] = {
    "/sdcard",
    "/storage",
    "cpu",
    NULL
};

/* 打印当前挂载信息到内核日志（调试用） */
static void debug_mountinfo(struct seq_file *m)
{
    char *buf;
    char *p_buf;
    char *end;
    char line[256];
    int len;
    
    if (!m || !m->buf || !m->count) {
        pr_info("mountinfo: 空\n");
        return;
    }
    
    buf = m->buf;
    pr_info("=== mountinfo 内容 (%zu 字节) ===\n", m->count);
    
    p_buf = buf;
    while (p_buf && *p_buf) {
        end = strchr(p_buf, '\n');
        if (end) {
            len = end - p_buf;
            if (len < 256) {
                strncpy(line, p_buf, len);
                line[len] = '\0';
                pr_info("  %s\n", line);
            }
            p_buf = end + 1;
        } else {
            break;
        }
    }
}

static int pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    char *buf;
    char *new_buf;
    char *p_buf;
    char *end;
    char line[512];
    int len;
    int total_len;
    int hidden_count;
    
#ifdef CONFIG_ARM64
    m = (struct seq_file *)regs->regs[0];
#else
    m = (struct seq_file *)regs->di;
#endif

    if (!m || !m->buf || !m->count) {
        pr_info("mountinfo: 空或无效\n");
        return 0;
    }
    
    buf = m->buf;
    hidden_count = 0;
    
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
                } else {
                    hidden_count++;
                }
            }
            p_buf = end + 1;
        } else {
            break;
        }
    }
    
    if (hidden_count > 0) {
        pr_info("隐藏了 %d 个挂载点\n", hidden_count);
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
    
    kp.pre_handler = pre_handler;
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
    
    pr_err("所有钩子注册失败\n");
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