#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>

static struct kretprobe krp;

static const char *hide_keywords[] = {
    "/sdcard",
    "/storage", 
    "/mnt",
    "/usb",
    "/pass_through",
    "/user",
    "/图标",
    "123云盘",
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

/* kretprobe - 在 show_mountinfo 执行完后修改输出 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
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
    
    /* 获取第一个参数 (seq_file *) */
#ifdef CONFIG_ARM64
    m = (struct seq_file *)regs->regs[0];
#else
    m = (struct seq_file *)regs->di;
#endif

    if (!m || !m->buf || m->count == 0) return 0;
    
    hidden_count = 0;
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
        pr_info("✅ 过滤了 %d 个挂载点\n", hidden_count);
    }
    
    /* 替换内容 */
    if (total_len > 0) {
        memcpy(buf, new_buf, total_len + 1);
        m->count = total_len;
    } else {
        buf[0] = '\0';
        m->count = 0;
        pr_info("✅ 所有挂载点已被隐藏\n");
    }
    
    kfree(new_buf);
    return 0;
}

static int __init init(void)
{
    int i;
    
    pr_info("=== 挂载点过滤器 (kretprobe) ===\n");
    pr_info("隐藏关键词:\n");
    for (i = 0; hide_keywords[i] != NULL; i++) {
        pr_info("  - %s\n", hide_keywords[i]);
    }
    
    krp.kp.symbol_name = "show_mountinfo";
    krp.handler = ret_handler;
    
    if (register_kretprobe(&krp) == 0) {
        pr_info("✅ show_mountinfo 已拦截 (kretprobe)\n");
        return 0;
    }
    
    pr_err("注册失败\n");
    return -ENOENT;
}

static void __exit exit(void)
{
    unregister_kretprobe(&krp);
    pr_info("✅ 已恢复\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");