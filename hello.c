#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>

#define MAX_HOOKS 10

static struct kprobe kp[MAX_HOOKS];
static int hook_count = 0;

/* 要隐藏的关键词 - 使用精确匹配 */
static const char *hide_keywords[] = {
    "/mnt/user/0/emulated/0/图标",  // ← 精确匹配这条
    "/mnt/installer",
    "/mnt/androidwritable",
    "/storage/emulated",
    "123云盘",
    "/mnt/user",
    "/sdcard",
    "/storage",
    "/mnt",
    "/usb",
    "/pass_through",
    "/图标",
    "fuse",
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

static int filter_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    char *buf;
    char *new_buf;
    char *p_buf;
    char *end;
    char line[1024];  // ← 增大缓冲区
    int len;
    int total_len;
    int hidden_count;
    
#ifdef CONFIG_ARM64
    m = (struct seq_file *)regs->regs[0];
#else
    m = (struct seq_file *)regs->di;
#endif

    if (!m || !m->buf || m->count == 0) return 0;
    
    buf = m->buf;
    
    new_buf = kmalloc(65536, GFP_ATOMIC);
    if (!new_buf) return 0;
    new_buf[0] = '\0';
    total_len = 0;
    hidden_count = 0;
    
    p_buf = buf;
    while (p_buf && *p_buf) {
        end = strchr(p_buf, '\n');
        if (end) {
            len = end - p_buf;
            if (len < 1024) {
                strncpy(line, p_buf, len);
                line[len] = '\0';
                
                /* 调试：打印每行 */
                if (strstr(line, "图标") || strstr(line, "fuse")) {
                    pr_info("🔍 检查行: %s\n", line);
                }
                
                if (!should_hide(line)) {
                    strcat(new_buf, line);
                    strcat(new_buf, "\n");
                    total_len += len + 1;
                } else {
                    hidden_count++;
                    pr_info("✅ 隐藏: %s\n", line);
                }
            }
            p_buf = end + 1;
        } else {
            break;
        }
    }
    
    if (hidden_count > 0) {
        pr_info("隐藏了 %d 个挂载点 (%s)\n", hidden_count, p->symbol_name);
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

static int register_hooks(void)
{
    const char *symbols[] = {
        "show_mountinfo",
        "show_vfsmnt",
        "mounts_show",
        NULL
    };
    
    int i;
    int success = 0;
    
    for (i = 0; symbols[i] != NULL && hook_count < MAX_HOOKS; i++) {
        kp[hook_count].pre_handler = filter_handler;
        kp[hook_count].symbol_name = symbols[i];
        
        if (register_kprobe(&kp[hook_count]) == 0) {
            pr_info("✅ %s 已拦截\n", symbols[i]);
            hook_count++;
            success++;
        }
    }
    
    return success;
}

static int __init init(void)
{
    int i;
    
    pr_info("=== 挂载点过滤器 ===\n");
    pr_info("隐藏关键词:\n");
    for (i = 0; hide_keywords[i] != NULL; i++) {
        pr_info("  - %s\n", hide_keywords[i]);
    }
    
    if (register_hooks() > 0) {
        pr_info("✅ 已启用 (%d 个钩子)\n", hook_count);
        return 0;
    }
    
    pr_err("注册失败\n");
    return -ENOENT;
}

static void __exit exit(void)
{
    int i;
    for (i = 0; i < hook_count; i++) {
        unregister_kprobe(&kp[i]);
    }
    pr_info("✅ 已恢复\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");