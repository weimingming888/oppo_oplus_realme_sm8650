#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");

static struct kprobe kp;

static void post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct seq_file *m;
    char *buf;
    unsigned long count;
    char *line_start, *line_end;
    unsigned long src_pos, dst_pos;
    char *src, *dst;
    unsigned long remaining, line_len;
    char line[256];
    int len;
    int i;
    int has_text;
    int modify;
    char new_perms[5];
    char *perm_pos;
    int spaces;
    
    (void)p;
    (void)flags;
    
#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
#else
    m = NULL;
#endif
    
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
        } else {
            line_start = src + src_pos;
            line_len = (unsigned long)(line_end - line_start) + 1;
        }
        
        /* 复制行用于检查 */
        len = (line_len < 255) ? line_len : 255;
        memcpy(line, line_start, len);
        line[len] = '\0';
        if (len > 0 && line[len-1] == '\n')
            line[len-1] = '\0';
        
        /* 检查是否应该修改权限 */
        modify = 0;
        strcpy(new_perms, "----");
        
        /* 条件1: 匿名映射 (00:00 0) */
        if (strstr(line, "00:00 0")) {
            /* 检查末尾是否有文字 */
            has_text = 0;
            for (i = strlen(line) - 1; i >= 0; i--) {
                if (line[i] == ' ' || line[i] == '\t')
                    continue;
                if (line[i] != '\0') {
                    has_text = 1;
                    break;
                }
            }
            
            /* 如果是纯匿名（末尾无文字） */
            if (!has_text) {
                /* 检查权限：rwxp → r--p */
                if (strstr(line, "rwxp")) {
                    modify = 1;
                    strcpy(new_perms, "r--p");
                }
                /* 检查权限：r-xp → r--p */
                else if (strstr(line, "r-xp")) {
                    modify = 1;
                    strcpy(new_perms, "r--p");
                }
            }
        }
        
        /* 如果需要修改权限 */
        if (modify) {
            /* 在原行中查找权限位置并替换 */
            perm_pos = line_start;
            spaces = 0;
            
            /* 跳过地址段，找到权限字段 */
            while (perm_pos < line_start + line_len && *perm_pos != ' ')
                perm_pos++;
            while (perm_pos < line_start + line_len && *perm_pos == ' ')
                perm_pos++;
            while (perm_pos < line_start + line_len && *perm_pos != ' ')
                perm_pos++;
            while (perm_pos < line_start + line_len && *perm_pos == ' ')
                perm_pos++;
            while (perm_pos < line_start + line_len && *perm_pos != ' ')
                perm_pos++;
            while (perm_pos < line_start + line_len && *perm_pos == ' ')
                perm_pos++;
            
            /* 现在 perm_pos 指向权限字段 */
            if (perm_pos + 4 <= line_start + line_len) {
                /* 替换权限为 r--p */
                perm_pos[0] = 'r';
                perm_pos[1] = '-';
                perm_pos[2] = '-';
                perm_pos[3] = 'p';
            }
        }
        
        /* 保留该行（修改过或未修改的） */
        if (dst_pos != src_pos) {
            memmove(dst + dst_pos, line_start, line_len);
        }
        dst_pos += line_len;
        
        src_pos += line_len;
        
        if (!line_end)
            break;
    }
    
    /* 更新 buffer 大小 */
    m->count = dst_pos;
    if (m->count < m->size) {
        m->buf[m->count] = '\0';
    }
}

static int __init init(void)
{
    int ret;
    const char *symbols[] = {
        "show_map_vma",
        "proc_pid_maps_show",
        "seq_show_map_vma",
        "maps_show",
        "show_map",
        NULL
    };
    int i;
    
    for (i = 0; symbols[i] != NULL; i++) {
        memset(&kp, 0, sizeof(struct kprobe));
        kp.symbol_name = symbols[i];
        kp.post_handler = post_handler;
        
        ret = register_kprobe(&kp);
        if (ret == 0) {
            printk(KERN_INFO "[MAPS] ✅ Hooked: %s\n", symbols[i]);
            printk(KERN_INFO "[MAPS] Replacing: rwxp → r--p, anonymous r-xp → r--p\n");
            return 0;
        }
    }
    
    printk(KERN_ERR "[MAPS] ❌ Failed to register kprobe\n");
    return -1;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "[MAPS] Unloaded\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");