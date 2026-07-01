#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");

static struct kprobe kp;
static unsigned long last_addr = 0;

static void post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct seq_file *m;
    char *buf;
    unsigned long count;
    char line[256];
    int len;
    char *line_end;
    unsigned long vma_start;
    char *perm_pos;
    int i;
    int has_text;
    
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
    
    /* 只取第一行 */
    line_end = memchr(buf, '\n', count);
    if (!line_end)
        return;
    
    len = (int)(line_end - buf);
    if (len > 255)
        len = 255;
    
    memcpy(line, buf, len);
    line[len] = '\0';
    
    /* 提取起始地址用于去重 */
    if (sscanf(line, "%lx", &vma_start) != 1)
        return;
    
    /* 如果地址相同，说明是重复调用，跳过 */
    if (vma_start == last_addr)
        return;
    
    last_addr = vma_start;
    
    /* 检查是否为匿名映射 */
    if (!strstr(line, "00:00 0"))
        return;
    
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
    
    /* 如果有文字（如 [vdso]），放行 */
    if (has_text)
        return;
    
    /* 检查权限：rwxp 或 r-xp */
    if (!strstr(line, "rwxp") && !strstr(line, "r-xp"))
        return;
    
    /* ====== 修改权限 ====== */
    perm_pos = buf;
    
    /* 跳过地址段，找到权限字段 */
    while (perm_pos < line_end && *perm_pos != ' ')
        perm_pos++;
    while (perm_pos < line_end && *perm_pos == ' ')
        perm_pos++;
    while (perm_pos < line_end && *perm_pos != ' ')
        perm_pos++;
    while (perm_pos < line_end && *perm_pos == ' ')
        perm_pos++;
    while (perm_pos < line_end && *perm_pos != ' ')
        perm_pos++;
    while (perm_pos < line_end && *perm_pos == ' ')
        perm_pos++;
    
    /* 替换权限为 r--p */
    if (perm_pos + 4 <= line_end) {
        perm_pos[0] = 'r';
        perm_pos[1] = '-';
        perm_pos[2] = '-';
        perm_pos[3] = 'p';
    }
}

static int __init init(void)
{
    int ret;
    
    last_addr = 0;
    
    memset(&kp, 0, sizeof(struct kprobe));
    kp.symbol_name = "show_map";
    kp.post_handler = post_handler;
    
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "[MAPS] ❌ Failed to hook show_map\n");
        return ret;
    }
    
    printk(KERN_INFO "[MAPS] ✅ Hooked: show_map at %p\n", kp.addr);
    printk(KERN_INFO "[MAPS] Replacing: rwxp → r--p, anonymous r-xp → r--p\n");
    return 0;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "[MAPS] Unloaded\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");