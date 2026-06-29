#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

static struct kprobe kp;
static char **snapshot = NULL;
static int snapshot_count = 0;
static bool snapshot_taken = false;

/* 读取当前挂载点列表 */
static int take_snapshot(void)
{
    struct file *f;
    char *buf;
    char *p;
    int count = 0;
    loff_t pos = 0;
    mm_segment_t old_fs;
    int ret;
    
    f = filp_open("/proc/self/mountinfo", O_RDONLY, 0);
    if (IS_ERR(f)) return -1;
    
    buf = kmalloc(65536, GFP_KERNEL);
    if (!buf) {
        filp_close(f, NULL);
        return -1;
    }
    
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = vfs_read(f, (char __user *)buf, 65535, &pos);
    set_fs(old_fs);
    filp_close(f, NULL);
    
    if (ret <= 0) {
        kfree(buf);
        return -1;
    }
    buf[ret] = '\0';
    
    /* 统计行数 */
    p = buf;
    while (p && *p) {
        char *end = strchr(p, '\n');
        if (end) {
            count++;
            p = end + 1;
        } else {
            break;
        }
    }
    
    snapshot_count = count;
    snapshot = kmalloc(count * sizeof(char *), GFP_KERNEL);
    if (!snapshot) {
        kfree(buf);
        return -1;
    }
    
    /* 保存每一行 */
    count = 0;
    p = buf;
    while (p && *p && count < snapshot_count) {
        char *end = strchr(p, '\n');
        if (end) *end = '\0';
        
        snapshot[count] = kmalloc(strlen(p) + 1, GFP_KERNEL);
        if (snapshot[count]) {
            strcpy(snapshot[count], p);
            count++;
        }
        p = end + 1;
    }
    
    snapshot_taken = true;
    kfree(buf);
    return count;
}

/* 检查是否是新增的挂载点 */
static int is_new_mount(const char *line)
{
    if (!snapshot_taken || !snapshot) return 1;
    
    for (int i = 0; i < snapshot_count; i++) {
        if (snapshot[i] && strcmp(snapshot[i], line) == 0) {
            return 0;  /* 已存在 */
        }
    }
    return 1;  /* 新增的 */
}

/* 拦截 show_mountinfo，过滤掉新增的挂载点 */
static int pre_show_mountinfo(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    char *buf;
    char *p_buf;
    char *new_buf;
    int new_len = 0;
    unsigned long addr;
    
#ifdef CONFIG_ARM64
    m = (struct seq_file *)regs->regs[0];
#else
    m = (struct seq_file *)regs->di;
#endif

    if (!m || !m->buf || !m->count) return 0;
    
    buf = m->buf;
    
    /* 构建新的输出（只包含快照中的挂载点） */
    new_buf = kmalloc(65536, GFP_ATOMIC);
    if (!new_buf) return 0;
    new_buf[0] = '\0';
    
    p_buf = buf;
    while (p_buf && *p_buf) {
        char *end = strchr(p_buf, '\n');
        char line[512];
        int len;
        
        if (end) {
            len = end - p_buf;
            if (len < 512) {
                strncpy(line, p_buf, len);
                line[len] = '\0';
                
                /* 只保留快照中已有的挂载点 */
                if (!is_new_mount(line)) {
                    strcat(new_buf, line);
                    strcat(new_buf, "\n");
                }
            }
            p_buf = end + 1;
        } else {
            break;
        }
    }
    
    /* 替换原有内容 */
    memcpy(buf, new_buf, strlen(new_buf) + 1);
    m->count = strlen(new_buf);
    
    kfree(new_buf);
    return 0;  /* 继续执行，但使用修改后的数据 */
}

static int __init init(void)
{
    int ret;
    
    pr_info("=== 挂载点过滤器 ===\n");
    
    /* 记录当前挂载点快照 */
    ret = take_snapshot();
    if (ret < 0) {
        pr_err("快照失败\n");
        return -ENOENT;
    }
    pr_info("已记录 %d 个挂载点\n", ret);
    
    /* 注册 kprobe */
    kp.pre_handler = pre_show_mountinfo;
    kp.symbol_name = "show_mountinfo";
    
    if (register_kprobe(&kp) == 0) {
        pr_info("✅ 过滤器已启用\n");
        pr_info("  已有挂载: %d 个（显示）\n", snapshot_count);
        pr_info("  新增挂载: 隐藏\n");
        return 0;
    }
    
    pr_err("注册失败\n");
    return -ENOENT;
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
    
    /* 释放快照内存 */
    if (snapshot) {
        for (int i = 0; i < snapshot_count; i++) {
            if (snapshot[i]) kfree(snapshot[i]);
        }
        kfree(snapshot);
    }
    
    pr_info("✅ 过滤器已禁用\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");