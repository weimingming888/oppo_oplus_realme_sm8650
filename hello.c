#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/namei.h>

static struct kprobe kp;
static char **snapshot;
static int snapshot_count;
static bool snapshot_taken;

/* 使用 vfs_read 读取文件（不需要 filp_open） */
static int read_file(const char *path, char *buf, size_t size)
{
    struct file *f;
    struct path p;
    int ret;
    loff_t pos;
    mm_segment_t old_fs;
    
    pos = 0;
    
    /* 通过 kern_path 获取路径 */
    ret = kern_path(path, LOOKUP_FOLLOW, &p);
    if (ret < 0) return ret;
    
    f = dentry_open(&p, O_RDONLY, current_cred());
    if (IS_ERR(f)) {
        path_put(&p);
        return PTR_ERR(f);
    }
    
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = vfs_read(f, (char __user *)buf, size - 1, &pos);
    set_fs(old_fs);
    
    filp_close(f, NULL);
    path_put(&p);
    
    if (ret >= 0) {
        buf[ret] = '\0';
    }
    return ret;
}

static int take_snapshot(void)
{
    char *buf;
    char *p;
    char *end;
    int count;
    int ret;
    
    count = 0;
    
    buf = kmalloc(65536, GFP_KERNEL);
    if (!buf) return -1;
    
    ret = read_file("/proc/self/mountinfo", buf, 65536);
    if (ret <= 0) {
        kfree(buf);
        return -1;
    }
    
    /* 统计行数 */
    p = buf;
    while (p && *p) {
        end = strchr(p, '\n');
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
        end = strchr(p, '\n');
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

static int is_new_mount(const char *line)
{
    int i;
    
    if (!snapshot_taken || !snapshot) return 1;
    
    for (i = 0; i < snapshot_count; i++) {
        if (snapshot[i] && strcmp(snapshot[i], line) == 0) {
            return 0;
        }
    }
    return 1;
}

static int pre_show_mountinfo(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    char *buf;
    char *p_buf;
    char *new_buf;
    char *end;
    char line[512];
    int len;
    
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
    
    p_buf = buf;
    while (p_buf && *p_buf) {
        end = strchr(p_buf, '\n');
        if (end) {
            len = end - p_buf;
            if (len < 512) {
                strncpy(line, p_buf, len);
                line[len] = '\0';
                
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
    
    memcpy(buf, new_buf, strlen(new_buf) + 1);
    m->count = strlen(new_buf);
    
    kfree(new_buf);
    return 0;
}

static int __init init(void)
{
    int ret;
    
    pr_info("=== 挂载点过滤器 ===\n");
    
    ret = take_snapshot();
    if (ret < 0) {
        pr_err("快照失败\n");
        return -ENOENT;
    }
    pr_info("已记录 %d 个挂载点\n", ret);
    
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
    int i;
    
    unregister_kprobe(&kp);
    
    if (snapshot) {
        for (i = 0; i < snapshot_count; i++) {
            if (snapshot[i]) kfree(snapshot[i]);
        }
        kfree(snapshot);
    }
    
    pr_info("✅ 过滤器已禁用\n");
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");