#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>

static struct proc_ops orig_mounts_pops;
static struct proc_dir_entry *proc_mounts_de;

// 劫持seq_show，直接返回空，挂载表无内容
static int empty_mounts_show(struct seq_file *m, void *v)
{
    // 不输出任何挂载行，直接空
    return 0;
}

static int empty_mounts_open(struct inode *inode, struct file *file)
{
    return single_open(file, empty_mounts_show, NULL);
}

static struct proc_ops hijack_mounts_pops = {
    .proc_open = empty_mounts_open,
    .proc_release = single_release,
};

static int __init hide_mount_table_init(void)
{
    // 获取 /proc/mounts 目录项
    proc_mounts_de = proc_lookup("mounts", NULL);
    if (!proc_mounts_de) {
        pr_err("get /proc/mounts failed\n");
        return -ENOENT;
    }
    // 保存原始操作集
    memcpy(&orig_mounts_pops, proc_mounts_de->proc_ops, sizeof(struct proc_ops));
    // 替换成空输出回调
    proc_mounts_de->proc_ops = &hijack_mounts_pops;

    pr_info("Mount table hidden, real mount still work\n");
    return 0;
}

static void __exit hide_mount_table_exit(void)
{
    // 恢复原生挂载表输出
    if (proc_mounts_de) {
        proc_mounts_de->proc_ops = &orig_mounts_pops;
    }
    pr_info("Mount table restored\n");
}

module_init(hide_mount_table_init);
module_exit(hide_mount_table_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Test");
MODULE_DESCRIPTION("Hide all entries in /proc/mounts, real mount unchanged");
