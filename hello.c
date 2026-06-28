#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/version.h>

static struct kprobe seq_mounts_kp;

static int pre_seq_show_mounts(struct kprobe *p, struct pt_regs *regs)
{
    // 在 ARM64 上，函数第一个参数通过 x0 传递
    struct seq_file *m = (struct seq_file *)regs->regs[0];
    if (!m)
        return 0;

    // 直接跳过原始函数执行，并设置返回值为 0 (成功)
    // 在 ARM64 上，返回值通过 x0 传递
    regs->regs[0] = 0;

    // 返回 1 告知 kprobe 跳过原始函数
    return 1;
}

static int __init hide_mount_table_init(void)
{
    int ret;
    // 劫持 mountinfo_show，此函数控制 /proc/mounts 和 /proc/self/mountinfo 的输出
    seq_mounts_kp.symbol_name = "mountinfo_show";
    seq_mounts_kp.pre_handler = pre_seq_show_mounts;

    ret = register_kprobe(&seq_mounts_kp);
    if (ret < 0) {
        pr_err("register kprobe mountinfo_show failed: %d\n", ret);
        return ret;
    }
    pr_info("hide mount table ok, real mount still valid\n");
    return 0;
}

static void __exit hide_mount_table_exit(void)
{
    unregister_kprobe(&seq_mounts_kp);
    pr_info("mount table show restored\n");
}

module_init(hide_mount_table_init);
module_exit(hide_mount_table_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Mask /proc/mounts & /proc/self/mountinfo output, no modify real mount");