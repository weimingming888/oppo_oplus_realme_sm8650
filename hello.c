#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>

static struct kprobe seq_mounts_kp;

// 劫持 mounts 打印函数，直接返回 0 不输出任何挂载行
static int pre_seq_show_mounts(struct kprobe *p, struct pt_regs *regs)
{
    // seq_show 标准传参：regs[0]=seq_file*, regs[1]=v
    struct seq_file *m = (struct seq_file *)regs->regs[0];
    if (!m)
        return 0;

    // 直接跳过原生打印逻辑，返回成功，无任何文本输出
    regs->regs[0] = 0;
    return 1;
}

static int __init hide_mount_table_init(void)
{
    int ret;
    // 内核导出函数：mountinfo/mounts 共用的遍历打印函数
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
MODULE_KPROBE();
MODULE_DESCRIPTION("Mask /proc/mounts & /proc/self/mountinfo output, no modify real mount");
