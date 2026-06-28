#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/version.h>

static struct kprobe seq_mounts_kp;

static int pre_seq_show_mounts(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m = (struct seq_file *)regs->regs[0];
    if (!m)
        return 0;

    pr_info("kprobe: hijacking mountinfo_show\n");
    regs->regs[0] = 0;
    return 1;
}

static int __init hide_mount_table_init(void)
{
    int ret;

    pr_info("Loading hide_mount module...\n");

    // 尝试多个可能的函数名
    const char *symbols[] = {
        "mountinfo_show",
        "show_mountinfo",
        "show_vfsmnt",
        "mounts_show",
        NULL
    };

    for (int i = 0; symbols[i] != NULL; i++) {
        seq_mounts_kp.symbol_name = symbols[i];
        ret = register_kprobe(&seq_mounts_kp);
        if (ret == 0) {
            pr_info("Successfully hooked: %s\n", symbols[i]);
            return 0;
        }
        pr_warn("Failed to hook %s: %d\n", symbols[i], ret);
    }

    pr_err("Failed to hook any mount show function\n");
    return -ENOENT;
}

static void __exit hide_mount_table_exit(void)
{
    unregister_kprobe(&seq_mounts_kp);
    pr_info("mount table show restored\n");
}

module_init(hide_mount_table_init);
module_exit(hide_mount_table_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Mask /proc/mounts & /proc/self/mountinfo output");
MODULE_AUTHOR("Your Name");