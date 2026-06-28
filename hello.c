#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>

static struct kprobe seq_puts_kp;

// 拦截所有seq输出文本，挂载相关打印直接跳过
static int pre_seq_puts(struct kprobe *p, struct pt_regs *regs)
{
    // 直接返回1，跳过原函数执行，不输出任何字符串
    return 1;
}

static int __init hide_mount_init(void)
{
    int ret;

    seq_puts_kp.symbol_name = "seq_puts";
    seq_puts_kp.pre_handler = pre_seq_puts;

    ret = register_kprobe(&seq_puts_kp);
    if (ret < 0) {
        pr_err("register seq_puts kprobe fail: %d\n", ret);
        return ret;
    }

    pr_info("Mount table hidden loaded\n");
    return 0;
}

static void __exit hide_mount_exit(void)
{
    unregister_kprobe(&seq_puts_kp);
    pr_info("Mount table restored\n");
}

module_init(hide_mount_init);
module_exit(hide_mount_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Test");
MODULE_DESCRIPTION("Hide /proc/mounts output, real mount unchanged");
MODULE_KPROBE();
