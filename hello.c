#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

static struct kprobe kp;

/* kprobe 前处理函数 */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    char __user *buf;
    size_t len;
    char *data;

    /* ARM64: x1=buf, x2=len */
    buf = (char __user *)regs->regs[1];
    len = (size_t)regs->regs[2];

    if (len > 0 && len < 1024) {
        data = kmalloc(len + 1, GFP_ATOMIC);
        if (data != NULL) {
            if (copy_from_user(data, buf, len) == 0) {
                data[len] = '\0';
                printk(KERN_INFO "gnss_read: len=%zu, data=%s\n", len, data);
                print_hex_dump(KERN_INFO, "gnss_raw: ", DUMP_PREFIX_OFFSET,
                               16, 1, data, len, 1);
            }
            kfree(data);
        }
    }

    return 0;
}

/* 模块初始化函数 */
static int __init kprobe_init(void)
{
    int ret;

    kp.symbol_name = "gnss_read";
    kp.pre_handler = handler_pre;
    /* post_handler 和 fault_handler 不需要显式赋值，默认为 NULL */

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "register_kprobe failed: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "kprobe registered on gnss_read\n");
    return 0;
}

/* 模块退出函数 */
static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "kprobe unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");