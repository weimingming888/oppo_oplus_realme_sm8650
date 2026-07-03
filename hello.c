#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

static struct kprobe kp;

// kprobe 的前处理函数
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    char __user *buf;
    size_t len;
    char *data;
    int i;

    // ARM64: x1 是第二个参数 (buf), x2 是第三个参数 (len)
    buf = (char __user *)regs->regs[1];
    len = (size_t)regs->regs[2];

    if (len > 0 && len < 1024) {
        data = kmalloc(len + 1, GFP_ATOMIC);
        if (data) {
            // 从用户空间拷贝数据到内核空间
            if (copy_from_user(data, buf, len) == 0) {
                data[len] = '\0';
                // 打印到内核日志
                printk(KERN_INFO "gnss_read: len=%zu, data=%s\n", len, data);
                // 同时打印十六进制
                print_hex_dump(KERN_INFO, "gnss_raw: ", DUMP_PREFIX_OFFSET, 16, 1, data, len, true);
            }
            kfree(data);
        }
    }

    return 0;
}

static int __init kprobe_init(void)
{
    // 设置要探测的函数名
    kp.symbol_name = "gnss_read";
    kp.pre_handler = handler_pre;

    int ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "register_kprobe failed: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "kprobe registered on gnss_read\n");
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "kprobe unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");