#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/tty.h>
#include <linux/string.h>

static struct kprobe kp;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned char *chars;
    size_t size;
    char *data;
    int i;

    /*
     * tty_insert_flip_string_fixed_flag 原型：
     * int tty_insert_flip_string_fixed_flag(struct tty_port *port,
     *                                      const unsigned char *chars,
     *                                      size_t size,
     *                                      char flag)
     * ARM64: x0=port, x1=chars, x2=size, x3=flag
     */
    chars = (unsigned char *)regs->regs[1];
    size = (size_t)regs->regs[2];

    if (chars == NULL || size == 0 || size > 4096)
        return 0;

    data = kmalloc(size + 1, GFP_ATOMIC);
    if (data == NULL)
        return 0;

    /* 直接从内核地址拷贝数据（注意：chars 是内核地址，不需要 copy_from_user） */
    memcpy(data, chars, size);
    data[size] = '\0';

    /* 只打印 NMEA 句子（以 $ 开头） */
    if (data[0] == '$') {
        printk(KERN_INFO "TTY_INSERT_GPS: %s\n", data);
    }

    kfree(data);
    return 0;
}

static int __init kprobe_init(void)
{
    int ret;

    kp.symbol_name = "tty_insert_flip_string_fixed_flag";
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "register_kprobe failed: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "kprobe registered on tty_insert_flip_string_fixed_flag\n");
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