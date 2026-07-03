#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/string.h>

static struct kprobe kp;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct file *filp;
    char __user *buf;
    size_t len;
    char *data;
    char *path_buf;
    char *file_path;
    unsigned int fd;

    fd = (unsigned int)regs->regs[0];
    buf = (char __user *)regs->regs[1];
    len = (size_t)regs->regs[2];

    if (len == 0 || len > 4096)
        return 0;

    filp = fget(fd);
    if (filp == NULL)
        return 0;

    path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
    if (path_buf == NULL) {
        fput(filp);
        return 0;
    }

    file_path = d_path(&filp->f_path, path_buf, PATH_MAX);
    fput(filp);

    if (IS_ERR(file_path)) {
        kfree(path_buf);
        return 0;
    }

    /* 只过滤 /dev/gpsmdl-nmea */
    if (strstr(file_path, "gpsmdl-nmea") != NULL) {
        data = kmalloc(len + 1, GFP_ATOMIC);
        if (data != NULL) {
            if (copy_from_user(data, buf, len) == 0) {
                data[len] = '\0';
                /* 打印 NMEA 句子（以 $ 开头） */
                if (data[0] == '$') {
                    printk(KERN_INFO "GPS_MD_READ: %s\n", data);
                }
            }
            kfree(data);
        }
    }

    kfree(path_buf);
    return 0;
}

static int __init kprobe_init(void)
{
    int ret;

    /* 使用 sys_read（不区分架构） */
    kp.symbol_name = "sys_read";
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        /* 如果 sys_read 不行，试试 ksys_read */
        kp.symbol_name = "ksys_read";
        ret = register_kprobe(&kp);
        if (ret < 0) {
            printk(KERN_ERR "register_kprobe failed on both sys_read and ksys_read\n");
            return ret;
        }
    }

    printk(KERN_INFO "kprobe registered on %s\n", kp.symbol_name);
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