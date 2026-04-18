#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>

#define BUF_SIZE 16384
static char g_buf[BUF_SIZE];
static size_t g_len;

static ssize_t read(struct file *file, char __user *buf, size_t cnt, loff_t *ppos)
{
    if (cnt > g_len)
        cnt = g_len;
    if (copy_to_user(buf, g_buf, cnt))
        return -EFAULT;
    return cnt;
}

static ssize_t write(struct file *file, const char __user *buf, size_t cnt, loff_t *ppos)
{
    if (cnt > BUF_SIZE)
        cnt = BUF_SIZE;
    if (copy_from_user(g_buf, buf, cnt))
        return -EFAULT;
    g_len = cnt;
    return cnt;
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .read  = read,
    .write = write,
};

static struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "virt_mic",
    .fops  = &fops,
};

static int __init init(void) {
    misc_register(&misc);
    pr_info("virt_mic: loaded\n");
    return 0;
}

static void __exit exit(void) {
    misc_deregister(&misc);
    pr_info("virt_mic: unloaded\n");
}

module_init(init);
module_exit(exit);

MODULE_LICENSE("GPL");
