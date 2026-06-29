#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

/* 定义函数指针类型 */
typedef struct file *(*filp_open_t)(const char *, int, umode_t);
typedef int (*filp_close_t)(struct file *, fl_owner_t);
typedef ssize_t (*kernel_read_t)(struct file *, void *, size_t, loff_t *);

static filp_open_t my_filp_open = NULL;
static filp_close_t my_filp_close = NULL;
static kernel_read_t my_kernel_read = NULL;

/* 读取文件内容并打印 */
static void read_file_content(struct file *file)
{
    char *buf;
    ssize_t ret;
    loff_t pos = 0;
    
    if (!file || !my_kernel_read)
        return;
    
    buf = kmalloc(256, GFP_KERNEL);
    if (!buf) {
        printk(KERN_ERR "Failed to allocate buffer\n");
        return;
    }
    
    ret = my_kernel_read(file, buf, 255, &pos);
    if (ret > 0) {
        buf[ret] = '\0';
        printk(KERN_INFO "File content: %s\n", buf);
    } else {
        printk(KERN_ERR "Read failed: %zd\n", ret);
    }
    
    kfree(buf);
}

/* 模块初始化函数 */
static int __init file_open_test_init(void)
{
    struct file *file;
    const char *path = "/data/local/tmp/test.txt";
    
    printk(KERN_INFO "File open test module loaded\n");
    
    /* 查找符号地址 */
    my_filp_open = (filp_open_t)kallsyms_lookup_name("filp_open");
    my_filp_close = (filp_close_t)kallsyms_lookup_name("filp_close");
    my_kernel_read = (kernel_read_t)kallsyms_lookup_name("kernel_read");
    
    if (!my_filp_open) {
        printk(KERN_ERR "filp_open not found\n");
        return -EFAULT;
    }
    if (!my_filp_close) {
        printk(KERN_ERR "filp_close not found\n");
        return -EFAULT;
    }
    if (!my_kernel_read) {
        printk(KERN_WARNING "kernel_read not found, trying vfs_read\n");
        my_kernel_read = (kernel_read_t)kallsyms_lookup_name("vfs_read");
        if (!my_kernel_read) {
            printk(KERN_ERR "vfs_read not found either\n");
            return -EFAULT;
        }
    }
    
    printk(KERN_INFO "Symbols found: filp_open=0x%p, filp_close=0x%p, read=0x%p\n",
           my_filp_open, my_filp_close, my_kernel_read);
    
    /* 打开文件 */
    file = my_filp_open(path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open file: %ld\n", PTR_ERR(file));
        return -ENOENT;
    }
    
    printk(KERN_INFO "File opened successfully: %p\n", file);
    
    /* 读取文件内容 */
    read_file_content(file);
    
    /* 关闭文件 */
    my_filp_close(file, NULL);
    printk(KERN_INFO "File closed\n");
    
    return 0;
}

/* 模块清理函数 */
static void __exit file_open_test_exit(void)
{
    printk(KERN_INFO "File open test module unloaded\n");
}

module_init(file_open_test_init);
module_exit(file_open_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Test");
MODULE_DESCRIPTION("Test file open via kallsyms");