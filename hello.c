#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

/* ---------- 硬编码 filp_open 地址 ---------- */
#define FILP_OPEN_ADDR 0xffffffdbb6db8144

/* 声明函数指针类型 */
typedef struct file *(*filp_open_t)(const char *, int, int);

/* 全局函数指针 */
static filp_open_t my_filp_open = NULL;

/* ---------- 测试打开文件 ---------- */
static void test_filp_open(void)
{
    struct file *file;
    char *path = "/system/build.prop";
    char *buf;
    loff_t pos = 0;
    ssize_t ret;
    int i;

    /* 初始化函数指针 */
    my_filp_open = (filp_open_t)FILP_OPEN_ADDR;
    if (!my_filp_open) {
        printk(KERN_ERR "Invalid filp_open address\n");
        return;
    }

    /* 打开文件 */
    file = my_filp_open(path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "filp_open failed: %ld\n", PTR_ERR(file));
        return;
    }

    printk(KERN_INFO "filp_open success, file=%p\n", file);

    /* 分配缓冲区 */
    buf = kmalloc(1024, GFP_KERNEL);
    if (!buf) {
        filp_close(file, NULL);
        return;
    }

    /* 读取文件前100字节 */
    ret = kernel_read(file, buf, 100, &pos);
    if (ret > 0) {
        printk(KERN_INFO "Read %ld bytes:\n", ret);
        /* 打印前100字节（十六进制） */
        for (i = 0; i < ret && i < 100; i++) {
            printk(KERN_CONT "%02x ", (unsigned char)buf[i]);
            if ((i + 1) % 16 == 0)
                printk(KERN_CONT "\n");
        }
        printk(KERN_CONT "\n");
    }

    kfree(buf);
    filp_close(file, NULL);
}

/* ---------- 模块初始化 ---------- */
static int __init test_init(void)
{
    printk(KERN_INFO "Test module loaded\n");
    test_filp_open();
    return 0;
}

/* ---------- 模块退出 ---------- */
static void __exit test_exit(void)
{
    printk(KERN_INFO "Test module unloaded\n");
}

module_init(test_init);
module_exit(test_exit);