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
#include <linux/sched.h>

static struct kprobe kp;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct file *filp;
    char __user *buf;
    size_t len;
    unsigned int fd;
    char *data;
    char *path_buf;
    char *file_path;
    char comm[TASK_COMM_LEN];
    pid_t pid;

    /* __arm64_sys_read: x0=fd, x1=buf, x2=len */
    fd = (unsigned int)regs->regs[0];
    buf = (char __user *)regs->regs[1];
    len = (size_t)regs->regs[2];

    if (len == 0 || len > 4096)
        return 0;

    /* 获取当前进程信息 */
    pid = current->pid;
    get_task_comm(comm, current);

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

    /* 打印系统调用信息 */
    printk(KERN_INFO "===== SYSCALL_READ =====\n");
    printk(KERN_INFO "PID: %d, COMM: %s, FD: %d, LEN: %zu\n", pid, comm, fd, len);
    printk(KERN_INFO "FILE: %s\n", file_path);

    /* 读取数据内容 */
    if (buf != NULL && len > 0) {
        data = kmalloc(len + 1, GFP_ATOMIC);
        if (data != NULL) {
            if (copy_from_user(data, buf, len) == 0) {
                data[len] = '\0';
                /* 打印前 256 字节 */
                printk(KERN_INFO "DATA[%zu]: %s\n", len, data);
                /* 同时打印十六进制（前64字节） */
                print_hex_dump(KERN_INFO, "HEX: ", DUMP_PREFIX_OFFSET, 16, 1,
                               data, min(len, (size_t)64), 1);
            } else {
                printk(KERN_INFO "DATA: failed to copy from user\n");
            }
            kfree(data);
        }
    }

    printk(KERN_INFO "=========================\n");

    kfree(path_buf);
    return 0;
}

static int __init kprobe_init(void)
{
    int ret;

    kp.symbol_name = "__arm64_sys_read";
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "register_kprobe failed: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "kprobe registered on __arm64_sys_read at %p\n", kp.addr);
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
MODULE_AUTHOR("Kprobe GPS Debug");
MODULE_DESCRIPTION("Capture all sys_read calls with data dump");