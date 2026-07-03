#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched.h>

static struct kprobe kp_read;
static struct kprobe kp_write;
static struct kprobe kp_ioctl;
static struct kprobe kp_open;
static struct kprobe kp_close;

/* ========== read ========== */
static int read_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->regs[0];
    size_t len = (size_t)regs->regs[2];
    char comm[TASK_COMM_LEN];
    get_task_comm(comm, current);
    printk(KERN_INFO "[SYS_READ] PID=%d COMM=%s FD=%d LEN=%zu",
           current->pid, comm, fd, len);
    return 0;
}

/* ========== write ========== */
static int write_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->regs[0];
    size_t len = (size_t)regs->regs[2];
    char comm[TASK_COMM_LEN];
    get_task_comm(comm, current);
    printk(KERN_INFO "[SYS_WRITE] PID=%d COMM=%s FD=%d LEN=%zu",
           current->pid, comm, fd, len);
    return 0;
}

/* ========== ioctl ========== */
static int ioctl_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->regs[0];
    unsigned int cmd = (unsigned int)regs->regs[1];
    char comm[TASK_COMM_LEN];
    get_task_comm(comm, current);
    printk(KERN_INFO "[SYS_IOCTL] PID=%d COMM=%s FD=%d CMD=0x%x",
           current->pid, comm, fd, cmd);
    return 0;
}

/* ========== open ========== */
static int open_pre(struct kprobe *p, struct pt_regs *regs)
{
    const char __user *filename = (const char __user *)regs->regs[0];
    int flags = (int)regs->regs[1];
    char comm[TASK_COMM_LEN];
    char *name_buf;
    get_task_comm(comm, current);

    name_buf = kmalloc(256, GFP_ATOMIC);
    if (name_buf) {
        if (strncpy_from_user(name_buf, filename, 255) > 0) {
            name_buf[255] = '\0';
            printk(KERN_INFO "[SYS_OPEN] PID=%d COMM=%s FILE=%s FLAGS=0x%x",
                   current->pid, comm, name_buf, flags);
        }
        kfree(name_buf);
    }
    return 0;
}

/* ========== close ========== */
static int close_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->regs[0];
    char comm[TASK_COMM_LEN];
    get_task_comm(comm, current);
    printk(KERN_INFO "[SYS_CLOSE] PID=%d COMM=%s FD=%d",
           current->pid, comm, fd);
    return 0;
}

/* ==================================================== */
/* 注册所有探针 */

static int __init kprobe_init(void)
{
    int ret = 0;

    /* read */
    kp_read.symbol_name = "__arm64_sys_read";
    kp_read.pre_handler = read_pre;
    ret = register_kprobe(&kp_read);
    if (ret < 0) {
        /* 如果不行，换 ksys_read */
        kp_read.symbol_name = "ksys_read";
        ret = register_kprobe(&kp_read);
    }
    if (ret == 0)
        printk(KERN_INFO "[KPROBE] registered: read\n");
    else
        printk(KERN_ERR "[KPROBE] FAILED: read\n");

    /* write */
    kp_write.symbol_name = "__arm64_sys_write";
    kp_write.pre_handler = write_pre;
    ret = register_kprobe(&kp_write);
    if (ret < 0) {
        kp_write.symbol_name = "ksys_write";
        ret = register_kprobe(&kp_write);
    }
    if (ret == 0)
        printk(KERN_INFO "[KPROBE] registered: write\n");
    else
        printk(KERN_ERR "[KPROBE] FAILED: write\n");

    /* ioctl */
    kp_ioctl.symbol_name = "__arm64_sys_ioctl";
    kp_ioctl.pre_handler = ioctl_pre;
    ret = register_kprobe(&kp_ioctl);
    if (ret < 0) {
        kp_ioctl.symbol_name = "ksys_ioctl";
        ret = register_kprobe(&kp_ioctl);
    }
    if (ret == 0)
        printk(KERN_INFO "[KPROBE] registered: ioctl\n");
    else
        printk(KERN_ERR "[KPROBE] FAILED: ioctl\n");

    /* open */
    kp_open.symbol_name = "__arm64_sys_open";
    kp_open.pre_handler = open_pre;
    ret = register_kprobe(&kp_open);
    if (ret < 0) {
        kp_open.symbol_name = "__arm64_sys_openat";
        ret = register_kprobe(&kp_open);
    }
    if (ret == 0)
        printk(KERN_INFO "[KPROBE] registered: open\n");
    else
        printk(KERN_ERR "[KPROBE] FAILED: open\n");

    /* close */
    kp_close.symbol_name = "__arm64_sys_close";
    kp_close.pre_handler = close_pre;
    ret = register_kprobe(&kp_close);
    if (ret < 0) {
        kp_close.symbol_name = "ksys_close";
        ret = register_kprobe(&kp_close);
    }
    if (ret == 0)
        printk(KERN_INFO "[KPROBE] registered: close\n");
    else
        printk(KERN_ERR "[KPROBE] FAILED: close\n");

    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp_read);
    unregister_kprobe(&kp_write);
    unregister_kprobe(&kp_ioctl);
    unregister_kprobe(&kp_open);
    unregister_kprobe(&kp_close);
    printk(KERN_INFO "[KPROBE] all unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kprobe test for read/write/ioctl/open/close");