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

static struct kprobe kp_read;
static struct kprobe kp_write;
static struct kprobe kp_ioctl;
static struct kprobe kp_open;
static struct kprobe kp_close;

/* 检查文件描述符对应的设备路径 */
static int is_gps_device(unsigned int fd, char *buf, size_t buf_size)
{
    struct file *filp;
    char *path_buf, *file_path;
    int ret = 0;

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

    if (!IS_ERR(file_path) && strstr(file_path, "gpsmdl-nmea") != NULL) {
        strncpy(buf, file_path, buf_size - 1);
        buf[buf_size - 1] = '\0';
        ret = 1;
    }

    kfree(path_buf);
    return ret;
}

/* ========== read ========== */
static int read_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->regs[0];
    size_t len = (size_t)regs->regs[2];
    char path_buf[256] = {0};
    char comm[TASK_COMM_LEN];

    if (len == 0 || len > 4096)
        return 0;

    if (is_gps_device(fd, path_buf, sizeof(path_buf))) {
        get_task_comm(comm, current);
        printk(KERN_INFO "🎯 [GPS_READ] PID=%d COMM=%s FD=%d LEN=%zu PATH=%s\n",
               current->pid, comm, fd, len, path_buf);
    }
    return 0;
}

/* ========== write ========== */
static int write_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->regs[0];
    char path_buf[256] = {0};
    char comm[TASK_COMM_LEN];

    if (is_gps_device(fd, path_buf, sizeof(path_buf))) {
        get_task_comm(comm, current);
        printk(KERN_INFO "🎯 [GPS_WRITE] PID=%d COMM=%s FD=%d PATH=%s\n",
               current->pid, comm, fd, path_buf);
    }
    return 0;
}

/* ========== ioctl ========== */
static int ioctl_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->regs[0];
    unsigned int cmd = (unsigned int)regs->regs[1];
    char path_buf[256] = {0};
    char comm[TASK_COMM_LEN];

    if (is_gps_device(fd, path_buf, sizeof(path_buf))) {
        get_task_comm(comm, current);
        printk(KERN_INFO "🎯 [GPS_IOCTL] PID=%d COMM=%s FD=%d CMD=0x%x PATH=%s\n",
               current->pid, comm, fd, cmd, path_buf);
    }
    return 0;
}

/* ========== open ========== */
static int open_pre(struct kprobe *p, struct pt_regs *regs)
{
    const char __user *filename = (const char __user *)regs->regs[0];
    char *name_buf;
    char comm[TASK_COMM_LEN];

    name_buf = kmalloc(256, GFP_ATOMIC);
    if (!name_buf)
        return 0;

    if (strncpy_from_user(name_buf, filename, 255) > 0) {
        name_buf[255] = '\0';
        if (strstr(name_buf, "gpsmdl-nmea") != NULL) {
            get_task_comm(comm, current);
            printk(KERN_INFO "🎯 [GPS_OPEN] PID=%d COMM=%s FILE=%s\n",
                   current->pid, comm, name_buf);
        }
    }
    kfree(name_buf);
    return 0;
}

/* ========== close ========== */
static int close_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->regs[0];
    char path_buf[256] = {0};
    char comm[TASK_COMM_LEN];

    if (is_gps_device(fd, path_buf, sizeof(path_buf))) {
        get_task_comm(comm, current);
        printk(KERN_INFO "🎯 [GPS_CLOSE] PID=%d COMM=%s FD=%d PATH=%s\n",
               current->pid, comm, fd, path_buf);
    }
    return 0;
}

/* ==================================================== */
static int __init kprobe_init(void)
{
    int ret = 0;

    kp_read.symbol_name = "__arm64_sys_read";
    kp_read.pre_handler = read_pre;
    ret = register_kprobe(&kp_read);
    if (ret < 0) {
        kp_read.symbol_name = "ksys_read";
        ret = register_kprobe(&kp_read);
    }
    printk(ret == 0 ? KERN_INFO "[KPROBE] ✅ GPS read 监控已启动\n" : KERN_ERR "[KPROBE] ❌ read 注册失败\n");

    kp_write.symbol_name = "__arm64_sys_write";
    kp_write.pre_handler = write_pre;
    ret = register_kprobe(&kp_write);
    if (ret < 0) {
        kp_write.symbol_name = "ksys_write";
        ret = register_kprobe(&kp_write);
    }
    printk(ret == 0 ? KERN_INFO "[KPROBE] ✅ GPS write 监控已启动\n" : KERN_ERR "[KPROBE] ❌ write 注册失败\n");

    kp_ioctl.symbol_name = "__arm64_sys_ioctl";
    kp_ioctl.pre_handler = ioctl_pre;
    ret = register_kprobe(&kp_ioctl);
    if (ret < 0) {
        kp_ioctl.symbol_name = "ksys_ioctl";
        ret = register_kprobe(&kp_ioctl);
    }
    printk(ret == 0 ? KERN_INFO "[KPROBE] ✅ GPS ioctl 监控已启动\n" : KERN_ERR "[KPROBE] ❌ ioctl 注册失败\n");

    kp_open.symbol_name = "__arm64_sys_open";
    kp_open.pre_handler = open_pre;
    ret = register_kprobe(&kp_open);
    if (ret < 0) {
        kp_open.symbol_name = "__arm64_sys_openat";
        ret = register_kprobe(&kp_open);
    }
    printk(ret == 0 ? KERN_INFO "[KPROBE] ✅ GPS open 监控已启动\n" : KERN_ERR "[KPROBE] ❌ open 注册失败\n");

    kp_close.symbol_name = "__arm64_sys_close";
    kp_close.pre_handler = close_pre;
    ret = register_kprobe(&kp_close);
    if (ret < 0) {
        kp_close.symbol_name = "ksys_close";
        ret = register_kprobe(&kp_close);
    }
    printk(ret == 0 ? KERN_INFO "[KPROBE] ✅ GPS close 监控已启动\n" : KERN_ERR "[KPROBE] ❌ close 注册失败\n");

    printk(KERN_INFO "[KPROBE] 🚀 GPS 数据流监控已就绪，等待 /dev/gpsmdl-nmea 被读取...\n");
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp_read);
    unregister_kprobe(&kp_write);
    unregister_kprobe(&kp_ioctl);
    unregister_kprobe(&kp_open);
    unregister_kprobe(&kp_close);
    printk(KERN_INFO "[KPROBE] 所有探针已卸载\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GPS kprobe monitor for /dev/gpsmdl-nmea");