#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>

static struct kprobe kp_show_maps;

/* 目标进程名 */
#define TARGET_COMM "com.eltavine.duckdetector"

/* ========== 通过进程名获取 PID ========== */
static pid_t find_pid_by_comm(const char *comm)
{
    struct task_struct *task;
    pid_t pid = -1;

    rcu_read_lock();
    for_each_process(task) {
        if (strcmp(task->comm, comm) == 0) {
            pid = task->pid;
            break;
        }
    }
    rcu_read_unlock();

    return pid;
}

/* ========== 打印进程的内存映射 ========== */
static void print_process_maps(pid_t pid)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    char *buf;
    size_t buf_size = 4096;
    loff_t pos = 0;
    int ret;

    /* 获取 task_struct */
    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task == NULL) {
        rcu_read_unlock();
        printk(KERN_ERR "[MAPS] 找不到进程 PID=%d\n", pid);
        return;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = task->mm;
    if (mm == NULL) {
        printk(KERN_ERR "[MAPS] 进程没有 mm_struct\n");
        put_task_struct(task);
        return;
    }

    printk(KERN_INFO "[MAPS] ========================================");
    printk(KERN_INFO "[MAPS] 进程: %s (PID=%d)", task->comm, pid);
    printk(KERN_INFO "[MAPS] ========================================");

    /* 遍历 VMA */
    down_read(&mm->mmap_lock);
    for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
        char flags[5] = {0};
        char *path = NULL;
        struct file *file = vma->vm_file;

        /* 构建权限标志 */
        flags[0] = (vma->vm_flags & VM_READ) ? 'r' : '-';
        flags[1] = (vma->vm_flags & VM_WRITE) ? 'w' : '-';
        flags[2] = (vma->vm_flags & VM_EXEC) ? 'x' : '-';
        flags[3] = (vma->vm_flags & VM_MAYSHARE) ? 's' : 'p';
        flags[4] = '\0';

        /* 获取文件路径 */
        if (file != NULL) {
            char *path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
            if (path_buf != NULL) {
                path = d_path(&file->f_path, path_buf, PATH_MAX);
                if (IS_ERR(path)) {
                    path = NULL;
                }
                /* 注意：不能在此处 kfree(path_buf)，因为 path 指向它 */
                /* 我们稍后处理 */
            }
        }

        printk(KERN_INFO "[MAPS] %016lx-%016lx %s %08lx %s",
               vma->vm_start,
               vma->vm_end,
               flags,
               vma->vm_pgoff,
               path ? path : "");

        /* 释放路径缓冲区 */
        if (file != NULL) {
            char *path_buf = (char *)path;
            if (path_buf != NULL && !IS_ERR(path_buf)) {
                kfree(path_buf);
            }
        }
    }
    up_read(&mm->mmap_lock);

    printk(KERN_INFO "[MAPS] ========================================");
    printk(KERN_INFO "[MAPS] VMA 数量: %d", mm->map_count);

    put_task_struct(task);
}

/* ========== kprobe 触发函数 ========== */
static int show_maps_pre(struct kprobe *p, struct pt_regs *regs)
{
    pid_t pid;
    char *comm;

    /* show_maps 原型: void show_maps(struct seq_file *m, struct mm_struct *mm) */
    /* 参数在 ARM64: x0=seq_file, x1=mm_struct */

    printk(KERN_INFO "[KPROBE] show_maps 被调用");

    /* 查找目标进程 */
    pid = find_pid_by_comm(TARGET_COMM);
    if (pid > 0) {
        printk(KERN_INFO "[KPROBE] 找到目标进程: %s (PID=%d)", TARGET_COMM, pid);
        print_process_maps(pid);
    } else {
        printk(KERN_INFO "[KPROBE] 未找到进程: %s", TARGET_COMM);
    }

    return 0;
}

/* ==================================================== */
static int __init kprobe_init(void)
{
    int ret;

    /* 方法1：尝试通过符号名 hook show_maps */
    kp_show_maps.symbol_name = "show_maps";
    kp_show_maps.pre_handler = show_maps_pre;

    ret = register_kprobe(&kp_show_maps);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ 已钩住 show_maps");
        printk(KERN_INFO "[KPROBE] 🎯 目标进程: %s", TARGET_COMM);
        printk(KERN_INFO "[KPROBE] ⚡ 当 show_maps 被调用时，将打印目标进程的内存映射");
        return 0;
    }

    printk(KERN_ERR "[KPROBE] ❌ show_maps 注册失败: %d", ret);

    /* 方法2：如果 show_maps 无法钩住，直接在初始化时打印 */
    printk(KERN_INFO "[KPROBE] 🔄 尝试直接打印进程内存映射...");
    pid_t pid = find_pid_by_comm(TARGET_COMM);
    if (pid > 0) {
        print_process_maps(pid);
    } else {
        printk(KERN_ERR "[KPROBE] ❌ 进程 %s 未找到", TARGET_COMM);
    }

    return -1;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp_show_maps);
    printk(KERN_INFO "[KPROBE] 已卸载");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Print process memory maps using show_maps");