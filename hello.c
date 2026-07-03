#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/seq_file.h>

static struct kprobe kp_show_map;

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

/* ========== 打印进程内存映射 ========== */
static void print_maps(pid_t pid)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct file *file;
    char *path_buf;
    char *path;
    char flags[5];

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

    mmap_read_lock(mm);

    for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
        flags[0] = (vma->vm_flags & VM_READ) ? 'r' : '-';
        flags[1] = (vma->vm_flags & VM_WRITE) ? 'w' : '-';
        flags[2] = (vma->vm_flags & VM_EXEC) ? 'x' : '-';
        flags[3] = (vma->vm_flags & VM_MAYSHARE) ? 's' : 'p';
        flags[4] = '\0';

        file = vma->vm_file;
        path = NULL;
        if (file != NULL) {
            path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
            if (path_buf != NULL) {
                path = d_path(&file->f_path, path_buf, PATH_MAX);
                if (IS_ERR(path)) {
                    path = NULL;
                    kfree(path_buf);
                }
            }
        }

        printk(KERN_INFO "[MAPS] %016lx-%016lx %s %08lx %s",
               vma->vm_start,
               vma->vm_end,
               flags,
               vma->vm_pgoff,
               path ? path : "");

        if (file != NULL && path != NULL && !IS_ERR(path)) {
            kfree(path);
        }
    }

    mmap_read_unlock(mm);
    printk(KERN_INFO "[MAPS] ========================================");
    printk(KERN_INFO "[MAPS] VMA 数量: %d", mm->map_count);

    put_task_struct(task);
}

/* ========== kprobe 触发函数 ========== */
static int show_map_pre(struct kprobe *p, struct pt_regs *regs)
{
    pid_t pid;

    printk(KERN_INFO "[KPROBE] show_map 被调用");

    pid = find_pid_by_comm(TARGET_COMM);
    if (pid > 0) {
        printk(KERN_INFO "[KPROBE] 找到目标进程: %s (PID=%d)", TARGET_COMM, pid);
        print_maps(pid);
    } else {
        printk(KERN_INFO "[KPROBE] 未找到进程: %s", TARGET_COMM);
    }

    return 0;
}

/* ==================================================== */
static int __init kprobe_init(void)
{
    int ret;
    pid_t pid;

    printk(KERN_INFO "[KPROBE] 🔍 模块加载开始");

    /* 尝试钩住 show_map_vma */
    kp_show_map.symbol_name = "show_map_vma";
    kp_show_map.pre_handler = show_map_pre;

    ret = register_kprobe(&kp_show_map);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ 已钩住 show_map_vma");
        printk(KERN_INFO "[KPROBE] ⚡ 当 show_map_vma 被调用时将触发");
        goto done;
    }

    /* 如果 show_map_vma 失败，尝试 show_map */
    printk(KERN_WARNING "[KPROBE] ⚠️ show_map_vma 注册失败: %d, 尝试 show_map", ret);
    kp_show_map.symbol_name = "show_map";
    ret = register_kprobe(&kp_show_map);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ 已钩住 show_map");
        printk(KERN_INFO "[KPROBE] ⚡ 当 show_map 被调用时将触发");
        goto done;
    }

    printk(KERN_WARNING "[KPROBE] ⚠️ show_map 注册失败: %d", ret);
    printk(KERN_INFO "[KPROBE] 💡 将继续直接打印目标进程的内存映射");

done:
    /* 查找目标进程并打印内存映射 */
    pid = find_pid_by_comm(TARGET_COMM);
    if (pid > 0) {
        printk(KERN_INFO "[KPROBE] ✅ 找到目标进程: %s (PID=%d)", TARGET_COMM, pid);
        print_maps(pid);
    } else {
        printk(KERN_WARNING "[KPROBE] ⚠️ 进程 %s 未找到", TARGET_COMM);
        printk(KERN_INFO "[KPROBE] 💡 启动目标 App 后重新加载本模块");
    }

    printk(KERN_INFO "[KPROBE] 🚀 模块加载完成");
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp_show_map);
    printk(KERN_INFO "[KPROBE] 已卸载");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Print process memory maps via show_map_vma/show_map");