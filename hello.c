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

static struct kprobe kp_show_maps;

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

/* ========== 获取进程的 mm_struct ========== */
static struct mm_struct *get_task_mm_struct(pid_t pid)
{
    struct task_struct *task;
    struct mm_struct *mm = NULL;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task != NULL) {
        get_task_struct(task);
        mm = task->mm;
        if (mm != NULL) {
            mmget(mm);
        }
        put_task_struct(task);
    }
    rcu_read_unlock();

    return mm;
}

/* ========== 通过 show_maps 打印进程内存映射 ========== */
static void print_maps_via_show_maps(pid_t pid)
{
    struct mm_struct *mm;
    struct seq_file *seq;
    char *buf;
    loff_t pos = 0;
    int ret;

    mm = get_task_mm_struct(pid);
    if (mm == NULL) {
        printk(KERN_ERR "[MAPS] 无法获取 mm_struct\n");
        return;
    }

    printk(KERN_INFO "[MAPS] ========================================");
    printk(KERN_INFO "[MAPS] 通过 show_maps 打印进程 %s (PID=%d) 的内存映射", TARGET_COMM, pid);
    printk(KERN_INFO "[MAPS] ========================================");

    /* 创建 seq_file 缓冲区 */
    buf = kmalloc(16384, GFP_ATOMIC);
    if (buf == NULL) {
        mmput(mm);
        printk(KERN_ERR "[MAPS] 内存分配失败\n");
        return;
    }

    seq = kmalloc(sizeof(struct seq_file), GFP_ATOMIC);
    if (seq == NULL) {
        kfree(buf);
        mmput(mm);
        printk(KERN_ERR "[MAPS] seq_file 分配失败\n");
        return;
    }

    /* 初始化 seq_file */
    memset(seq, 0, sizeof(struct seq_file));
    seq->buf = buf;
    seq->size = 16384;
    seq->count = 0;

    /* 直接调用 show_maps (内核符号) */
    /* void show_maps(struct seq_file *m, struct mm_struct *mm) */
    show_maps(seq, mm);

    /* 打印结果 */
    if (seq->count > 0) {
        buf[seq->count] = '\0';
        printk(KERN_INFO "[MAPS]\n%s", buf);
    } else {
        printk(KERN_INFO "[MAPS] 没有输出 (show_maps 可能未产生数据)");
    }

    printk(KERN_INFO "[MAPS] ========================================");

    kfree(seq->buf);
    kfree(seq);
    mmput(mm);
}

/* ========== kprobe 触发函数 ========== */
static int show_maps_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *seq;
    struct mm_struct *mm;
    pid_t pid;

    /* show_maps 原型: void show_maps(struct seq_file *m, struct mm_struct *mm) */
    /* ARM64: x0=seq_file, x1=mm_struct */
    seq = (struct seq_file *)regs->regs[0];
    mm = (struct mm_struct *)regs->regs[1];

    printk(KERN_INFO "[KPROBE] show_maps 被调用 (seq=%p, mm=%p)", seq, mm);

    pid = find_pid_by_comm(TARGET_COMM);
    if (pid > 0) {
        printk(KERN_INFO "[KPROBE] 找到目标进程: %s (PID=%d)", TARGET_COMM, pid);
        /* 打印当前 show_maps 调用的进程信息 */
        if (mm != NULL) {
            struct task_struct *task = mm->owner;
            if (task != NULL) {
                printk(KERN_INFO "[KPROBE] show_maps 正在打印进程: %s (PID=%d)",
                       task->comm, task->pid);
                /* 如果是目标进程，额外打印完整信息 */
                if (strcmp(task->comm, TARGET_COMM) == 0) {
                    printk(KERN_INFO "[KPROBE] ✅ 目标进程内存映射开始...");
                }
            }
        }
    }

    return 0;
}

/* ==================================================== */
static int __init kprobe_init(void)
{
    int ret;
    pid_t pid;

    printk(KERN_INFO "[KPROBE] 🔍 模块加载开始");

    /* 检查 show_maps 符号是否存在 */
    kp_show_maps.symbol_name = "show_maps";
    kp_show_maps.pre_handler = show_maps_pre;

    ret = register_kprobe(&kp_show_maps);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ 已钩住 show_maps (地址: %p)", kp_show_maps.addr);
        printk(KERN_INFO "[KPROBE] ⚡ 当 show_maps 被调用时将触发");
    } else {
        printk(KERN_ERR "[KPROBE] ❌ show_maps 注册失败: %d", ret);
        printk(KERN_INFO "[KPROBE] 💡 提示: 符号可能不存在或内核未导出");
        return -1;
    }

    /* 查找目标进程并手动触发打印 */
    pid = find_pid_by_comm(TARGET_COMM);
    if (pid > 0) {
        printk(KERN_INFO "[KPROBE] ✅ 找到目标进程: %s (PID=%d)", TARGET_COMM, pid);
        /* 直接调用 show_maps 打印目标进程的内存映射 */
        print_maps_via_show_maps(pid);
    } else {
        printk(KERN_WARNING "[KPROBE] ⚠️ 进程 %s 未找到", TARGET_COMM);
        printk(KERN_INFO "[KPROBE] 💡 启动目标 App 后，show_maps 被调用时会自动打印");
    }

    printk(KERN_INFO "[KPROBE] 🚀 模块加载完成");
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp_show_maps);
    printk(KERN_INFO "[KPROBE] 已卸载");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Print process maps via show_maps symbol");