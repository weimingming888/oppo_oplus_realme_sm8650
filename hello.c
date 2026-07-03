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

static struct kprobe kp_show_map_vma;

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

/* ========== kprobe 触发函数 ========== */
static int show_map_vma_pre(struct kprobe *p, struct pt_regs *regs)
{
    pid_t pid;

    printk(KERN_INFO "[KPROBE] show_map_vma 被调用");

    pid = find_pid_by_comm(TARGET_COMM);
    if (pid > 0) {
        printk(KERN_INFO "[KPROBE] ✅ 找到目标进程: %s (PID=%d)", TARGET_COMM, pid);
    } else {
        printk(KERN_INFO "[KPROBE] ⚠️ 未找到进程: %s", TARGET_COMM);
    }

    return 0;
}

/* ==================================================== */
static int __init kprobe_init(void)
{
    int ret;
    pid_t pid;

    printk(KERN_INFO "[KPROBE] 🔍 模块加载开始");

    /* ===== 直接使用符号名注册 ===== */
    kp_show_map_vma.symbol_name = "show_map_vma";
    kp_show_map_vma.pre_handler = show_map_vma_pre;

    ret = register_kprobe(&kp_show_map_vma);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ 已钩住 show_map_vma");
        printk(KERN_INFO "[KPROBE] ⚡ 当 show_map_vma 被调用时将触发");
    } else {
        printk(KERN_WARNING "[KPROBE] ⚠️ show_map_vma 注册失败: %d", ret);
        printk(KERN_INFO "[KPROBE] 💡 符号可能不存在或未导出");
        return -1;
    }

    /* ===== 查找目标进程 ===== */
    pid = find_pid_by_comm(TARGET_COMM);
    if (pid > 0) {
        printk(KERN_INFO "[KPROBE] ✅ 找到目标进程: %s (PID=%d)", TARGET_COMM, pid);
    } else {
        printk(KERN_WARNING "[KPROBE] ⚠️ 进程 %s 未找到", TARGET_COMM);
        printk(KERN_INFO "[KPROBE] 💡 启动目标 App 后重新加载本模块");
    }

    printk(KERN_INFO "[KPROBE] 🚀 模块加载完成");
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp_show_map_vma);
    printk(KERN_INFO "[KPROBE] 已卸载");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hook show_map_vma");