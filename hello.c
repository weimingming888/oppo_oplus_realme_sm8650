#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/seq_file.h>

static struct kprobe kp;

/* ========== 触发函数：打印所有信息 ========== */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    struct mm_struct *mm;
    struct task_struct *task;

    /* show_map 原型: void show_map(struct seq_file *m, struct mm_struct *mm) */
    /* ARM64: x0=seq_file, x1=mm_struct */
    m = (struct seq_file *)regs->regs[0];
    mm = (struct mm_struct *)regs->regs[1];

    printk(KERN_INFO "========================================");
    printk(KERN_INFO "[KPROBE] show_map 被调用!");
    printk(KERN_INFO "[KPROBE] seq_file = %p", m);
    printk(KERN_INFO "[KPROBE] mm_struct = %p", mm);

    if (mm != NULL) {
        task = mm->owner;
        if (task != NULL) {
            printk(KERN_INFO "[KPROBE] 进程: %s (PID=%d)", task->comm, task->pid);
            printk(KERN_INFO "[KPROBE] tgid=%d, ppid=%d", task->tgid, task->parent->pid);
            printk(KERN_INFO "[KPROBE] mm->map_count = %d", mm->map_count);
        } else {
            printk(KERN_INFO "[KPROBE] mm->owner = NULL");
        }
    } else {
        printk(KERN_INFO "[KPROBE] mm_struct = NULL");
    }

    printk(KERN_INFO "========================================");
    return 0;
}

/* ==================================================== */
static int __init kprobe_init(void)
{
    int ret;

    kp.symbol_name = "show_map";
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ 已钩住 show_map");
        printk(KERN_INFO "[KPROBE] 📌 等待 show_map 被调用...");
    } else {
        printk(KERN_ERR "[KPROBE] ❌ 注册失败: %d", ret);
        return -1;
    }

    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "[KPROBE] 已卸载");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hook show_map and print all info");