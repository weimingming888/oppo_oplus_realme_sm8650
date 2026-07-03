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

/* ========== kprobe 触发函数（不过滤，打印所有） ========== */
static int show_map_vma_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    struct vm_area_struct *vma;
    struct mm_struct *mm;
    struct task_struct *task;
    char *path_buf = NULL;
    char *path = NULL;
    char flags[5];

    /* show_map_vma 原型: void show_map_vma(struct seq_file *m, struct vm_area_struct *vma) */
    /* ARM64: x0=seq_file, x1=vm_area_struct */
    m = (struct seq_file *)regs->regs[0];
    vma = (struct vm_area_struct *)regs->regs[1];

    if (vma == NULL)
        return 0;

    mm = vma->vm_mm;
    if (mm == NULL)
        return 0;

    /* 获取进程信息 */
    task = mm->owner;
    if (task == NULL)
        return 0;

    /* 构建权限标志 */
    flags[0] = (vma->vm_flags & VM_READ) ? 'r' : '-';
    flags[1] = (vma->vm_flags & VM_WRITE) ? 'w' : '-';
    flags[2] = (vma->vm_flags & VM_EXEC) ? 'x' : '-';
    flags[3] = (vma->vm_flags & VM_MAYSHARE) ? 's' : 'p';
    flags[4] = '\0';

    /* 获取文件路径 */
    if (vma->vm_file != NULL) {
        path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
        if (path_buf != NULL) {
            path = d_path(&vma->vm_file->f_path, path_buf, PATH_MAX);
            if (IS_ERR(path)) {
                path = NULL;
            }
        }
    }

    /* 打印所有 VMA 信息（不过滤） */
    printk(KERN_INFO "[MAPS] PID=%d COMM=%s %016lx-%016lx %s %08lx %s",
           task->pid,
           task->comm,
           vma->vm_start,
           vma->vm_end,
           flags,
           vma->vm_pgoff,
           path ? path : "");

    /* 释放路径缓冲区 */
    if (path_buf != NULL && !IS_ERR(path_buf)) {
        kfree(path_buf);
    }

    return 0;
}

/* ==================================================== */
static int __init kprobe_init(void)
{
    int ret;

    printk(KERN_INFO "[KPROBE] 🔍 模块加载开始");
    printk(KERN_INFO "[KPROBE] 📌 不过滤进程名，打印所有 show_map_vma 调用");

    kp_show_map_vma.symbol_name = "show_map_vma";
    kp_show_map_vma.pre_handler = show_map_vma_pre;

    ret = register_kprobe(&kp_show_map_vma);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ 已钩住 show_map_vma");
        printk(KERN_INFO "[KPROBE] ⚡ 正在等待 show_map_vma 被调用...");
    } else {
        printk(KERN_WARNING "[KPROBE] ⚠️ show_map_vma 注册失败: %d", ret);
        printk(KERN_INFO "[KPROBE] 💡 尝试使用 show_map");
        kp_show_map_vma.symbol_name = "show_map";
        ret = register_kprobe(&kp_show_map_vma);
        if (ret == 0) {
            printk(KERN_INFO "[KPROBE] ✅ 已钩住 show_map");
        } else {
            printk(KERN_ERR "[KPROBE] ❌ 所有符号注册失败");
            return -1;
        }
    }

    printk(KERN_INFO "[KPROBE] 🚀 模块加载完成");
    printk(KERN_INFO "[KPROBE] 💡 触发方式: cat /proc/<PID>/maps");
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
MODULE_DESCRIPTION("Hook show_map_vma - print all VMA info");