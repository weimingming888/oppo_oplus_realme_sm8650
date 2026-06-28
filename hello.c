#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/dcache.h>
#include <linux/namei.h>

static struct kprobe kp;
static struct proc_dir_entry *proc_entry;
static bool hooked = false;

/* 获取挂载点信息 */
static void show_mount_info(struct seq_file *m)
{
    struct file *file;
    char *buf;
    loff_t pos = 0;
    int ret;
    
    seq_printf(m, "=== Mount Table Query (Kernel 6.1.75) ===\n");
    seq_printf(m, "Device: %s\n", current->comm);
    seq_printf(m, "PID: %d\n", current->pid);
    seq_printf(m, "===========================================\n\n");
    
    /* 通过读取 /proc/self/mountinfo 获取挂载信息 */
    file = filp_open("/proc/self/mountinfo", O_RDONLY, 0);
    if (IS_ERR(file)) {
        seq_printf(m, "Failed to open mountinfo: %ld\n", PTR_ERR(file));
        return;
    }
    
    buf = kmalloc(8192, GFP_KERNEL);
    if (!buf) {
        seq_printf(m, "Memory allocation failed\n");
        filp_close(file, NULL);
        return;
    }
    
    ret = kernel_read(file, buf, 8191, &pos);
    if (ret > 0) {
        buf[ret] = '\0';
        seq_printf(m, "%s\n", buf);
    } else {
        seq_printf(m, "No mount info available (ret=%d)\n", ret);
    }
    
    kfree(buf);
    filp_close(file, NULL);
    
    /* 显示当前进程的挂载信息 */
    seq_printf(m, "\n=== Current Process Mount Info ===\n");
    if (current->fs) {
        char *path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (path) {
            char *p = dentry_path_raw(current->fs->root.dentry, path, PATH_MAX);
            if (!IS_ERR(p)) {
                seq_printf(m, "Root: %s\n", p);
            }
            if (current->fs->root.mnt && current->fs->root.mnt->mnt_sb) {
                seq_printf(m, "FS Type: %s\n", 
                    current->fs->root.mnt->mnt_sb->s_type->name);
            }
            kfree(path);
        }
    }
}

/* Kprobe pre_handler - 拦截 show_mountinfo */
static int pre_show_mountinfo(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    
#ifdef CONFIG_X86_64
    m = (struct seq_file *)regs->di;
#elif defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#else
    m = (struct seq_file *)regs->regs[0];
#endif

    if (!m)
        return 0;

    pr_info("=== Mount Info Accessed ===\n");
    pr_info("Process: %s (PID: %d)\n", current->comm, current->pid);
    pr_info("Hook triggered at: %px\n", p->addr);
    
    /* 显示挂载信息到内核日志 */
    show_mount_info(m);
    
    return 0;  /* 继续执行原函数 */
}

/* /proc/mount_query 读取函数 */
static int mount_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "========================================\n");
    seq_printf(m, "Mount Table Query Module\n");
    seq_printf(m, "Kernel: %s\n", utsname()->release);
    seq_printf(m, "Arch: %s\n", utsname()->machine);
    seq_printf(m, "========================================\n\n");
    
    show_mount_info(m);
    
    if (hooked) {
        seq_printf(m, "\n✅ show_mountinfo hooked at: %px\n", kp.addr);
    } else {
        seq_printf(m, "\n❌ No hook active\n");
    }
    
    return 0;
}

static int mount_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, mount_proc_show, NULL);
}

static const struct proc_ops mount_proc_fops = {
    .proc_open = mount_proc_open,
    .proc_read = seq_read,
    .proc_release = single_release,
};

/* 查找并hook show_mountinfo */
static int hook_mountinfo(void)
{
    int ret;
    unsigned long addr;
    
    /* 尝试多个可能的符号名 */
    const char *symbols[] = {
        "show_mountinfo",    // 你的手机有这个
        "mountinfo_show",    // 备选
        NULL
    };
    
    for (int i = 0; symbols[i] != NULL; i++) {
        addr = kallsyms_lookup_name(symbols[i]);
        if (addr) {
            pr_info("Found symbol: %s at %px", symbols[i], (void *)addr);
            
            memset(&kp, 0, sizeof(struct kprobe));
            kp.pre_handler = pre_show_mountinfo;
            kp.symbol_name = symbols[i];
            
            ret = register_kprobe(&kp);
            if (ret == 0) {
                pr_info("✅ Successfully hooked: %s", symbols[i]);
                hooked = true;
                return 0;
            } else {
                pr_err("Failed to register kprobe for %s: %d", symbols[i], ret);
            }
        } else {
            pr_debug("Symbol %s not found", symbols[i]);
        }
    }
    
    return -ENOENT;
}

/* 模块初始化 */
static int __init mount_query_init(void)
{
    int ret;
    
    pr_info("===========================================\n");
    pr_info("Mount Table Query Module\n");
    pr_info("Kernel: %s\n", utsname()->release);
    pr_info("===========================================\n");
    
    /* 创建 /proc/mount_query */
    proc_entry = proc_create("mount_query", 0444, NULL, &mount_proc_fops);
    if (!proc_entry) {
        pr_err("Failed to create /proc/mount_query\n");
        return -ENOMEM;
    }
    pr_info("Created /proc/mount_query");
    
    /* Hook show_mountinfo */
    ret = hook_mountinfo();
    if (ret == 0) {
        pr_info("Module loaded with hook active");
    } else {
        pr_warn("Module loaded without hook (only /proc/mount_query available)");
    }
    
    pr_info("===========================================\n");
    pr_info("Usage: cat /proc/mount_query\n");
    pr_info("Check: dmesg | tail -20\n");
    pr_info("===========================================\n");
    
    return 0;
}

/* 模块退出 */
static void __exit mount_query_exit(void)
{
    if (hooked) {
        unregister_kprobe(&kp);
        pr_info("Unhooked show_mountinfo");
    }
    
    if (proc_entry) {
        proc_remove(proc_entry);
        pr_info("Removed /proc/mount_query");
    }
    
    pr_info("Mount Query Module unloaded");
}

module_init(mount_query_init);
module_exit(mount_query_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Mount Table Query for Kernel 6.1.75");
MODULE_AUTHOR("Your Name");
MODULE_VERSION("1.0");