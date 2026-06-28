#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/dcache.h>
#include <linux/path.h>

static struct kprobe seq_mounts_kp;
static unsigned long show_mountinfo_addr = 0;
static unsigned long mounts_show_addr = 0;
static bool hooked_mountinfo = false;
static bool hooked_mounts = false;

/* 查找静态符号地址 */
static unsigned long find_symbol_addr(const char *sym_name)
{
    unsigned long addr = 0;
    char type;
    char namebuf[KSYM_NAME_LEN];
    struct kallsym_iter iter;
    
    /* 先尝试kallsyms_lookup_name */
    addr = kallsyms_lookup_name(sym_name);
    if (addr) {
        pr_info("Found %s at %px\n", sym_name, (void *)addr);
        return addr;
    }
    
    /* 遍历所有符号 */
    reset_iter(&iter, 0);
    while (kallsyms_get_next_symbol(&iter)) {
        if (strcmp(iter.name, sym_name) == 0) {
            if (iter.type == 't' || iter.type == 'T') {
                addr = iter.addr;
                pr_info("Found static symbol: %s at %px (type: %c)\n", 
                        iter.name, (void *)addr, iter.type);
                return addr;
            }
        }
    }
    
    return 0;
}

/* show_mountinfo的pre_handler - 直接返回1跳过原函数 */
static int pre_show_mountinfo(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    
#ifdef CONFIG_X86_64
    m = (struct seq_file *)regs->di;
#elif defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_ARM)
    m = (struct seq_file *)regs->ARM_r0;
#else
    m = (struct seq_file *)regs->regs[0];
#endif

    if (!m)
        return 0;

    pr_info("Blocked mountinfo_show call (seq_file: %px)\n", m);
    
    /* 返回1跳过原函数，不输出任何内容 */
    return 1;
}

/* mounts_show的pre_handler - 直接返回1跳过原函数 */
static int pre_mounts_show(struct kprobe *p, struct pt_regs *regs)
{
    struct seq_file *m;
    
#ifdef CONFIG_X86_64
    m = (struct seq_file *)regs->di;
#elif defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
#elif defined(CONFIG_ARM)
    m = (struct seq_file *)regs->ARM_r0;
#else
    m = (struct seq_file *)regs->regs[0];
#endif

    if (!m)
        return 0;

    pr_info("Blocked mounts_show call (seq_file: %px)\n", m);
    
    /* 返回1跳过原函数，不输出任何内容 */
    return 1;
}

/* 模块初始化 */
static int __init hide_mount_table_init(void)
{
    int ret = 0;
    int success_count = 0;

    pr_info("===========================================\n");
    pr_info("Loading hide_mount module (FULL HIDE MODE)\n");
    pr_info("   Kernel: 6.1.75\n");
    pr_info("===========================================\n");

    /* ================================================
     * 1. Hook show_mountinfo (/proc/self/mountinfo)
     * ================================================ */
    show_mountinfo_addr = find_symbol_addr("show_mountinfo");
    
    if (show_mountinfo_addr) {
        memset(&seq_mounts_kp, 0, sizeof(struct kprobe));
        seq_mounts_kp.pre_handler = pre_show_mountinfo;
        seq_mounts_kp.addr = (kprobe_opcode_t *)show_mountinfo_addr;

        ret = register_kprobe(&seq_mounts_kp);
        if (ret == 0) {
            hooked_mountinfo = true;
            success_count++;
            pr_info("Hooked show_mountinfo at %px\n", 
                    (void *)show_mountinfo_addr);
        } else {
            pr_err("Failed to hook show_mountinfo: %d\n", ret);
        }
    } else {
        pr_warn("show_mountinfo not found\n");
    }

    /* ================================================
     * 2. Hook mounts_show (/proc/mounts)
     * ================================================ */
    /* 重新初始化kprobe结构 */
    memset(&seq_mounts_kp, 0, sizeof(struct kprobe));
    seq_mounts_kp.pre_handler = pre_mounts_show;
    
    /* 尝试多个可能的函数名 */
    const char *mounts_symbols[] = {
        "mounts_show",
        "show_mounts",
        "proc_mounts_show",
        NULL
    };

    for (int i = 0; mounts_symbols[i] != NULL; i++) {
        mounts_show_addr = find_symbol_addr(mounts_symbols[i]);
        if (mounts_show_addr) {
            seq_mounts_kp.addr = (kprobe_opcode_t *)mounts_show_addr;
            ret = register_kprobe(&seq_mounts_kp);
            if (ret == 0) {
                hooked_mounts = true;
                success_count++;
                pr_info("Hooked %s at %px\n", 
                        mounts_symbols[i], (void *)mounts_show_addr);
                break;
            }
        }
    }

    if (!hooked_mounts) {
        pr_warn("mounts_show not found\n");
    }

    /* ================================================
     * 3. 显示结果
     * ================================================ */
    pr_info("===========================================\n");
    pr_info("Hiding status:\n");
    pr_info("   - /proc/self/mountinfo: %s\n", 
            hooked_mountinfo ? "HIDDEN" : "FAILED");
    pr_info("   - /proc/mounts:          %s\n", 
            hooked_mounts ? "HIDDEN" : "FAILED");
    
    if (success_count == 0) {
        pr_err("No functions hooked! Module will not work.\n");
        return -ENOENT;
    }
    
    pr_info("%d function(s) hooked successfully\n", success_count);
    pr_info("===========================================\n");
    
    return 0;
}

/* 模块退出 */
static void __exit hide_mount_table_exit(void)
{
    pr_info("===========================================\n");
    pr_info("Unloading hide_mount module...\n");
    
    if (hooked_mountinfo) {
        unregister_kprobe(&seq_mounts_kp);
        pr_info("Unhooked show_mountinfo\n");
    }
    
    if (hooked_mounts) {
        unregister_kprobe(&seq_mounts_kp);
        pr_info("Unhooked mounts_show\n");
    }
    
    pr_info("All hooks removed, mount table restored\n");
    pr_info("===========================================\n");
}

module_init(hide_mount_table_init);
module_exit(hide_mount_table_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Completely hide /proc/mounts & /proc/self/mountinfo for kernel 6.1.75");
MODULE_AUTHOR("Your Name");
MODULE_VERSION("1.0");