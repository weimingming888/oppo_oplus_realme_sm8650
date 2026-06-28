#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>

static struct kprobe kp;
static unsigned long target_addr = 0;

/* 查找符号的回调函数 */
static int find_symbol_cb(void *data, const char *name, struct module *mod, unsigned long addr)
{
    if (strcmp(name, (char *)data) == 0) {
        target_addr = addr;
        return 1;  /* 找到就停止 */
    }
    return 0;
}

/* kprobe 处理函数 */
static int handler(struct kprobe *p, struct pt_regs *regs)
{
    pr_info("Mount info accessed!\n");
    return 0;
}

/* 模块初始化 */
static int __init hello_init(void)
{
    pr_info("Loading hello module...\n");
    
    /* 使用 kallsyms_on_each_symbol 查找 show_mountinfo */
    kallsyms_on_each_symbol(find_symbol_cb, "show_mountinfo");
    
    if (!target_addr) {
        pr_err("show_mountinfo not found\n");
        return -ENOENT;
    }
    
    pr_info("Found show_mountinfo at %px\n", (void *)target_addr);
    
    /* 注册 kprobe */
    kp.pre_handler = handler;
    kp.addr = (kprobe_opcode_t *)target_addr;
    
    if (register_kprobe(&kp) < 0) {
        pr_err("Failed to register kprobe\n");
        return -EINVAL;
    }
    
    pr_info("Hello module loaded successfully!\n");
    return 0;
}

/* 模块退出 */
static void __exit hello_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("Hello module unloaded\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Simple mount hook module");