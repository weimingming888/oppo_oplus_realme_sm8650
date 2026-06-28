#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>

static struct kprobe kp;

static int handler(struct kprobe *p, struct pt_regs *regs)
{
    pr_info("Mount accessed!\n");
    return 0;
}

static int __init init(void)
{
    kp.pre_handler = handler;
    kp.addr = (kprobe_opcode_t *)module_kallsyms_lookup_name("show_mountinfo");
    return register_kprobe(&kp);
}

static void __exit exit(void)
{
    unregister_kprobe(&kp);
}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");