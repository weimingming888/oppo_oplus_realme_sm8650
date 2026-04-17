#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

// 核心修复：用 KERN_DEBUG 不会被屏蔽，安卓全版本可见
static int __init hello_init(void) {
    pr_debug("GKI_Module: 安卓 15 内核模块加载成功！\n");
    return 0;
}

static void __exit hello_exit(void) {
    pr_debug("GKI_Module: 模块已卸载。\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YourName");
MODULE_DESCRIPTION("Android 15 GKI Test Module");
MODULE_VERSION("1.0");
