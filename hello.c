#include <linux/module.h>
#include <linux/init.h>

static int __init hello_init(void)
{
    pr_info("Hello Kernel Test Driver Loaded!\n");
    return 0;
}

static void __exit hello_exit(void)
{
    pr_info("Hello Kernel Test Driver Unloaded!\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Test");
MODULE_DESCRIPTION("Simple Hello Print Test Driver");
