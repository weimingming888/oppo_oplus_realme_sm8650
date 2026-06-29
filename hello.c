#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>

static unsigned long get_printk_addr(void)
{
    struct file *f;
    char *buf;
    unsigned long addr = 0;
    loff_t pos = 0;
    char *p;
    
    f = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(f)) return 0;
    
    buf = kmalloc(65536, GFP_KERNEL);
    if (!buf) {
        filp_close(f, NULL);
        return 0;
    }
    
    kernel_read(f, buf, 65535, &pos);
    filp_close(f, NULL);
    
    p = buf;
    while (p && *p) {
        char *end = strchr(p, '\n');
        if (end) *end = '\0';
        
        char *name = strrchr(p, ' ');
        if (name) {
            name++;
            if (strcmp(name, "_printk") == 0) {
                char a[17];
                strncpy(a, p, 16);
                a[16] = '\0';
                addr = simple_strtoul(a, NULL, 16);
                break;
            }
        }
        p = end ? end + 1 : p + strlen(p);
    }
    
    kfree(buf);
    return addr;
}

static int __init init(void)
{
    unsigned long addr = get_printk_addr();
    if (!addr) return -ENOENT;
    
    int (*p)(const char *fmt, ...) = (int (*)(const char *fmt, ...))addr;
    p("成功找到地址: 0x%lx\n", addr);
    return 0;
}

static void __exit exit(void) {}

module_init(init);
module_exit(exit);
MODULE_LICENSE("GPL");