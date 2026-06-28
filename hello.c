#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>

static struct kprobe kp;
static unsigned long target_addr = 0;

/* 从 /proc/kallsyms 读取符号地址 */
static unsigned long get_symbol_addr(const char *sym_name)
{
    struct file *file;
    char *buf;
    loff_t pos = 0;
    unsigned long addr = 0;
    int ret;
    char *p, *line;
    
    /* 打开 /proc/kallsyms */
    file = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(file)) {
        pr_err("Cannot open /proc/kallsyms\n");
        return 0;
    }
    
    buf = kmalloc(65536, GFP_KERNEL);
    if (!buf) {
        filp_close(file, NULL);
        return 0;
    }
    
    /* 读取整个文件 */
    ret = kernel_read(file, buf, 65535, &pos);
    filp_close(file, NULL);
    
    if (ret <= 0) {
        kfree(buf);
        return 0;
    }
    buf[ret] = '\0';
    
    /* 逐行解析 */
    p = buf;
    while (p && *p) {
        char *line_end = strchr(p, '\n');
        if (line_end) *line_end = '\0';
        
        /* 格式: 地址 类型 名称 */
        char *name = strrchr(p, ' ');
        if (name) {
            name++;  /* 跳过空格 */
            if (strcmp(name, sym_name) == 0) {
                /* 提取地址 */
                char addr_str[17];
                strncpy(addr_str, p, 16);
                addr_str[16] = '\0';
                addr = simple_strtoul(addr_str, NULL, 16);
                if (addr) {
                    pr_info("Found %s at %px\n", sym_name, (void *)addr);
                }
                break;
            }
        }
        
        p = line_end ? line_end + 1 : p + strlen(p);
    }
    
    kfree(buf);
    return addr;
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
    int ret;
    
    pr_info("Loading hello module...\n");
    
    /* 从 /proc/kallsyms 读取 show_mountinfo 地址 */
    target_addr = get_symbol_addr("show_mountinfo");
    
    if (!target_addr) {
        pr_err("show_mountinfo not found\n");
        return -ENOENT;
    }
    
    pr_info("Found show_mountinfo at %px\n", (void *)target_addr);
    
    /* 注册 kprobe */
    kp.pre_handler = handler;
    kp.addr = (kprobe_opcode_t *)target_addr;
    
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("Failed to register kprobe: %d\n", ret);
        return ret;
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
MODULE_DESCRIPTION("Mount hook module using file read");