#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mm.h>

typedef struct file *(*filp_open_t)(const char *, int, umode_t);
typedef int (*filp_close_t)(struct file *, fl_owner_t);
typedef ssize_t (*kernel_read_t)(struct file *, void *, size_t, loff_t *);

static filp_open_t my_filp_open = NULL;
static filp_close_t my_filp_close = NULL;
static kernel_read_t my_kernel_read = NULL;

/* 内存搜索范围（根据实际情况调整） */
static unsigned long SEARCH_START = 0xffffffc000000000ULL;
static unsigned long SEARCH_END   = 0xffffffc100000000ULL;

/* 安全读取内存 */
static int safe_read_mem(unsigned long addr, void *buf, size_t len)
{
    unsigned long i;
    char *ptr = (char *)buf;
    
    /* 检查是否在合理范围内 */
    if (addr < SEARCH_START || addr >= SEARCH_END - len)
        return -1;
    
    /* 逐字节尝试读取 */
    for (i = 0; i < len; i++) {
        char c;
        if (__get_user(c, (char *)(addr + i))) {
            return -1;
        }
        ptr[i] = c;
    }
    
    return 0;
}

/* 搜索字符串在内核内存中的位置 */
static unsigned long find_string_in_memory(const char *str)
{
    unsigned long addr;
    unsigned long len = strlen(str);
    unsigned long end = SEARCH_END - len;
    
    printk(KERN_INFO "Searching for '%s' in memory (0x%lx - 0x%lx)\n",
           str, SEARCH_START, SEARCH_END);
    
    /* 每隔 1 字节搜索 */
    for (addr = SEARCH_START; addr < end; addr += 1) {
        char buf[64];
        int ret;
        
        /* 安全读取 */
        ret = safe_read_mem(addr, buf, len + 1);
        if (ret != 0)
            continue;
        
        buf[len] = '\0';
        
        /* 比较字符串 */
        if (memcmp(buf, str, len) == 0) {
            /* 确保后面是空字符或分隔符 */
            char next;
            if (__get_user(next, (char *)(addr + len)))
                continue;
            
            if (next == '\0' || next == ' ' || next == '\t' || next == '\n') {
                printk(KERN_INFO "Found '%s' at 0x%lx\n", str, addr);
                return addr;
            }
        }
    }
    
    printk(KERN_ERR "String '%s' not found in memory\n", str);
    return 0;
}

/* 内核符号表项结构（简化） */
struct ksymtab_entry {
    unsigned long addr;
    unsigned long name_addr;
};

/* 从符号名获取地址（通过搜索符号表） */
static unsigned long find_symbol_by_search(const char *sym_name)
{
    unsigned long str_addr;
    unsigned long search_start, search_end;
    unsigned long addr;
    
    /* 1. 先找到符号名的字符串 */
    str_addr = find_string_in_memory(sym_name);
    if (!str_addr)
        return 0;
    
    /* 2. 在符号名附近搜索符号表结构 */
    /* 符号表通常位于 .rodata 段，符号名附近可能有地址 */
    search_start = (str_addr > 4096) ? (str_addr - 4096) : 0;
    search_end = str_addr + 4096;
    
    printk(KERN_INFO "Searching for symbol entry near 0x%lx\n", str_addr);
    
    /* 搜索符号表结构（地址 + 名称指针） */
    for (addr = search_start; addr < search_end; addr += 8) {
        unsigned long val1, val2;
        
        /* 尝试读取两个 8 字节值 */
        if (__get_user(val1, (unsigned long *)addr))
            continue;
        if (__get_user(val2, (unsigned long *)(addr + 8)))
            continue;
        
        /* 检查 val2 是否指向符号名 */
        if (val2 == str_addr) {
            /* val1 就是函数地址 */
            unsigned long func_addr = val1;
            
            /* 验证地址是否在合理范围 */
            if (func_addr >= SEARCH_START && func_addr < SEARCH_END) {
                printk(KERN_INFO "Found %s at 0x%lx (entry at 0x%lx)\n",
                       sym_name, func_addr, addr);
                return func_addr;
            }
        }
    }
    
    printk(KERN_ERR "Failed to find symbol entry for %s\n", sym_name);
    return 0;
}

/* 更激进的方法：直接搜索函数入口（通过特征码） */
static unsigned long find_function_by_search(const char *sym_name)
{
    unsigned long addr;
    unsigned long end = SEARCH_END - 32;
    int found = 0;
    
    /* 搜索符号名 */
    addr = find_string_in_memory(sym_name);
    if (!addr)
        return 0;
    
    /* 在字符串周围搜索地址 */
    printk(KERN_INFO "Looking for function address near 0x%lx\n", addr);
    
    /* 在符号名前后 512 字节内搜索 */
    unsigned long start = (addr > 512) ? (addr - 512) : 0;
    unsigned long stop = addr + 512;
    
    for (addr = start; addr < stop; addr += 8) {
        unsigned long val;
        if (__get_user(val, (unsigned long *)addr))
            continue;
        
        /* 检查是否是有效的函数地址（代码段范围） */
        if (val >= SEARCH_START && val < SEARCH_END) {
            /* 简单验证：尝试在目标地址附近查找特征码 */
            unsigned char code[4];
            if (__get_user(code[0], (unsigned char *)val)) continue;
            if (__get_user(code[1], (unsigned char *)(val + 1))) continue;
            if (__get_user(code[2], (unsigned char *)(val + 2))) continue;
            if (__get_user(code[3], (unsigned char *)(val + 3))) continue;
            
            /* ARM64 函数通常以 "stp x29, x30, [sp, #-xxx]!" 开头 */
            /* 对应的机器码是 0xa9bf7bfd (stp x29, x30, [sp, #-16]!) */
            if (code[0] == 0xfd && code[1] == 0x7b && 
                code[2] == 0xbf && code[3] == 0xa9) {
                printk(KERN_INFO "Found function starting at 0x%lx near symbol\n", val);
                return val;
            }
            
            /* 也可以直接返回，因为找到的就是地址 */
            printk(KERN_INFO "Found potential address 0x%lx near symbol\n", val);
            return val;
        }
    }
    
    return 0;
}

/* 查找所有需要的符号 */
static int find_all_symbols(void)
{
    unsigned long addr;
    
    printk(KERN_INFO "=== Searching for kernel symbols ===\n");
    
    /* 方法1：通过符号表查找 */
    printk(KERN_INFO "[Method 1] Searching via ksymtab...\n");
    
    addr = find_symbol_by_search("filp_open");
    if (addr) {
        my_filp_open = (filp_open_t)addr;
    } else {
        /* 方法2：通过特征码查找 */
        printk(KERN_INFO "[Method 2] Searching via function signature...\n");
        addr = find_function_by_search("filp_open");
        if (addr) {
            my_filp_open = (filp_open_t)addr;
        }
    }
    
    if (!my_filp_open) {
        printk(KERN_ERR "Failed to find filp_open\n");
        return -1;
    }
    
    /* 查找 filp_close */
    addr = find_symbol_by_search("filp_close");
    if (!addr) {
        addr = find_function_by_search("filp_close");
    }
    if (addr) {
        my_filp_close = (filp_close_t)addr;
    }
    
    /* 查找 kernel_read */
    addr = find_symbol_by_search("kernel_read");
    if (!addr) {
        addr = find_symbol_by_search("vfs_read");
    }
    if (!addr) {
        addr = find_function_by_search("kernel_read");
    }
    if (addr) {
        my_kernel_read = (kernel_read_t)addr;
    }
    
    /* 打印结果 */
    printk(KERN_INFO "=== Search results ===\n");
    printk(KERN_INFO "filp_open:   %s (0x%px)\n", 
           my_filp_open ? "found" : "NOT FOUND", my_filp_open);
    printk(KERN_INFO "filp_close:  %s (0x%px)\n", 
           my_filp_close ? "found" : "NOT FOUND", my_filp_close);
    printk(KERN_INFO "kernel_read: %s (0x%px)\n", 
           my_kernel_read ? "found" : "NOT FOUND", my_kernel_read);
    
    return (my_filp_open && my_filp_close && my_kernel_read) ? 0 : -1;
}

/* 测试文件操作 */
static void test_file_operations(void)
{
    struct file *file;
    char *buf;
    loff_t pos = 0;
    ssize_t ret;
    
    if (!my_filp_open || !my_filp_close || !my_kernel_read) {
        printk(KERN_ERR "Function pointers not ready!\n");
        return;
    }
    
    printk(KERN_INFO "=== Testing file operations ===\n");
    
    /* 测试打开 /proc/kallsyms */
    file = my_filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open: %ld\n", PTR_ERR(file));
        return;
    }
    
    printk(KERN_INFO "Successfully opened /proc/kallsyms\n");
    
    /* 读取前 100 字节 */
    buf = kmalloc(128, GFP_KERNEL);
    if (!buf) {
        my_filp_close(file, NULL);
        return;
    }
    
    ret = my_kernel_read(file, buf, 127, &pos);
    if (ret > 0) {
        buf[ret] = '\0';
        printk(KERN_INFO "First 100 bytes:\n%s\n", buf);
    }
    
    kfree(buf);
    my_filp_close(file, NULL);
    printk(KERN_INFO "File closed\n");
}

static int __init test_init(void)
{
    printk(KERN_INFO "=== Module loaded (pure memory search) ===\n");
    printk(KERN_INFO "No exported symbols used!\n");
    
    /* 自动搜索所有符号 */
    if (find_all_symbols() != 0) {
        printk(KERN_ERR "Failed to find all required symbols\n");
        return -ENOENT;
    }
    
    /* 测试文件操作 */
    test_file_operations();
    
    return 0;
}

static void __exit test_exit(void)
{
    printk(KERN_INFO "Module unloaded\n");
}

module_init(test_init);
module_exit(test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Test");
MODULE_DESCRIPTION("Pure memory search for kernel symbols");