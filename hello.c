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

/* 使用内核导出的 _stext 和 _etext 来限定搜索范围 */
extern char _stext[], _etext[];

static unsigned long SEARCH_START;
static unsigned long SEARCH_END;

/* 安全读取内存 */
static int safe_read_mem(unsigned long addr, void *buf, size_t len)
{
    unsigned long i;
    char *ptr = (char *)buf;
    
    if (addr < SEARCH_START || addr >= SEARCH_END - len)
        return -1;
    
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
    unsigned long end = SEARCH_END - len - 1;
    int match_count = 0;
    
    pr_info("Searching for '%s' in memory (0x%lx - 0x%lx)\n",
            str, SEARCH_START, SEARCH_END);
    
    for (addr = SEARCH_START; addr < end; addr += 4) {
        char buf[64];
        int ret;
        
        ret = safe_read_mem(addr, buf, len + 1);
        if (ret != 0)
            continue;
        
        buf[len] = '\0';
        
        if (memcmp(buf, str, len) == 0) {
            char next;
            if (__get_user(next, (char *)(addr + len)))
                continue;
            
            if (next == '\0' || next == ' ' || next == '\t' || next == '\n') {
                match_count++;
                pr_info("Found '%s' at 0x%lx (match #%d)\n", 
                        str, addr, match_count);
                return addr;
            }
        }
    }
    
    pr_err("String '%s' not found in memory\n", str);
    return 0;
}

/* 从符号名获取地址 */
static unsigned long find_symbol_by_search(const char *sym_name)
{
    unsigned long str_addr;
    unsigned long addr;
    unsigned long start, end;
    
    str_addr = find_string_in_memory(sym_name);
    if (!str_addr)
        return 0;
    
    start = (str_addr > 4096) ? (str_addr - 4096) : SEARCH_START;
    end = str_addr + 4096;
    
    pr_info("Searching symbol entry for '%s' near 0x%lx\n", sym_name, str_addr);
    
    for (addr = start; addr < end; addr += 8) {
        unsigned long val1, val2;
        
        if (__get_user(val1, (unsigned long *)addr))
            continue;
        if (__get_user(val2, (unsigned long *)(addr + 8)))
            continue;
        
        if (val2 == str_addr) {
            if (val1 >= SEARCH_START && val1 < SEARCH_END) {
                pr_info("Found %s at 0x%lx\n", sym_name, val1);
                return val1;
            }
        }
    }
    
    pr_err("Failed to find symbol entry for %s\n", sym_name);
    return 0;
}

/* 查找所有需要的符号 */
static int find_all_symbols(void)
{
    unsigned long addr;
    int ret = 0;
    
    pr_info("=== Searching for kernel symbols ===\n");
    
    addr = find_symbol_by_search("filp_open");
    if (addr) {
        my_filp_open = (filp_open_t)addr;
    } else {
        pr_err("Failed to find filp_open\n");
        ret = -1;
    }
    
    addr = find_symbol_by_search("filp_close");
    if (addr) {
        my_filp_close = (filp_close_t)addr;
    } else {
        pr_err("Failed to find filp_close\n");
        ret = -1;
    }
    
    addr = find_symbol_by_search("kernel_read");
    if (!addr) {
        pr_info("kernel_read not found, trying vfs_read...\n");
        addr = find_symbol_by_search("vfs_read");
    }
    
    if (addr) {
        my_kernel_read = (kernel_read_t)addr;
    } else {
        pr_err("Failed to find kernel_read/vfs_read\n");
        ret = -1;
    }
    
    pr_info("=== Search results ===\n");
    pr_info("filp_open:   %s (0x%px)\n", 
            my_filp_open ? "FOUND" : "NOT FOUND", my_filp_open);
    pr_info("filp_close:  %s (0x%px)\n", 
            my_filp_close ? "FOUND" : "NOT FOUND", my_filp_close);
    pr_info("kernel_read: %s (0x%px)\n", 
            my_kernel_read ? "FOUND" : "NOT FOUND", my_kernel_read);
    
    return ret;
}

/* 测试文件读取 */
static void test_file_read(void)
{
    struct file *file;
    char *buf;
    loff_t pos = 0;
    ssize_t ret;
    
    if (!my_filp_open || !my_filp_close || !my_kernel_read) {
        pr_err("Function pointers not ready!\n");
        return;
    }
    
    pr_info("=== Testing file read ===\n");
    
    file = my_filp_open("/proc/version", O_RDONLY, 0);
    if (IS_ERR(file)) {
        pr_err("Failed to open /proc/version: %ld\n", PTR_ERR(file));
        return;
    }
    
    pr_info("Successfully opened /proc/version\n");
    
    buf = kmalloc(256, GFP_KERNEL);
    if (!buf) {
        my_filp_close(file, NULL);
        return;
    }
    
    ret = my_kernel_read(file, buf, 255, &pos);
    if (ret > 0) {
        buf[ret] = '\0';
        pr_info("Content: %s\n", buf);
    } else {
        pr_err("Read failed: %zd\n", ret);
    }
    
    kfree(buf);
    my_filp_close(file, NULL);
    pr_info("File closed\n");
}

static int __init hello_init(void)
{
    pr_info("=== Hello module loaded ===\n");
    
    SEARCH_START = (unsigned long)_stext;
    SEARCH_END = (unsigned long)_etext;
    
    pr_info("Search range: 0x%lx - 0x%lx\n", SEARCH_START, SEARCH_END);
    
    if (SEARCH_START == 0 || SEARCH_END == 0 || SEARCH_START >= SEARCH_END) {
        pr_warn("_stext/_etext not available, using fallback range\n");
        SEARCH_START = 0xffffffc000000000ULL;
        SEARCH_END = 0xffffffc100000000ULL;
    }
    
    if (find_all_symbols() != 0) {
        pr_err("Failed to find all required symbols\n");
        return -ENOENT;
    }
    
    test_file_read();
    
    return 0;
}

static void __exit hello_exit(void)
{
    pr_info("Hello module unloaded\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Test");
MODULE_DESCRIPTION("Find kernel symbols via memory search");