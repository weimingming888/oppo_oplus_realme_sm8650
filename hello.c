#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

/* ARM64 特征码：kallsyms_lookup_name 函数开头 */
#define PATTERN_WORD1 0xa9bf7bfd  /* stp x29, x30, [sp, #-32]! */
#define PATTERN_WORD2 0x910003fd  /* mov x29, sp */

/* ---------- 手动比较 8 字节（不用 memcmp） ---------- */
static int manual_match_8(const unsigned char *a, const unsigned char *b)
{
    int i;
    for (i = 0; i < 8; i++) {
        if (a[i] != b[i])
            return 0;
    }
    return 1;
}

/* ---------- 通过内联汇编读取 8 字节（带异常保护） ---------- */
static int read_memory_8(unsigned long addr, unsigned char *buf)
{
    unsigned long val;
    int ret = 0;
    
    __asm__ volatile(
        "1: ldr %0, [%2]\n"
        "   mov %w1, wzr\n"          /* 使用 w1 寄存器（32位） */
        "2:\n"
        ".pushsection .fixup,\"ax\"\n"
        "3: mov %w1, #1\n"           /* 使用 w1 寄存器 */
        "   mov %0, xzr\n"
        "   b 2b\n"
        ".popsection\n"
        ".pushsection __ex_table,\"a\"\n"
        "   .align 3\n"
        "   .quad 1b, 3b\n"
        ".popsection\n"
        : "=r"(val), "=r"(ret)
        : "r"(addr)
        : "memory"
    );
    
    if (ret == 0) {
        buf[0] = val & 0xff;
        buf[1] = (val >> 8) & 0xff;
        buf[2] = (val >> 16) & 0xff;
        buf[3] = (val >> 24) & 0xff;
        buf[4] = (val >> 32) & 0xff;
        buf[5] = (val >> 40) & 0xff;
        buf[6] = (val >> 48) & 0xff;
        buf[7] = (val >> 56) & 0xff;
    }
    return ret;
}

/* ---------- 验证地址是否可读 ---------- */
static int verify_address_readable(unsigned long addr)
{
    unsigned long val;
    int ret = 0;
    
    __asm__ volatile(
        "1: ldr %0, [%2]\n"
        "   mov %w1, wzr\n"
        "2:\n"
        ".pushsection .fixup,\"ax\"\n"
        "3: mov %w1, #1\n"
        "   mov %0, xzr\n"
        "   b 2b\n"
        ".popsection\n"
        ".pushsection __ex_table,\"a\"\n"
        "   .align 3\n"
        "   .quad 1b, 3b\n"
        ".popsection\n"
        : "=r"(val), "=r"(ret)
        : "r"(addr)
        : "memory"
    );
    
    return (ret == 0);
}

/* ---------- 扫描查找 kallsyms_lookup_name ---------- */
static unsigned long find_kallsyms_lookup_name(void)
{
    unsigned long p;
    unsigned char buf[8];
    const unsigned char pattern[8] = {
        0xfd, 0x7b, 0xbf, 0xa9,  /* stp x29, x30, [sp, #-32]! */
        0xfd, 0x03, 0x00, 0x91,  /* mov x29, sp */
    };
    unsigned long start, end;
    
    /* ARM64 内核文本段范围 */
    start = 0xffffff8000000000ULL;
    end = 0xfffffffe00000000ULL;
    
    printk(KERN_INFO "Scanning 0x%lx - 0x%lx\n", start, end);
    
    for (p = start; p < end; p += 4) {
        /* 每 16MB 打印一次进度 */
        if ((p & 0xFFFFFF) == 0) {
            printk(KERN_DEBUG "Scanning at 0x%lx\n", p);
        }
        
        if (read_memory_8(p, buf) == 0) {
            if (manual_match_8(buf, pattern)) {
                printk(KERN_INFO "Found signature at 0x%lx\n", p);
                return p;
            }
        }
    }
    
    return 0;
}

/* ---------- 模块初始化 ---------- */
static int __init finder_init(void)
{
    unsigned long addr;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "kallsyms_lookup_name Finder\n");
    printk(KERN_INFO "(Zero Symbol Dependencies)\n");
    printk(KERN_INFO "========================================\n");
    
    addr = find_kallsyms_lookup_name();
    
    if (addr) {
        printk(KERN_INFO "✅ Found at: 0x%lx\n", addr);
        
        /* 验证地址可读 */
        if (verify_address_readable(addr)) {
            printk(KERN_INFO "✅ Address is readable and valid\n");
            printk(KERN_INFO "\n");
            printk(KERN_INFO "🔑 kallsyms_lookup_name = 0x%lx\n", addr);
            printk(KERN_INFO "========================================\n");
            return 0;
        } else {
            printk(KERN_WARNING "⚠️  Address not readable\n");
        }
    } else {
        printk(KERN_ERR "❌ Not found\n");
    }
    
    printk(KERN_INFO "========================================\n");
    return -ENOENT;
}

/* ---------- 退出 ---------- */
static void __exit finder_exit(void)
{
    printk(KERN_INFO "Finder module unloaded\n");
}

module_init(finder_init);
module_exit(finder_exit);