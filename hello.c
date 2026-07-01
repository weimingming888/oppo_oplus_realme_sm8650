#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

/* ARM64 特征码：kallsyms_lookup_name 函数开头 */
#define PATTERN_WORD1 0xa9bf7bfd  /* stp x29, x30, [sp, #-32]! */
#define PATTERN_WORD2 0x910003fd  /* mov x29, sp */

/* ---------- 手动比较两个 8 字节块（不用 memcmp） ---------- */
static int manual_match(const unsigned char *a, const unsigned char *b)
{
    int i;
    for (i = 0; i < 8; i++) {
        if (a[i] != b[i])
            return 0;
    }
    return 1;
}

/* ---------- 通过内联汇编读取内存（不用 probe_kernel_read） ---------- */
static int read_memory_8(unsigned long addr, unsigned char *buf)
{
    unsigned long val;
    int ret = 0;
    
    /* 使用内联汇编直接读取 */
    __asm__ volatile(
        "1: ldr %0, [%2]\n"
        "   mov %1, #0\n"
        "2:\n"
        ".pushsection .fixup,\"ax\"\n"
        "3: mov %1, #1\n"
        "   mov %0, #0\n"
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
        /* 复制到 buf（小端） */
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

/* ---------- 主查找函数 ---------- */
static unsigned long find_kallsyms_lookup_name(void)
{
    unsigned long p;
    unsigned char buf[8];
    const unsigned char pattern[] = {
        0xfd, 0x7b, 0xbf, 0xa9,
        0xfd, 0x03, 0x00, 0x91,
    };
    
    /* 扫描内核文本段 */
    for (p = 0xffffff8000000000ULL; p < 0xfffffffe00000000ULL; p += 4) {
        /* 每扫描 1MB 放一次行，避免看门狗超时 */
        if ((p & 0xFFFFF) == 0) {
            /* 空转，不调用任何函数 */
        }
        
        if (read_memory_8(p, buf) == 0) {
            if (manual_match(buf, pattern)) {
                return p;
            }
        }
        
        /* 防止无限循环 */
        if (p > 0xfffffffe00000000ULL)
            break;
    }
    return 0;
}

/* ---------- 验证找到的地址 ---------- */
static int verify_address(unsigned long addr)
{
    unsigned long val;
    int ret;
    
    /* 尝试读取 addr 处的第一条指令 */
    __asm__ volatile(
        "1: ldr %0, [%2]\n"
        "   mov %1, #0\n"
        "2:\n"
        ".pushsection .fixup,\"ax\"\n"
        "3: mov %1, #1\n"
        "   mov %0, #0\n"
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
        printk(KERN_INFO "Address 0x%lx is readable, first instr: 0x%08lx\n", 
               addr, val & 0xffffffff);
        return 1;
    } else {
        printk(KERN_WARNING "Address 0x%lx is NOT readable\n", addr);
        return 0;
    }
}

/* ---------- 模块初始化 ---------- */
static int __init finder_init(void)
{
    unsigned long addr;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "kallsyms_lookup_name Finder (Zero Symbol)\n");
    printk(KERN_INFO "========================================\n");
    
    addr = find_kallsyms_lookup_name();
    if (addr) {
        printk(KERN_INFO "Found signature at: 0x%lx\n", addr);
        if (verify_address(addr)) {
            printk(KERN_INFO "✅ SUCCESS! kallsyms_lookup_name = 0x%lx\n", addr);
            printk(KERN_INFO "========================================\n");
            return 0;
        }
    }
    
    printk(KERN_ERR "❌ Failed to find kallsyms_lookup_name\n");
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