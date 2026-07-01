#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

static struct kprobe kp_show_map_vma;
static unsigned long g_show_map_vma_addr;

/* ---------- 获取符号地址 ---------- */
static unsigned long get_symbol_addr(const char *name)
{
    struct kprobe kp;
    unsigned long addr;
    int ret;
    
    addr = 0;
    memset(&kp, 0, sizeof(struct kprobe));
    kp.symbol_name = name;
    
    ret = register_kprobe(&kp);
    if (ret == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
        printk(KERN_INFO "[Filter] ✅ %s = 0x%lx\n", name, addr);
    }
    return addr;
}

/* ---------- 判断 VMA 是否应该隐藏 ---------- */
static int should_skip_vma(struct vm_area_struct *vma)
{
    unsigned long prot;
    char *path_buf;
    char *path;
    int has_file;
    int has_vdso;
    int result;
    
    if (!vma) {
        return 0;
    }
    
    result = 0;
    prot = vma->vm_flags;
    has_file = 0;
    has_vdso = 0;
    
    /* 检查是否有文件映射 */
    if (vma->vm_file) {
        path_buf = (char *)__get_free_page(GFP_ATOMIC);
        if (path_buf) {
            path = d_path(&vma->vm_file->f_path, path_buf, PAGE_SIZE);
            if (!IS_ERR(path)) {
                if (strstr(path, "[vdso]") != NULL) {
                    has_vdso = 1;
                }
                if (strstr(path, "/") != NULL) {
                    has_file = 1;
                }
            }
            free_page((unsigned long)path_buf);
        }
    }
    
    /* [vdso] 保留 */
    if (has_vdso) {
        return 0;
    }
    
    /* 有文件路径的保留 */
    if (has_file) {
        return 0;
    }
    
    /*
     * 匿名可执行 VMA = LSPosed 注入痕迹
     * 
     * VM_EXEC  = 可执行
     * VM_WRITE = 可写
     * 没有文件 = 匿名
     */
    if (prot & VM_EXEC) {
        /* rwxp 或 r-xp 匿名都隐藏 */
        return 1;
    }
    
    return 0;
}

/* ---------- show_map_vma pre_handler ---------- */
static int show_map_vma_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct vm_area_struct *vma;
    struct seq_file *m;
    
    (void)p;
    
    /*
     * ARM64:
     *   x0 = struct seq_file *m
     *   x1 = struct vm_area_struct *vma
     * 
     * x86_64:
     *   rdi = struct seq_file *m
     *   rsi = struct vm_area_struct *vma
     */
#if defined(CONFIG_ARM64)
    m = (struct seq_file *)regs->regs[0];
    vma = (struct vm_area_struct *)regs->regs[1];
#elif defined(CONFIG_X86_64)
    m = (struct seq_file *)regs->di;
    vma = (struct vm_area_struct *)regs->si;
#else
    m = NULL;
    vma = NULL;
#endif
    
    if (!m || !vma) {
        return 0;
    }
    
    /* 判断是否跳过这个 VMA */
    if (should_skip_vma(vma)) {
        printk(KERN_DEBUG "[Filter] 🧹 Skipped VMA 0x%lx-0x%lx (anonymous exec)\n",
               vma->vm_start, vma->vm_end);
        return 1;  /* 返回 1 = 跳过原函数，不输出这一行 */
    }
    
    return 0;  /* 正常输出 */
}

/* ---------- 模块初始化 ---------- */
static int __init filter_init(void)
{
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[Filter] show_map_vma hook (VMA level)\n");
    printk(KERN_INFO "[Filter] Skipping anonymous executable VMA\n");
    printk(KERN_INFO "[Filter] Keeping: [vdso], file-backed, non-exec\n");
    printk(KERN_INFO "========================================\n");
    
    /* 尝试获取 show_map_vma 地址 */
    g_show_map_vma_addr = get_symbol_addr("show_map_vma");
    if (!g_show_map_vma_addr) {
        g_show_map_vma_addr = get_symbol_addr("show_map");
    }
    if (!g_show_map_vma_addr) {
        g_show_map_vma_addr = get_symbol_addr("proc_pid_maps_show");
    }
    
    if (!g_show_map_vma_addr) {
        printk(KERN_ERR "[Filter] ❌ show_map_vma not found!\n");
        return -ENOENT;
    }
    
    memset(&kp_show_map_vma, 0, sizeof(struct kprobe));
    kp_show_map_vma.addr = (void *)g_show_map_vma_addr;
    kp_show_map_vma.pre_handler = show_map_vma_pre_handler;
    
    if (register_kprobe(&kp_show_map_vma) == 0) {
        printk(KERN_INFO "[Filter] ✅ Hook registered\n");
        return 0;
    }
    
    printk(KERN_ERR "[Filter] ❌ Failed to register\n");
    return -EINVAL;
}

/* ---------- 模块退出 ---------- */
static void __exit filter_exit(void)
{
    unregister_kprobe(&kp_show_map_vma);
    printk(KERN_INFO "[Filter] Unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);