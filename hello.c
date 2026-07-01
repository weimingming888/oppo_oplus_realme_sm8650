#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/version.h>

static struct kprobe kp_show_map_vma;

static int pre_show_map_vma(struct kprobe *kp, struct pt_regs *regs)
{
    struct vm_area_struct *vma = NULL;
    int ret = 0;
    unsigned long vma_size;
    bool is_anon, is_private;

#if defined(CONFIG_ARM64)
    vma = (struct vm_area_struct *)regs->regs[0];
#elif defined(CONFIG_X86_64)
    vma = (struct vm_area_struct *)regs->di;
#elif defined(CONFIG_ARM)
    vma = (struct vm_area_struct *)regs->ARM_r0;
#else
    vma = NULL;
#endif

    if (!vma)
        return 0;

    vma_size = vma->vm_end - vma->vm_start;
    is_anon = (!vma->vm_file);
    is_private = (!(vma->vm_flags & VM_SHARED));

    /* ====== 规则1: 匿名私有 rwxp 直接隐藏 ====== */
    if (is_anon && is_private &&
        (vma->vm_flags & VM_READ) &&
        (vma->vm_flags & VM_WRITE) &&
        (vma->vm_flags & VM_EXEC))
    {
        /* 使用 printk_deferred 避免递归 */
        printk_deferred(KERN_INFO "[Filter] HIDE rwxp anon: 0x%lx\n", vma->vm_start);
        return 1;
    }

    /* ====== 规则2: 隐藏大块匿名 r-xp (>64KB) ====== */
    if (is_anon && is_private &&
        (vma->vm_flags & VM_EXEC) &&
        !(vma->vm_flags & VM_WRITE) &&
        vma_size > 0x10000)
    {
        printk_deferred(KERN_INFO "[Filter] HIDE rx anon: 0x%lx size=0x%lx\n", 
                        vma->vm_start, vma_size);
        return 1;
    }

    return 0;
}

static int filter_init(void)
{
    int ret;
    const char *symbols[] = {
        "show_map_vma",
        "seq_show_map_vma",
        "proc_pid_maps_show",
        "show_map",
        NULL
    };
    int i;
    
    memset(&kp_show_map_vma, 0, sizeof(struct kprobe));
    kp_show_map_vma.pre_handler = pre_show_map_vma;
    
    for (i = 0; symbols[i] != NULL; i++) {
        kp_show_map_vma.symbol_name = symbols[i];
        ret = register_kprobe(&kp_show_map_vma);
        if (ret == 0) {
            printk(KERN_INFO "[Filter] Hooked %s at %p\n", 
                   symbols[i], kp_show_map_vma.addr);
            return 0;
        }
    }
    
    printk(KERN_ERR "[Filter] Failed to register kprobe: %d\n", ret);
    return -ENOENT;
}

static void filter_exit(void)
{
    unregister_kprobe(&kp_show_map_vma);
    printk(KERN_INFO "[Filter] Unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide rwxp and big rx anon vma");