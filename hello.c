#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/string.h>

static struct kprobe kp_show_map_vma;

static int pre_show_map_vma(struct kprobe *kp, struct pt_regs *regs)
{
    struct vm_area_struct *vma = NULL;
    char *buf = NULL;
    char *fname = NULL;
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

    buf = kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf)
        return 0;

    vma_size = vma->vm_end - vma->vm_start;
    is_anon = (!vma->vm_file);
    is_private = (!(vma->vm_flags & VM_SHARED));

    /* 规则1：所有匿名私有 rwxp 直接隐藏，不设尺寸阈值 */
    if (is_anon && is_private &&
        (vma->vm_flags & VM_READ) &&
        (vma->vm_flags & VM_WRITE) &&
        (vma->vm_flags & VM_EXEC))
    {
        printk(KERN_INFO "[Filter] ❌ HIDE rwxp anon: 0x%lx-0x%lx size=0x%lx flags=0x%lx\n",
               vma->vm_start, vma->vm_end, vma_size, vma->vm_flags);
        ret = 1;
        goto out;
    }

    /* 规则2：隐藏 frida / inject.so 映射 */
    if (vma->vm_file)
    {
        char *path_ptr = d_path(&vma->vm_file->f_path, buf, PATH_MAX);
        if (!IS_ERR(path_ptr))
        {
            fname = path_ptr;
            if (strstr(fname, "frida") || strstr(fname, "inject.so"))
            {
                printk(KERN_INFO "[Filter] ❌ HIDE lib: %s\n", fname);
                ret = 1;
                goto out;
            }
        }
    }

    /* 规则3：无写权限的大块匿名r-xp(>64KB)隐藏，放过vdso小段 */
    if (is_anon && is_private &&
        (vma->vm_flags & VM_EXEC) &&
        !(vma->vm_flags & VM_WRITE))
    {
        if (vma_size > 0x10000)
        {
            printk(KERN_INFO "[Filter] ❌ HIDE rx anon big size=0x%lx flags=0x%lx\n",
                   vma_size, vma->vm_flags);
            ret = 1;
        }
        else
        {
            printk(KERN_DEBUG "[Filter] ✅ KEEP small rx anon size=0x%lx flags=0x%lx\n",
                   vma_size, vma->vm_flags);
        }
    }

out:
    kfree(buf);
    return ret;
}

static int filter_init(void)
{
    int ret;
    kp_show_map_vma.kp_symbol_name = "show_map_vma";
    kp_show_map_vma.pre_handler = pre_show_map_vma;

    ret = register_kprobe(&kp_show_map_vma);
    if (ret < 0)
    {
        printk(KERN_ERR "[Filter] register kprobe failed, ret=%d\n", ret);
        return ret;
    }
    printk(KERN_INFO "[Filter] VMA filter loaded, hook show_map_vma\n");
    return 0;
}

static void filter_exit(void)
{
    unregister_kprobe(&kp_show_map_vma);
    printk(KERN_INFO "[Filter] VMA filter unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide inject rwxp/frida/big rx anon vma");
