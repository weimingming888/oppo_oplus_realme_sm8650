#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/preempt.h>

static struct kprobe kp_show_map_vma;

static int pre_show_map_vma(struct kprobe *kp, struct pt_regs *regs)
{
    struct vm_area_struct *vma = NULL;
    char *buf = NULL;
    char *fname = NULL;
    unsigned long size;
    char perm[5] = "----";
    int ret = 0;

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

    size = vma->vm_end - vma->vm_start;

    /* 构建权限字符串 */
    if (vma->vm_flags & VM_READ) perm[0] = 'r';
    if (vma->vm_flags & VM_WRITE) perm[1] = 'w';
    if (vma->vm_flags & VM_EXEC) perm[2] = 'x';
    perm[3] = (vma->vm_flags & VM_SHARED) ? 's' : 'p';
    perm[4] = '\0';

    /* ====== 安全检查：只有在非原子上下文才能调用 d_path ====== */
    if (in_atomic() || irqs_disabled() || preemptible() == 0) {
        /* 原子上下文，只打印基本信息，不获取路径 */
        printk(KERN_INFO "[MAP_DBG] %016lx-%016lx %s size=0x%lx (atomic, skip path)\n",
               vma->vm_start, vma->vm_end, perm, size);
        return 0;
    }

    /* ====== 安全获取路径 ====== */
    buf = kmalloc(PATH_MAX, GFP_KERNEL);  /* 这里可以用 GFP_KERNEL，因为不在原子上下文 */
    if (!buf) {
        printk(KERN_INFO "[MAP_DBG] %016lx-%016lx %s size=0x%lx (no mem)\n",
               vma->vm_start, vma->vm_end, perm, size);
        return 0;
    }

    if (vma->vm_file) {
        char *path_ptr = d_path(&vma->vm_file->f_path, buf, PATH_MAX);
        if (!IS_ERR(path_ptr)) {
            fname = path_ptr;
        }
    }

    printk(KERN_INFO "[MAP_DBG] %016lx-%016lx %s size=0x%lx %s\n",
           vma->vm_start, vma->vm_end, perm, size,
           fname ? fname : "anon");

    kfree(buf);
    return 0;
}

static int mapdbg_init(void)
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
    kp_show_map_vma.symbol_name = "show_map_vma";  /* 先尝试这个 */
    kp_show_map_vma.pre_handler = pre_show_map_vma;

    for (i = 0; symbols[i] != NULL; i++) {
        kp_show_map_vma.symbol_name = symbols[i];
        ret = register_kprobe(&kp_show_map_vma);
        if (ret == 0) {
            printk(KERN_INFO "[MAP_DBG] ✅ Hooked: %s\n", symbols[i]);
            return 0;
        }
    }

    printk(KERN_ERR "[MAP_DBG] ❌ Failed to register kprobe\n");
    return -ENOENT;
}

static void mapdbg_exit(void)
{
    unregister_kprobe(&kp_show_map_vma);
    printk(KERN_INFO "[MAP_DBG] Unloaded\n");
}

module_init(mapdbg_init);
module_exit(mapdbg_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Debug print all VMA info with path (safe version)");