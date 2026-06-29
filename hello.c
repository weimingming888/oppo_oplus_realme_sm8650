#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/nodemask.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide all post root mount points, no blacklist");

static struct kprobe filp_open_kp;
static struct vfsmount *root_mnt; // 保存系统初始根挂载

// 判断当前路径是否落在「非根的后续挂载点」
static bool is_post_mount_path(const char *user_path)
{
    struct mount *mnt;
    struct mount *root_mount = mnt_from_mnt(root_mnt);
    char tmp_buf[512];
    const char *mnt_path;

    // 遍历全局挂载链表
    list_for_each_entry(mnt, &mnt_list, mnt_list) {
        // 跳过根文件系统挂载
        if (mnt == root_mount)
            continue;

        // 获取挂载点完整路径
        d_path(&mnt->mnt_mountpoint, tmp_buf, sizeof(tmp_buf));
        mnt_path = tmp_buf;

        // 空路径跳过
        if (!mnt_path || strlen(mnt_path) == 0)
            continue;

        // 匹配：访问路径以该挂载点开头
        if (!strncmp(user_path, mnt_path, strlen(mnt_path))) {
            return true;
        }
    }
    return false;
}

// filp_open 前置拦截钩子
static int pre_hook_filp_open(struct kprobe *p, struct pt_regs *regs)
{
    // ARM64: x0 = pathname
    const char __user *u_path = (const char __user *)regs->regs[0];
    char k_path[256] = {0};
    long cp_ret;

    cp_ret = strncpy_from_user(k_path, u_path, sizeof(k_path) - 1);
    if (cp_ret < 0)
        return 0;

    // 命中任意后期挂载点，直接屏蔽
    if (is_post_mount_path(k_path)) {
        pr_info("[hide_mnt] Block post mount access: %s\n", k_path);
        // 跳过原函数，返回文件不存在
        regs->regs[0] = (unsigned long)ERR_PTR(-ENOENT);
        p->flags |= KPROBE_FLAG_SKIP_FUNCTION;
    }
    return 0;
}

static int __init hide_mnt_init(void)
{
    int ret;
    struct path root_p;

    // 保存系统启动初始根挂载
    get_task_root(current, &root_p);
    root_mnt = root_p.mnt;
    mntget(root_mnt);

    // 注册kprobe挂钩filp_open
    memset(&filp_open_kp, 0, sizeof(filp_open_kp));
    filp_open_kp.symbol_name = "filp_open";
    filp_open_kp.pre_handler = pre_hook_filp_open;

    ret = register_kprobe(&filp_open_kp);
    if (ret < 0) {
        pr_err("register filp_open kprobe failed, err:%d\n", ret);
        mntput(root_mnt);
        return ret;
    }

    pr_info("Module loaded: all post root mounts hidden\n");
    return 0;
}

static void __exit hide_mnt_exit(void)
{
    unregister_kprobe(&filp_open_kp);
    mntput(root_mnt);
    pr_info("Module unloaded, mount visibility restored\n");
}

module_init(hide_mnt_init);
module_exit(hide_mnt_exit);
