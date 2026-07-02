#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");

/* ============================================================
 *  伪造的 GPS NMEA 数据 (上海浦东)
 * ============================================================ */

static const char fake_nmea_data[] =
    "$GPGGA,123519.00,3114.0000,N,12128.0000,E,1,08,0.9,545.4,M,46.9,M,,*47\r\n"
    "$GPGSA,A,3,07,02,26,27,09,04,15,,,,,1.8,1.0,1.5*33\r\n"
    "$GPGSV,3,1,11,03,03,111,00,04,15,270,00,06,01,010,00,13,06,292,00*74\r\n"
    "$GPRMC,123519.00,A,3114.0000,N,12128.0000,E,022.4,084.4,230394,003.1,W*6A\r\n";

/* ============================================================
 *  kprobe 结构
 * ============================================================ */

static struct kprobe kp_read;
static struct kprobe kp_ioctl;
static int hook_count = 0;

/* ============================================================
 *  判断是否是 GPS 设备
 * ============================================================ */

static int is_gps_device(unsigned int fd) {
    struct file *file;
    char *path_buf;
    char *path;
    int ret = 0;
    
    file = fget(fd);
    if (!file)
        return 0;
    
    path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!path_buf) {
        fput(file);
        return 0;
    }
    
    path = d_path(&file->f_path, path_buf, PATH_MAX);
    if (!IS_ERR(path)) {
        /* MTK GPS 设备匹配 */
        if (strstr(path, "gpsmdl-nmea") ||    /* NMEA 数据 */
            strstr(path, "gpsmdl-mnl") ||     /* 控制接口 */
            strstr(path, "gps2scp") ||        /* GPS 通信 */
            strstr(path, "gpsmdl-meas") ||    /* 测量数据 */
            strstr(path, "gps")) {
            ret = 1;
            printk(KERN_DEBUG "[GPS_HOOK] Found GPS device: %s\n", path);
        }
    }
    
    kfree(path_buf);
    fput(file);
    return ret;
}

/* ============================================================
 *  read pre_handler: 拦截 GPS 数据读取
 * ============================================================ */

static int pre_read_handler(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd;
    char __user *buf;
    size_t count;
    
    (void)p;
    
    fd = (unsigned int)regs->regs[0];
    buf = (char __user *)regs->regs[1];
    count = (size_t)regs->regs[2];
    
    if (!is_gps_device(fd))
        return 0;
    
    hook_count++;
    
    /* 注入假 NMEA 数据 */
    if (hook_count <= 5) {
        size_t fake_len = strlen(fake_nmea_data);
        size_t copy_len = (count < fake_len) ? count : fake_len;
        
        if (copy_to_user(buf, fake_nmea_data, copy_len) == 0) {
            printk(KERN_INFO "[GPS_HOOK] ✅ 注入假 NMEA 数据! (#%d, fd=%d)\n", 
                   hook_count, fd);
            printk(KERN_INFO "[GPS_HOOK] 📍 位置: 31°14'N 121°28'E (上海浦东)\n");
            printk(KERN_INFO "[GPS_HOOK] 📊 数据: %s", fake_nmea_data);
            
            regs->regs[0] = copy_len;
            return 1;  /* 跳过原函数 */
        }
    }
    
    return 0;
}

/* ============================================================
 *  ioctl pre_handler: 拦截 GPS 控制命令
 * ============================================================ */

static int pre_ioctl_handler(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int fd;
    unsigned int cmd;
    unsigned long arg;
    
    (void)p;
    
    fd = (unsigned int)regs->regs[0];
    cmd = (unsigned int)regs->regs[1];
    arg = (unsigned long)regs->regs[2];
    
    if (!is_gps_device(fd))
        return 0;
    
    /* 记录 ioctl 命令 */
    if (cmd != 0) {
        printk(KERN_DEBUG "[GPS_HOOK] ioctl: fd=%d, cmd=0x%x, arg=0x%lx\n", 
               fd, cmd, arg);
    }
    
    return 0;
}

/* ============================================================
 *  模块初始化
 * ============================================================ */

static int __init gps_hook_init(void)
{
    int ret;
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[GPS_HOOK] MTK GPS kprobe 劫持模块 v3.0\n");
    printk(KERN_INFO "[GPS_HOOK] 目标设备: gpsmdl-nmea, gps2scp\n");
    printk(KERN_INFO "[GPS_HOOK] 假位置: 31°14'N 121°28'E (上海浦东)\n");
    printk(KERN_INFO "========================================\n");
    
    /* ====== Hook read ====== */
    memset(&kp_read, 0, sizeof(struct kprobe));
    kp_read.symbol_name = "__arm64_sys_read";
    kp_read.pre_handler = pre_read_handler;
    
    ret = register_kprobe(&kp_read);
    if (ret < 0) {
        printk(KERN_WARNING "[GPS_HOOK] ⚠️ __arm64_sys_read hook 失败: %d\n", ret);
    } else {
        printk(KERN_INFO "[GPS_HOOK] ✅ Hooked: __arm64_sys_read\n");
    }
    
    /* ====== Hook ioctl ====== */
    memset(&kp_ioctl, 0, sizeof(struct kprobe));
    kp_ioctl.symbol_name = "__arm64_sys_ioctl";
    kp_ioctl.pre_handler = pre_ioctl_handler;
    
    ret = register_kprobe(&kp_ioctl);
    if (ret < 0) {
        printk(KERN_WARNING "[GPS_HOOK] ⚠️ __arm64_sys_ioctl hook 失败: %d\n", ret);
    } else {
        printk(KERN_INFO "[GPS_HOOK] ✅ Hooked: __arm64_sys_ioctl\n");
    }
    
    printk(KERN_INFO "[GPS_HOOK] ✅ 等待 GPS 数据被读取...\n");
    printk(KERN_INFO "[GPS_HOOK] 运行: dmesg -w | grep GPS_HOOK\n");
    printk(KERN_INFO "========================================\n");
    
    return 0;
}

/* ============================================================
 *  模块卸载
 * ============================================================ */

static void __exit gps_hook_exit(void)
{
    unregister_kprobe(&kp_read);
    unregister_kprobe(&kp_ioctl);
    
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[GPS_HOOK] 模块卸载\n");
    printk(KERN_INFO "[GPS_HOOK] 共拦截 %d 次 GPS 读取\n", hook_count);
    printk(KERN_INFO "[GPS_HOOK] GPS 数据已恢复正常\n");
    printk(KERN_INFO "========================================\n");
}

module_init(gps_hook_init);
module_exit(gps_hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MTK GPS Hacker");
MODULE_DESCRIPTION("kprobe-based GPS interception for MTK platform");
MODULE_VERSION("3.0");