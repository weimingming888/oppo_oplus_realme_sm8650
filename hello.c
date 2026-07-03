#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/slab.h>

static struct kprobe kp_recv;

/* ========== 打印 NMEA 数据 ========== */
static void dump_nmea(char *buf, size_t len)
{
    char *p;
    char line[512];
    int line_len;

    if (buf == NULL || len == 0)
        return;

    p = buf;
    while (*p != '\0' && (p - buf) < len) {
        char *end = strchr(p, '\n');
        if (end == NULL)
            break;

        line_len = end - p;
        if (line_len > 0 && line_len < sizeof(line) - 1) {
            memset(line, 0, sizeof(line));
            strncpy(line, p, line_len);
            line[line_len] = '\0';

            /* 去掉 \r */
            if (line_len > 0 && line[line_len - 1] == '\r')
                line[line_len - 1] = '\0';

            /* 只打印 NMEA 语句（以 $ 开头） */
            if (line[0] == '$') {
                printk(KERN_INFO "📡 [NMEA] %s\n", line);
            }
        }
        p = end + 1;
    }
}

/* ========== gps_mcudl_mcu2ap_ydata_recv ========== */
static int recv_pre(struct kprobe *p, struct pt_regs *regs)
{
    char *data_ptr;
    size_t data_len;
    unsigned long arg0, arg1;

    /* ARM64: x0=第一个参数, x1=第二个参数 */
    arg0 = regs->regs[0];
    arg1 = regs->regs[1];

    data_ptr = (char *)arg0;
    data_len = (size_t)arg1;

    if (data_ptr == NULL || data_len == 0 || data_len > 4096)
        return 0;

    /* 直接打印数据（不需要拷贝，因为 data_ptr 是内核地址） */
    dump_nmea(data_ptr, data_len);

    return 0;
}

/* ==================================================== */
static int __init kprobe_init(void)
{
    int ret;

    kp_recv.symbol_name = "gps_mcudl_mcu2ap_ydata_recv";
    kp_recv.pre_handler = recv_pre;

    ret = register_kprobe(&kp_recv);
    if (ret < 0) {
        printk(KERN_ERR "[KPROBE] ❌ 注册失败: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "[KPROBE] ✅ 已钩住: gps_mcudl_mcu2ap_ydata_recv\n");
    printk(KERN_INFO "[KPROBE] 📡 等待 NMEA 数据...\n");

    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp_recv);
    printk(KERN_INFO "[KPROBE] 已卸载\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GPS NMEA output via kprobe");