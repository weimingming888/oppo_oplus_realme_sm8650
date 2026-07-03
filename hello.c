#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/slab.h>

static struct kprobe kp_proc;
static struct kprobe kp_recv;
static struct kprobe kp_parse;
static struct kprobe kp_submit;
static struct kprobe kp_read_link;
static struct kprobe kp_send;

/* ========== 从寄存器提取数据 ========== */
static void dump_data(struct pt_regs *regs, const char *func_name)
{
    char *data_ptr;
    size_t data_len;
    char *buf;
    unsigned long arg0, arg1, arg2;

    /* ARM64: x0=第一个参数, x1=第二个参数, x2=第三个参数 */
    arg0 = regs->regs[0];
    arg1 = regs->regs[1];
    arg2 = regs->regs[2];

    /* 尝试不同的参数组合 */
    data_ptr = (char *)arg0;
    data_len = (size_t)arg1;

    if (data_len > 4096 || data_len == 0) {
        data_ptr = (char *)arg1;
        data_len = (size_t)arg2;
    }

    if (data_ptr == NULL || data_len == 0 || data_len > 4096)
        return;

    buf = kmalloc(data_len + 1, GFP_ATOMIC);
    if (buf == NULL)
        return;

    memcpy(buf, data_ptr, data_len);
    buf[data_len] = '\0';

    /* 检查是否是 NMEA 数据（以 $ 开头） */
    if (buf[0] == '$') {
        /* 直接打印 NMEA 句子 */
        printk(KERN_INFO "📡 [%s] NMEA: %s\n", func_name, buf);
    } else {
        /* 尝试查找 $ 字符（可能数据在中间） */
        int i;
        int found = 0;
        for (i = 0; i < data_len && i < 1024; i++) {
            if (buf[i] == '$') {
                printk(KERN_INFO "📡 [%s] NMEA(found): %s\n", func_name, buf + i);
                found = 1;
                break;
            }
        }
        if (!found) {
            /* 打印 ASCII 可读字符 */
            char ascii_buf[128];
            int j, k = 0;
            for (j = 0; j < data_len && j < 64 && k < sizeof(ascii_buf) - 1; j++) {
                if (buf[j] >= 32 && buf[j] < 127) {
                    ascii_buf[k++] = buf[j];
                } else {
                    ascii_buf[k++] = '.';
                }
            }
            ascii_buf[k] = '\0';
            printk(KERN_INFO "📦 [%s] ASCII(len=%zu): %s\n", func_name, data_len, ascii_buf);
        }
    }

    kfree(buf);
}

/* ========== gps_mcudl_data_pkt_submit ========== */
static int submit_pre(struct kprobe *p, struct pt_regs *regs)
{
    dump_data(regs, "SUBMIT");
    return 0;
}

/* ========== gps_mcudl_mcu2ap_ydata_recv ========== */
static int recv_pre(struct kprobe *p, struct pt_regs *regs)
{
    dump_data(regs, "RECV");
    return 0;
}

/* ========== gps_mcudl_mcu2ap_ydata_proc ========== */
static int proc_pre(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

/* ========== gps_mcudl_data_pkt_parse ========== */
static int parse_pre(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

/* ========== gps_mcudl_each_link_read ========== */
static int read_link_pre(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

/* ========== gps_mcudl_ap2mcu_xdata_send ========== */
static int send_pre(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

/* ==================================================== */
static int __init kprobe_init(void)
{
    int ret = 0;
    int registered = 0;

    kp_recv.symbol_name = "gps_mcudl_mcu2ap_ydata_recv";
    kp_recv.pre_handler = recv_pre;
    ret = register_kprobe(&kp_recv);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: ydata_recv\n");
        registered++;
    }

    kp_proc.symbol_name = "gps_mcudl_mcu2ap_ydata_proc";
    kp_proc.pre_handler = proc_pre;
    ret = register_kprobe(&kp_proc);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: ydata_proc\n");
        registered++;
    }

    kp_parse.symbol_name = "gps_mcudl_data_pkt_parse";
    kp_parse.pre_handler = parse_pre;
    ret = register_kprobe(&kp_parse);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: data_pkt_parse\n");
        registered++;
    }

    kp_submit.symbol_name = "gps_mcudl_data_pkt_submit";
    kp_submit.pre_handler = submit_pre;
    ret = register_kprobe(&kp_submit);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: data_pkt_submit\n");
        registered++;
    }

    kp_read_link.symbol_name = "gps_mcudl_each_link_read";
    kp_read_link.pre_handler = read_link_pre;
    ret = register_kprobe(&kp_read_link);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: each_link_read\n");
        registered++;
    }

    kp_send.symbol_name = "gps_mcudl_ap2mcu_xdata_send";
    kp_send.pre_handler = send_pre;
    ret = register_kprobe(&kp_send);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: ap2mcu_xdata_send\n");
        registered++;
    }

    printk(KERN_INFO "[KPROBE] 🚀 GPS 数据流监控已启动（成功 %d/6）\n", registered);
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp_proc);
    unregister_kprobe(&kp_recv);
    unregister_kprobe(&kp_parse);
    unregister_kprobe(&kp_submit);
    unregister_kprobe(&kp_read_link);
    unregister_kprobe(&kp_send);
    printk(KERN_INFO "[KPROBE] 所有探针已卸载\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GPS driver function monitor with ASCII dump");