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

/* ========== 打印所有数据（ASCII + HEX） ========== */
static void dump_all_data(struct pt_regs *regs, const char *func_name)
{
    char *data_ptr;
    size_t data_len;
    char *buf;
    unsigned long arg0, arg1, arg2;

    arg0 = regs->regs[0];
    arg1 = regs->regs[1];
    arg2 = regs->regs[2];

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

    /* ===== 打印函数名和长度 ===== */
    printk(KERN_INFO "========================================");
    printk(KERN_INFO "[%s] len=%zu\n", func_name, data_len);

    /* ===== 打印 ASCII（可读字符） ===== */
    {
        char ascii_buf[256];
        int j, k = 0;
        for (j = 0; j < data_len && j < 200 && k < sizeof(ascii_buf) - 1; j++) {
            if (buf[j] >= 32 && buf[j] < 127) {
                ascii_buf[k++] = buf[j];
            } else if (buf[j] == '\n') {
                ascii_buf[k++] = '\\';
                ascii_buf[k++] = 'n';
            } else if (buf[j] == '\r') {
                ascii_buf[k++] = '\\';
                ascii_buf[k++] = 'r';
            } else {
                ascii_buf[k++] = '.';
            }
        }
        ascii_buf[k] = '\0';
        printk(KERN_INFO "[%s] ASCII: %s\n", func_name, ascii_buf);
    }

    /* ===== 打印十六进制（前128字节） ===== */
    printk(KERN_INFO "[%s] HEX (first 128 bytes):", func_name);
    print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET, 16, 1,
                   buf, data_len < 128 ? data_len : 128, 1);

    /* ===== 如果有 NMEA 数据，额外打印 ===== */
    if (buf[0] == '$') {
        printk(KERN_INFO "[%s] NMEA: %s\n", func_name, buf);
    } else {
        int i;
        for (i = 0; i < data_len && i < 1024; i++) {
            if (buf[i] == '$') {
                printk(KERN_INFO "[%s] NMEA(found at %d): %s\n", func_name, i, buf + i);
                break;
            }
        }
    }

    printk(KERN_INFO "========================================\n");

    kfree(buf);
}

/* ========== 所有探针处理函数 ========== */
static int proc_pre(struct kprobe *p, struct pt_regs *regs)
{
    dump_all_data(regs, "YDATA_PROC");
    return 0;
}

static int recv_pre(struct kprobe *p, struct pt_regs *regs)
{
    dump_all_data(regs, "YDATA_RECV");
    return 0;
}

static int parse_pre(struct kprobe *p, struct pt_regs *regs)
{
    dump_all_data(regs, "DATA_PKT_PARSE");
    return 0;
}

static int submit_pre(struct kprobe *p, struct pt_regs *regs)
{
    dump_all_data(regs, "DATA_PKT_SUBMIT");
    return 0;
}

static int read_link_pre(struct kprobe *p, struct pt_regs *regs)
{
    dump_all_data(regs, "EACH_LINK_READ");
    return 0;
}

static int send_pre(struct kprobe *p, struct pt_regs *regs)
{
    dump_all_data(regs, "AP2MCU_XDATA_SEND");
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
    } else {
        printk(KERN_ERR "[KPROBE] ❌ ydata_recv: %d\n", ret);
    }

    kp_proc.symbol_name = "gps_mcudl_mcu2ap_ydata_proc";
    kp_proc.pre_handler = proc_pre;
    ret = register_kprobe(&kp_proc);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: ydata_proc\n");
        registered++;
    } else {
        printk(KERN_ERR "[KPROBE] ❌ ydata_proc: %d\n", ret);
    }

    kp_parse.symbol_name = "gps_mcudl_data_pkt_parse";
    kp_parse.pre_handler = parse_pre;
    ret = register_kprobe(&kp_parse);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: data_pkt_parse\n");
        registered++;
    } else {
        printk(KERN_ERR "[KPROBE] ❌ data_pkt_parse: %d\n", ret);
    }

    kp_submit.symbol_name = "gps_mcudl_data_pkt_submit";
    kp_submit.pre_handler = submit_pre;
    ret = register_kprobe(&kp_submit);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: data_pkt_submit\n");
        registered++;
    } else {
        printk(KERN_ERR "[KPROBE] ❌ data_pkt_submit: %d\n", ret);
    }

    kp_read_link.symbol_name = "gps_mcudl_each_link_read";
    kp_read_link.pre_handler = read_link_pre;
    ret = register_kprobe(&kp_read_link);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: each_link_read\n");
        registered++;
    } else {
        printk(KERN_ERR "[KPROBE] ❌ each_link_read: %d\n", ret);
    }

    kp_send.symbol_name = "gps_mcudl_ap2mcu_xdata_send";
    kp_send.pre_handler = send_pre;
    ret = register_kprobe(&kp_send);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: ap2mcu_xdata_send\n");
        registered++;
    } else {
        printk(KERN_ERR "[KPROBE] ❌ ap2mcu_xdata_send: %d\n", ret);
    }

    printk(KERN_INFO "[KPROBE] 🚀 已启动（成功 %d/6），输出所有符号数据\n", registered);
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
    printk(KERN_INFO "[KPROBE] 已卸载\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GPS driver full data dump (ASCII + HEX)");