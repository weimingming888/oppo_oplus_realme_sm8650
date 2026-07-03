#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/sched.h>

static struct kprobe kp_proc;
static struct kprobe kp_recv;
static struct kprobe kp_parse;
static struct kprobe kp_submit;
static struct kprobe kp_read_link;
static struct kprobe kp_send;

/* ========== gps_mcudl_mcu2ap_ydata_proc ========== */
static int proc_pre(struct kprobe *p, struct pt_regs *regs)
{
    printk(KERN_INFO "🔵 [YDATA_PROC] called\n");
    return 0;
}

/* ========== gps_mcudl_mcu2ap_ydata_recv ========== */
static int recv_pre(struct kprobe *p, struct pt_regs *regs)
{
    printk(KERN_INFO "🟢 [YDATA_RECV] called\n");
    return 0;
}

/* ========== gps_mcudl_data_pkt_parse ========== */
static int parse_pre(struct kprobe *p, struct pt_regs *regs)
{
    printk(KERN_INFO "🟡 [DATA_PKT_PARSE] called\n");
    return 0;
}

/* ========== gps_mcudl_data_pkt_submit ========== */
static int submit_pre(struct kprobe *p, struct pt_regs *regs)
{
    printk(KERN_INFO "🟠 [DATA_PKT_SUBMIT] called\n");
    return 0;
}

/* ========== gps_mcudl_each_link_read ========== */
static int read_link_pre(struct kprobe *p, struct pt_regs *regs)
{
    printk(KERN_INFO "🔴 [EACH_LINK_READ] called\n");
    return 0;
}

/* ========== gps_mcudl_ap2mcu_xdata_send ========== */
static int send_pre(struct kprobe *p, struct pt_regs *regs)
{
    printk(KERN_INFO "🟣 [AP2MCU_XDATA_SEND] called\n");
    return 0;
}

/* ==================================================== */
static int __init kprobe_init(void)
{
    int ret = 0;
    int registered = 0;

    /* 1. gps_mcudl_mcu2ap_ydata_proc */
    kp_proc.symbol_name = "gps_mcudl_mcu2ap_ydata_proc";
    kp_proc.pre_handler = proc_pre;
    ret = register_kprobe(&kp_proc);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: ydata_proc\n");
        registered++;
    } else {
        printk(KERN_ERR "[KPROBE] ❌ ydata_proc: %d\n", ret);
    }

    /* 2. gps_mcudl_mcu2ap_ydata_recv */
    kp_recv.symbol_name = "gps_mcudl_mcu2ap_ydata_recv";
    kp_recv.pre_handler = recv_pre;
    ret = register_kprobe(&kp_recv);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: ydata_recv\n");
        registered++;
    } else {
        printk(KERN_ERR "[KPROBE] ❌ ydata_recv: %d\n", ret);
    }

    /* 3. gps_mcudl_data_pkt_parse */
    kp_parse.symbol_name = "gps_mcudl_data_pkt_parse";
    kp_parse.pre_handler = parse_pre;
    ret = register_kprobe(&kp_parse);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: data_pkt_parse\n");
        registered++;
    } else {
        printk(KERN_ERR "[KPROBE] ❌ data_pkt_parse: %d\n", ret);
    }

    /* 4. gps_mcudl_data_pkt_submit */
    kp_submit.symbol_name = "gps_mcudl_data_pkt_submit";
    kp_submit.pre_handler = submit_pre;
    ret = register_kprobe(&kp_submit);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: data_pkt_submit\n");
        registered++;
    } else {
        printk(KERN_ERR "[KPROBE] ❌ data_pkt_submit: %d\n", ret);
    }

    /* 5. gps_mcudl_each_link_read */
    kp_read_link.symbol_name = "gps_mcudl_each_link_read";
    kp_read_link.pre_handler = read_link_pre;
    ret = register_kprobe(&kp_read_link);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: each_link_read\n");
        registered++;
    } else {
        printk(KERN_ERR "[KPROBE] ❌ each_link_read: %d\n", ret);
    }

    /* 6. gps_mcudl_ap2mcu_xdata_send */
    kp_send.symbol_name = "gps_mcudl_ap2mcu_xdata_send";
    kp_send.pre_handler = send_pre;
    ret = register_kprobe(&kp_send);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ registered: ap2mcu_xdata_send\n");
        registered++;
    } else {
        printk(KERN_ERR "[KPROBE] ❌ ap2mcu_xdata_send: %d\n", ret);
    }

    printk(KERN_INFO "[KPROBE] 🚀 GPS驱动函数监控已启动（成功 %d/6）\n", registered);
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
MODULE_DESCRIPTION("GPS driver function monitor");