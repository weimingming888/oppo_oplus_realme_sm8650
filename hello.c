#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/slab.h>

static struct kprobe kp_recv;
static struct kprobe kp_submit;

/* 目标坐标 */
#define FAKE_LAT "3123.0400"
#define FAKE_LON "12128.3700"
#define FAKE_ALT "10.0"

/* ========== NMEA 校验和计算 ========== */
static char nmea_checksum(const char *str)
{
    char ch;
    char checksum = 0;
    int i = 0;

    if (str[0] == '$')
        i = 1;

    while ((ch = str[i]) != '\0' && ch != '*' && ch != '\r' && ch != '\n') {
        checksum ^= ch;
        i++;
    }

    return checksum;
}

/* ========== 修改 GGA ========== */
static void modify_gga(char *buf, size_t len)
{
    char tmp[512];
    char *fields[20];
    int i = 0;
    char *p, *saveptr;
    char final[512];

    if (len < 10 || len > 512)
        return;

    memset(tmp, 0, sizeof(tmp));
    strncpy(tmp, buf, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    p = tmp;
    saveptr = NULL;
    while ((saveptr = strsep(&p, ",")) != NULL && i < 20) {
        fields[i++] = saveptr;
    }

    if (i < 6)
        return;

    /* 修改关键字段 */
    fields[6] = "1";          /* 定位状态: 有效 */
    fields[7] = "8";          /* 卫星数: 8 颗 */
    fields[8] = "1.2";        /* HDOP */

    /* 重建 GGA */
    snprintf(tmp, sizeof(tmp),
             "%s,%s,%s,N,%s,E,%s,%s,%s,%s,M,0.0,M,,",
             fields[0], fields[1], FAKE_LAT, FAKE_LON,
             fields[6], fields[7], fields[8], FAKE_ALT);

    /* 计算校验和并写回 */
    {
        unsigned char checksum = nmea_checksum(tmp);
        snprintf(final, sizeof(final), "%s*%02X", tmp, checksum);
        memset(buf, 0, len);
        strncpy(buf, final, len - 1);
        buf[len - 1] = '\0';
        printk(KERN_INFO "🔄 [GGA_FAKE] %s\n", final);
    }
}

/* ========== 修改 RMC ========== */
static void modify_rmc(char *buf, size_t len)
{
    char tmp[512];
    char *fields[20];
    int i = 0;
    char *p, *saveptr;
    char final[512];

    if (len < 10 || len > 512)
        return;

    memset(tmp, 0, sizeof(tmp));
    strncpy(tmp, buf, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    p = tmp;
    saveptr = NULL;
    while ((saveptr = strsep(&p, ",")) != NULL && i < 20) {
        fields[i++] = saveptr;
    }

    if (i < 6)
        return;

    fields[2] = "A";          /* 定位状态: 有效 */
    fields[3] = FAKE_LAT;     /* 纬度 */
    fields[5] = FAKE_LON;     /* 经度 */
    fields[7] = "0.0";        /* 速度 */
    fields[8] = "0.0";        /* 航向 */

    snprintf(tmp, sizeof(tmp),
             "%s,%s,%s,%s,N,%s,E,%s,%s,%s,%s,%s,",
             fields[0], fields[1], fields[2], fields[3],
             fields[5], fields[7], fields[8], fields[9],
             fields[10], fields[11]);

    {
        unsigned char checksum = nmea_checksum(tmp);
        snprintf(final, sizeof(final), "%s*%02X", tmp, checksum);
        memset(buf, 0, len);
        strncpy(buf, final, len - 1);
        buf[len - 1] = '\0';
        printk(KERN_INFO "🔄 [RMC_FAKE] %s\n", final);
    }
}

/* ========== 处理数据 ========== */
static void process_nmea(char *buf, size_t len, const char *source)
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

            if (line_len > 0 && line[line_len - 1] == '\r')
                line[line_len - 1] = '\0';

            /* 打印原始数据 */
            if (line[0] == '$') {
                printk(KERN_INFO "📡 [%s] %s\n", source, line);
            }

            /* 修改 GGA 和 RMC */
            if (strstr(line, "GGA") != NULL) {
                modify_gga(line, sizeof(line));
                memset(p, 0, end - p + 1);
                strncpy(p, line, strlen(line));
                strncpy(p + strlen(line), "\n", 1);
            } else if (strstr(line, "RMC") != NULL) {
                modify_rmc(line, sizeof(line));
                memset(p, 0, end - p + 1);
                strncpy(p, line, strlen(line));
                strncpy(p + strlen(line), "\n", 1);
            }
        }
        p = end + 1;
    }
}

/* ========== recv_pre ========== */
static int recv_pre(struct kprobe *p, struct pt_regs *regs)
{
    char *data_ptr;
    size_t data_len;
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
        return 0;

    process_nmea(data_ptr, data_len, "RECV");
    return 0;
}

/* ========== submit_pre ========== */
static int submit_pre(struct kprobe *p, struct pt_regs *regs)
{
    char *data_ptr;
    size_t data_len;
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
        return 0;

    process_nmea(data_ptr, data_len, "SUBMIT");
    return 0;
}

/* ==================================================== */
static int __init kprobe_init(void)
{
    int ret = 0;
    int success = 0;

    kp_recv.symbol_name = "gps_mcudl_mcu2ap_ydata_recv";
    kp_recv.pre_handler = recv_pre;
    ret = register_kprobe(&kp_recv);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ 已钩住: ydata_recv\n");
        success++;
    }

    kp_submit.symbol_name = "gps_mcudl_data_pkt_submit";
    kp_submit.pre_handler = submit_pre;
    ret = register_kprobe(&kp_submit);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ 已钩住: data_pkt_submit\n");
        success++;
    }

    printk(KERN_INFO "[KPROBE] 🚀 GPS 数据篡改已启动 (成功 %d/2)\n", success);
    printk(KERN_INFO "[KPROBE] 🎯 目标坐标: %s,N  %s,E\n", FAKE_LAT, FAKE_LON);
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp_recv);
    unregister_kprobe(&kp_submit);
    printk(KERN_INFO "[KPROBE] 已卸载\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GPS data modifier with dual hooks");