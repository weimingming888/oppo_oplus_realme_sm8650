#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/slab.h>

static struct kprobe kp_recv;
static struct kprobe kp_submit;

/* 目标坐标（上海东方明珠） */
#define FAKE_LAT "3123.0400"    /* 31°23.0400' N */
#define FAKE_LON "12128.3700"   /* 121°28.3700' E */
#define FAKE_ALT "10.0"

/* ========== NMEA 校验和计算 ========== */
static char nmea_checksum(const char *str)
{
    char ch;
    char checksum = 0;
    int i = 0;

    /* 跳过 '$' */
    if (str[0] == '$')
        i = 1;

    /* 从 '$' 后面开始异或，直到 '*' 或结束 */
    while ((ch = str[i]) != '\0' && ch != '*' && ch != '\r' && ch != '\n') {
        checksum ^= ch;
        i++;
    }

    return checksum;
}

/* ========== 重建 NMEA 语句并计算校验和 ========== */
static void rebuild_nmea(char *buf, size_t buf_len, const char *prefix,
                         const char *time, const char *lat, const char *lon,
                         const char *status, const char *satellites,
                         const char *hdop, const char *alt)
{
    char new_stmt[512];
    char checksum_str[4];
    unsigned char checksum;
    size_t len;

    /* 构建不含校验和的语句 */
    snprintf(new_stmt, sizeof(new_stmt),
             "%s,%s,%s,N,%s,E,%s,%s,%s,%s,M,0.0,M,,",
             prefix, time, lat, lon, status, satellites, hdop, alt);

    /* 计算校验和 */
    checksum = nmea_checksum(new_stmt);

    /* 追加校验和 */
    len = strlen(new_stmt);
    snprintf(new_stmt + len, sizeof(new_stmt) - len, "*%02X", checksum);

    /* 写回缓冲区（确保不溢出） */
    memset(buf, 0, buf_len);
    strncpy(buf, new_stmt, buf_len - 1);
    buf[buf_len - 1] = '\0';
}

/* ========== 修改 GGA 语句 ========== */
static int modify_gga(char *buf, size_t len)
{
    char tmp[512];
    char *p;
    char *fields[20];
    int i = 0;
    char *token;
    char *saveptr;

    if (len < 10 || len > 512)
        return -1;

    memset(tmp, 0, sizeof(tmp));
    strncpy(tmp, buf, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    /* 按逗号分割 */
    p = tmp;
    while ((token = strsep(&p, ",")) != NULL && i < 20) {
        fields[i++] = token;
    }

    if (i < 6)
        return -1;

    /* fields[0] = $GNGGA 或 $GPGGA */
    /* fields[1] = UTC 时间 */
    /* fields[2] = 纬度 */
    /* fields[3] = N/S */
    /* fields[4] = 经度 */
    /* fields[5] = E/W */
    /* fields[6] = 定位状态 */
    /* fields[7] = 卫星数 */
    /* fields[8] = HDOP */
    /* fields[9] = 海拔 */

    /* 修改关键字段 */
    fields[6] = "1";          /* 有效定位 */
    fields[7] = "8";          /* 8颗卫星 */
    fields[8] = "1.2";        /* HDOP */

    /* 重建 GGA */
    snprintf(tmp, sizeof(tmp),
             "%s,%s,%s,N,%s,E,%s,%s,%s,%s,M,0.0,M,,",
             fields[0],   /* $GNGGA */
             fields[1],   /* 时间 */
             FAKE_LAT,    /* 纬度 */
             FAKE_LON,    /* 经度 */
             fields[6],   /* 定位状态 */
             fields[7],   /* 卫星数 */
             fields[8],   /* HDOP */
             FAKE_ALT);   /* 海拔 */

    /* 计算并追加校验和 */
    {
        char final[512];
        unsigned char checksum = nmea_checksum(tmp);
        snprintf(final, sizeof(final), "%s*%02X", tmp, checksum);

        memset(buf, 0, len);
        strncpy(buf, final, len - 1);
        buf[len - 1] = '\0';

        printk(KERN_INFO "🔄 [GGA_FAKE] %s\n", final);
    }

    return 0;
}

/* ========== 修改 RMC 语句 ========== */
static int modify_rmc(char *buf, size_t len)
{
    char tmp[512];
    char *p;
    char *fields[20];
    int i = 0;
    char *token;
    char *saveptr;

    if (len < 10 || len > 512)
        return -1;

    memset(tmp, 0, sizeof(tmp));
    strncpy(tmp, buf, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    p = tmp;
    while ((token = strsep(&p, ",")) != NULL && i < 20) {
        fields[i++] = token;
    }

    if (i < 6)
        return -1;

    /* fields[0] = $GNRMC 或 $GPRMC */
    /* fields[1] = UTC 时间 */
    /* fields[2] = 状态 (A=有效, V=无效) */
    /* fields[3] = 纬度 */
    /* fields[4] = N/S */
    /* fields[5] = 经度 */
    /* fields[6] = E/W */
    /* fields[7] = 速度 */
    /* fields[8] = 航向 */
    /* fields[9] = 日期 */
    /* fields[10] = 磁偏角 */

    /* 修改为有效定位 */
    fields[2] = "A";          /* 有效 */
    fields[3] = FAKE_LAT;     /* 纬度 */
    fields[5] = FAKE_LON;     /* 经度 */
    fields[7] = "0.0";        /* 速度 */
    fields[8] = "0.0";        /* 航向 */

    /* 重建 RMC */
    snprintf(tmp, sizeof(tmp),
             "%s,%s,%s,%s,N,%s,E,%s,%s,%s,%s,%s,",
             fields[0],   /* $GNRMC */
             fields[1],   /* 时间 */
             fields[2],   /* 状态 */
             fields[3],   /* 纬度 */
             fields[5],   /* 经度 */
             fields[7],   /* 速度 */
             fields[8],   /* 航向 */
             fields[9],   /* 日期 */
             fields[10],  /* 磁偏角 */
             fields[11]); /* 磁偏角方向 */

    /* 计算并追加校验和 */
    {
        char final[512];
        unsigned char checksum = nmea_checksum(tmp);
        snprintf(final, sizeof(final), "%s*%02X", tmp, checksum);

        memset(buf, 0, len);
        strncpy(buf, final, len - 1);
        buf[len - 1] = '\0';

        printk(KERN_INFO "🔄 [RMC_FAKE] %s\n", final);
    }

    return 0;
}

/* ========== 处理 NMEA 数据包 ========== */
static void process_nmea(char *buf, size_t len, const char *source)
{
    char *p;
    char line[512];
    int line_len;

    if (buf == NULL || len == 0)
        return;

    /* 按行处理（NMEA 以 \n 或 \r\n 分隔） */
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

            /* 处理不同类型的 NMEA 语句 */
            if (strstr(line, "GGA") != NULL) {
                modify_gga(line, sizeof(line));
                /* 将修改后的行写回原缓冲区 */
                memset(p, 0, end - p + 1);
                strncpy(p, line, strlen(line));
                strncpy(p + strlen(line), "\n", 1);
            } else if (strstr(line, "RMC") != NULL) {
                modify_rmc(line, sizeof(line));
                memset(p, 0, end - p + 1);
                strncpy(p, line, strlen(line));
                strncpy(p + strlen(line), "\n", 1);
            } else {
                /* 打印其他 NMEA 语句（调试） */
                printk(KERN_INFO "📡 [%s] %s\n", source, line);
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
    char *buf;
    unsigned long arg0, arg1;

    arg0 = regs->regs[0];
    arg1 = regs->regs[1];

    data_ptr = (char *)arg0;
    data_len = (size_t)arg1;

    if (data_ptr == NULL || data_len == 0 || data_len > 4096)
        return 0;

    buf = kmalloc(data_len + 1, GFP_ATOMIC);
    if (buf == NULL)
        return 0;

    memcpy(buf, data_ptr, data_len);
    buf[data_len] = '\0';

    /* 处理接收到的数据 */
    process_nmea(data_ptr, data_len, "RECV");

    kfree(buf);
    return 0;
}

/* ========== gps_mcudl_data_pkt_submit ========== */
static int submit_pre(struct kprobe *p, struct pt_regs *regs)
{
    char *data_ptr;
    size_t data_len;
    char *buf;
    unsigned long arg0, arg1;

    arg0 = regs->regs[0];
    arg1 = regs->regs[1];

    data_ptr = (char *)arg0;
    data_len = (size_t)arg1;

    if (data_ptr == NULL || data_len == 0 || data_len > 4096)
        return 0;

    buf = kmalloc(data_len + 1, GFP_ATOMIC);
    if (buf == NULL)
        return 0;

    memcpy(buf, data_ptr, data_len);
    buf[data_len] = '\0';

    /* 处理提交的数据 */
    process_nmea(data_ptr, data_len, "SUBMIT");

    kfree(buf);
    return 0;
}

/* ==================================================== */
static int __init kprobe_init(void)
{
    int ret = 0;
    int success = 0;

    /* 1. gps_mcudl_mcu2ap_ydata_recv */
    kp_recv.symbol_name = "gps_mcudl_mcu2ap_ydata_recv";
    kp_recv.pre_handler = recv_pre;
    ret = register_kprobe(&kp_recv);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ 已钩住: gps_mcudl_mcu2ap_ydata_recv\n");
        success++;
    } else {
        printk(KERN_ERR "[KPROBE] ❌ 注册失败: gps_mcudl_mcu2ap_ydata_recv (%d)\n", ret);
    }

    /* 2. gps_mcudl_data_pkt_submit */
    kp_submit.symbol_name = "gps_mcudl_data_pkt_submit";
    kp_submit.pre_handler = submit_pre;
    ret = register_kprobe(&kp_submit);
    if (ret == 0) {
        printk(KERN_INFO "[KPROBE] ✅ 已钩住: gps_mcudl_data_pkt_submit\n");
        success++;
    } else {
        printk(KERN_ERR "[KPROBE] ❌ 注册失败: gps_mcudl_data_pkt_submit (%d)\n", ret);
    }

    if (success == 0) {
        printk(KERN_ERR "[KPROBE] ❌ 所有钩子注册失败！\n");
        return -1;
    }

    printk(KERN_INFO "[KPROBE] 🚀 GPS 数据篡改已启动 (成功 %d/2)\n", success);
    printk(KERN_INFO "[KPROBE] 🎯 目标坐标: %s,N  %s,E\n", FAKE_LAT, FAKE_LON);
    printk(KERN_INFO "[KPROBE] 🔄 拦截函数: ydata_recv + data_pkt_submit\n");

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
MODULE_DESCRIPTION("GPS data modifier with dual hooks + NMEA checksum");