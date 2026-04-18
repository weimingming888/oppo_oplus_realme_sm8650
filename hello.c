#include <linux/module.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/slab.h>
#include <linux/device.h>

/* 虚拟输入设备结构体 */
static struct input_dev *vinput_dev;

/* 
 * sysfs 写入回调函数
 * 格式: echo "X Y P" > /sys/class/input/eventX/device/vinput_event
 * X: X坐标, Y: Y坐标, P: 压力 (1按下, 0抬起)
 */
static ssize_t vinput_send_event(struct device *dev, 
                                 struct device_attribute *attr, 
                                 const char *buf, 
                                 size_t count)
{
    int x, y, pressure;

    /* 解析用户空间传入的字符串 */
    if (sscanf(buf, "%d %d %d", &x, &y, &pressure) == 3) {
        /* 报告绝对坐标 */
        input_report_abs(vinput_dev, ABS_X, x);
        input_report_abs(vinput_dev, ABS_Y, y);
        /* 报告触摸状态 (BTN_TOUCH) */
        input_report_key(vinput_dev, BTN_TOUCH, pressure);
        /* 同步事件，通知上层事件结束 */
        input_sync(vinput_dev);
    }

    return count;
}

/* 定义 sysfs 属性：只写权限 (0200) */
static DEVICE_ATTR(vinput_event, 0200, NULL, vinput_send_event);

static int __init hello_init(void)
{
    int ret;

    /* 1. 分配输入设备 */
    vinput_dev = input_allocate_device();
    if (!vinput_dev) {
        pr_err("hello: Failed to allocate input device\n");
        return -ENOMEM;
    }

    /* 2. 设置设备名称，Android上层会根据这个名字匹配规则 */
    vinput_dev->name = "virtual_touch_screen";
    vinput_dev->id.bustype = BUS_VIRTUAL;

    /* 3. 设置支持的事件类型 */
    set_bit(EV_ABS, vinput_dev->evbit);       // 绝对坐标事件
    set_bit(EV_KEY, vinput_dev->evbit);       // 按键事件
    set_bit(BTN_TOUCH, vinput_dev->keybit);   // 触摸按键

    /* 4. 设置绝对坐标范围 (假设模拟一个 1080x2400 的安卓屏幕) */
    input_set_abs_params(vinput_dev, ABS_X, 0, 1079, 0, 0);
    input_set_abs_params(vinput_dev, ABS_Y, 0, 2399, 0, 0);
    input_set_abs_params(vinput_dev, ABS_MT_POSITION_X, 0, 1079, 0, 0);
    input_set_abs_params(vinput_dev, ABS_MT_POSITION_Y, 0, 2399, 0, 0);

    /* 5. 注册输入设备到内核 */
    ret = input_register_device(vinput_dev);
    if (ret) {
        pr_err("hello: Failed to register input device\n");
        input_free_device(vinput_dev);
        return ret;
    }

    /* 6. 在 /sys/class/input/eventX/device/ 下创建读写节点 */
    ret = device_create_file(&vinput_dev->dev, &dev_attr_vinput_event);
    if (ret) {
        pr_err("hello: Failed to create sysfs file\n");
        input_unregister_device(vinput_dev);
        return ret;
    }

    pr_info("hello: Virtual touch screen loaded successfully\n");
    return 0;
}

static void __exit hello_exit(void)
{
    /* 移除 sysfs 节点 */
    device_remove_file(&vinput_dev->dev, &dev_attr_vinput_event);
    /* 注销并释放设备 */
    input_unregister_device(vinput_dev);
    pr_info("hello: Virtual touch screen unloaded\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AI Assistant");
MODULE_DESCRIPTION("Virtual Touch Screen Input Driver for Kernel 6.1");
