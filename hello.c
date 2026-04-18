#include <linux/module.h>
#include <linux/input.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/delay.h>   // 这个补上，msleep 需要

#define TOUCH_MAX_X 1080
#define TOUCH_MAX_Y 2400

static struct input_dev *virt_touch;

struct touch_cmd {
	int x;
	int y;
};

static ssize_t touch_write(struct file *file, const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	struct touch_cmd cmd;
	int trk_id = 100;
	int pressure = 35;
	int major = 6;

	if (cnt < sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(&cmd, ubuf, sizeof(cmd)))
		return -EFAULT;

	// 按下
	input_report_abs(virt_touch, ABS_MT_SLOT, 0);
	input_report_abs(virt_touch, ABS_MT_TRACKING_ID, trk_id);
	input_report_abs(virt_touch, ABS_MT_POSITION_X, cmd.x);
	input_report_abs(virt_touch, ABS_MT_POSITION_Y, cmd.y);
	input_report_abs(virt_touch, ABS_MT_PRESSURE, pressure);
	input_report_abs(virt_touch, ABS_MT_TOUCH_MAJOR, major);
	input_report_key(virt_touch, BTN_TOUCH, 1);
	input_sync(virt_touch);

	msleep(50);

	// 抬起
	input_report_abs(virt_touch, ABS_MT_TRACKING_ID, -1);
	input_report_key(virt_touch, BTN_TOUCH, 0);
	input_sync(virt_touch);

	return cnt;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.write = touch_write,
};

static struct miscdevice misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "virt_touch",
	.fops  = &fops,
};

static int __init hello_init(void)
{
	int ret;

	virt_touch = input_allocate_device();
	if (!virt_touch)
		return -ENOMEM;

	virt_touch->name = "Virtual Touchscreen";
	virt_touch->phys = "virt/input0";
	virt_touch->id.bustype = BUS_VIRTUAL;

	__set_bit(EV_KEY, virt_touch->evbit);
	__set_bit(EV_ABS, virt_touch->evbit);
	__set_bit(BTN_TOUCH, virt_touch->keybit);

	input_set_abs_params(virt_touch, ABS_MT_SLOT, 0, 1, 0, 0);
	input_set_abs_params(virt_touch, ABS_MT_TRACKING_ID, 0, 0xFFFF, 0, 0);
	input_set_abs_params(virt_touch, ABS_MT_POSITION_X, 0, TOUCH_MAX_X, 0, 0);
	input_set_abs_params(virt_touch, ABS_MT_POSITION_Y, 0, TOUCH_MAX_Y, 0, 0);
	input_set_abs_params(virt_touch, ABS_MT_PRESSURE, 0, 255, 0, 0);
	input_set_abs_params(virt_touch, ABS_MT_TOUCH_MAJOR, 0, 255, 0, 0);

	ret = input_register_device(virt_touch);
	if (ret) {
		input_free_device(virt_touch);
		return ret;
	}

	ret = misc_register(&misc);
	if (ret) {
		input_unregister_device(virt_touch);
		input_free_device(virt_touch);
		return ret;
	}

	pr_info("hello: virtual touch loaded\n");
	return 0;
}

static void __exit hello_exit(void)
{
	misc_deregister(&misc);
	input_unregister_device(virt_touch);
	input_free_device(virt_touch);
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
