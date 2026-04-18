#include <linux/module.h>
#include <linux/input.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>

#define TOUCH_X_MAX 1080
#define TOUCH_Y_MAX 2400

struct input_dev *virt_touch;

struct touch_cmd {
	int x;
	int y;
	int press; // 1=按下 0=抬起
};

static ssize_t touch_write(struct file *file, const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	struct touch_cmd cmd;

	if (cnt < sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(&cmd, ubuf, sizeof(cmd)))
		return -EFAULT;

	if (cmd.press) {
		input_report_abs(virt_touch, ABS_MT_SLOT, 0);
		input_report_abs(virt_touch, ABS_MT_TRACKING_ID, 100);
		input_report_abs(virt_touch, ABS_MT_POSITION_X, cmd.x);
		input_report_abs(virt_touch, ABS_MT_POSITION_Y, cmd.y);
		input_report_key(virt_touch, BTN_TOUCH, 1);
	} else {
		input_report_abs(virt_touch, ABS_MT_SLOT, 0);
		input_report_abs(virt_touch, ABS_MT_TRACKING_ID, -1);
		input_report_key(virt_touch, BTN_TOUCH, 0);
	}

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

	virt_touch->name = "Virtual Touch";
	virt_touch->phys = "virt/input";
	virt_touch->id.bustype = BUS_VIRTUAL;

	__set_bit(EV_KEY, virt_touch->evbit);
	__set_bit(EV_ABS, virt_touch->evbit);
	__set_bit(BTN_TOUCH, virt_touch->keybit);

	input_set_abs_params(virt_touch, ABS_MT_POSITION_X, 0, TOUCH_X_MAX, 0, 0);
	input_set_abs_params(virt_touch, ABS_MT_POSITION_Y, 0, TOUCH_Y_MAX, 0, 0);
	input_set_abs_params(virt_touch, ABS_MT_SLOT, 0, 1, 0, 0);
	input_set_abs_params(virt_touch, ABS_MT_TRACKING_ID, 0, 0xFF, 0, 0);

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
	pr_info("hello: exit\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Virtual Touch Screen");
