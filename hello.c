#include <linux/module.h>
#include <linux/slab.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/soc.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>

#define VIRT_MIC_BUF_SIZE 16384
static char *virt_mic_buf;
static size_t buf_len;

static struct snd_card *card;
static struct snd_pcm *pcm;

/* 用户态接口：/dev/virt_mic 写入音频数据 */
static ssize_t virt_mic_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    if (count > VIRT_MIC_BUF_SIZE)
        count = VIRT_MIC_BUF_SIZE;

    if (copy_from_user(virt_mic_buf, buf, count))
        return -EFAULT;

    buf_len = count;
    return count;
}

static const struct file_operations virt_mic_fops = {
    .owner = THIS_MODULE,
    .write = virt_mic_write,
};

static struct miscdevice virt_mic_misc = {
    .name  = "virt_mic",
    .fops  = &virt_mic_fops,
    .minor = MISC_DYNAMIC_MINOR,
};

/* PCM 读取：系统录音时会调用这里 */
static int virt_pcm_capture(struct snd_pcm_substream *substream,
                             struct snd_pcm_runtime *runtime,
                             unsigned char __user *buf,
                             snd_pcm_uframes_t frames,
                             int xrun)
{
    size_t bytes = frames * 2; // S16_LE mono

    if (bytes > buf_len)
        bytes = buf_len;

    if (copy_to_user(buf, virt_mic_buf, bytes))
        return -EFAULT;

    return bytes;
}

static int virt_pcm_open(struct snd_pcm_substream *substream)   { return 0; }
static int virt_pcm_close(struct snd_pcm_substream *substream)  { return 0; }
static snd_pcm_uframes_t virt_pcm_pointer(struct snd_pcm_substream *substream) { return 0; }

static struct snd_pcm_ops virt_pcm_ops = {
    .open    = virt_pcm_open,
    .close   = virt_pcm_close,
    .pointer = virt_pcm_pointer,
    .capture = virt_pcm_capture,
};

static struct snd_pcm_hardware virt_pcm_hw = {
    .info            = SNDRV_PCM_INFO_CAPTURE | SNDRV_PCM_INFO_INTERLEAVED,
    .formats         = SNDRV_PCM_FMTBIT_S16_LE,
    .rates           = SNDRV_PCM_RATE_48000,
    .rate_min        = 48000,
    .rate_max        = 48000,
    .channels_min    = 1,
    .channels_max    = 1,
    .buffer_bytes_max = VIRT_MIC_BUF_SIZE,
};

static int __init virt_mic_init(void)
{
    int ret;

    virt_mic_buf = kmalloc(VIRT_MIC_BUF_SIZE, GFP_KERNEL);
    if (!virt_mic_buf)
        return -ENOMEM;

    ret = misc_register(&virt_mic_misc);
    if (ret)
        goto fail_buf;

    ret = snd_card_new(NULL, -1, NULL, THIS_MODULE, sizeof(*card), &card);
    if (ret)
        goto fail_misc;

    ret = snd_pcm_new(card, "VirtualMic", 0, 0, 1, &pcm);
    if (ret)
        goto fail_card;

    snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_CAPTURE, &virt_pcm_ops);
    pcm->runtime->hw = virt_pcm_hw;

    strcpy(card->driver, "virtmic");
    strcpy(card->shortname, "VirtualMic");
    strcpy(card->longname, "Virtual Microphone");

    ret = snd_card_register(card);
    if (ret)
        goto fail_card;

    pr_info("virtmic: Virtual microphone loaded\n");
    return 0;

fail_card:
    snd_card_free(card);
fail_misc:
    misc_deregister(&virt_mic_misc);
fail_buf:
    kfree(virt_mic_buf);
    return ret;
}

static void __exit virt_mic_exit(void)
{
    snd_card_free(card);
    misc_deregister(&virt_mic_misc);
    kfree(virt_mic_buf);
    pr_info("virtmic: unloaded\n");
}

module_init(virt_mic_init);
module_exit(virt_mic_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Virtual Microphone for MTK Platform");
