#include <linux/module.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/soc.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>

#define VIRT_MIC_BUF_SIZE (16 * 1024)
static char virt_mic_buf[VIRT_MIC_BUF_SIZE];
static size_t virt_mic_len;

static snd_pcm_substream_t *capture_substream;

static int virt_pcm_open(struct snd_pcm_substream *substream)
{
    capture_substream = substream;
    snd_pcm_set_sync(substream);
    return 0;
}

static int virt_pcm_close(struct snd_pcm_substream *substream)
{
    capture_substream = NULL;
    return 0;
}

static int virt_pcm_hw_params(struct snd_pcm_substream *substream,
                              struct snd_pcm_hw_params *params)
{
    return 0;
}

static snd_pcm_uframes_t virt_pcm_pointer(struct snd_pcm_substream *substream)
{
    return 0;
}

static int virt_pcm_capture(struct snd_pcm_substream *substream,
                            struct snd_pcm_runtime *runtime,
                            unsigned char __user *buf,
                            snd_pcm_uframes_t frames,
                            unsigned int channels)
{
    size_t bytes = frames * 2; // 16bit mono

    if (bytes > virt_mic_len)
        bytes = virt_mic_len;

    if (bytes > 0 && copy_to_user(buf, virt_mic_buf, bytes))
        return -EFAULT;

    return bytes;
}

static struct snd_pcm_ops virt_pcm_ops = {
    .open      = virt_pcm_open,
    .close     = virt_pcm_close,
    .hw_params = virt_pcm_hw_params,
    .pointer   = virt_pcm_pointer,
    .capture   = virt_pcm_capture,
};

static struct snd_pcm_hardware virt_pcm_hw = {
    .info           = SNDRV_PCM_INFO_MMAP |
                      SNDRV_PCM_INFO_INTERLEAVED |
                      SNDRV_PCM_INFO_CAPTURE,
    .formats        = SNDRV_PCM_FMTBIT_S16_LE,
    .rates          = SNDRV_PCM_RATE_44100 | SNDRV_PCM_RATE_48000,
    .rate_min       = 44100,
    .rate_max       = 48000,
    .channels_min   = 1,
    .channels_max   = 1,
    .buffer_bytes_max = VIRT_MIC_BUF_SIZE,
    .period_bytes_max = 4096,
};

static int virt_snd_probe(struct snd_card *card)
{
    struct snd_pcm *pcm;
    int ret;

    ret = snd_pcm_new(card, "virt-mic", 0, 0, 1, &pcm);
    if (ret)
        return ret;

    strcpy(pcm->name, "Virtual Microphone");
    snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_CAPTURE, &virt_pcm_ops);
    pcm->info_flags = 0;
    pcm->private_data = NULL;

    snd_pcm_set_hw_constraints(pcm, SNDRV_PCM_STREAM_CAPTURE, &virt_pcm_hw);
    return 0;
}

static struct snd_card_driver virt_card_drv = {
    .probe = virt_snd_probe,
};

static struct snd_card *card;

// 用户态接口 /dev/virt_mic_data 写入音频数据
static ssize_t data_write(struct file *file, const char __user *buf,
                          size_t count, loff_t *ppos)
{
    if (count > VIRT_MIC_BUF_SIZE)
        count = VIRT_MIC_BUF_SIZE;

    if (copy_from_user(virt_mic_buf, buf, count))
        return -EFAULT;

    virt_mic_len = count;
    return count;
}

static const struct file_operations data_fops = {
    .owner = THIS_MODULE,
    .write = data_write,
};

static struct miscdevice data_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "virt_mic_data",
    .fops  = &data_fops,
};

static int __init virt_mic_init(void)
{
    int ret;

    ret = snd_card_register(&virt_card_drv);
    if (ret)
        return ret;

    ret = misc_register(&data_misc);
    if (ret) {
        snd_card_unregister(&virt_card_drv);
        return ret;
    }

    pr_info("virt-mic: virtual microphone loaded\n");
    return 0;
}

static void __exit virt_mic_exit(void)
{
    misc_deregister(&data_misc);
    snd_card_unregister(&virt_card_drv);
    pr_info("virt-mic: unloaded\n");
}

module_init(virt_mic_init);
module_exit(virt_mic_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Android Virtual Microphone ALSA Driver");
MODULE_AUTHOR("virt-mic");
