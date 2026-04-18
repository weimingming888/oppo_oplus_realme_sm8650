#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <sound/core.h>
#include <sound/pcm.h>

#define VMIC_NAME "VirtualKernelMic"

/* 虚拟麦克风私有结构体 */
struct vmic_dev {
    struct snd_card *card;
    struct snd_pcm *pcm;
};

/* 保存为全局变量，方便在 exit 时释放 */
static struct vmic_dev *g_vmic;

/* 
 * Kernel 6.1 变更：.copy 被替换为 .copy_user
 * 当上层 App 读取数据时调用，buf 是用户空间指针
 */
static int vmic_pcm_copy_user(struct snd_pcm_substream *substream,
                              int channel, unsigned long pos,
                              void __user *buf, unsigned long bytes)
{
    struct snd_pcm_runtime *runtime = substream->runtime;
    char *hwbuf = runtime->dma_area + pos;
    int i;

    /* Kernel 6.1 变更：使用 get_random_u32() 生成白噪声 */
    for (i = 0; i < bytes; i += 2) {
        short noise = (short)get_random_u32();
        memcpy(hwbuf + i, &noise, 2);
    }

    /* 将内核态数据拷贝给用户空间的录音 App */
    if (copy_to_user(buf, hwbuf, bytes))
        return -EFAULT;

    /* 更新硬件指针 (将字节数转换为帧数) */
    snd_pcm_uframes_t frames = bytes_to_frames(runtime, bytes);
    runtime->status->hw_ptr += frames;
    if (runtime->status->hw_ptr >= runtime->buffer_size)
        runtime->status->hw_ptr -= runtime->buffer_size;

    return 0;
}

/* 告诉 ALSA 当前硬件缓冲区的位置 */
static snd_pcm_uframes_t vmic_pcm_pointer(struct snd_pcm_substream *substream)
{
    return substream->runtime->status->hw_ptr;
}

/* 打开设备时，固定硬件能力 (强制 48kHz, 16-bit, 单声道) */
static int vmic_pcm_open(struct snd_pcm_substream *substream)
{
    struct snd_pcm_runtime *runtime = substream->runtime;

    runtime->hw.info = SNDRV_PCM_INFO_INTERLEAVED;
    runtime->hw.formats = SNDRV_PCM_FMTBIT_S16_LE;
    runtime->hw.channels_min = 1;
    runtime->hw.channels_max = 1;
    runtime->hw.rates = SNDRV_PCM_RATE_48000;
    runtime->hw.rate_min = 48000;
    runtime->hw.rate_max = 48000;

    runtime->hw.period_bytes_min = 4096;
    runtime->hw.period_bytes_max = 4096;
    runtime->hw.periods_min = 2;
    runtime->hw.periods_max = 4;

    return 0;
}

/* PCM 操作函数集 */
static const struct snd_pcm_ops vmic_pcm_ops = {
    .open      = vmic_pcm_open,
    /* Kernel 6.1 变更：直接删除 .close，ALSA 核心会自动处理 managed buffer 的释放 */
    .copy_user = vmic_pcm_copy_user,      /* 替换原来的 .copy */
    .pointer   = vmic_pcm_pointer,
};

/* 创建 PCM 设备 (只有 Capture 录音端) */
static int vmic_new_pcm(struct vmic_dev *vmic)
{
    int err;

    err = snd_pcm_new(vmic->card, VMIC_NAME, 0, 0, 1, &vmic->pcm);
    if (err < 0)
        return err;

    vmic->pcm->private_data = vmic;
    strcpy(vmic->pcm->name, VMIC_NAME);
    
    snd_pcm_set_ops(vmic->pcm, SNDRV_PCM_STREAM_CAPTURE, &vmic_pcm_ops);

    /* 预分配 VMALLOC 缓冲区 */
    snd_pcm_set_managed_buffer_all(vmic->pcm, SNDRV_DMA_TYPE_VMALLOC, NULL, 0, 0);

    return 0;
}

static int __init hello_init(void)
{
    struct vmic_dev *vmic;
    int err;

    /* 1. 创建一张虚拟声卡 */
    err = snd_card_new(NULL, -1, VMIC_NAME, THIS_MODULE, 
                       sizeof(struct vmic_dev), &vmic->card);
    if (err < 0)
        return err;

    /* 修复笔误：使用 vmic->card 而不是裸用 card */
    vmic = vmic->card->private_data;
    vmic->card = vmic->card; // 保持内部指针一致

    /* 2. 挂载 PCM 设备 */
    err = vmic_new_pcm(vmic);
    if (err < 0)
        goto error_card;

    /* 3. 注册声卡 */
    err = snd_card_register(vmic->card);
    if (err < 0)
        goto error_card;

    /* 赋值给全局变量 */
    g_vmic = vmic;

    pr_info("hello: Virtual Kernel Microphone loaded for Android 15 (Kernel 6.1)\n");
    return 0;

error_card:
    snd_card_free(vmic->card);
    return err;
}

static void __exit hello_exit(void)
{
    /* 安全释放声卡资源 */
    if (g_vmic && g_vmic->card) {
        snd_card_free(g_vmic->card);
        g_vmic = NULL;
    }
    pr_info("hello: Virtual Kernel Microphone unloaded\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AI Assistant");
MODULE_DESCRIPTION("Virtual Kernel Microphone for Android 15 GKI 6.1");
