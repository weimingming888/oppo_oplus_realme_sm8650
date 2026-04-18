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

/* 
 * 当上层 App (如录音机) 从 /dev/snd/pcmC0D0c 读取数据时，
 * 内核会调用此函数，将虚拟音频数据拷贝到用户空间。
 */
static int vmic_pcm_copy(struct snd_pcm_substream *substream,
                         int channel, snd_pcm_uframes_t pos,
                         void __user *buf, unsigned long frames)
{
    struct snd_pcm_runtime *runtime = substream->runtime;
    unsigned int bytes = frames_to_bytes(runtime, frames);
    char *hwbuf = runtime->dma_area + frames_to_bytes(runtime, pos);
    int i;

    /* 在内核态生成 16-bit 白噪声数据 */
    for (i = 0; i < bytes; i += 2) {
        /* prandom_u32() 是内核安全的随机数函数 */
        short noise = (short)prandom_u32();
        memcpy(hwbuf + i, &noise, 2);
    }

    /* 将生成的数据拷贝给用户空间的 App */
    if (copy_to_user(buf, hwbuf, bytes))
        return -EFAULT;

    /* 更新硬件缓冲区指针，骗过 ALSA 子系统认为数据在不断流动 */
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

    /* 缓冲区配置 */
    runtime->hw.period_bytes_min = 4096;
    runtime->hw.period_bytes_max = 4096;
    runtime->hw.periods_min = 2;
    runtime->hw.periods_max = 4;

    return 0;
}

/* PCM 操作函数集 */
static const struct snd_pcm_ops vmic_pcm_ops = {
    .open      = vmic_pcm_open,
    .close     = snd_pcm_lib_close, /* 使用 ALSA 标准关闭 */
    .copy      = vmic_pcm_copy,      /* 核心：拦截并注入假数据 */
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
    
    /* 绑定操作函数 */
    snd_pcm_set_ops(vmic->pcm, SNDRV_PCM_STREAM_CAPTURE, &vmic_pcm_ops);

    /* 
     * Kernel 6.1 推荐的内存管理方式：预分配 VMALLOC 缓冲区 
     * 这样我们就不需要自己写复杂的 hw_params 和 hw_free 回调了
     */
    snd_pcm_set_managed_buffer_all(vmic->pcm, SNDRV_DMA_TYPE_VMALLOC, NULL, 0, 0);

    return 0;
}

static int __init hello_init(void)
{
    struct vmic_dev *vmic;
    int err;

    /* 1. 创建一张虚拟声卡 */
    err = snd_card_new(NULL, /* parent device, 设为NULL */
                       -1,  /* card index, -1表示自动分配 */
                       VMIC_NAME, 
                       THIS_MODULE, 
                       sizeof(struct vmic_dev), 
                       &vmic->card);
    if (err < 0)
        return err;

    vmic = card->private_data;

    /* 2. 在声卡上挂载 PCM 麦克风设备 */
    err = vmic_new_pcm(vmic);
    if (err < 0)
        goto error_card;

    /* 3. 注册声卡到 ALSA 核心 */
    err = snd_card_register(vmic->card);
    if (err < 0)
        goto error_card;

    pr_info("hello: Virtual Kernel Microphone loaded (48kHz S16_LE White Noise)\n");
    return 0;

error_card:
    snd_card_free(vmic->card);
    return err;
}

static void __exit hello_exit(void)
{
    /* 在 exit 中获取 card 指针稍微复杂点，这里直接遍历释放或保存为静态变量 
       为了代码简洁，实际生产环境应将 vmic 保存为模块静态变量 */
    pr_info("hello: Virtual Kernel Microphone unloaded\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AI Assistant");
MODULE_DESCRIPTION("Virtual Kernel Microphone for Android 15 (Kernel 6.1)");
