#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/capability.h>

#define DEVICE_NAME "filecopy"
#define FILECOPY_MAX_PATH 256
#define FILECOPY_BUF_SIZE (64 * 1024)

/* IOCTL definitions */
#define FILECOPY_IOC_MAGIC  'F'
#define FILECOPY_IOC_COPY   _IOW(FILECOPY_IOC_MAGIC, 1, struct filecopy_args)

MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);

struct filecopy_args {
    char src[FILECOPY_MAX_PATH];
    char dst[FILECOPY_MAX_PATH];
};

static int do_copy_file(const char *src, const char *dst)
{
    struct file *in = NULL;
    struct file *out = NULL;
    loff_t in_pos = 0;
    loff_t out_pos = 0;
    ssize_t r;
    ssize_t w;
    char *buf = NULL;
    int ret = 0;

    /* Open source file read-only */
    in = filp_open(src, O_RDONLY, 0);
    if (IS_ERR(in)) {
        ret = PTR_ERR(in);
        pr_err("filecopy: filp_open(src) failed: %d\n", ret);
        in = NULL;
        goto out;
    }

    /* Open destination file (create/truncate) */
    out = filp_open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(out)) {
        ret = PTR_ERR(out);
        pr_err("filecopy: filp_open(dst) failed: %d\n", ret);
        out = NULL;
        goto out;
    }

    buf = kmalloc(FILECOPY_BUF_SIZE, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    /* Copy loop */
    while (true) {
        r = kernel_read(in, buf, FILECOPY_BUF_SIZE, &in_pos);
        if (r < 0) {
            ret = (int)r;
            pr_err("filecopy: kernel_read failed: %d\n", ret);
            goto out;
        }
        if (r == 0) {
            /* EOF */
            break;
        }

        w = kernel_write(out, buf, r, &out_pos);
        if (w < 0) {
            ret = (int)w;
            pr_err("filecopy: kernel_write failed: %d\n", ret);
            goto out;
        }
        if (w != r) {
            /* Partial write */
            ret = -EIO;
            pr_err("filecopy: partial write %zd/%zd\n", w, r);
            goto out;
        }
    }

out:
    if (buf)
        kfree(buf);
    if (out)
        filp_close(out, NULL);
    if (in)
        filp_close(in, NULL);

    return ret;
}

static long filecopy_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct filecopy_args args;
    int ret;

    /* Basic cmd check */
    if (_IOC_TYPE(cmd) != FILECOPY_IOC_MAGIC)
        return -ENOTTY;

    /* Security gate: allow only root or CAP_SYS_ADMIN */
    if (!uid_eq(current_uid(), GLOBAL_ROOT_UID) && !capable(CAP_SYS_ADMIN)) {
        pr_warn("filecopy: permission denied uid=%u\n", __kuid_val(current_uid()));
        return -EPERM;
    }

    switch (cmd) {
    case FILECOPY_IOC_COPY:
        if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
            return -EFAULT;

        /* Ensure NUL-terminated */
        args.src[FILECOPY_MAX_PATH - 1] = '\0';
        args.dst[FILECOPY_MAX_PATH - 1] = '\0';

        pr_info("filecopy: copy '%s' -> '%s'\n", args.src, args.dst);

        ret = do_copy_file(args.src, args.dst);
        return ret;

    default:
        return -ENOTTY;
    }
}

static const struct file_operations filecopy_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = filecopy_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = filecopy_ioctl,
#endif
};

static struct miscdevice filecopy_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &filecopy_fops,
    .mode  = 0600, /* root-only by default */
};

static int __init filecopy_init(void)
{
    int ret = misc_register(&filecopy_dev);
    if (ret) {
        pr_err("filecopy: misc_register failed: %d\n", ret);
        return ret;
    }
    pr_info("filecopy: loaded. device=/dev/%s\n", DEVICE_NAME);
    return 0;
}

static void __exit filecopy_exit(void)
{
    misc_deregister(&filecopy_dev);
    pr_info("filecopy: unloaded.\n");
}

module_init(filecopy_init);
module_exit(filecopy_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("example");
MODULE_DESCRIPTION("Android kernel driver: copy file via ioctl(src,dst)");
