#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/namei.h>
#include <linux/path.h>

#define DEVICE_NAME "filecopy"
#define FILECOPY_MAX_PATH 256
#define FILECOPY_BUF_SIZE (64 * 1024)

/* IOCTL definitions */
#define FILECOPY_IOC_MAGIC  'F'
#define FILECOPY_IOC_COPY   _IOW(FILECOPY_IOC_MAGIC, 1, struct filecopy_args)

/* Function pointers - prototypes exactly match <linux/fs.h> */
static struct file* (*filp_open_ptr)(const char *, int, umode_t);
static int (*filp_close_ptr)(struct file *, fl_owner_t);
static ssize_t (*kernel_read_ptr)(struct file *, void *, size_t, loff_t *);
static ssize_t (*kernel_write_ptr)(struct file *, const void *, size_t, loff_t *);

/* -------------------- CFI bypass wrappers -------------------- */
/* These wrapper functions are marked no_sanitize("cfi") to avoid CFI checks
 * on the indirect calls made inside them.
 */
__attribute__((no_sanitize("cfi")))
static inline struct file *filp_open_wrapper(const char *filename, int flags, umode_t mode)
{
    return filp_open_ptr(filename, flags, mode);
}

__attribute__((no_sanitize("cfi")))
static inline int filp_close_wrapper(struct file *filp, fl_owner_t id)
{
    return filp_close_ptr(filp, id);
}

__attribute__((no_sanitize("cfi")))
static inline ssize_t kernel_read_wrapper(struct file *file, void *buf, size_t count, loff_t *pos)
{
    return kernel_read_ptr(file, buf, count, pos);
}

__attribute__((no_sanitize("cfi")))
static inline ssize_t kernel_write_wrapper(struct file *file, const void *buf, size_t count, loff_t *pos)
{
    return kernel_write_ptr(file, buf, count, pos);
}
/* ------------------------------------------------------------ */

/* -------------------- Generic kallsyms_lookup_name helper -------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)

static unsigned long (*kallsyms_lookup_name_sym)(const char *name);

static int _kallsyms_lookup_kprobe(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

static unsigned long get_kallsyms_func(void)
{
    struct kprobe probe;
    int ret;
    unsigned long addr;

    memset(&probe, 0, sizeof(probe));
    probe.pre_handler = _kallsyms_lookup_kprobe;
    probe.symbol_name = "kallsyms_lookup_name";
    ret = register_kprobe(&probe);
    if (ret)
        return 0;
    addr = (unsigned long)probe.addr;
    unregister_kprobe(&probe);
    return addr;
}

unsigned long generic_kallsyms_lookup_name(const char *name)
{
    if (!kallsyms_lookup_name_sym) {
        kallsyms_lookup_name_sym = (void *)get_kallsyms_func();
        if (!kallsyms_lookup_name_sym)
            return 0;
    }
    return kallsyms_lookup_name_sym(name);
}

#else   /* kernel version < 5.7.0, kallsyms_lookup_name is exported directly */

unsigned long generic_kallsyms_lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}

#endif
/* -------------------------------------------------------------------------- */

struct filecopy_args {
    char src[FILECOPY_MAX_PATH];
    char dst[FILECOPY_MAX_PATH];
};

static int do_copy_file(const char *src, const char *dst)
{
    struct file *in = NULL;
    struct file *out = NULL;
    loff_t in_pos = 0, out_pos = 0;
    ssize_t r, w;
    char *buf = NULL;
    int ret = 0;

    pr_info("do_copy_file: ENTER src=%s dst=%s\n", src, dst);

    /* 1. Open source file */
    pr_info("do_copy_file: BEFORE filp_open src=%s flags=O_RDONLY\n", src);
    in = filp_open_wrapper(src, O_RDONLY, 0);
    pr_info("do_copy_file: AFTER filp_open src, in=%px\n", in);

    if (IS_ERR(in)) {
        ret = PTR_ERR(in);
        pr_err("do_copy_file: filp_open(src) failed: %d\n", ret);
        in = NULL;
        goto out;
    }

    /* 2. Open destination file (create/truncate) */
    pr_info("do_copy_file: BEFORE filp_open dst=%s flags=O_WRONLY|O_CREAT|O_TRUNC mode=0644\n", dst);
    out = filp_open_wrapper(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    pr_info("do_copy_file: AFTER filp_open dst, out=%px\n", out);

    if (IS_ERR(out)) {
        ret = PTR_ERR(out);
        pr_err("do_copy_file: filp_open(dst) failed: %d\n", ret);
        out = NULL;
        goto out;
    }

    /* 3. Allocate buffer */
    buf = kmalloc(FILECOPY_BUF_SIZE, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        pr_err("do_copy_file: kmalloc failed\n");
        goto out;
    }
    pr_info("do_copy_file: buf allocated at %px\n", buf);

    /* 4. Copy loop */
    while (true) {
        pr_info("do_copy_file: BEFORE kernel_read, in_pos=%lld\n", in_pos);
        r = kernel_read_wrapper(in, buf, FILECOPY_BUF_SIZE, &in_pos);
        pr_info("do_copy_file: AFTER kernel_read, r=%zd, in_pos=%lld\n", r, in_pos);

        if (r < 0) {
            ret = r;
            pr_err("do_copy_file: kernel_read failed %d\n", ret);
            goto out;
        }
        if (r == 0) {
            pr_info("do_copy_file: EOF reached\n");
            break;
        }

        pr_info("do_copy_file: BEFORE kernel_write, out_pos=%lld, len=%zd\n", out_pos, r);
        w = kernel_write_wrapper(out, buf, r, &out_pos);
        pr_info("do_copy_file: AFTER kernel_write, w=%zd, out_pos=%lld\n", w, out_pos);

        if (w < 0) {
            ret = w;
            pr_err("do_copy_file: kernel_write failed %d\n", ret);
            goto out;
        }
        if (w != r) {
            ret = -EIO;
            pr_err("do_copy_file: partial write %zd/%zd\n", w, r);
            goto out;
        }
    }

    pr_info("do_copy_file: copy completed\n");

out:
    pr_info("do_copy_file: CLEANUP start, ret=%d, in=%px, out=%px, buf=%px\n",
            ret, in, out, buf);

    if (buf) {
        kfree(buf);
        pr_info("do_copy_file: buf freed\n");
    }
    if (out && !IS_ERR(out)) {
        pr_info("do_copy_file: BEFORE filp_close out\n");
        filp_close_wrapper(out, NULL);
        pr_info("do_copy_file: AFTER filp_close out\n");
    }
    if (in && !IS_ERR(in)) {
        pr_info("do_copy_file: BEFORE filp_close in\n");
        filp_close_wrapper(in, NULL);
        pr_info("do_copy_file: AFTER filp_close in\n");
    }

    pr_info("do_copy_file: EXIT ret=%d\n", ret);
    return ret;
}

static long filecopy_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct filecopy_args args;
    int ret;

    pr_info("filecopy_ioctl: cmd=%u, arg=%lx\n", cmd, arg);

    if (_IOC_TYPE(cmd) != FILECOPY_IOC_MAGIC)
        return -ENOTTY;

    if (!uid_eq(current_uid(), GLOBAL_ROOT_UID) && !capable(CAP_SYS_ADMIN)) {
        pr_warn("filecopy: permission denied uid=%u\n", __kuid_val(current_uid()));
        return -EPERM;
    }

    switch (cmd) {
    case FILECOPY_IOC_COPY:
        if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
            return -EFAULT;

        args.src[FILECOPY_MAX_PATH - 1] = '\0';
        args.dst[FILECOPY_MAX_PATH - 1] = '\0';

        pr_info("filecopy: copy '%s' -> '%s'\n", args.src, args.dst);

        ret = do_copy_file(args.src, args.dst);
        pr_info("filecopy_ioctl: returning %d\n", ret);
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
    .mode  = 0600,
};

static int __init filecopy_init(void)
{
    int ret;
    unsigned long addr;

    addr = generic_kallsyms_lookup_name("filp_open");
    if (!addr) {
        pr_err("filecopy: failed to find filp_open\n");
        return -ENXIO;
    }
    filp_open_ptr = (void *)addr;
    pr_info("filecopy: filp_open found at %px\n", (void *)addr);

    addr = generic_kallsyms_lookup_name("filp_close");
    if (!addr) {
        pr_err("filecopy: failed to find filp_close\n");
        return -ENXIO;
    }
    filp_close_ptr = (void *)addr;
    pr_info("filecopy: filp_close found at %px\n", (void *)addr);

    addr = generic_kallsyms_lookup_name("kernel_read");
    if (!addr) {
        pr_err("filecopy: failed to find kernel_read\n");
        return -ENXIO;
    }
    kernel_read_ptr = (void *)addr;
    pr_info("filecopy: kernel_read found at %px\n", (void *)addr);

    addr = generic_kallsyms_lookup_name("kernel_write");
    if (!addr) {
        pr_err("filecopy: failed to find kernel_write\n");
        return -ENXIO;
    }
    kernel_write_ptr = (void *)addr;
    pr_info("filecopy: kernel_write found at %px\n", (void *)addr);

    ret = misc_register(&filecopy_dev);
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
MODULE_AUTHOR("systemnb");
MODULE_DESCRIPTION("Android kernel driver: copy file via ioctl(src,dst) with CFI bypass");