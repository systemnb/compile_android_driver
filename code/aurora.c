#include "aurora.h"

int dispatch_open(struct inode *node, struct file *file)
{
	printk(KERN_INFO "Device opened\n");
	return 0;
}

int dispatch_close(struct inode *node, struct file *file)
{
	printk(KERN_INFO "Device closed\n");
	return 0;
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg)
{
	printk(KERN_INFO "IOCTL called: %u\n", cmd);
	return 0;
}

struct file_operations dispatch_functions = {
	.owner = THIS_MODULE,
	.open = dispatch_open,
	.release = dispatch_close,
	.unlocked_ioctl = dispatch_ioctl,
};

struct miscdevice misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &dispatch_functions,
};

int __init driver_entry(void)
{
	int ret;
	printk(KERN_INFO "[+] driver_entry\n");
	ret = misc_register(&misc);
	return ret;
}

void __exit driver_unload(void)
{
	printk(KERN_INFO "[+] driver_unload\n");
	misc_deregister(&misc);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel.");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("JiangNight");
