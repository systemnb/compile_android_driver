#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include "comm.h"
#include "memory.h"
#include "process.h"

// Forward declarations to solve order-of-definition issues
int dispatch_open(struct inode *node, struct file *file);
int dispatch_close(struct inode *node, struct file *file);
long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg);

// Define structs before they are used in open/close
struct file_operations dispatch_functions = {
	.owner = THIS_MODULE,
	.open = dispatch_open,
	.release = dispatch_close,
	.unlocked_ioctl = dispatch_ioctl,
};

struct miscdevice misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = NULL, // Set at runtime in driver_entry to avoid compile error
	.fops = &dispatch_functions,
};

int dispatch_open(struct inode *node, struct file *file)
{
	// 连接后立即注销设备节点，防止被检测
	misc_deregister(&misc);
	return 0;
}

int dispatch_close(struct inode *node, struct file *file)
{
	// 断开连接后，使用新的随机名称重新注册设备节点
	misc.name = get_rand_str();
	misc_register(&misc);
	return 0;
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg)
{
	static COPY_MEMORY cm;
	static MODULE_BASE mb;
	static char key[0x100] = "f698a4532a48637c6af673f09f5cd65cg45183a6g2e905bb018g8ec772759defd9f8981d";
	static char name[0x100] = {0};
	static bool is_verified = false;

	if (cmd == OP_INIT_KEY && !is_verified)
	{
		if (copy_from_user(key, (void __user *)arg, sizeof(key) - 1) != 0)
		{
			return -1;
		}
	}
	switch (cmd)
	{
	case OP_READ_MEM:
	{
		if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
		{
			return -1;
		}
		if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
		{
			return -1;
		}
		break;
	}
	case OP_WRITE_MEM:
	{
		if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
		{
			return -1;
		}
		if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
		{
			return -1;
		}
		break;
	}
	case OP_MODULE_BASE:
	{
		if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) != 0 || copy_from_user(name, (void __user *)mb.name, sizeof(name) - 1) != 0)
		{
			return -1;
		}
		mb.base = get_module_base(mb.pid, name);
		if (copy_to_user((void __user *)arg, &mb, sizeof(mb)) != 0)
		{
			return -1;
		}
		break;
	}
	default:
		break;
	}
	return 0;
}

int __init driver_entry(void)
{
	int ret;
	printk("[+] driver_entry");

	// Set random name at runtime
	misc.name = get_rand_str();
	ret = misc_register(&misc);

	if (ret == 0)
	{
		remove_proc_entry("uevents_records", NULL);
		remove_proc_entry("sched_debug", NULL);
		list_del_rcu(&THIS_MODULE->list);
		kobject_del(&THIS_MODULE->mkobj.kobj);
	}

	return ret;
}

void __exit driver_unload(void)
{
	printk("[+] driver_unload");
	misc_deregister(&misc);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_LICENSE("GPL");