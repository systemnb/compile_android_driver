#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_process.h"
//#include "verify.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
extern struct task_struct *task;
struct task_struct *hide_pid_process_task;
int hide_process_pid = 0;
int hide_process_state = 0;
static struct mem_tool_device {
    struct cdev cdev;
    struct device *dev;
    int max;
} memdev;

static dev_t mem_tool_dev_t;
static struct class *mem_tool_class;
const char *devicename;

static bool is_node_removed = false;
long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg)
{
	static COPY_MEMORY cm;
	static MODULE_BASE mb;
	static struct process p_process;
	static char name[0x100] = {0};
	/*static char key[0x100] = {0};
	static bool is_key_initialized = false;  // 标记密钥是否已初始化

	if (cmd == OP_INIT_KEY) {
		if (copy_from_user(key, (void __user*)arg, sizeof(key)-1) != 0) {
			return -1;
		}
		if (init_key(key, sizeof(key))) {  // 只有密钥初始化成功，才允许执行其他命令
			is_key_initialized = true;
		}
		return 0;  // 直接返回，不继续执行后面的逻辑
	}

	// 如果密钥未初始化，则拒绝所有操作
	if (!is_key_initialized) {
		return -1;
	}*/
	switch (cmd) {
		case OP_READ_MEM:
			{
				if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
					return -1;
				}
				if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
					return -1;
				}
			}
			break;

		case OP_WRITE_MEM:
			{
				if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
					return -1;
				}
				if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
					return -1;
				}
			}
			break;

		case OP_MODULE_BASE:
			{
				if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0 
				|| copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) != 0) {
					return -1;
				}
				mb.base = get_module_base(mb.pid, name);
				if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) != 0) {
					return -1;
				}
			}
			break;

		case OP_HIDE_PROCESS:
			hide_process(task, &hide_process_state);
			break;

		case OP_PID_HIDE_PROCESS:
			if (copy_from_user(&hide_process_pid, (void __user*)arg, sizeof(hide_process_pid)) != 0) {
					return -1;
			}
			hide_pid_process_task = pid_task(find_vpid(hide_process_pid), PIDTYPE_PID);
			hide_pid_process(hide_pid_process_task);
			break;
		case OP_GET_PROCESS_PID:
			if (copy_from_user(&p_process, (void __user*)arg, sizeof(p_process)) != 0) {
					return -1;
			}
			p_process.process_pid = get_process_pid(p_process.process_comm);
			if (copy_to_user((void __user*)arg, &p_process, sizeof(p_process)) != 0) {
					return -1;
			}
			break;
		default:
			break;
	}
	return 0;
}

pid_t temp_pid;
const char *devicename;
struct task_struct *task;
int dispatch_open(struct inode *node, struct file *file)
{
	//获取连接驱动进程的pid
	file->private_data = &memdev;
	task = current;  // 获取当前进程的task_struct
	printk("隐藏进程成功pid:%d\n", task->pid);
	if (!is_node_removed) {
        device_destroy(mem_tool_class, mem_tool_dev_t);
        is_node_removed = true;
    }
	return 0;
}

int dispatch_close(struct inode *node, struct file *file)
{
	if (hide_process_state) {
		recover_process(task);
	}
	if (hide_process_pid != 0) {
		recover_process(hide_pid_process_task);
	}
    if (is_node_removed) {
        memdev.dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, devicename);
        if (IS_ERR(memdev.dev)) {
            printk("device_create failed\n");
        }
        is_node_removed = false;
    }
    return 0;
}

struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

static int __init driver_entry(void) {
    int ret;
    
    devicename = get_rand_str();//注释此行关闭随机驱动

    ret = alloc_chrdev_region(&mem_tool_dev_t, 0, 1, devicename);
    if (ret < 0) {
        return ret;
    }

    cdev_init(&memdev.cdev, &dispatch_functions);
    memdev.cdev.owner = THIS_MODULE;

    ret = cdev_add(&memdev.cdev, mem_tool_dev_t, 1);
    if (ret) {
        unregister_chrdev_region(mem_tool_dev_t, 1);
        return ret;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    mem_tool_class = class_create(devicename);
#else
    mem_tool_class = class_create(THIS_MODULE, devicename);
#endif
    
    if (IS_ERR(mem_tool_class)) {
        cdev_del(&memdev.cdev);
        unregister_chrdev_region(mem_tool_dev_t, 1);
        return PTR_ERR(mem_tool_class);
    }

    memdev.dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, devicename);
    if (IS_ERR(memdev.dev)) {
        class_destroy(mem_tool_class);
        cdev_del(&memdev.cdev);
        unregister_chrdev_region(mem_tool_dev_t, 1);
        return PTR_ERR(memdev.dev);
    }
    remove_proc_entry("uevents_records", NULL); // 删除 uevents_records 日志
    remove_proc_entry("sched_debug", NULL);     // 删除 sched_debug 日志
    list_del_rcu(&THIS_MODULE->list);           // 摘除链表，/proc/modules 中不可见
    kobject_del(&THIS_MODULE->mkobj.kobj);      // 摘除 kobj，/sys/modules/ 中不可见
    return 0;
}

static void __exit driver_unload(void) {
    if (!is_node_removed) {
        device_destroy(mem_tool_class, mem_tool_dev_t);
    }
    class_destroy(mem_tool_class);
    cdev_del(&memdev.cdev);
    unregister_chrdev_region(mem_tool_dev_t, 1);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_LICENSE("GPL");
