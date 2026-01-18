// 简化版本，只保留基本框架
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>

#define DEVICE_NAME "aKVM"
