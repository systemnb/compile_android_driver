#ifndef _ARM64_HW_BP_H
#define _ARM64_HW_BP_H

#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/list.h>
#include <linux/signal.h>
#include <linux/compat.h>

#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/ptrace.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <asm/pgalloc.h>
#include <linux/mmap_lock.h>
#endif

// 设备名称
#define DEVICE_NAME "arm64_hw_bp"

// 断点类型定义
enum BP_TYPES {
    BP_TYPE_INST = 0,   // 指令执行断点
    BP_TYPE_READ = 1,   // 数据读断点
    BP_TYPE_WRITE = 2,  // 数据写断点
    BP_TYPE_RW = 3      // 数据读写断点
};

#endif /* _ARM64_HW_BP_H */