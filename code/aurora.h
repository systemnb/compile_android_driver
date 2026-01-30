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

#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#else
#include <asm/pgtable.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#endif
