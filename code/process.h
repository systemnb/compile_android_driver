#include "linux/sched/signal.h"
#include "linux/types.h"
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/pid.h>
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,83))
#include <linux/sched/mm.h>
#endif
#define ARC_PATH_MAX 256

#include <linux/fs.h>    // For file and d_path
#include <linux/path.h>  // For struct path
#include <linux/dcache.h>// For d_path
#ifndef ARC_PATH_MAX
#define ARC_PATH_MAX PATH_MAX
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static size_t get_module_base(pid_t pid, char* name)
{
	struct task_struct* task;
	struct mm_struct* mm;
	struct vm_area_struct *vma;
	size_t count = 0;
	char buf[ARC_PATH_MAX];
	char *path_nm = NULL;

	rcu_read_lock();
	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!task) {
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	mm = get_task_mm(task);
	if (!mm) {
		return 0;
	}
	vma = find_vma(mm, 0);
	while (vma) {
		if (vma->vm_file) {
			path_nm = d_path(&vma->vm_file->f_path, buf, ARC_PATH_MAX-1);
			if (!IS_ERR(path_nm) && !strcmp(kbasename(path_nm), name)) {
				count = (uintptr_t)vma->vm_start;
				break;
			}
		}
		if (vma->vm_end >= ULONG_MAX) break; // Prevent wrapping around
		vma = find_vma(mm, vma->vm_end);
	}
	mmput(mm);
	return count;
}
#else
uintptr_t get_module_base(pid_t pid, const char *name)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    size_t count = 0;
    char buf[ARC_PATH_MAX];
    char *path_nm = "";
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        return 0;
    }

    mm = task->mm;
    if (!mm) {
        return 0;
    }
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
            struct file *file = vma->vm_file;
            if (file) {
                path_nm = d_path(&file->f_path, buf, ARC_PATH_MAX-1);
                if (!strcmp(kbasename(path_nm), name)) {
                    count = vma->vm_start;
                    break;
                }
            }
    }

    mmput(mm);
    return count;
}
#endif

pid_t get_process_pid(char *comm)
{
	struct task_struct *task;
	for_each_process(task) {
		if (strstr(task->comm, comm) != NULL) {
			return task->pid;
		}
	}
	return 0;
}