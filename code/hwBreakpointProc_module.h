#ifndef _HWBP_PROC_H_
#define _HWBP_PROC_H_

#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/compat.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/ksm.h>
#include <linux/mutex.h>
#include <linux/ktime.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/iovec.h>

//////////////////////////////////////////////////////////////////
// 版本控制宏定义
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#ifndef MY_LINUX_VERSION_CODE 
#define MY_LINUX_VERSION_CODE KERNEL_VERSION(6,6,30)
#endif

// 调试打印模式
//#define CONFIG_DEBUG_PRINTK

#ifdef CONFIG_DEBUG_PRINTK
#define printk_debug printk
#else
static inline void printk_debug(const char *fmt, ...) { (void)fmt; }
#endif

// 配置选项
#define CONFIG_MODULE_GUIDE_ENTRY
#define CONFIG_USE_PROC_FILE_NODE
#define CONFIG_PROC_NODE_AUTH_KEY "dce3771681d4c7a143d5d06b7d32548e"
#define CONFIG_KALLSYMS_LOOKUP_NAME
#define CONFIG_MODIFY_HIT_NEXT_MODE
#define CONFIG_ANTI_PTRACE_DETECTION_MODE

//////////////////////////////////////////////////////////////////
// 命令定义
enum {
    CMD_OPEN_PROCESS,                 // 打开进程
    CMD_CLOSE_PROCESS,                // 关闭进程
    CMD_GET_NUM_BRPS,                 // 获取CPU硬件执行断点支持数量
    CMD_GET_NUM_WRPS,                 // 获取CPU硬件访问断点支持数量
    CMD_INST_PROCESS_HWBP,            // 安装进程硬件断点
    CMD_UNINST_PROCESS_HWBP,          // 卸载进程硬件断点
    CMD_SUSPEND_PROCESS_HWBP,         // 暂停进程硬件断点
    CMD_RESUME_PROCESS_HWBP,          // 恢复进程硬件断点
    CMD_GET_HWBP_HIT_COUNT,           // 获取硬件断点命中地址数量
    CMD_GET_HWBP_HIT_DETAIL,          // 获取硬件断点命中详细信息
    CMD_SET_HOOK_PC,                  // 设置无条件Hook跳转
    CMD_HIDE_KERNEL_MODULE,           // 隐藏驱动
};

//////////////////////////////////////////////////////////////////
// 结构体定义
#pragma pack(push,1)
struct my_user_pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
    uint64_t orig_x0;
    uint64_t syscallno;
};

struct HWBP_HIT_ITEM {
    uint64_t task_id;
    uint64_t hit_addr;
    uint64_t hit_time;
    struct my_user_pt_regs regs_info;
};

struct ioctl_request {
    char     cmd;        /* 1 字节命令 */
    uint64_t param1;     /* 参数1 */
    uint64_t param2;     /* 参数2 */
    uint64_t param3;     /* 参数3 */
    uint64_t buf_size;    /* 紧随其后的动态数据长度 */
};
#pragma pack(pop)

struct HWBP_HANDLE_INFO {
    uint64_t task_id;
    struct perf_event * sample_hbp;
    struct perf_event_attr original_attr;
    bool is_32bit_task;
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
    struct perf_event_attr next_instruction_attr;
#endif
    size_t hit_total_count;
    void* hit_item_arr;  // cvector 类型
};

struct hwBreakpointProcDev {
#ifdef CONFIG_USE_PROC_FILE_NODE
    struct proc_dir_entry *proc_parent;
    struct proc_dir_entry *proc_entry;
#endif
    bool is_hidden_module; //是否已经隐藏过驱动列表了
};

//////////////////////////////////////////////////////////////////
// 全局变量声明
extern struct hwBreakpointProcDev *g_hwBreakpointProc_devp;
extern struct mutex g_hwbp_handle_info_mutex;
extern void* g_hwbp_handle_info_arr; // cvector 类型

//////////////////////////////////////////////////////////////////
// 函数声明
// 设备操作函数
ssize_t hwBreakpointProc_read(struct file* filp, char __user* buf, size_t size, loff_t* ppos);
int hwBreakpointProc_release(struct inode *inode, struct file *filp);

// proc文件操作
#ifdef CONFIG_USE_PROC_FILE_NODE
extern const struct proc_ops hwBreakpointProc_proc_ops;
#endif

// 硬件断点处理函数
void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs);

// 辅助函数
int getCpuNumBrps(void);
int getCpuNumWrps(void);
bool toggle_bp_registers_directly(const struct perf_event_attr * attr, bool is_32bit_task, int enable);

// 进程管理函数
void* get_proc_pid_struct(uint64_t pid);
void release_proc_pid_struct(void* proc_pid_struct);

// 其他功能
bool start_anti_ptrace_detection(struct mutex *p_mutex, void* p_vector);
void stop_anti_ptrace_detection(void);
bool start_hide_procfs_dir(const char* hide_dir_name);
void stop_hide_procfs_dir(void);

#endif /* _HWBP_PROC_H_ */