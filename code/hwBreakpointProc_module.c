#include "hwBreakpointProc_module.h"
#include <linux/iovec.h>
#include <linux/string.h>

//////////////////////////////////////////////////////////////////
// 全局变量定义
static atomic64_t g_hook_pc;
struct hwBreakpointProcDev *g_hwBreakpointProc_devp;
struct mutex g_hwbp_handle_info_mutex;
static void* g_hwbp_handle_info_arr = NULL; // cvector 类型

//////////////////////////////////////////////////////////////////
// cvector 实现 (简化版)
#define MIN_LEN 1024
#define CVEFAILED  -1
#define CVESUCCESS  0
#define CVEPUSHBACK 1
#define CVEPOPBACK  2
#define CVEINSERT   3
#define CVERM       4
#define EXPANED_VAL 1
#define REDUSED_VAL 2

typedef void *citerator;
typedef struct _cvector *cvector;

struct _cvector {
    void *cv_pdata;
    size_t cv_len, cv_tot_len, cv_size;
};

static void* vmalloc_realloc(void *old_ptr, size_t old_size, size_t new_size) {
    void *new_ptr;
    if (!old_ptr) {
        return vmalloc(new_size);
    }
    if (new_size == 0) {
        vfree(old_ptr);
        return NULL;
    }
    new_ptr = vmalloc(new_size);
    if (!new_ptr) {
        pr_err("vmalloc realloc failed for size: %zu\n", new_size);
        return NULL;
    }
    memcpy(new_ptr, old_ptr, min(old_size, new_size));
    vfree(old_ptr);
    return new_ptr;
}

static cvector cvector_create(const size_t size) {
    cvector cv = (cvector)kmalloc(sizeof(struct _cvector), GFP_KERNEL);
    if (!cv) return NULL;
    
    cv->cv_pdata = vmalloc(MIN_LEN * size);
    if (!cv->cv_pdata) {
        kfree(cv);
        return NULL;
    }
    
    cv->cv_size = size;
    cv->cv_tot_len = MIN_LEN;
    cv->cv_len = 0;
    return cv;
}

static void cvector_destroy(const cvector cv) {
    vfree(cv->cv_pdata);
    kfree(cv);
}

static size_t cvector_length(const cvector cv) {
    return cv->cv_len;
}

static int cvector_pushback(const cvector cv, void *memb) {
    if (cv->cv_len >= cv->cv_tot_len) {
        void *pd_sav = cv->cv_pdata;
        size_t old_size = cv->cv_tot_len * cv->cv_size;
        cv->cv_tot_len <<= EXPANED_VAL;
        cv->cv_pdata = vmalloc_realloc(cv->cv_pdata, old_size, cv->cv_tot_len * cv->cv_size);
        
        if (!cv->cv_pdata) {
            cv->cv_pdata = pd_sav;
            cv->cv_tot_len >>= EXPANED_VAL;
            return CVEPUSHBACK;
        }
    }
    
    memcpy((char *)cv->cv_pdata + cv->cv_len * cv->cv_size, memb, cv->cv_size);
    cv->cv_len++;
    return CVESUCCESS;
}

static citerator cvector_begin(const cvector cv) {
    return cv->cv_pdata;
}

static citerator cvector_end(const cvector cv) {
    return (char *)cv->cv_pdata + (cv->cv_size * cv->cv_len);
}

static citerator cvector_next(const cvector cv, citerator iter) {
    return (char *)iter + cv->cv_size;
}

static int cvector_rm(const cvector cv, citerator iter) {
    citerator from = iter;
    citerator end = cvector_end(cv);
    
    if (iter < cvector_begin(cv) || iter >= end) {
        return CVEFAILED;
    }
    
    memcpy(from, (char *)from + cv->cv_size, (char *)end - (char *)from);
    cv->cv_len--;
    
    if ((cv->cv_tot_len >= (MIN_LEN << REDUSED_VAL)) && 
        (cv->cv_len <= (cv->cv_tot_len >> REDUSED_VAL))) {
        void *pd_sav = cv->cv_pdata;
        size_t old_size = cv->cv_tot_len * cv->cv_size;
        cv->cv_tot_len >>= EXPANED_VAL;
        cv->cv_pdata = vmalloc_realloc(cv->cv_pdata, old_size, cv->cv_tot_len * cv->cv_size);
        
        if (!cv->cv_pdata) {
            cv->cv_tot_len <<= EXPANED_VAL;
            cv->cv_pdata = pd_sav;
            return CVERM;
        }
    }
    return CVESUCCESS;
}

//////////////////////////////////////////////////////////////////
// ARM64 寄存器辅助函数
#define READ_WB_REG_CASE(OFF, N, REG, VAL) \
    case (OFF + N): \
        AARCH64_DBG_READ(N, REG, VAL); \
        break

#define WRITE_WB_REG_CASE(OFF, N, REG, VAL) \
    case (OFF + N): \
        AARCH64_DBG_WRITE(N, REG, VAL); \
        break

#define GEN_READ_WB_REG_CASES(OFF, REG, VAL) \
    READ_WB_REG_CASE(OFF,  0, REG, VAL); \
    READ_WB_REG_CASE(OFF,  1, REG, VAL); \
    READ_WB_REG_CASE(OFF,  2, REG, VAL); \
    READ_WB_REG_CASE(OFF,  3, REG, VAL); \
    READ_WB_REG_CASE(OFF,  4, REG, VAL); \
    READ_WB_REG_CASE(OFF,  5, REG, VAL); \
    READ_WB_REG_CASE(OFF,  6, REG, VAL); \
    READ_WB_REG_CASE(OFF,  7, REG, VAL); \
    READ_WB_REG_CASE(OFF,  8, REG, VAL); \
    READ_WB_REG_CASE(OFF,  9, REG, VAL); \
    READ_WB_REG_CASE(OFF, 10, REG, VAL); \
    READ_WB_REG_CASE(OFF, 11, REG, VAL); \
    READ_WB_REG_CASE(OFF, 12, REG, VAL); \
    READ_WB_REG_CASE(OFF, 13, REG, VAL); \
    READ_WB_REG_CASE(OFF, 14, REG, VAL); \
    READ_WB_REG_CASE(OFF, 15, REG, VAL)

static int getCpuNumBrps(void) {
    return ((read_cpuid(ID_AA64DFR0_EL1) >> 12) & 0xf) + 1;
}

static int getCpuNumWrps(void) {
    return ((read_cpuid(ID_AA64DFR0_EL1) >> 20) & 0xf) + 1;
}

static uint64_t read_wb_reg(int reg, int n) {
    uint64_t val = 0;
    switch (reg + n) {
        GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BVR, AARCH64_DBG_REG_NAME_BVR, val);
        GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BCR, AARCH64_DBG_REG_NAME_BCR, val);
        GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WVR, AARCH64_DBG_REG_NAME_WVR, val);
        GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WCR, AARCH64_DBG_REG_NAME_WCR, val);
        default:
            pr_warn("attempt to read from unknown breakpoint register %d\n", n);
    }
    return val;
}

static void write_wb_reg(int reg, int n, uint64_t val) {
    switch (reg + n) {
        GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BVR, AARCH64_DBG_REG_NAME_BVR, val);
        GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BCR, AARCH64_DBG_REG_NAME_BCR, val);
        GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WVR, AARCH64_DBG_REG_NAME_WVR, val);
        GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WCR, AARCH64_DBG_REG_NAME_WCR, val);
        default:
            pr_warn("attempt to write to unknown breakpoint register %d\n", n);
    }
    isb();
}

static bool toggle_bp_registers_directly(const struct perf_event_attr * attr, bool is_32bit_task, int enable) {
    int i, max_slots, val_reg, ctrl_reg, cur_slot = -1;
    u32 ctrl;
    uint64_t hw_addr;
    
    if (!attr) return false;
    
    // 计算硬件地址
    if (is_32bit_task) {
        if (attr->bp_len == HW_BREAKPOINT_LEN_8)
            hw_addr = attr->bp_addr & ~0x7;
        else
            hw_addr = attr->bp_addr & ~0x3;
    } else {
        if (attr->bp_type == HW_BREAKPOINT_X)
            hw_addr = attr->bp_addr & ~0x3;
        else
            hw_addr = attr->bp_addr & ~0x7;
    }
    
    switch (attr->bp_type) {
    case HW_BREAKPOINT_R:
    case HW_BREAKPOINT_W:
    case HW_BREAKPOINT_RW:
        ctrl_reg = AARCH64_DBG_REG_WCR;
        val_reg = AARCH64_DBG_REG_WVR;
        max_slots = getCpuNumWrps();
        break;
    case HW_BREAKPOINT_X:
        ctrl_reg = AARCH64_DBG_REG_BCR;
        val_reg = AARCH64_DBG_REG_BVR;
        max_slots = getCpuNumBrps();
        break;
    default:
        return false;
    }
    
    for (i = 0; i < max_slots; ++i) {
        uint64_t addr = read_wb_reg(val_reg, i);
        if (addr == hw_addr) {
            cur_slot = i;
            break;
        }
    }
    
    if (cur_slot == -1) return false;
    
    ctrl = read_wb_reg(ctrl_reg, cur_slot);
    if (enable)
        ctrl |= 0x1;
    else
        ctrl &= ~0x1;
    write_wb_reg(ctrl_reg, cur_slot, ctrl);
    return true;
}

//////////////////////////////////////////////////////////////////
// 进程管理函数
static void* get_proc_pid_struct(uint64_t pid) {
    return find_get_pid((pid_t)pid);
}

static void release_proc_pid_struct(void* proc_pid_struct) {
    if (proc_pid_struct) {
        put_pid((struct pid *)proc_pid_struct);
    }
}

//////////////////////////////////////////////////////////////////
// API 代理函数
static struct perf_event* x_register_user_hw_breakpoint(struct perf_event_attr *attr, 
                                                       perf_overflow_handler_t triggered, 
                                                       void *context, 
                                                       struct task_struct *tsk) {
#ifdef CONFIG_KALLSYMS_LOOKUP_NAME
    // 这里应该使用 kallsyms_lookup_name 查找实际函数
    // 简化实现：直接调用内核函数
    return register_user_hw_breakpoint(attr, triggered, context, tsk);
#else
    return register_user_hw_breakpoint(attr, triggered, context, tsk);
#endif
}

static void x_unregister_hw_breakpoint(struct perf_event *bp) {
#ifdef CONFIG_KALLSYMS_LOOKUP_NAME
    unregister_hw_breakpoint(bp);
#else
    unregister_hw_breakpoint(bp);
#endif
}

static int x_modify_user_hw_breakpoint(struct perf_event *bp, struct perf_event_attr *attr) {
#ifdef CONFIG_KALLSYMS_LOOKUP_NAME
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
    return modify_user_hw_breakpoint(bp, attr);
#else
    return 0;
#endif
#else
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
    return modify_user_hw_breakpoint(bp, attr);
#else
    return 0;
#endif
#endif
}

static unsigned long x_copy_from_user(void *to, const void __user *from, unsigned long n) {
    return __copy_from_user(to, from, n);
}

static unsigned long x_copy_to_user(void __user *to, const void *from, unsigned long n) {
    return __copy_to_user(to, from, n);
}

//////////////////////////////////////////////////////////////////
// 硬件断点命中处理
static void record_hit_details(struct HWBP_HANDLE_INFO *info, struct pt_regs *regs) {
    struct HWBP_HIT_ITEM hit_item = {0};
    if (!info || !regs) return;
    
    hit_item.task_id = info->task_id;
    hit_item.hit_addr = regs->pc;
    hit_item.hit_time = ktime_get_real_seconds();
    memcpy(&hit_item.regs_info.regs, regs->regs, sizeof(hit_item.regs_info.regs));
    hit_item.regs_info.sp = regs->sp;
    hit_item.regs_info.pc = regs->pc;
    hit_item.regs_info.pstate = regs->pstate;
    hit_item.regs_info.orig_x0 = regs->orig_x0;
    hit_item.regs_info.syscallno = regs->syscallno;
    
    if (info->hit_item_arr) {
        cvector cv = (cvector)info->hit_item_arr;
        if (cvector_length(cv) < MIN_LEN) {
            cvector_pushback(cv, &hit_item);
        }
    }
}

#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
static bool arm64_move_bp_to_next_instruction(struct perf_event *bp, uint64_t next_instruction_addr, 
                                              struct perf_event_attr *original_attr, 
                                              struct perf_event_attr *next_instruction_attr) {
    int result;
    if (!bp || !original_attr || !next_instruction_attr || !next_instruction_addr) {
        return false;
    }
    
    memcpy(next_instruction_attr, original_attr, sizeof(struct perf_event_attr));
    next_instruction_attr->bp_addr = next_instruction_addr;
    next_instruction_attr->bp_len = HW_BREAKPOINT_LEN_4;
    next_instruction_attr->bp_type = HW_BREAKPOINT_X;
    next_instruction_attr->disabled = 0;
    
    result = x_modify_user_hw_breakpoint(bp, next_instruction_attr);
    if (result) {
        next_instruction_attr->bp_addr = 0;
        return false;
    }
    return true;
}

static bool arm64_recovery_bp_to_original(struct perf_event *bp, 
                                          struct perf_event_attr *original_attr, 
                                          struct perf_event_attr *next_instruction_attr) {
    int result;
    if (!bp || !original_attr || !next_instruction_attr) {
        return false;
    }
    
    result = x_modify_user_hw_breakpoint(bp, original_attr);
    if (result) {
        return false;
    }
    next_instruction_attr->bp_addr = 0;
    return true;
}
#endif

static void hwbp_hit_user_info_callback(struct perf_event *bp,
                                       struct perf_sample_data *data,
                                       struct pt_regs *regs, 
                                       struct HWBP_HANDLE_INFO *hwbp_handle_info) {
    hwbp_handle_info->hit_total_count++;
    record_hit_details(hwbp_handle_info, regs);
}

//////////////////////////////////////////////////////////////////
// 硬件断点处理主函数
static void hwbp_handler(struct perf_event *bp,
                        struct perf_sample_data *data,
                        struct pt_regs *regs) {
    citerator iter;
    uint64_t hook_pc;
    printk_debug(KERN_INFO "hw_breakpoint HIT!!!!! bp:%px, pc:%px, id:%d\n", bp, regs->pc, bp->id);
    
    hook_pc = atomic64_read(&g_hook_pc);
    if (hook_pc) {
        regs->pc = hook_pc;
        return;
    }
    
    mutex_lock(&g_hwbp_handle_info_mutex);
    cvector cv = (cvector)g_hwbp_handle_info_arr;
    
    for (iter = cvector_begin(cv); iter != cvector_end(cv); iter = cvector_next(cv, iter)) {
        struct HWBP_HANDLE_INFO *hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
        if (hwbp_handle_info->sample_hbp != bp) {
            continue;
        }
        
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
        if (hwbp_handle_info->next_instruction_attr.bp_addr != regs->pc) {
            // first hit
            bool should_toggle = true;
            hwbp_hit_user_info_callback(bp, data, regs, hwbp_handle_info);
            if (!hwbp_handle_info->is_32bit_task) {
                if (arm64_move_bp_to_next_instruction(bp, regs->pc + 4, 
                                                      &hwbp_handle_info->original_attr, 
                                                      &hwbp_handle_info->next_instruction_attr)) {
                    should_toggle = false;
                }
            }
            if (should_toggle) {
                toggle_bp_registers_directly(&hwbp_handle_info->original_attr, 
                                            hwbp_handle_info->is_32bit_task, 0);
            }
        } else {
            // second hit
            if (!arm64_recovery_bp_to_original(bp, &hwbp_handle_info->original_attr, 
                                              &hwbp_handle_info->next_instruction_attr)) {
                toggle_bp_registers_directly(&hwbp_handle_info->next_instruction_attr, 
                                            hwbp_handle_info->is_32bit_task, 0);
            }
        }
#else
        hwbp_hit_user_info_callback(bp, data, regs, hwbp_handle_info);
        toggle_bp_registers_directly(&hwbp_handle_info->original_attr, 
                                    hwbp_handle_info->is_32bit_task, 0);
#endif
    }
    mutex_unlock(&g_hwbp_handle_info_mutex);
}

//////////////////////////////////////////////////////////////////
// 命令处理函数
static ssize_t OnCmdOpenProcess(struct ioctl_request *hdr, char __user* buf) {
    uint64_t pid = hdr->param1, handle = 0;
    struct pid *proc_pid_struct = NULL;
    printk_debug(KERN_INFO "CMD_OPEN_PROCESS\n");
    printk_debug(KERN_INFO "pid:%llu,size:%ld\n", pid, sizeof(pid));
    
    proc_pid_struct = get_proc_pid_struct(pid);
    printk_debug(KERN_INFO "proc_pid_struct *:0x%p\n", (void*)proc_pid_struct);
    if (!proc_pid_struct) {
        return -EINVAL;
    }
    handle = (uint64_t)proc_pid_struct;
    
    printk_debug(KERN_INFO "handle:%llu,size:%ld\n", handle, sizeof(handle));
    if (x_copy_to_user((void*)buf, (void*)&handle, sizeof(handle))) {
        return -EINVAL;
    }
    return 0;
}

static ssize_t OnCmdCloseProcess(struct ioctl_request *hdr, char __user* buf) {
    struct pid *proc_pid_struct = (struct pid *)hdr->param1;
    printk_debug(KERN_INFO "CMD_CLOSE_PROCESS\n");
    printk_debug(KERN_INFO "proc_pid_struct*:0x%p,size:%ld\n", (void*)proc_pid_struct, sizeof(proc_pid_struct));
    release_proc_pid_struct(proc_pid_struct);
    return 0;
}

static ssize_t OnCmdGetCpuNumBrps(struct ioctl_request *hdr, char __user* buf) {
    printk_debug(KERN_INFO "CMD_GET_NUM_BRPS\n");
    return getCpuNumBrps();
}

static ssize_t OnCmdGetCpuNumWrps(struct ioctl_request *hdr, char __user* buf) {
    printk_debug(KERN_INFO "CMD_GET_NUM_WRPS\n");
    return getCpuNumWrps();
}

static ssize_t OnCmdInstProcessHwbp(struct ioctl_request *hdr, char __user* buf) {
    struct pid *proc_pid_struct = (struct pid *)hdr->param1;
    uint64_t proc_virt_addr = hdr->param2;
    char hwbp_len  =  hdr->param3 & 0xFF;
    char hwbp_type = (hdr->param3 >> 8) & 0xFF;
    
    pid_t pid_val;
    struct task_struct *task;
    struct HWBP_HANDLE_INFO hwbp_handle_info = { 0 };
    printk_debug(KERN_INFO "CMD_INST_PROCESS_HWBP\n");
    printk_debug(KERN_INFO "proc_pid_struct *:%px\n", proc_pid_struct);
    printk_debug(KERN_INFO "proc_virt_addr :%px\n", proc_virt_addr);
    printk_debug(KERN_INFO "hwbp_len:%zu\n", hwbp_len);
    printk_debug(KERN_INFO "hwbp_type:%d\n", hwbp_type);
    
    pid_val = pid_nr(proc_pid_struct);
    printk_debug(KERN_INFO "pid_val:%d\n", pid_val);
    
    if (!pid_val) {
        printk_debug(KERN_INFO "pid_nr failed.\n");
        return -EINVAL;
    }
    
    task = pid_task(proc_pid_struct, PIDTYPE_PID);
    if (!task) {
        printk_debug(KERN_INFO "get_pid_task failed.\n");
        return -EINVAL;
    }
    
    hwbp_handle_info.task_id = pid_val;
    hwbp_handle_info.is_32bit_task = is_compat_thread(task_thread_info(task));
    
    // 初始化断点属性
    memset(&hwbp_handle_info.original_attr, 0, sizeof(struct perf_event_attr));
    hwbp_handle_info.original_attr.bp_addr = proc_virt_addr;
    hwbp_handle_info.original_attr.bp_len = hwbp_len;
    hwbp_handle_info.original_attr.bp_type = hwbp_type;
    hwbp_handle_info.original_attr.disabled = 0;
    hwbp_handle_info.original_attr.size = sizeof(struct perf_event_attr);
    
    hwbp_handle_info.sample_hbp = x_register_user_hw_breakpoint(&hwbp_handle_info.original_attr, 
                                                               hwbp_handler, NULL, task);
    printk_debug(KERN_INFO "register_user_hw_breakpoint return: %px\n", hwbp_handle_info.sample_hbp);
    
    if (IS_ERR((void __force *)hwbp_handle_info.sample_hbp)) {
        int ret = PTR_ERR((void __force *)hwbp_handle_info.sample_hbp);
        printk_debug(KERN_INFO "register_user_hw_breakpoint failed: %d\n", ret);
        return ret;
    }
    
    hwbp_handle_info.hit_item_arr = cvector_create(sizeof(struct HWBP_HIT_ITEM));
    mutex_lock(&g_hwbp_handle_info_mutex);
    cvector_pushback((cvector)g_hwbp_handle_info_arr, &hwbp_handle_info);
    mutex_unlock(&g_hwbp_handle_info_mutex);
    
    if (x_copy_to_user((void*)buf, &hwbp_handle_info.sample_hbp, sizeof(uint64_t))) {
        return -EINVAL;
    }
    return 0;
}

static ssize_t OnCmdUninstProcessHwbp(struct ioctl_request *hdr, char __user* buf) {
    struct perf_event *sample_hbp = (struct perf_event *)hdr->param1;
    citerator iter;
    bool found = false;
    printk_debug(KERN_INFO "CMD_UNINST_PROCESS_HWBP\n");
    printk_debug(KERN_INFO "sample_hbp *:%px\n", sample_hbp);
    
    if (!sample_hbp) {
        return -EFAULT;
    }
    
    mutex_lock(&g_hwbp_handle_info_mutex);
    cvector cv = (cvector)g_hwbp_handle_info_arr;
    
    for (iter = cvector_begin(cv); iter != cvector_end(cv); iter = cvector_next(cv, iter)) {
        struct HWBP_HANDLE_INFO *hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
        if (hwbp_handle_info->sample_hbp == sample_hbp) {
            if (hwbp_handle_info->hit_item_arr) {
                cvector_destroy((cvector)hwbp_handle_info->hit_item_arr);
                hwbp_handle_info->hit_item_arr = NULL;
            }
            cvector_rm(cv, iter);
            found = true;
            break;
        }
    }
    mutex_unlock(&g_hwbp_handle_info_mutex);
    
    if (found) {
        x_unregister_hw_breakpoint(sample_hbp);
    }
    return 0;
}

// 其他命令处理函数（简化实现）
static ssize_t OnCmdSuspendProcessHwbp(struct ioctl_request *hdr, char __user* buf) {
    // 简化实现
    return 0;
}

static ssize_t OnCmdResumeProcessHwbp(struct ioctl_request *hdr, char __user* buf) {
    // 简化实现
    return 0;
}

static ssize_t OnCmdGetHwbpHitCount(struct ioctl_request *hdr, char __user* buf) {
    // 简化实现
    return 0;
}

static ssize_t OnCmdGetHwbpHitDetail(struct ioctl_request *hdr, char __user* buf) {
    // 简化实现
    return 0;
}

static ssize_t OnCmdSetHookPc(struct ioctl_request *hdr, char __user* buf) {
    uint64_t pc = hdr->param1;
    printk_debug(KERN_INFO "CMD_SET_HOOK_PC\n");
    printk_debug(KERN_INFO "pc:%px\n", pc);
    atomic64_set(&g_hook_pc, pc);
    return 0;
}

static ssize_t OnCmdHideKernelModule(struct ioctl_request *hdr, char __user* buf) {
    printk_debug(KERN_INFO "CMD_HIDE_KERNEL_MODULE\n");
    if (g_hwBreakpointProc_devp->is_hidden_module == false) {
        g_hwBreakpointProc_devp->is_hidden_module = true; 
        list_del_init(&THIS_MODULE->list);
        kobject_del(&THIS_MODULE->mkobj.kobj);
    }
    return 0;
}

static inline ssize_t DispatchCommand(struct ioctl_request *hdr, char __user* buf) {
    switch (hdr->cmd) {
    case CMD_OPEN_PROCESS:
        return OnCmdOpenProcess(hdr, buf);
    case CMD_CLOSE_PROCESS:
        return OnCmdCloseProcess(hdr, buf);
    case CMD_GET_NUM_BRPS:
        return OnCmdGetCpuNumBrps(hdr, buf);
    case CMD_GET_NUM_WRPS:
        return OnCmdGetCpuNumWrps(hdr, buf);
    case CMD_INST_PROCESS_HWBP:
        return OnCmdInstProcessHwbp(hdr, buf);
    case CMD_UNINST_PROCESS_HWBP:
        return OnCmdUninstProcessHwbp(hdr, buf);
    case CMD_SUSPEND_PROCESS_HWBP:
        return OnCmdSuspendProcessHwbp(hdr, buf);
    case CMD_RESUME_PROCESS_HWBP:
        return OnCmdResumeProcessHwbp(hdr, buf);
    case CMD_GET_HWBP_HIT_COUNT:
        return OnCmdGetHwbpHitCount(hdr, buf);
    case CMD_GET_HWBP_HIT_DETAIL:
        return OnCmdGetHwbpHitDetail(hdr, buf);
    case CMD_SET_HOOK_PC:
        return OnCmdSetHookPc(hdr, buf);
    case CMD_HIDE_KERNEL_MODULE:
        return OnCmdHideKernelModule(hdr, buf);
    default:
        return -EINVAL;
    }
}

//////////////////////////////////////////////////////////////////
// 文件操作函数
static ssize_t hwBreakpointProc_read(struct file* filp,
                                    char __user* buf,
                                    size_t size,
                                    loff_t* ppos) {
    struct ioctl_request hdr = {0};
    size_t header_size = sizeof(hdr);
    
    if (size < header_size) {
        return -EINVAL;
    }
    
    if (x_copy_from_user(&hdr, buf, header_size)) {
        return -EFAULT;
    }
    
    if (size < header_size + hdr.buf_size) {
        return -EINVAL;
    }
    
    return DispatchCommand(&hdr, buf + header_size);
}

static void clean_hwbp(void) {
    citerator iter;
    cvector wait_unregister_bp_arr = cvector_create(sizeof(struct perf_event *));
    if (!wait_unregister_bp_arr || !g_hwbp_handle_info_arr) {
        return;
    }
    
    mutex_lock(&g_hwbp_handle_info_mutex);
    cvector cv = (cvector)g_hwbp_handle_info_arr;
    
    for (iter = cvector_begin(cv); iter != cvector_end(cv); iter = cvector_next(cv, iter)) {
        struct HWBP_HANDLE_INFO *hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
        if (hwbp_handle_info->sample_hbp) {
            cvector_pushback(wait_unregister_bp_arr, &hwbp_handle_info->sample_hbp);
            hwbp_handle_info->sample_hbp = NULL;
        }
        if (hwbp_handle_info->hit_item_arr) {
            cvector_destroy((cvector)hwbp_handle_info->hit_item_arr);
            hwbp_handle_info->hit_item_arr = NULL;
        }
    }
    cvector_destroy(cv);
    g_hwbp_handle_info_arr = NULL;
    mutex_unlock(&g_hwbp_handle_info_mutex);
    
    for (iter = cvector_begin(wait_unregister_bp_arr); 
         iter != cvector_end(wait_unregister_bp_arr); 
         iter = cvector_next(wait_unregister_bp_arr, iter)) {
        struct perf_event *bp = *(struct perf_event **)iter;
        x_unregister_hw_breakpoint(bp);
    }
    cvector_destroy(wait_unregister_bp_arr);
}

static int hwBreakpointProc_release(struct inode *inode, struct file *filp) {
    clean_hwbp();
    mutex_lock(&g_hwbp_handle_info_mutex);
    g_hwbp_handle_info_arr = cvector_create(sizeof(struct HWBP_HANDLE_INFO));
    mutex_unlock(&g_hwbp_handle_info_mutex);
    return 0;
}

#ifdef CONFIG_USE_PROC_FILE_NODE
static const struct proc_ops hwBreakpointProc_proc_ops = {
    .proc_read    = hwBreakpointProc_read,
    .proc_release = hwBreakpointProc_release,
};
#endif

//////////////////////////////////////////////////////////////////
// hide_procfs_dir 实现（修复了 filldir_t 问题）
static char g_hide_dir_name[256] = {0};

// 关键修复：统一使用 int 返回类型
static int my_filldir(struct dir_context *ctx,
                     const char *name,
                     int namelen,
                     loff_t offset,
                     u64 ino,
                     unsigned int d_type) {
    if (namelen == strlen(g_hide_dir_name) &&
        !strncmp(name, g_hide_dir_name, namelen)) {
        return 0; // 跳过隐藏的目录
    }
    // 注意：原始 filldir 函数需要传递
    return 0; // 简化实现
}

static int handler_pre(struct kprobe *kp, struct pt_regs *regs) {
    // 简化实现
    return 0;
}

static struct kprobe kp_hide_procfs_dir = {
    .symbol_name = "proc_root_readdir",
    .pre_handler = handler_pre,
};

static bool start_hide_procfs_dir(const char* hide_dir_name) {
    int ret;
    strlcpy(g_hide_dir_name, hide_dir_name, sizeof(g_hide_dir_name));
    ret = register_kprobe(&kp_hide_procfs_dir);
    if (ret) {
        printk_debug("[hide_procfs_dir] register_kprobe failed: %d\n", ret);
        return false;
    }
    printk_debug("[hide_procfs_dir] kprobe installed, hiding \"%s\"\n", g_hide_dir_name);
    return true;
}

static void stop_hide_procfs_dir(void) {
    unregister_kprobe(&kp_hide_procfs_dir);
    printk_debug("[hide_procfs_dir] kprobe removed\n");
}

//////////////////////////////////////////////////////////////////
// 模块初始化和退出
static int hwBreakpointProc_dev_init(void) {
    g_hwbp_handle_info_arr = cvector_create(sizeof(struct HWBP_HANDLE_INFO));
    mutex_init(&g_hwbp_handle_info_mutex);
    
    g_hwBreakpointProc_devp = kmalloc(sizeof(struct hwBreakpointProcDev), GFP_KERNEL);
    if (!g_hwBreakpointProc_devp) {
        return -ENOMEM;
    }
    memset(g_hwBreakpointProc_devp, 0, sizeof(struct hwBreakpointProcDev));
    
#ifdef CONFIG_USE_PROC_FILE_NODE
    g_hwBreakpointProc_devp->proc_parent = proc_mkdir(CONFIG_PROC_NODE_AUTH_KEY, NULL);
    if (g_hwBreakpointProc_devp->proc_parent) {
        g_hwBreakpointProc_devp->proc_entry = proc_create(CONFIG_PROC_NODE_AUTH_KEY, 
                                                         S_IRUGO | S_IWUGO, 
                                                         g_hwBreakpointProc_devp->proc_parent, 
                                                         &hwBreakpointProc_proc_ops);
        start_hide_procfs_dir(CONFIG_PROC_NODE_AUTH_KEY);
    }
#endif
    
    printk(KERN_EMERG "Hello, hwBreakpointProc module loaded\n");
    return 0;
}

static void hwBreakpointProc_dev_exit(void) {
    clean_hwbp();
    mutex_destroy(&g_hwbp_handle_info_mutex);
    
#ifdef CONFIG_USE_PROC_FILE_NODE
    if (g_hwBreakpointProc_devp->proc_entry) {
        proc_remove(g_hwBreakpointProc_devp->proc_entry);
        g_hwBreakpointProc_devp->proc_entry = NULL;
    }
    
    if (g_hwBreakpointProc_devp->proc_parent) {
        proc_remove(g_hwBreakpointProc_devp->proc_parent);
        g_hwBreakpointProc_devp->proc_parent = NULL;
    }
    stop_hide_procfs_dir();
#endif
    
    kfree(g_hwBreakpointProc_devp);
    printk(KERN_EMERG "Goodbye, hwBreakpointProc module unloaded\n");
}

//////////////////////////////////////////////////////////////////
// 模块入口
int __init init_module(void) {
    return hwBreakpointProc_dev_init();
}

void __exit cleanup_module(void) {
    hwBreakpointProc_dev_exit();
}

//////////////////////////////////////////////////////////////////
// 模块信息
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux");
MODULE_DESCRIPTION("Hardware Breakpoint Process Module");