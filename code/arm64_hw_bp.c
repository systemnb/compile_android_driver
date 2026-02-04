/*
 * ARM64硬件断点内核模块 - 修复版本
 * 硬件断点正确绑定到线程(task_struct)而非进程ID
 * 适配Linux 5.10+内核
 */

#include "arm64_hw_bp.h"

// 断点数据结构 - 修复：存储task_struct而非pid
typedef struct _HW_BREAKPOINT_INFO {
    pid_t tid;                    // 线程ID
    pid_t tgid;                   // 线程组ID（进程ID）
    uintptr_t addr;
    uint32_t type;                // 断点类型
    bool active;
    struct perf_event *pe;        // perf事件
} HW_BREAKPOINT_INFO, *PHW_BREAKPOINT_INFO;

typedef struct _BREAKPOINT_OPERATION {
    pid_t tid;                    // 线程ID
    uintptr_t addr;
    uint32_t type;
} BREAKPOINT_OPERATION, *PBREAKPOINT_OPERATION;

typedef struct _COPY_MEMORY {
    pid_t pid;                    // 进程ID
    uintptr_t addr;
    void __user *buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char __user *name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

// ARM64寄存器结构
typedef struct _ARM64_REGISTERS {
    uint64_t x[31];    // 通用寄存器 X0-X30
    uint64_t fp;       // 帧指针
    uint64_t lr;       // 链接寄存器
    uint64_t sp;       // 栈指针
    uint64_t pc;       // 程序计数器
    uint64_t pstate;   // 处理器状态
    uint64_t v[32];    // 向量寄存器 (可选)
} ARM64_REGISTERS, *PARM64_REGISTERS;

typedef struct _REGISTER_OPERATION {
    pid_t tid;        // 线程ID
    ARM64_REGISTERS __user *regs;
    bool read;        // true: 读取寄存器, false: 写入寄存器
} REGISTER_OPERATION, *PREGISTER_OPERATION;

typedef struct _PROCESS_CONTROL {
    pid_t tid;        // 线程ID
    bool suspend;     // true: 暂停, false: 恢复
} PROCESS_CONTROL, *PPROCESS_CONTROL;

// IOCTL操作码
enum HW_BREAKPOINT_OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
    OP_SET_BREAKPOINT = 0x804,
    OP_CLEAR_BREAKPOINT = 0x805,
    OP_LIST_BREAKPOINTS = 0x806,
    OP_CLEAR_ALL_BREAKPOINTS = 0x807,
    OP_GET_REGISTERS = 0x808,
    OP_SET_REGISTERS = 0x809,
    OP_SUSPEND_THREAD = 0x80A,
    OP_RESUME_THREAD = 0x80B,
    OP_SINGLE_STEP = 0x80C,
};

// 暂停线程信息结构
struct suspended_thread {
    pid_t tid;
    struct task_struct *task;
    struct list_head list;
    bool stepping;  // 单步执行模式
};

// 内部断点结构
struct hw_breakpoint_entry {
    HW_BREAKPOINT_INFO info;
    struct task_struct *task;    // 指向线程的task_struct
    struct list_head list;
};

// 全局变量
static DEFINE_MUTEX(bp_mutex);
static LIST_HEAD(bp_list);
static LIST_HEAD(suspended_list);
static int bp_count = 0;
#define MAX_BREAKPOINTS 16

// 函数声明
static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va);
static bool read_physical_address(phys_addr_t pa, void __user *buffer, size_t size);
static bool write_physical_address(phys_addr_t pa, const void __user *buffer, size_t size);
static bool read_process_memory(pid_t pid, uintptr_t addr, void __user *buffer, size_t size);
static bool write_process_memory(pid_t pid, uintptr_t addr, const void __user *buffer, size_t size);
static uintptr_t get_module_base(pid_t pid, const char *name);
static void hw_breakpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs);
static int set_hw_breakpoint(pid_t tid, uintptr_t addr, uint32_t type);
static int clear_hw_breakpoint(pid_t tid, uintptr_t addr);
static void clear_all_breakpoints(void);
static int get_thread_registers(pid_t tid, ARM64_REGISTERS __user *regs);
static int set_thread_registers(pid_t tid, ARM64_REGISTERS __user *regs);
static int suspend_thread(pid_t tid);
static int resume_thread(pid_t tid);
static int single_step_thread(pid_t tid);
static struct suspended_thread *find_suspended_thread(pid_t tid);
static struct task_struct *get_thread_by_tid(pid_t tid);

// 根据线程ID获取task_struct
static struct task_struct *get_thread_by_tid(pid_t tid)
{
    struct task_struct *task = NULL;
    struct pid *pid_struct = NULL;
    
    pid_struct = find_get_pid(tid);
    if (!pid_struct)
        return NULL;
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    return task;
}

// 物理地址翻译函数
static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
    phys_addr_t page_addr;
    uintptr_t page_offset;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    p4d_t *p4d;
    
    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;
    
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return 0;
    
    pud = pud_offset(p4d, va);
#else
    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;
    
    pud = pud_offset(pgd, va);
#endif

    if (pud_none(*pud) || pud_bad(*pud))
        return 0;

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd))
        return 0;

    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte) || !pte_present(*pte))
        return 0;

    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE - 1);

    return page_addr + page_offset;
}

// 检查物理地址范围
static inline bool is_valid_phys_addr_range(phys_addr_t addr, size_t size)
{
    return (addr + size <= virt_to_phys(high_memory));
}

// 读取物理地址
static bool read_physical_address(phys_addr_t pa, void __user *buffer, size_t size)
{
    void *mapped;

    if (!pfn_valid(__phys_to_pfn(pa)))
        return false;
    
    if (!is_valid_phys_addr_range(pa, size))
        return false;

    mapped = ioremap_cache(pa, size);
    if (!mapped)
        return false;

    if (copy_to_user(buffer, mapped, size)) {
        iounmap(mapped);
        return false;
    }

    iounmap(mapped);
    return true;
}

// 写入物理地址
static bool write_physical_address(phys_addr_t pa, const void __user *buffer, size_t size)
{
    void *mapped;

    if (!pfn_valid(__phys_to_pfn(pa)))
        return false;
    
    if (!is_valid_phys_addr_range(pa, size))
        return false;

    mapped = ioremap_cache(pa, size);
    if (!mapped)
        return false;

    if (copy_from_user(mapped, buffer, size)) {
        iounmap(mapped);
        return false;
    }

    iounmap(mapped);
    return true;
}

// 读取进程内存
static bool read_process_memory(pid_t pid, uintptr_t addr, 
                               void __user *buffer, size_t size)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    struct pid *pid_struct = NULL;
    phys_addr_t pa;
    bool result = false;
    struct vm_area_struct *vma;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return false;
    }

    mm = get_task_mm(task);
    put_pid(pid_struct);
    
    if (!mm) {
        put_task_struct(task);
        return false;
    }

    // Linux 5.10使用mmap_lock而不是mmap_sem
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif
    
    pa = translate_linear_address(mm, addr);
    
    if (pa) {
        result = read_physical_address(pa, buffer, size);
    } else {
        vma = find_vma(mm, addr);
        if (vma) {
            if (clear_user(buffer, size) == 0) {
                result = true;
            }
        }
    }
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif
    
    mmput(mm);
    put_task_struct(task);
    return result;
}

// 写入进程内存
static bool write_process_memory(pid_t pid, uintptr_t addr, 
                                const void __user *buffer, size_t size)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    struct pid *pid_struct = NULL;
    phys_addr_t pa;
    bool result = false;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return false;
    }

    mm = get_task_mm(task);
    put_pid(pid_struct);
    
    if (!mm) {
        put_task_struct(task);
        return false;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif
    
    pa = translate_linear_address(mm, addr);
    
    if (pa) {
        result = write_physical_address(pa, buffer, size);
    }
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif
    
    mmput(mm);
    put_task_struct(task);
    return result;
}

// 获取模块基址
#define ARC_PATH_MAX 256
static uintptr_t get_module_base(pid_t pid, const char *name)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    struct pid *pid_struct = NULL;
    struct vm_area_struct *vma = NULL;
    uintptr_t base_addr = 0;
    int path_len;
    char buf[ARC_PATH_MAX];
    char *path_nm;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return 0;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return 0;
    }

    mm = get_task_mm(task);
    put_pid(pid_struct);
    
    if (!mm) {
        put_task_struct(task);
        return 0;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    struct vma_iterator vmi;
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma) {
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
        if (!vma->vm_file)
            continue;

        path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX - 1);
        if (IS_ERR(path_nm))
            continue;

        path_len = strlen(path_nm);
        if (path_len <= 0)
            continue;

        if (strstr(path_nm, name) != NULL) {
            base_addr = vma->vm_start;
            break;
        }
    }
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif
    
    mmput(mm);
    put_task_struct(task);
    return base_addr;
}

// 查找暂停线程
static struct suspended_thread *find_suspended_thread(pid_t tid)
{
    struct suspended_thread *st;
    
    list_for_each_entry(st, &suspended_list, list) {
        if (st->tid == tid) {
            return st;
        }
    }
    
    return NULL;
}

// 硬件断点处理函数
static void hw_breakpoint_handler(struct perf_event *bp,
                                 struct perf_sample_data *data,
                                 struct pt_regs *regs)
{
    struct hw_breakpoint_entry *entry = bp->overflow_handler_context;
    struct suspended_thread *st;
    
    if (!entry) {
        printk(KERN_ERR "No breakpoint context found\n");
        return;
    }
    
    // 检查是否是期望的线程触发了断点
    if (current->pid != entry->info.tid) {
        printk(KERN_WARNING "[HW_BP] Breakpoint triggered by unexpected thread: %d (expected: %d)\n",
               current->pid, entry->info.tid);
        return;
    }
    
    printk(KERN_INFO "[HW_BP] Breakpoint hit!\n");
    printk(KERN_INFO "  Thread: %d (TGID: %d)\n", 
           entry->info.tid, entry->info.tgid);
    printk(KERN_INFO "  Address: 0x%016lx\n", (unsigned long)entry->info.addr);
    printk(KERN_INFO "  Type: %u\n", entry->info.type);
    printk(KERN_INFO "  PC: 0x%016lx\n", (unsigned long)instruction_pointer(regs));
    
    // 检查是否已经暂停
    st = find_suspended_thread(entry->info.tid);
    if (st && st->stepping) {
        // 单步执行模式，恢复执行
        st->stepping = false;
        printk(KERN_INFO "[HW_BP] Single step completed for thread %d\n", entry->info.tid);
    } else {
        // 暂停线程
        printk(KERN_INFO "[HW_BP] Suspending thread %d at breakpoint\n", entry->info.tid);
        // 设置线程状态为TASK_STOPPED
        __set_current_state(TASK_STOPPED);
    }
}

// 设置硬件断点 - 修复版本：作用在线程上
static int set_hw_breakpoint(pid_t tid, uintptr_t addr, uint32_t type)
{
    struct task_struct *task = NULL;
    struct perf_event_attr attr;
    struct hw_breakpoint_entry *entry;
    struct hw_breakpoint_entry *tmp;
    int bp_len;
    int ret = 0;
    
    // 检查断点数量限制
    mutex_lock(&bp_mutex);
    if (bp_count >= MAX_BREAKPOINTS) {
        mutex_unlock(&bp_mutex);
        printk(KERN_ERR "Maximum breakpoints reached (%d)\n", MAX_BREAKPOINTS);
        return -ENOSPC;
    }
    mutex_unlock(&bp_mutex);
    
    // 根据线程ID获取task_struct
    task = get_thread_by_tid(tid);
    if (!task) {
        printk(KERN_ERR "Thread %d not found\n", tid);
        return -ESRCH;
    }
    
    mutex_lock(&bp_mutex);
    
    // 检查是否已存在断点
    list_for_each_entry(tmp, &bp_list, list) {
        if (tmp->info.tid == tid && tmp->info.addr == addr) {
            printk(KERN_INFO "Breakpoint already exists at 0x%lx for thread %d\n", 
                   (unsigned long)addr, tid);
            ret = -EEXIST;
            goto out_unlock;
        }
    }
    
    // 分配断点条目
    entry = kmalloc(sizeof(struct hw_breakpoint_entry), GFP_KERNEL);
    if (!entry) {
        ret = -ENOMEM;
        goto out_unlock;
    }
    
    // 设置perf事件属性
    memset(&attr, 0, sizeof(struct perf_event_attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(struct perf_event_attr);
    
    // 设置断点类型和大小
    bp_len = 4;  // 默认4字节
    
    switch (type) {
        case BP_TYPE_INST:
            attr.bp_type = HW_BREAKPOINT_X;
            bp_len = 4;
            break;
        case BP_TYPE_READ:
            attr.bp_type = HW_BREAKPOINT_R;
            bp_len = 8;
            break;
        case BP_TYPE_WRITE:
            attr.bp_type = HW_BREAKPOINT_W;
            bp_len = 8;
            break;
        case BP_TYPE_RW:
            attr.bp_type = HW_BREAKPOINT_RW;
            bp_len = 8;
            break;
        default:
            kfree(entry);
            ret = -EINVAL;
            goto out_unlock;
    }
    
    attr.bp_addr = addr;
    attr.bp_len = bp_len;
    attr.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_IP;
    attr.wakeup_events = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    
    // 创建perf事件 - 关键：传递给具体的task_struct（线程）
    entry->info.pe = perf_event_create_kernel_counter(&attr, -1, task,
                                                     hw_breakpoint_handler, entry);
    
    if (IS_ERR(entry->info.pe)) {
        ret = PTR_ERR(entry->info.pe);
        printk(KERN_ERR "Failed to create hardware breakpoint: %d\n", ret);
        kfree(entry);
        goto out_unlock;
    }
    
    // 初始化断点信息
    entry->info.tid = tid;
    entry->info.tgid = task->tgid;
    entry->info.addr = addr;
    entry->info.type = type;
    entry->info.active = true;
    entry->task = get_task_struct(task);  // 增加引用计数
    INIT_LIST_HEAD(&entry->list);
    
    // 添加到链表
    list_add_tail(&entry->list, &bp_list);
    bp_count++;
    
    // 启用断点
    perf_event_enable(entry->info.pe);
    
    printk(KERN_INFO "Hardware breakpoint set at 0x%lx for thread %d (TGID %d, type: %u)\n", 
           (unsigned long)addr, tid, task->tgid, type);
    
    ret = 0;
    
out_unlock:
    mutex_unlock(&bp_mutex);
    if (task)
        put_task_struct(task);
    return ret;
}

// 清除硬件断点
static int clear_hw_breakpoint(pid_t tid, uintptr_t addr)
{
    struct hw_breakpoint_entry *entry, *tmp;
    int ret = -ENOENT;
    
    mutex_lock(&bp_mutex);
    
    list_for_each_entry_safe(entry, tmp, &bp_list, list) {
        if (entry->info.tid == tid && entry->info.addr == addr) {
            // 禁用并释放perf事件
            if (entry->info.pe) {
                perf_event_disable(entry->info.pe);
                perf_event_release_kernel(entry->info.pe);
            }
            
            // 释放task引用
            if (entry->task) {
                put_task_struct(entry->task);
            }
            
            // 从链表删除
            list_del(&entry->list);
            kfree(entry);
            bp_count--;
            
            printk(KERN_INFO "Hardware breakpoint cleared at 0x%lx for thread %d\n", 
                   (unsigned long)addr, tid);
            ret = 0;
            break;
        }
    }
    
    mutex_unlock(&bp_mutex);
    return ret;
}

// 清除所有断点
static void clear_all_breakpoints(void)
{
    struct hw_breakpoint_entry *entry, *tmp;
    
    mutex_lock(&bp_mutex);
    
    list_for_each_entry_safe(entry, tmp, &bp_list, list) {
        if (entry->info.pe) {
            perf_event_disable(entry->info.pe);
            perf_event_release_kernel(entry->info.pe);
        }
        
        // 释放task引用
        if (entry->task) {
            put_task_struct(entry->task);
        }
        
        list_del(&entry->list);
        kfree(entry);
    }
    
    bp_count = 0;
    mutex_unlock(&bp_mutex);
    
    printk(KERN_INFO "All hardware breakpoints cleared\n");
}

// 获取线程寄存器
static int get_thread_registers(pid_t tid, ARM64_REGISTERS __user *regs)
{
    struct task_struct *task = NULL;
    struct pt_regs *task_regs;
    ARM64_REGISTERS kernel_regs;
    int i, ret = 0;
    
    if (!regs)
        return -EFAULT;
    
    // 获取线程
    task = get_thread_by_tid(tid);
    if (!task)
        return -ESRCH;
    
    // 获取线程的寄存器
    task_regs = task_pt_regs(task);
    
    if (!task_regs) {
        ret = -EFAULT;
        goto out;
    }
    
    // 填充寄存器结构
    memset(&kernel_regs, 0, sizeof(kernel_regs));
    
    // 复制通用寄存器 X0-X30
    for (i = 0; i < 31; i++) {
        kernel_regs.x[i] = task_regs->regs[i];
    }
    
    // 复制特殊寄存器
    kernel_regs.fp = task_regs->regs[29];     // X29作为帧指针
    kernel_regs.lr = task_regs->regs[30];     // X30作为链接寄存器
    kernel_regs.sp = task_regs->sp;
    kernel_regs.pc = task_regs->pc;
    kernel_regs.pstate = task_regs->pstate;
    
    // 复制到用户空间
    if (copy_to_user(regs, &kernel_regs, sizeof(kernel_regs))) {
        ret = -EFAULT;
        goto out;
    }
    
    printk(KERN_INFO "Registers read for thread %d, PC=0x%016lx\n", 
           tid, (unsigned long)kernel_regs.pc);
    
out:
    if (task)
        put_task_struct(task);
    return ret;
}

// 设置线程寄存器
static int set_thread_registers(pid_t tid, ARM64_REGISTERS __user *regs)
{
    struct task_struct *task = NULL;
    struct pt_regs *task_regs;
    ARM64_REGISTERS kernel_regs;
    int i, ret = 0;
    
    if (!regs)
        return -EFAULT;
    
    // 从用户空间复制寄存器数据
    if (copy_from_user(&kernel_regs, regs, sizeof(kernel_regs))) {
        return -EFAULT;
    }
    
    // 获取线程
    task = get_thread_by_tid(tid);
    if (!task)
        return -ESRCH;
    
    // 获取线程的寄存器
    task_regs = task_pt_regs(task);
    
    if (!task_regs) {
        ret = -EFAULT;
        goto out;
    }
    
    // 设置通用寄存器 X0-X30
    for (i = 0; i < 31; i++) {
        task_regs->regs[i] = kernel_regs.x[i];
    }
    
    // 设置特殊寄存器
    task_regs->regs[29] = kernel_regs.fp;     // 帧指针
    task_regs->regs[30] = kernel_regs.lr;     // 链接寄存器
    task_regs->sp = kernel_regs.sp;
    task_regs->pc = kernel_regs.pc;
    task_regs->pstate = kernel_regs.pstate;
    
    printk(KERN_INFO "Registers set for thread %d, PC=0x%016lx\n", 
           tid, (unsigned long)kernel_regs.pc);
    
out:
    if (task)
        put_task_struct(task);
    return ret;
}

// 暂停线程
static int suspend_thread(pid_t tid)
{
    struct task_struct *task = NULL;
    struct suspended_thread *st;
    int ret = 0;
    
    // 获取线程
    task = get_thread_by_tid(tid);
    if (!task)
        return -ESRCH;
    
    // 检查是否已经暂停
    st = find_suspended_thread(tid);
    if (st) {
        printk(KERN_INFO "Thread %d is already suspended\n", tid);
        ret = -EALREADY;
        goto out;
    }
    
    // 分配暂停线程结构
    st = kmalloc(sizeof(struct suspended_thread), GFP_KERNEL);
    if (!st) {
        ret = -ENOMEM;
        goto out;
    }
    
    // 初始化暂停线程信息
    st->tid = tid;
    st->task = get_task_struct(task);  // 增加引用计数
    st->stepping = false;
    INIT_LIST_HEAD(&st->list);
    
    // 添加到暂停列表
    list_add_tail(&st->list, &suspended_list);
    
    // 发送SIGSTOP信号暂停线程
    ret = send_sig(SIGSTOP, task, 1);
    if (ret) {
        list_del(&st->list);
        put_task_struct(st->task);
        kfree(st);
        goto out;
    }
    
    printk(KERN_INFO "Thread %d suspended\n", tid);
    
out:
    if (task)
        put_task_struct(task);
    return ret;
}

// 恢复线程
static int resume_thread(pid_t tid)
{
    struct task_struct *task = NULL;
    struct suspended_thread *st;
    int ret = 0;
    
    // 获取线程
    task = get_thread_by_tid(tid);
    if (!task)
        return -ESRCH;
    
    // 查找暂停线程
    st = find_suspended_thread(tid);
    if (!st) {
        printk(KERN_INFO "Thread %d is not suspended\n", tid);
        ret = -ENOENT;
        goto out;
    }
    
    // 发送SIGCONT信号恢复线程
    ret = send_sig(SIGCONT, task, 1);
    if (ret == 0) {
        // 从暂停列表中移除
        list_del(&st->list);
        put_task_struct(st->task);  // 释放之前获取的引用
        kfree(st);
        printk(KERN_INFO "Thread %d resumed\n", tid);
    }
    
out:
    if (task)
        put_task_struct(task);
    return ret;
}

// 单步执行
static int single_step_thread(pid_t tid)
{
    struct suspended_thread *st;
    
    // 查找暂停线程
    st = find_suspended_thread(tid);
    if (!st) {
        printk(KERN_INFO "Thread %d is not suspended\n", tid);
        return -ENOENT;
    }
    
    // 设置单步执行标志
    st->stepping = true;
    
    // 恢复线程执行一条指令
    // 注意：ARM64的单步执行通常通过设置调试寄存器实现
    // 这里简化为恢复线程，依靠断点再次捕获
    
    return resume_thread(tid);
}

// IOCTL分发函数
static int dispatch_open(struct inode *node, struct file *file)
{
    return 0;
}

static int dispatch_close(struct inode *node, struct file *file)
{
    // 清理所有暂停线程
    struct suspended_thread *st, *tmp;
    
    list_for_each_entry_safe(st, tmp, &suspended_list, list) {
        // 恢复线程
        resume_thread(st->tid);
    }
    
    return 0;
}

static long dispatch_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    static char key[256] = {0};
    static bool is_verified = false;
    long ret = 0;

    switch (cmd) {
    case OP_INIT_KEY:
        if (!is_verified) {
            if (copy_from_user(key, (void __user *)arg, sizeof(key) - 1) == 0) {
                key[sizeof(key) - 1] = '\0';
                is_verified = true;
                printk(KERN_INFO "Key initialized successfully\n");
            } else {
                return -EFAULT;
            }
        }
        break;

    case OP_READ_MEM: {
        COPY_MEMORY cm;
        
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;
        
        if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -EIO;
        
        break;
    }

    case OP_WRITE_MEM: {
        COPY_MEMORY cm;
        
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;
        
        if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -EIO;
        
        break;
    }

    case OP_MODULE_BASE: {
        MODULE_BASE mb;
        char module_name[256];
        
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)))
            return -EFAULT;
        
        if (!mb.name)
            return -EFAULT;
        
        if (copy_from_user(module_name, mb.name, sizeof(module_name) - 1))
            return -EFAULT;
        module_name[sizeof(module_name) - 1] = '\0';
        
        mb.base = get_module_base(mb.pid, module_name);
        
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
            return -EFAULT;
        
        break;
    }

    case OP_SET_BREAKPOINT: {
        BREAKPOINT_OPERATION bp_op;
        
        if (copy_from_user(&bp_op, (void __user *)arg, sizeof(bp_op)))
            return -EFAULT;
        
        ret = set_hw_breakpoint(bp_op.tid, bp_op.addr, bp_op.type);
        if (ret < 0)
            return ret;
        
        break;
    }

    case OP_CLEAR_BREAKPOINT: {
        BREAKPOINT_OPERATION bp_op;
        
        if (copy_from_user(&bp_op, (void __user *)arg, sizeof(bp_op)))
            return -EFAULT;
        
        ret = clear_hw_breakpoint(bp_op.tid, bp_op.addr);
        if (ret < 0)
            return ret;
        
        break;
    }

    case OP_LIST_BREAKPOINTS: {
        struct hw_breakpoint_entry *entry;
        HW_BREAKPOINT_INFO info;
        int idx = 0;
        
        mutex_lock(&bp_mutex);
        
        list_for_each_entry(entry, &bp_list, list) {
            // 复制信息到用户空间
            memset(&info, 0, sizeof(info));
            info.tid = entry->info.tid;
            info.tgid = entry->info.tgid;
            info.addr = entry->info.addr;
            info.type = entry->info.type;
            info.active = entry->info.active;
            
            if (copy_to_user((void __user *)(arg + idx * sizeof(info)), 
                            &info, sizeof(info))) {
                mutex_unlock(&bp_mutex);
                return -EFAULT;
            }
            idx++;
        }
        
        mutex_unlock(&bp_mutex);
        break;
    }

    case OP_CLEAR_ALL_BREAKPOINTS:
        clear_all_breakpoints();
        break;

    case OP_GET_REGISTERS: {
        REGISTER_OPERATION reg_op;
        
        if (copy_from_user(&reg_op, (void __user *)arg, sizeof(reg_op)))
            return -EFAULT;
        
        if (!reg_op.regs)
            return -EFAULT;
        
        ret = get_thread_registers(reg_op.tid, reg_op.regs);
        if (ret < 0)
            return ret;
        
        break;
    }

    case OP_SET_REGISTERS: {
        REGISTER_OPERATION reg_op;
        
        if (copy_from_user(&reg_op, (void __user *)arg, sizeof(reg_op)))
            return -EFAULT;
        
        if (!reg_op.regs)
            return -EFAULT;
        
        ret = set_thread_registers(reg_op.tid, reg_op.regs);
        if (ret < 0)
            return ret;
        
        break;
    }

    case OP_SUSPEND_THREAD: {
        PROCESS_CONTROL pc;
        
        if (copy_from_user(&pc, (void __user *)arg, sizeof(pc)))
            return -EFAULT;
        
        ret = suspend_thread(pc.tid);
        if (ret < 0)
            return ret;
        
        break;
    }

    case OP_RESUME_THREAD: {
        PROCESS_CONTROL pc;
        
        if (copy_from_user(&pc, (void __user *)arg, sizeof(pc)))
            return -EFAULT;
        
        ret = resume_thread(pc.tid);
        if (ret < 0)
            return ret;
        
        break;
    }

    case OP_SINGLE_STEP: {
        PROCESS_CONTROL pc;
        
        if (copy_from_user(&pc, (void __user *)arg, sizeof(pc)))
            return -EFAULT;
        
        ret = single_step_thread(pc.tid);
        if (ret < 0)
            return ret;
        
        break;
    }

    default:
        return -ENOTTY;
    }

    return ret;
}

// 文件操作结构
static const struct file_operations dispatch_fops = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
    .compat_ioctl = dispatch_ioctl,
};

// misc设备定义
static struct miscdevice misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &dispatch_fops,
    .mode = 0666,
};

// 模块初始化
static int __init driver_entry(void)
{
    int ret;
    int breakpoint_slots = 0;
    
    printk(KERN_INFO "ARM64 Hardware Breakpoint Module loading...\n");
    
#ifndef CONFIG_ARM64
    printk(KERN_ERR "This module is for ARM64 architecture only!\n");
    return -ENODEV;
#endif
    
    // 检查是否支持硬件断点
#ifdef CONFIG_HAVE_HW_BREAKPOINT
    printk(KERN_INFO "Hardware breakpoint support detected\n");
    
    // 尝试通过配置推断断点槽数量
#if defined(CONFIG_ARM64_HW_BREAKPOINT)
    // 如果定义了ARM64_HW_BREAKPOINT，通常支持更多断点
    breakpoint_slots = 16;
#else
    // 保守估计
    breakpoint_slots = 4;
#endif
    
    printk(KERN_INFO "Estimated hardware breakpoint slots: %d\n", breakpoint_slots);
#else
    printk(KERN_ERR "Hardware breakpoints not supported on this CPU\n");
    return -ENODEV;
#endif
    
    // 初始化列表
    INIT_LIST_HEAD(&bp_list);
    INIT_LIST_HEAD(&suspended_list);
    
    ret = misc_register(&misc_dev);
    if (ret) {
        printk(KERN_ERR "Failed to register misc device: %d\n", ret);
        return ret;
    }
    
    printk(KERN_INFO "ARM64 Hardware Breakpoint Module loaded. Device: /dev/%s\n", DEVICE_NAME);
    printk(KERN_INFO "Maximum hardware breakpoints: %d\n", MAX_BREAKPOINTS);
    printk(KERN_INFO "NOTE: Hardware breakpoints operate on threads, not processes\n");
    printk(KERN_INFO "      Use thread IDs (gettid()) instead of process IDs (getpid())\n");
    
    return 0;
}

// 模块卸载
static void __exit driver_unload(void)
{
    struct suspended_thread *st, *tmp;
    
    printk(KERN_INFO "ARM64 Hardware Breakpoint Module unloading...\n");
    
    // 恢复所有暂停线程
    list_for_each_entry_safe(st, tmp, &suspended_list, list) {
        resume_thread(st->tid);
    }
    
    // 清除所有断点
    clear_all_breakpoints();
    
    // 注销设备
    misc_deregister(&misc_dev);
    
    printk(KERN_INFO "ARM64 Hardware Breakpoint Module unloaded\n");
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("ARM64 Hardware Breakpoint Kernel Module with Thread Control");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("陈依涵");
MODULE_VERSION("2.0");