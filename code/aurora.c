#include "aurora.h"

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void __user* buffer;
    size_t size;
} COPY_MEMORY, * PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char __user* name;
    uintptr_t base;
} MODULE_BASE, * PMODULE_BASE;

typedef struct _CALL_PROCESS {
    pid_t pid;
    uintptr_t addr;
    void __user* params;
    void __user* RetValue;
    size_t ParamsSize;
} CALL_PROCESS, * PCALL_PROCESS;

enum OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
    OP_CALL_PROCESS = 0x804,
};

static phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va);
static bool read_physical_address(phys_addr_t pa, void __user* buffer, size_t size);
static bool write_physical_address(phys_addr_t pa, const void __user* buffer, size_t size);
static bool read_process_memory(pid_t pid, uintptr_t addr, void __user* buffer, size_t size);
static bool write_process_memory(pid_t pid, uintptr_t addr, const void __user* buffer, size_t size);
static uintptr_t get_module_base(pid_t pid, const char* name);
static void call_process_code(pid_t pid, uintptr_t addr, void __user* params, void __user* RetValue, size_t ParamsSize); //CALL_PROCESS


static void modify_task_registers(struct task_struct* task, uintptr_t addr, void __user* params, void __user* RetValue, size_t ParamsSize) {
    //这是一个基于ARM64架构的修改程序寄存器的函数，先备份寄存器状态，然后修改寄存器状态让其执行目标函数，执行完后取返回值
    //注意：该函数可能会引起系统不稳定，请谨慎使用
    struct pt_regs* regs;
    // 获取任务的寄存器状态
    regs = task_pt_regs(task);
    if (!regs)
        return;
    // 备份原始寄存器状态（使用 memcpy 而不是直接初始化，兼容性更好）
    struct pt_regs original_regs;
    memcpy(&original_regs, regs, sizeof(original_regs));
    // 设置目标函数地址
    regs->pc = addr;
    // 设置参数（假设最多传递4个参数）
    if (ParamsSize >= sizeof(uintptr_t)) {
        uintptr_t param1;
        if (copy_from_user(&param1, params, sizeof(uintptr_t)) == 0) {
            regs->regs[0] = param1;
        }
    }
    if (ParamsSize >= 2 * sizeof(uintptr_t)) {
        uintptr_t param2;
        if (copy_from_user(&param2, params + sizeof(uintptr_t), sizeof(uintptr_t)) == 0) {
            regs->regs[1] = param2;
        }
    }
    if (ParamsSize >= 3 * sizeof(uintptr_t)) {
        uintptr_t param3;
        if (copy_from_user(&param3, params + 2 * sizeof(uintptr_t), sizeof(uintptr_t)) == 0) {
            regs->regs[2] = param3;
        }
    }
    if (ParamsSize >= 4 * sizeof(uintptr_t)) {
        uintptr_t param4;
        if (copy_from_user(&param4, params + 3 * sizeof(uintptr_t), sizeof(uintptr_t)) == 0) {
            regs->regs[3] = param4;
        }
    }
    // 让任务执行目标函数（使用 wake_up_process，避免依赖可能不存在的 set_task_state 符号）
    wake_up_process(task);
    // 等待任务执行完毕代码
    // 简化实现：短轮询带超时，等待寄存器 PC 离开目标地址（表示指令流已向前推进），或超时后继续。
    // 说明：这是不完美的方案；更可靠的方法需要进程内配合（设置完成标志、信号或者使用 ptrace/single-step）。
    {
        const int max_wait_ms = 100;   // 最大等待时间：100 ms
        const int poll_interval_ms = 1; // 轮询间隔：1 ms
        int waited = 0;

        // 如果 regs 指向的结构在唤醒后仍然有效，则检查 pc 是否已改变
        while (waited < max_wait_ms) {
            // 如果 pc 已不再等于我们设置的 addr，认为目标函数已开始执行或已返回
            if (regs->pc != addr)
                break;
            msleep(poll_interval_ms);
            waited += poll_interval_ms;
        }
    }

    // 获取返回值
    if (RetValue) {
        uintptr_t ret_val = regs->regs[0];
        copy_to_user(RetValue, &ret_val, sizeof(uintptr_t));
    }
    // 恢复原始寄存器状态
    memcpy(regs, &original_regs, sizeof(original_regs));
}

static void call_process_code(pid_t pid, uintptr_t addr, void __user* params, void __user* RetValue, size_t ParamsSize) {
    //这是一个Call函数
    //函数原理是修改先备份主线程的寄存器状态，然后修改寄存器状态让其执行目标函数，函数执行完毕后恢复寄存器状态
    //注意：该函数可能会引起系统不稳定，请谨慎使用
    struct task_struct* task = NULL;
    struct pid* pid_struct = NULL;
    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return;
    }
    /* 保持对 task 的引用直到调用完成，避免 use-after-free */
    modify_task_registers(task, addr, params, RetValue, ParamsSize);
    put_task_struct(task);
    put_pid(pid_struct);
}

static phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va)
{
    pgd_t* pgd;
    pmd_t* pmd;
    pte_t* pte;
    pud_t* pud;
    phys_addr_t page_addr;
    uintptr_t page_offset;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61)
    p4d_t* p4d;

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

// 替换 valid_phys_addr_range 的替代实现
static inline bool is_valid_phys_addr_range(phys_addr_t addr, size_t size)
{
    // 简单的检查：确保地址在物理内存范围内
    // 对于ARM64架构，high_memory包含了高地址内存信息
    return (addr + size <= virt_to_phys(high_memory));
}

static bool read_physical_address(phys_addr_t pa, void __user* buffer, size_t size)
{
    void* mapped;

    if (!pfn_valid(__phys_to_pfn(pa)))
        return false;

    // 使用替代函数检查物理地址范围
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

static bool write_physical_address(phys_addr_t pa, const void __user* buffer, size_t size)
{
    void* mapped;

    if (!pfn_valid(__phys_to_pfn(pa)))
        return false;

    // 使用替代函数检查物理地址范围
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

static bool read_process_memory(pid_t pid, uintptr_t addr,
    void __user* buffer, size_t size)
{
    struct task_struct* task = NULL;
    struct mm_struct* mm = NULL;
    struct pid* pid_struct = NULL;
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

    pa = translate_linear_address(mm, addr);
    if (pa) {
        result = read_physical_address(pa, buffer, size);
    }
    else {
        struct vm_area_struct* vma = find_vma(mm, addr);
        if (vma) {
            if (clear_user(buffer, size) == 0) {
                result = true;
            }
        }
    }

    mmput(mm);
    put_task_struct(task);
    return result;
}

static bool write_process_memory(pid_t pid, uintptr_t addr,
    const void __user* buffer, size_t size)
{
    struct task_struct* task = NULL;
    struct mm_struct* mm = NULL;
    struct pid* pid_struct = NULL;
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

    pa = translate_linear_address(mm, addr);
    if (pa) {
        result = write_physical_address(pa, buffer, size);
    }

    mmput(mm);
    put_task_struct(task);
    return result;
}

#define ARC_PATH_MAX 256

static uintptr_t get_module_base(pid_t pid, const char* name)
{
    struct task_struct* task = NULL;
    struct mm_struct* mm = NULL;
    struct pid* pid_struct = NULL;
    struct vm_area_struct* vma = NULL;
    uintptr_t base_addr = 0;
    int path_len;

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    struct vma_iterator vmi;
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma) {
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
        char buf[ARC_PATH_MAX];
        char* path_nm;

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

    mmput(mm);
    put_task_struct(task);
    return base_addr;
    }

static int dispatch_open(struct inode* node, struct file* file)
{
    return 0;
}

static int dispatch_close(struct inode* node, struct file* file)
{
    return 0;
}

static long dispatch_ioctl(struct file* file, unsigned int cmd, unsigned long arg)
{
    static char key[256] = { 0 };
    static bool is_verified = false;

    switch (cmd) {
    case OP_INIT_KEY:
        if (!is_verified) {
            if (copy_from_user(key, (void __user*)arg, sizeof(key) - 1) == 0) {
                key[sizeof(key) - 1] = '\0';
                is_verified = true;
            }
            else {
                return -EFAULT;
            }
        }
        break;

    case OP_READ_MEM: {
        COPY_MEMORY cm;

        if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)))
            return -EFAULT;

        if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -EIO;

        break;
    }

    case OP_WRITE_MEM: {
        COPY_MEMORY cm;

        if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)))
            return -EFAULT;

        if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -EIO;

        break;
    }

    case OP_MODULE_BASE: {
        MODULE_BASE mb;
        char module_name[256];

        if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)))
            return -EFAULT;

        if (!mb.name)
            return -EFAULT;

        if (copy_from_user(module_name, mb.name, sizeof(module_name) - 1))
            return -EFAULT;
        module_name[sizeof(module_name) - 1] = '\0';

        mb.base = get_module_base(mb.pid, module_name);

        if (copy_to_user((void __user*)arg, &mb, sizeof(mb)))
            return -EFAULT;

        break;
    }

    case OP_CALL_PROCESS: {
        CALL_PROCESS cp;

        if (copy_from_user(&cp, (void __user*)arg, sizeof(cp)))
            return -EFAULT;

        if (!cp.addr)
            return -EFAULT;

        if (cp.params)
            return -EFAULT;

        if (cp.ParamsSize < 1)
            return -EFAULT;

        call_process_code(cp.pid, cp.addr, cp.params, cp.RetValue, cp.ParamsSize);

        break;
    }
    default:
        return -ENOTTY;
    }

    return 0;
}

static const struct file_operations dispatch_fops = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
    .compat_ioctl = dispatch_ioctl,
};

static struct miscdevice misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &dispatch_fops,
    .mode = 0777,
};

static int __init driver_entry(void)
{
    int ret;

    ret = misc_register(&misc_dev);
    if (ret)
        return ret;

    return 0;
}

static void __exit driver_unload(void)
{
    misc_deregister(&misc_dev);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel Module");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YihanChan");
MODULE_VERSION("1.0");