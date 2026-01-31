#include "aurora.h"
#include <linux/random.h>

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void __user *buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char __user *name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

enum OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
};

// 可选的设备名池
static const char* device_name_pool[] = {
    "SynapseKernel",
    "AetherBridge",
    "NexusGuard",
    "QuantumLink",
    "VortexCore",
    "PhantomNode",
    "TitanShield",
    "OrionDriver",
    "ZenithPath",
    "CelestialGate",
    "NebulaCore",
    "StellarLink",
    "InfinityHook",
    "EchoSys",
    "ChronoFrame",
    "PulseEngine",
    "ApexBridge",
    "NovaNode",
    "SolarFlare",
    "CosmicPath"
};

#define DEVICE_POOL_SIZE (sizeof(device_name_pool) / sizeof(device_name_pool[0]))
static char selected_device_name[64];  // 存储实际使用的设备名
static struct miscdevice misc_dev;

static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va);
static bool read_physical_address(phys_addr_t pa, void __user *buffer, size_t size);
static bool write_physical_address(phys_addr_t pa, const void __user *buffer, size_t size);
static bool read_process_memory(pid_t pid, uintptr_t addr, void __user *buffer, size_t size);
static bool write_process_memory(pid_t pid, uintptr_t addr, const void __user *buffer, size_t size);
static uintptr_t get_module_base(pid_t pid, const char *name);

// 从池中随机选择一个设备名
static void select_random_device_name(void)
{
    unsigned int rand_val;
    int index;
    
    get_random_bytes(&rand_val, sizeof(rand_val));
    index = rand_val % DEVICE_POOL_SIZE;
    
    snprintf(selected_device_name, sizeof(selected_device_name), 
             "%s", device_name_pool[index]);
    
    printk(KERN_INFO "Aurora: Selected random device name: %s\n", selected_device_name);
}

static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
    phys_addr_t page_addr;
    uintptr_t page_offset;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61)
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

static inline bool is_valid_phys_addr_range(phys_addr_t addr, size_t size)
{
    return (addr + size <= virt_to_phys(high_memory));
}

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

static bool read_process_memory(pid_t pid, uintptr_t addr, 
                               void __user *buffer, size_t size)
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

    pa = translate_linear_address(mm, addr);
    if (pa) {
        result = read_physical_address(pa, buffer, size);
    } else {
        struct vm_area_struct *vma = find_vma(mm, addr);
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

    pa = translate_linear_address(mm, addr);
    if (pa) {
        result = write_physical_address(pa, buffer, size);
    }

    mmput(mm);
    put_task_struct(task);
    return result;
}

#define ARC_PATH_MAX 256

static uintptr_t get_module_base(pid_t pid, const char *name)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    struct pid *pid_struct = NULL;
    struct vm_area_struct *vma = NULL;
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
        char *path_nm;

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

static int dispatch_open(struct inode *node, struct file *file)
{
    return 0;
}

static int dispatch_close(struct inode *node, struct file *file)
{
    return 0;
}

static long dispatch_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    static char key[256] = {0};
    static bool is_verified = false;

    switch (cmd) {
    case OP_INIT_KEY:
        if (!is_verified) {
            if (copy_from_user(key, (void __user *)arg, sizeof(key) - 1) == 0) {
                key[sizeof(key) - 1] = '\0';
                is_verified = true;
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

static int __init driver_entry(void)
{
    int ret;
    
    select_random_device_name();
    
    // 注册设备
    misc_dev.minor = MISC_DYNAMIC_MINOR;
    misc_dev.name = selected_device_name;
    misc_dev.fops = &dispatch_fops;
    misc_dev.mode = 0666;
    
    ret = misc_register(&misc_dev);
    if (ret) {
        printk(KERN_ERR "Aurora: Failed to register device %s, error %d\n", 
               selected_device_name, ret);
        return ret;
    }
    
    printk(KERN_INFO "Aurora: Successfully registered random device: %s\n", 
           selected_device_name);
    return 0;
}

static void __exit driver_unload(void)
{
    misc_deregister(&misc_dev);
    printk(KERN_INFO "Aurora: Unregistered device: %s\n", selected_device_name);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel Module");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YihanChan");
MODULE_VERSION("1.0");
