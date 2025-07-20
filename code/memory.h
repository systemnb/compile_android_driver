#include <linux/kernel.h>
#include <linux/sched.h>

static inline bool valid_phys_addr_range(phys_addr_t addr, size_t count);

phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va);

bool read_physical_address(phys_addr_t pa, void* buffer, size_t size);

bool write_physical_address(phys_addr_t pa, void* buffer, size_t size);

bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size);

bool write_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size);
