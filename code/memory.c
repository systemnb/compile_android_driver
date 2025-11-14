#include "memory.h"
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>

extern struct mm_struct *get_task_mm(struct task_struct *task);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
extern void mmput(struct mm_struct *);

phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{

	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
	{
		return 0;
	}
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
	{
		return 0;
	}
	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud))
	{
		return 0;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
	{
		return 0;
	}
	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte))
	{
		return 0;
	}
	if (!pte_present(*pte))
	{
		return 0;
	}
	// 页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	// 页内偏移
	page_offset = va & (PAGE_SIZE - 1);

	return page_addr + page_offset;
}
#else
phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{

	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
	{
		return 0;
	}
	pud = pud_offset(pgd, va);
	if (pud_none(*pud) || pud_bad(*pud))
	{
		return 0;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
	{
		return 0;
	}
	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte))
	{
		return 0;
	}
	if (!pte_present(*pte))
	{
		return 0;
	}
	// 页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	// 页内偏移
	page_offset = va & (PAGE_SIZE - 1);

	return page_addr + page_offset;
}
#endif

#ifndef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static inline int valid_phys_addr_range(phys_addr_t addr, size_t count)
{
	return addr + count <= __pa(high_memory);
}
#endif

bool read_physical_address(phys_addr_t pa, void *buffer, size_t size)
{
	void *mapped_page;
	void *vmapped_addr;
	unsigned long offset;
	unsigned int npages;
	struct page **pages;
	int i;
	phys_addr_t current_pa;

	if (!valid_phys_addr_range(pa, size))
	{
		return false;
	}

	offset = pa & (PAGE_SIZE - 1);
	npages = (offset + size + PAGE_SIZE - 1) / PAGE_SIZE;

	pages = kmalloc(npages * sizeof(struct page *), GFP_KERNEL);
	if (!pages)
	{
		return false;
	}

	current_pa = pa & PAGE_MASK;
	for (i = 0; i < npages; i++)
	{
		if (!pfn_valid(__phys_to_pfn(current_pa)))
		{
			kfree(pages);
			return false;
		}
		pages[i] = pfn_to_page(__phys_to_pfn(current_pa));
		current_pa += PAGE_SIZE;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	vmapped_addr = vmap(pages, npages, pgprot_noncached(PAGE_KERNEL));
#else
	vmapped_addr = vmap(pages, npages, VM_MAP, pgprot_noncached(PAGE_KERNEL));
#endif
	kfree(pages);

	if (!vmapped_addr)
	{
		return false;
	}

	mapped_page = vmapped_addr + offset;

	if (copy_to_user(buffer, mapped_page, size))
	{
		vunmap(vmapped_addr);
		return false;
	}
	vunmap(vmapped_addr);
	return true;
}

bool write_physical_address(phys_addr_t pa, void *buffer, size_t size)
{
	void *mapped_page;
	void *vmapped_addr;
	unsigned long offset;
	unsigned int npages;
	struct page **pages;
	int i;
	phys_addr_t current_pa;

	if (!valid_phys_addr_range(pa, size))
	{
		return false;
	}

	offset = pa & (PAGE_SIZE - 1);
	npages = (offset + size + PAGE_SIZE - 1) / PAGE_SIZE;

	pages = kmalloc(npages * sizeof(struct page *), GFP_KERNEL);
	if (!pages)
	{
		return false;
	}

	current_pa = pa & PAGE_MASK;
	for (i = 0; i < npages; i++)
	{
		if (!pfn_valid(__phys_to_pfn(current_pa)))
		{
			kfree(pages);
			return false;
		}
		pages[i] = pfn_to_page(__phys_to_pfn(current_pa));
		current_pa += PAGE_SIZE;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	vmapped_addr = vmap(pages, npages, pgprot_noncached(PAGE_KERNEL));
#else
	vmapped_addr = vmap(pages, npages, VM_MAP, pgprot_noncached(PAGE_KERNEL));
#endif
	kfree(pages);

	if (!vmapped_addr)
	{
		return false;
	}

	mapped_page = vmapped_addr + offset;

	if (copy_from_user(mapped_page, buffer, size))
	{
		vunmap(vmapped_addr);
		return false;
	}
	vunmap(vmapped_addr);
	return true;
}

bool read_process_memory(
	pid_t pid,
	uintptr_t addr,
	void *buffer,
	size_t size)
{

	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	phys_addr_t pa;
	bool result = false;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
	{
		return false;
	}
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
	{
		return false;
	}
	mm = get_task_mm(task);
	if (!mm)
	{
		return false;
	}

	pa = translate_linear_address(mm, addr);
	if (pa)
	{
		result = read_physical_address(pa, buffer, size);
	}
	else
	{
		if (find_vma(mm, addr))
		{
			if (clear_user(buffer, size) == 0)
			{
				result = true;
			}
		}
	}

	mmput(mm);
	return result;
}

bool write_process_memory(
	pid_t pid,
	uintptr_t addr,
	void *buffer,
	size_t size)
{

	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	phys_addr_t pa;
	bool result = false;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
	{
		return false;
	}
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
	{
		return false;
	}
	mm = get_task_mm(task);
	if (!mm)
	{
		return false;
	}

	pa = translate_linear_address(mm, addr);
	if (pa)
	{
		result = write_physical_address(pa, buffer, size);
	}

	mmput(mm);
	return result;
}