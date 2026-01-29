#include <linux/sched/debug.h>
#include <linux/kallsyms.h>
#include <linux/kgdb.h>
#include <linux/module.h>
#include <linux/version.h>
#include "ext_hw_breakpoint.h"

/*func extern*/
extern int hw_bp_register(struct hw_bp_info *__percpu *cpu_events,
			  hw_bp_attr *attr, int *state);
extern void hw_bp_unregister(struct hw_bp_info *__percpu *bp, int state);

struct hw_bp_manage_info {
	struct hw_bp_info **info; /*percpu bp info*/
	hw_bp_attr attr; /*bp attr*/
	int mask; /*bp register cpu mask*/
	char symbol_name[KSYM_SYMBOL_LEN]; /*symbol name of addr*/
};
struct hw_bp_manage {
	struct hw_bp_manage_info wp[ARM_MAX_WRP]; /*wp*/
	struct hw_bp_manage_info bp[ARM_MAX_BRP]; /*bp*/
	int max_wp_num; /*max num of wp*/
	int max_bp_num; /*max num of bp*/
	int cpu_mask; /*cpu mask, num of cpu*/
	int cpu_num; /**/
	struct mutex lock; /*mutex lock*/
} __aligned(512);

static struct hw_bp_manage g_hw_manage;
const char bp_type_str[4][30] = { "HW_BREAKPOINT_R", "HW_BREAKPOINT_W",
				  "HW_BREAKPOINT_RW", "HW_BREAKPOINT_X" };

/*show info of bp*/
static void hw_bp_show_one(struct hw_bp_manage_info *bp_info, int index)
{
	int cpu;
	struct hw_bp_info *bp_percpu;

	pr_info("--------------------------------------------------\n");
	/*index of bp*/
	switch (bp_info->attr.type) {
	case HW_BREAKPOINT_R:
	case HW_BREAKPOINT_W:
	case HW_BREAKPOINT_RW:
	case HW_BREAKPOINT_X: {
		pr_info("breakpoint[%d]:\n", index);
		break;
	}
	default: {
		pr_info("breakpoint[%d] type is error!\n", index);
		return;
	}
	}

	/*bp type*/
	pr_info("\ttype: \t%s\n", bp_type_str[bp_info->attr.type - 1]);
	/*symbol name of addr*/
	pr_info("\tname: \t%s\n", bp_info->symbol_name);
	/*the range of detect*/
	pr_info("\tmonit: \t0x%llx--->0x%llx\n", bp_info->attr.addr,
		bp_info->attr.addr + bp_info->attr.len - 1);
	/*detect len*/
	pr_info("\tlen: \t%llu\n", bp_info->attr.len);
	/*addr mask*/
	pr_info("\tmask: \t0x%x\n", bp_info->attr.mask);
	/*the fact of detect range*/
	pr_info("\trange: \t0x%llx--->0x%llx\n", bp_info->attr.start_addr,
		bp_info->attr.end_addr);
	pr_info("\tsize: \t%llu\n",
		bp_info->attr.end_addr - bp_info->attr.start_addr);
	pr_info("\ttimes:\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	cpus_read_lock();
#else
	get_online_cpus();
#endif
	for_each_possible_cpu(cpu) {
		if (bp_info->mask & 1 << cpu) {
			bp_percpu = per_cpu(*bp_info->info, cpu);
			pr_info("\t\tcpu[%d]: \tread: %llu, write: %llu, exec: %llu\n",
				cpu, bp_percpu->attr.times.read,
				bp_percpu->attr.times.write,
				bp_percpu->attr.times.exec);
		}
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	cpus_read_unlock();
#else
	put_online_cpus();
#endif
}

/*show all bp info*/
void hw_bp_show_all(void)
{
	struct hw_bp_manage_info *bp_info = NULL;
	int i = 0;

	mutex_lock(&g_hw_manage.lock);
	for (i = 0; i < g_hw_manage.max_bp_num; i++) {
		bp_info = &g_hw_manage.bp[i];
		if (bp_info->mask & g_hw_manage.cpu_mask) {
			hw_bp_show_one(bp_info, i);
		}
	}

	for (i = 0; i < g_hw_manage.max_wp_num; i++) {
		bp_info = &g_hw_manage.wp[i];
		if (bp_info->mask & g_hw_manage.cpu_mask) {
			hw_bp_show_one(bp_info, i + g_hw_manage.max_bp_num);
		}
	}
	mutex_unlock(&g_hw_manage.lock);
}

static void hw_bp_uninstall_all(void)
{
	struct hw_bp_manage_info *bp_info = NULL;
	int i = 0;

	mutex_lock(&g_hw_manage.lock);
	for (i = 0; i < g_hw_manage.max_bp_num; i++) {
		bp_info = &g_hw_manage.bp[i];
		if (bp_info->mask & g_hw_manage.cpu_mask) {
			hw_bp_unregister(bp_info->info, bp_info->mask);
			/*clear info*/
			memset(bp_info->symbol_name, 0,
			       sizeof(bp_info->symbol_name));
			memset(&bp_info->attr, 0, sizeof(bp_info->attr));
			bp_info->mask = 0;
		}
	}

	for (i = 0; i < g_hw_manage.max_wp_num; i++) {
		bp_info = &g_hw_manage.wp[i];
		if (bp_info->mask & g_hw_manage.cpu_mask) {
			hw_bp_unregister(bp_info->info, bp_info->mask);
			/*clear info*/
			memset(bp_info->symbol_name, 0,
			       sizeof(bp_info->symbol_name));
			memset(&bp_info->attr, 0, sizeof(bp_info->attr));
			bp_info->mask = 0;
		}
	}
	mutex_unlock(&g_hw_manage.lock);
}

static int hw_get_addr_mask(u64 addr, int len)
{
	/*end of the detect addr*/
	u64 addr_tmp = addr + len;
	u64 alignment_mask = 0;
	int mask, i = 0;

	/*log2(len)*/
	mask = (int)__ilog2_u64(len);
	if ((1 << mask) < len) {
		mask = mask + 1;
	}
	for (i = 0; i < mask; i++) {
		alignment_mask |= (1 << i);
	}

	/*Confirm that the end address is within the actual monitoring range*/
	while (1) {
		if ((addr | alignment_mask) >= addr_tmp) {
			break;
		}
		mask = mask + 1;
		alignment_mask |= (1 << i);
		i++;
	}

	if (mask > 31) {
		/*arm64 the mask is 0b11111*/
		mask = 31;
	}
	return mask;
}

static void hw_bp_handler_default(const hw_bp_callback_data *info,
				  const struct pt_regs *regs)
{
	pr_info("bp is triger = 0x%llx, type = %s\n", info->addr,
		bp_type_str[info->type - 1]);
	pr_info("times: read=%llu, write=%llu, exec=%llu\n", info->times.read,
		info->times.write, info->times.exec);
	HW_SYMS_FUNC(show_regs)((struct pt_regs *)regs);
}

/*install bp from addr*/
int hw_bp_install_from_addr(u64 addr, int len, int type, hw_bp_callback handler)
{
	int state, i, max_num, ret, mask = 0;
	struct hw_bp_manage_info *bp_info;
	u64 start_addr, end_addr;
	u64 alignment_mask = 0, real_len = len, offset;

	if ((0 == addr) || (addr < TASK_SIZE)) {
		pr_info("hw_bp_install_from_addr para is error\n");
		return -1;
	}

	switch (type) {
	case HW_BREAKPOINT_R:
	case HW_BREAKPOINT_W:
	case HW_BREAKPOINT_RW: {
		/*wp*/
		bp_info = g_hw_manage.wp;
		max_num = g_hw_manage.max_wp_num;
		if (len > 8) {
			/*len>8, use mask*/
			mask = hw_get_addr_mask(addr, len);
			real_len = 4;
		}
		if (mask != 0) {
			/*get mask startaddr&endaddr*/
			for (i = 0; i < mask; i++) {
				alignment_mask |= (1 << i);
			}
			start_addr = addr & ~(alignment_mask);
			end_addr = addr | alignment_mask;
		} else {
			/*len<=8, use LBN*/
			alignment_mask = 0x7;
			offset = addr & alignment_mask;
			real_len = len << offset;
			if (real_len > 8) {
				real_len = 8;
			}
			start_addr = addr & ~(alignment_mask);
			end_addr = start_addr + real_len;
		}
		break;
	}
	case HW_BREAKPOINT_X: {
		/*bp*/
		real_len = 4;
		bp_info = g_hw_manage.bp;
		max_num = g_hw_manage.max_bp_num;
		alignment_mask = 0x3;
		offset = addr & alignment_mask;
		real_len = len << offset;
		if (real_len > 8) {
			real_len = 8;
		}
		start_addr = addr & ~(alignment_mask);
		end_addr = start_addr + real_len;
		break;
	}
	default: {
		/*bp type error*/
		pr_info("breakpoint type error\n");
		return -1;
	}
	}

	mutex_lock(&g_hw_manage.lock);
	for (i = 0; i < max_num; i++) {
		if ((bp_info[i].mask & g_hw_manage.cpu_mask) != 0) {
			/*This bp has been set*/
			if (bp_info[i].attr.addr == addr) {
				pr_info("[install] The addr [%llx] is already set at index %d\n",
					addr, i);
				mutex_unlock(&g_hw_manage.lock);
				return -1;
			}
		}
	}

	for (i = 0; i < max_num; i++) {
		if ((bp_info[i].mask & g_hw_manage.cpu_mask) != 0) {
			continue;
		}
		bp_info[i].attr.len = len;
		bp_info[i].attr.real_len = real_len;
		bp_info[i].attr.mask = mask;
		bp_info[i].attr.type = type;
		bp_info[i].attr.addr = addr;
		bp_info[i].attr.start_addr = start_addr;
		bp_info[i].attr.end_addr = end_addr;
		bp_info[i].attr.handler = handler;
		if (bp_info[i].attr.handler == NULL) {
			bp_info[i].attr.handler = hw_bp_handler_default;
		}
		break;
	}

	if (i == max_num) {
		pr_info("[install] breakpoint is full type = %x\n", type);
		mutex_unlock(&g_hw_manage.lock);
		return -1;
	}

	// pr_info("gHwManage.wp[%d].info = %lx\n", i, gHwManage.wp[i].info);
	// pr_info("info = %lx,attr=%lx,state=%lx\n", bpInfo[i].info, &bpInfo[i].attr, &state);
	ret = hw_bp_register(bp_info[i].info, &bp_info[i].attr, &state);
	if (ret) {
		goto clear;
	}
	/*Several CPUs are registered with the breakpoint*/
	bp_info[i].mask = state;
	memset(bp_info[i].symbol_name, 0, sizeof(bp_info[i].symbol_name));
	sprint_symbol(bp_info[i].symbol_name, addr);
	mutex_unlock(&g_hw_manage.lock);
	hw_bp_show_one(&bp_info[i], i);
	return 0;
clear:
	pr_info("hw_bp_install_from_addr [%llx] error\n", addr);
	/*clear bp info*/
	memset(&bp_info[i].attr, 0, sizeof(bp_info[i].attr));
	memset(bp_info[i].symbol_name, 0, sizeof(bp_info[i].symbol_name));
	bp_info[i].mask = 0;
	mutex_unlock(&g_hw_manage.lock);
	return -1;
}
EXPORT_SYMBOL_GPL(hw_bp_install_from_addr);

/*从符号设置一个断点*/
int hw_bp_install_from_symbol(char *name, int len, int type,
			      hw_bp_callback handler)
{
	int ret = 0;
	u64 addr = 0;

	if ((NULL == name) || (HW_BREAKPOINT_INVALID == type)) {
		pr_info("HW_breakpointInstallFromSymbol para is error\n");
		return -1;
	}

	addr = HW_SYMS_FUNC(kallsyms_lookup_name)(name);
	if (0 == addr) {
		/*the symbol is invalid*/
		pr_info("Can not find the symbol, name: %s\n", name);
		return -1;
	}

	ret = hw_bp_install_from_addr(addr, len, type, handler);
	if (ret) {
		pr_info("HW_breakpointInstallFromSymbol error [%s]\n", name);
		return -1;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(hw_bp_install_from_symbol);

void hw_bp_uninstall_from_addr(u64 addr)
{
	int i = 0;
	struct hw_bp_manage_info *bp_info = NULL;

	/*traverse bp arrays*/
	/*find bp*/
	mutex_lock(&g_hw_manage.lock);
	for (i = 0; i < g_hw_manage.max_bp_num; i++) {
		if (g_hw_manage.bp[i].mask & g_hw_manage.cpu_mask) {
			if (g_hw_manage.bp[i].attr.addr == addr) {
				bp_info = &g_hw_manage.bp[i];
				pr_info("[uninstall] find addr: bp[%d]\n", i);
				break;
			}
		}
	}
	/*find wp*/
	for (i = 0; (i < g_hw_manage.max_wp_num) && (bp_info == NULL); i++) {
		if (g_hw_manage.wp[i].mask & g_hw_manage.cpu_mask) {
			if (g_hw_manage.wp[i].attr.addr == addr) {
				bp_info = &g_hw_manage.wp[i];
				pr_info("[uninstall] find addr: wp[%d]\n", i);
				break;
			}
		}
	}
	if (NULL == bp_info) {
		pr_info("HW_breakpointUnInstallFromAddr fail,can not find addr:0x%llx\n",
			addr);
		mutex_unlock(&g_hw_manage.lock);
		return;
	}
	hw_bp_unregister(bp_info->info, bp_info->mask);
	/*clear bp info*/
	memset(bp_info->symbol_name, 0, sizeof(bp_info->symbol_name));
	memset(&bp_info->attr, 0, sizeof(bp_info->attr));
	bp_info->mask = 0;
	mutex_unlock(&g_hw_manage.lock);
}
EXPORT_SYMBOL_GPL(hw_bp_uninstall_from_addr);

void hw_bp_uninstall_from_symbol(char *name)
{
	u64 addr = 0;

	if (NULL == name) {
		pr_info("HW_breakpointUnInstallFromSymbol para is error\n");
		return;
	}

	addr = HW_SYMS_FUNC(kallsyms_lookup_name)(name);
	if (0 == addr) {
		/*the symbol is invalid*/
		pr_info("[uninstall] Can not find the symbol, name: %s\n",
			name);
		return;
	}
	hw_bp_uninstall_from_addr(addr);
}
EXPORT_SYMBOL_GPL(hw_bp_uninstall_from_symbol);

void hw_free_bp_infos(hw_bp_info_list *info)
{
	hw_bp_info_list *node = NULL, *next = NULL;

	if (info) {
		list_for_each_entry_safe(node, next, &info->list, list) {
			list_del(&node->list);
			if (node->attr) {
				kfree(node->attr);
			}
			kfree(node);
		}
		if (info->attr) {
			kfree(info->attr);
		}
		kfree(info);
	}
}
EXPORT_SYMBOL_GPL(hw_free_bp_infos);

static void hw_fill_report_data(struct hw_bp_manage_info *bp_info,
				hw_bp_info_list *node)
{
	struct hw_bp_info *bp = NULL;
	int cpu = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	cpus_read_lock();
#else
	get_online_cpus();
#endif
	for_each_possible_cpu(cpu) {
		if (bp_info->mask & 1 << cpu) {
			bp = per_cpu(*bp_info->info, cpu);
			/*value*/
			node->attr[cpu].type = bp->attr.type;
			node->attr[cpu].addr = bp->attr.addr;
			node->attr[cpu].len = bp->attr.len;
			node->attr[cpu].mask = bp->attr.mask;
			node->attr[cpu].times = bp->attr.times;
		}
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	cpus_read_unlock();
#else
	put_online_cpus();
#endif
}

hw_bp_info_list *hw_get_bp_infos(void)
{
	hw_bp_info_list *head = NULL;
	hw_bp_info_list *node = NULL;
	struct hw_bp_manage_info *bp_info = NULL;
	int i = 0;

	mutex_lock(&g_hw_manage.lock);
	for (i = 0; i < g_hw_manage.max_bp_num; i++) {
		bp_info = &g_hw_manage.bp[i];
		if (bp_info->mask & g_hw_manage.cpu_mask) {
			/*bp is set*/
			if (head == NULL) {
				head = kzalloc(sizeof(hw_bp_info_list),
					       GFP_KERNEL);
				if (head == NULL) {
					goto err;
				}
				INIT_LIST_HEAD(&head->list);
				head->attr =
					kzalloc(sizeof(hw_bp_report) *
							g_hw_manage.cpu_num,
						GFP_KERNEL);
				if (head->attr == NULL) {
					goto err;
				}
				head->cpu_mask = bp_info->mask;
				head->cpu_num = g_hw_manage.cpu_num;
				hw_fill_report_data(bp_info, head);
			}
			node = kzalloc(sizeof(hw_bp_info_list), GFP_KERNEL);
			if (node == NULL) {
				goto err;
			}
			INIT_LIST_HEAD(&node->list);
			list_add_tail(&node->list, &head->list);
			node->attr = kzalloc(sizeof(hw_bp_report) *
						     g_hw_manage.cpu_num,
					     GFP_KERNEL);
			if (node->attr == NULL) {
				goto err;
			}
			node->cpu_mask = bp_info->mask;
			node->cpu_num = g_hw_manage.cpu_num;
			hw_fill_report_data(bp_info, node);
		}
	}

	for (i = 0; i < g_hw_manage.max_wp_num; i++) {
		bp_info = &g_hw_manage.wp[i];
		if (bp_info->mask & g_hw_manage.cpu_mask) {
			/*bp is set*/
			if (head == NULL) {
				head = kzalloc(sizeof(hw_bp_info_list),
					       GFP_KERNEL);
				if (head == NULL) {
					goto err;
				}
				INIT_LIST_HEAD(&head->list);
				head->attr =
					kzalloc(sizeof(hw_bp_report) *
							g_hw_manage.cpu_num,
						GFP_KERNEL);
				if (head->attr == NULL) {
					goto err;
				}
				head->cpu_mask = bp_info->mask;
				head->cpu_num = g_hw_manage.cpu_num;
				hw_fill_report_data(bp_info, head);
			}
			node = kzalloc(sizeof(hw_bp_info_list), GFP_KERNEL);
			if (node == NULL) {
				goto err;
			}
			INIT_LIST_HEAD(&node->list);
			list_add_tail(&node->list, &head->list);
			node->attr = kzalloc(sizeof(hw_bp_report) *
						     g_hw_manage.cpu_num,
					     GFP_KERNEL);
			if (node->attr == NULL) {
				goto err;
			}
			node->cpu_mask = bp_info->mask;
			node->cpu_num = g_hw_manage.cpu_num;
			hw_fill_report_data(bp_info, node);
		}
	}
	mutex_unlock(&g_hw_manage.lock);

	return head;

err:
	mutex_unlock(&g_hw_manage.lock);
	hw_free_bp_infos(head);
	return NULL;
}
EXPORT_SYMBOL_GPL(hw_get_bp_infos);

/*release bp*/
void hw_bp_manage_deinit(void)
{
	int i = 0;

	hw_bp_uninstall_all();

	for (i = 0; i < g_hw_manage.max_wp_num; i++) {
		free_percpu(g_hw_manage.wp[i].info);
	}

	for (i = 0; i < g_hw_manage.max_bp_num; i++) {
		free_percpu(g_hw_manage.bp[i].info);
	}
	mutex_destroy(&g_hw_manage.lock);
}

/*bp arch init*/
int hw_bp_manage_init(void)
{
	int cpu = -1, i = 0;
	struct hw_bp_info *__percpu *bp = NULL;

	/*get bp&wp num*/
	g_hw_manage.max_bp_num = hw_get_bp_num(TYPE_INST);
	g_hw_manage.max_wp_num = hw_get_bp_num(TYPE_DATA);

	/*get CPU num*/
	g_hw_manage.cpu_num = 0;
	for_each_online_cpu(cpu) {
		g_hw_manage.cpu_mask |= 1 << cpu;
		g_hw_manage.cpu_num++;
	}
	pr_info("CPU MASK =  %x\n", g_hw_manage.cpu_mask);

	/*mange mem of bp*/
	for (i = 0; i < g_hw_manage.max_wp_num; i++) {
		bp = alloc_percpu(typeof(*bp));
		if (!bp) {
			pr_info("wp alloc_percpu fail\n");
			goto free;
		}
		g_hw_manage.wp[i].info = bp;
		bp = NULL;
	}
	for (i = 0; i < g_hw_manage.max_bp_num; i++) {
		bp = alloc_percpu(typeof(*bp));
		if (!bp) {
			pr_info("wp alloc_percpu fail\n");
			goto free;
		}
		g_hw_manage.bp[i].info = bp;
		bp = NULL;
	}

	mutex_init(&g_hw_manage.lock);

	return 0;

free:
	hw_bp_manage_deinit();
	return -1;
}
