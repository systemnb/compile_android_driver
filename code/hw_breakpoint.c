#include <linux/module.h>
#include <asm-generic/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/sched/debug.h>
#include <linux/version.h>
#include <asm/system_misc.h>
#include <asm/debug-monitors.h>
#include "ext_hw_breakpoint.h"

/*func extern*/
extern int hw_bp_manage_init(void);
extern int hw_proc_init(void);

enum hw_breakpoint_ops {
	HW_BREAKPOINT_INSTALL,
	HW_BREAKPOINT_UNINSTALL,
	HW_BREAKPOINT_RESTORE
};

/* Breakpoint currently in use for each BRP. */
static DEFINE_PER_CPU(struct hw_bp_info *, bp_on_reg[ARM_MAX_BRP]);

/* Watchpoint currently in use for each WRP. */
static DEFINE_PER_CPU(struct hw_bp_info *, wp_on_reg[ARM_MAX_WRP]);

/* Currently stepping a per-CPU kernel breakpoint. */
static DEFINE_PER_CPU(int, stepping_kernel_bp);

/* Number of BRP/WRP registers on this CPU. */
static int core_num_brps;
static int core_num_wrps;

/*kernel vars*/
hw_kernel_api g_kernel_api;

/*get bp num*/
int hw_get_bp_num(int type)
{
	switch (type) {
	case TYPE_INST:
		return hw_get_num_brps();
	case TYPE_DATA:
		return hw_get_num_wrps();
	default:
		pr_info("unknown slot type: %d\n", type);
		return 0;
	}
}

#define READ_WB_REG_CASE(OFF, N, REG, VAL)                                     \
	case ((OFF) + (N)):                                                    \
		AARCH64_DBG_READ(N, REG, VAL);                                 \
		break

#define WRITE_WB_REG_CASE(OFF, N, REG, VAL)                                    \
	case ((OFF) + (N)):                                                    \
		AARCH64_DBG_WRITE(N, REG, VAL);                                \
		break

#define GEN_READ_WB_REG_CASES(OFF, REG, VAL)                                   \
	READ_WB_REG_CASE(OFF, 0, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 1, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 2, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 3, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 4, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 5, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 6, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 7, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 8, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 9, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 10, REG, VAL);                                   \
	READ_WB_REG_CASE(OFF, 11, REG, VAL);                                   \
	READ_WB_REG_CASE(OFF, 12, REG, VAL);                                   \
	READ_WB_REG_CASE(OFF, 13, REG, VAL);                                   \
	READ_WB_REG_CASE(OFF, 14, REG, VAL);                                   \
	READ_WB_REG_CASE(OFF, 15, REG, VAL)

#define GEN_WRITE_WB_REG_CASES(OFF, REG, VAL)                                  \
	WRITE_WB_REG_CASE(OFF, 0, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 1, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 2, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 3, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 4, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 5, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 6, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 7, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 8, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 9, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 10, REG, VAL);                                  \
	WRITE_WB_REG_CASE(OFF, 11, REG, VAL);                                  \
	WRITE_WB_REG_CASE(OFF, 12, REG, VAL);                                  \
	WRITE_WB_REG_CASE(OFF, 13, REG, VAL);                                  \
	WRITE_WB_REG_CASE(OFF, 14, REG, VAL);                                  \
	WRITE_WB_REG_CASE(OFF, 15, REG, VAL)

/*read bp reg*/
static u64 hw_read_bp_reg(int reg, int n)
{
	u64 val = 0;

	switch (reg + n) {
		GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BVR,
				      AARCH64_DBG_REG_NAME_BVR, val);
		GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BCR,
				      AARCH64_DBG_REG_NAME_BCR, val);
		GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WVR,
				      AARCH64_DBG_REG_NAME_WVR, val);
		GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WCR,
				      AARCH64_DBG_REG_NAME_WCR, val);
	default:
		pr_info("attempt to read from unknown breakpoint register %d\n",
			n);
	}

	return val;
}
NOKPROBE_SYMBOL(hw_read_bp_reg);

/*write bp reg*/
static void hw_write_bp_reg(int reg, int n, u64 val)
{
	switch (reg + n) {
		GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_BVR,
				       AARCH64_DBG_REG_NAME_BVR, val);
		GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_BCR,
				       AARCH64_DBG_REG_NAME_BCR, val);
		GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_WVR,
				       AARCH64_DBG_REG_NAME_WVR, val);
		GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_WCR,
				       AARCH64_DBG_REG_NAME_WCR, val);
	default:
		pr_info("attempt to write to unknown breakpoint register %d\n",
			n);
	}
	/*Clear the pipeline to ensure that all previous instructions have been completed before the new instructions are executed*/
	isb();
}
NOKPROBE_SYMBOL(hw_write_bp_reg);

/*get elx level*/
static enum dbg_active_el hw_get_debug_exception_level(int privilege)
{
	switch (privilege) {
	case AARCH64_BREAKPOINT_EL0:
		return DBG_ACTIVE_EL0;
	case AARCH64_BREAKPOINT_EL1:
		return DBG_ACTIVE_EL1;
	default:
		pr_info("invalid breakpoint privilege level %d\n", privilege);
		return -EINVAL;
	}
}
NOKPROBE_SYMBOL(hw_get_debug_exception_level);

/**
 * hw_bp_slot_setup - Insert/remove bp in global variables
 *
 * @slots: pointer to the global variables
 * @max_slots: max bp num
 * @bp: bp info
 * @ops: type of bp
 *
 * Return:
 *    success: return the number of bp
 *    -ENOSPC no space
 *    -EINVAL cmd ops
 */
static int hw_bp_slot_setup(struct hw_bp_info **slots, int max_slots,
			    struct hw_bp_info *bp, enum hw_breakpoint_ops ops)
{
	int i;
	struct hw_bp_info **slot;

	for (i = 0; i < max_slots; ++i) {
		slot = &slots[i];
		switch (ops) {
		case HW_BREAKPOINT_INSTALL:
			if (!*slot) {
				*slot = bp;
				return i;
			}
			break;
		case HW_BREAKPOINT_UNINSTALL:
			if (*slot == bp) {
				*slot = NULL;
				return i;
			}
			break;
		case HW_BREAKPOINT_RESTORE:
			if (*slot == bp)
				return i;
			break;
		default:
			pr_info("Unhandled hw breakpoint ops %d\n", ops);
			return -EINVAL;
		}
	}
	return -ENOSPC;
}

/*bp control install/uninstall*/
static int hw_bp_control(struct hw_bp_info *bp, enum hw_breakpoint_ops ops)
{
	hw_bp_vc *info = hw_get_vc(bp);
	struct hw_bp_info **slots;
	int i, max_slots, ctrl_reg, val_reg;
	enum dbg_active_el dbg_el =
		hw_get_debug_exception_level(info->ctrl.privilege);
	u32 ctrl;

	// pr_info("the real CPU = %d\n", smp_processor_id());

	if (info->ctrl.type == ARM_BREAKPOINT_EXECUTE) {
		/* Breakpoint */
		ctrl_reg = AARCH64_DBG_REG_BCR;
		val_reg = AARCH64_DBG_REG_BVR;
		slots = this_cpu_ptr(bp_on_reg);
		max_slots = core_num_brps;
	} else {
		/* Watchpoint */
		ctrl_reg = AARCH64_DBG_REG_WCR;
		val_reg = AARCH64_DBG_REG_WVR;
		slots = this_cpu_ptr(wp_on_reg);
		max_slots = core_num_wrps;
	}

	i = hw_bp_slot_setup(slots, max_slots, bp, ops);

	if (WARN_ONCE(i < 0, "Can't find any breakpoint slot"))
		return i;

	switch (ops) {
	case HW_BREAKPOINT_INSTALL:
		/*Ensure debug monitors are enabled at the correct exception level.*/
		HW_SYMS_FUNC(enable_debug_monitors)(dbg_el);
		fallthrough;
		/* Fall through */
	case HW_BREAKPOINT_RESTORE:
		/* Setup the address register. */
		hw_write_bp_reg(val_reg, i, info->address);

		/* Setup the control register. */
		ctrl = hw_encode_ctrl_reg(info->ctrl);
		// pr_info("CTRL REG = %x\n", ctrl);
		hw_write_bp_reg(ctrl_reg, i, ctrl);
		break;
	case HW_BREAKPOINT_UNINSTALL:
		/* Reset the control register. */
		hw_write_bp_reg(ctrl_reg, i, 0);

		/*Release the debug monitors for the correct exception level.*/
		HW_SYMS_FUNC(disable_debug_monitors)(dbg_el);
		break;
	}

	return 0;
}

/*
 * Install a breakpoint.
 */
int hw_bp_install(struct hw_bp_info *bp)
{
	return hw_bp_control(bp, HW_BREAKPOINT_INSTALL);
}

int hw_bp_uninstall(struct hw_bp_info *bp)
{
	return hw_bp_control(bp, HW_BREAKPOINT_UNINSTALL);
}

/*get len from LBN bit*/
static int hw_get_hbp_Len(u8 hbp_len)
{
	int len_in_bytes = 0;

	switch (hbp_len) {
	case ARM_BREAKPOINT_LEN_1:
		len_in_bytes = 1;
		break;
	case ARM_BREAKPOINT_LEN_2:
		len_in_bytes = 2;
		break;
	case ARM_BREAKPOINT_LEN_3:
		len_in_bytes = 3;
		break;
	case ARM_BREAKPOINT_LEN_4:
		len_in_bytes = 4;
		break;
	case ARM_BREAKPOINT_LEN_5:
		len_in_bytes = 5;
		break;
	case ARM_BREAKPOINT_LEN_6:
		len_in_bytes = 6;
		break;
	case ARM_BREAKPOINT_LEN_7:
		len_in_bytes = 7;
		break;
	case ARM_BREAKPOINT_LEN_8:
	default:
		len_in_bytes = 8;
		break;
	}

	return len_in_bytes;
}

/*
 * Check whether bp virtual address is in kernel space.
 */
int hw_arch_check_bp_in_kspace(hw_bp_vc *hw)
{
	unsigned int len;
	unsigned long va;

	va = hw->address;
	len = hw_get_hbp_Len(hw->ctrl.len);

	/*get addr & len from mask*/
	if (hw->ctrl.mask) {
		len = 1 << hw->ctrl.mask;
	}

	return (va >= TASK_SIZE) && ((va + len - 1) >= TASK_SIZE);
}

/*
 * bp info to ctrl reg
 */
static int hw_arch_build_bp_info(struct hw_bp_info *bp, const hw_bp_attr *attr,
				 hw_bp_vc *hw)
{
	/* Type */
	switch (attr->type) {
	case HW_BREAKPOINT_X:
		hw->ctrl.type = ARM_BREAKPOINT_EXECUTE;
		break;
	case HW_BREAKPOINT_R:
		hw->ctrl.type = ARM_BREAKPOINT_LOAD;
		break;
	case HW_BREAKPOINT_W:
		hw->ctrl.type = ARM_BREAKPOINT_STORE;
		break;
	case HW_BREAKPOINT_RW:
		hw->ctrl.type = ARM_BREAKPOINT_LOAD | ARM_BREAKPOINT_STORE;
		break;
	default:
		return -EINVAL;
	}

	/* Len */
	switch (attr->real_len) {
	case HW_BREAKPOINT_LEN_1:
		hw->ctrl.len = ARM_BREAKPOINT_LEN_1;
		break;
	case HW_BREAKPOINT_LEN_2:
		hw->ctrl.len = ARM_BREAKPOINT_LEN_2;
		break;
	case HW_BREAKPOINT_LEN_3:
		hw->ctrl.len = ARM_BREAKPOINT_LEN_3;
		break;
	case HW_BREAKPOINT_LEN_4:
		hw->ctrl.len = ARM_BREAKPOINT_LEN_4;
		break;
	case HW_BREAKPOINT_LEN_5:
		hw->ctrl.len = ARM_BREAKPOINT_LEN_5;
		break;
	case HW_BREAKPOINT_LEN_6:
		hw->ctrl.len = ARM_BREAKPOINT_LEN_6;
		break;
	case HW_BREAKPOINT_LEN_7:
		hw->ctrl.len = ARM_BREAKPOINT_LEN_7;
		break;
	case HW_BREAKPOINT_LEN_8:
		hw->ctrl.len = ARM_BREAKPOINT_LEN_8;
		break;
	default:
		return -EINVAL;
	}

	/* only permit breakpoints of length 4 */
	if (hw->ctrl.type == ARM_BREAKPOINT_EXECUTE) {
		hw->ctrl.len = ARM_BREAKPOINT_LEN_4;
	}

	/* wp addr mask */
	hw->ctrl.mask = attr->mask;
	/* Address */
	hw->address = attr->start_addr;

	/*
	 * Privilege
	 * Note that we disallow combined EL0/EL1 breakpoints because
	 * that would complicate the stepping code.
	 */
	if (hw_arch_check_bp_in_kspace(hw))
		hw->ctrl.privilege = AARCH64_BREAKPOINT_EL1;
	else
		hw->ctrl.privilege = AARCH64_BREAKPOINT_EL0;

	/* Enabled */
	hw->ctrl.enabled = !attr->disabled;

	return 0;
}

/* parse bp info */
int hw_bp_arch_parse(struct hw_bp_info *bp, const hw_bp_attr *attr,
		     hw_bp_vc *hw)
{
	int ret;

	/* Build the arch_hw_breakpoint. */
	ret = hw_arch_build_bp_info(bp, attr, hw);
	if (ret)
		return ret;

	pr_info("ctrl.len=%x,mask=%d,enabled=%d,address=%llx\n", hw->ctrl.len,
		hw->ctrl.mask, hw->ctrl.enabled, hw->address);

	return 0;
}

/* enable/disable a bp */
static void hw_toggle_bp_registers(int reg, enum dbg_active_el el, int enable)
{
	int i, max_slots, privilege;
	u32 ctrl;
	struct hw_bp_info **slots;

	switch (reg) {
	case AARCH64_DBG_REG_BCR:
		slots = this_cpu_ptr(bp_on_reg);
		max_slots = core_num_brps;
		break;
	case AARCH64_DBG_REG_WCR:
		slots = this_cpu_ptr(wp_on_reg);
		max_slots = core_num_wrps;
		break;
	default:
		return;
	}

	for (i = 0; i < max_slots; ++i) {
		if (!slots[i])
			continue;

		privilege = hw_get_vc(slots[i])->ctrl.privilege;
		if (hw_get_debug_exception_level(privilege) != el)
			continue;

		ctrl = hw_read_bp_reg(reg, i);
		if (enable)
			ctrl |= 0x1;
		else
			ctrl &= ~0x1;
		hw_write_bp_reg(reg, i, ctrl);
	}
}
NOKPROBE_SYMBOL(hw_toggle_bp_registers);

/*bp events exception handler*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
static int hw_bp_handler(unsigned long unused, unsigned long esr,
			 struct pt_regs *regs)
#else
static int hw_bp_handler(unsigned long unused, unsigned int esr,
			 struct pt_regs *regs)
#endif
{
	int i, *kernel_step;
	u32 ctrl_reg;
	u64 addr, val;
	struct hw_bp_info *bp, **slots;
	hw_bp_ctrl_reg ctrl;

	slots = this_cpu_ptr(bp_on_reg);
	addr = instruction_pointer(regs);

	for (i = 0; i < core_num_brps; ++i) {
		rcu_read_lock();

		bp = slots[i];

		if (bp == NULL)
			goto unlock;

		/* Check if the breakpoint value matches. */
		val = hw_read_bp_reg(AARCH64_DBG_REG_BVR, i);
		if (val != (addr & ~0x3))
			goto unlock;

		/* Possible match, check the byte address select to confirm. */
		ctrl_reg = hw_read_bp_reg(AARCH64_DBG_REG_BCR, i);
		hw_decode_ctrl_reg(ctrl_reg, &ctrl);
		if (!((1 << (addr & 0x3)) & ctrl.len))
			goto unlock;

		hw_get_vc(bp)->trigger = addr;

	unlock:
		rcu_read_unlock();
	}

	hw_toggle_bp_registers(AARCH64_DBG_REG_BCR, DBG_ACTIVE_EL1, 0);
	kernel_step = this_cpu_ptr(&stepping_kernel_bp);

	if (*kernel_step != ARM_KERNEL_STEP_NONE)
		return 0;

	if (HW_SYMS_FUNC(kernel_active_single_step)()) {
		*kernel_step = ARM_KERNEL_STEP_SUSPEND;
	} else {
		*kernel_step = ARM_KERNEL_STEP_ACTIVE;
		HW_SYMS_FUNC(kernel_enable_single_step)(regs);
	}

	return 0;
}
NOKPROBE_SYMBOL(hw_bp_handler);

/*get dist from trigger to wp addr*/
static u64 hw_get_distance_from_wp(unsigned long addr, u64 val,
				   hw_bp_ctrl_reg *ctrl)
{
	addr = untagged_addr(addr);
	val = untagged_addr(val);
	return addr - val;
}

/*wp events exception handler*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
static int hw_wp_handler(unsigned long addr, unsigned long esr,
			 struct pt_regs *regs)
#else
static int hw_wp_handler(unsigned long addr, unsigned int esr,
			 struct pt_regs *regs)
#endif
{
	int i, *kernel_step, access, closest_match = -1;
	u64 min_dist = -1, dist;
	u32 ctrl_reg;
	u64 val;
	struct hw_bp_info *wp, **slots;
	hw_bp_vc *info = NULL;
	hw_bp_ctrl_reg ctrl;

	slots = this_cpu_ptr(wp_on_reg);

	/*find the nearest trigger address*/
	rcu_read_lock();
	for (i = 0; i < core_num_wrps; ++i) {
		wp = slots[i];
		if (wp == NULL)
			continue;

		/*check type of wp*/
		access = (esr & AARCH64_ESR_ACCESS_MASK) ? HW_BREAKPOINT_W :
							   HW_BREAKPOINT_R;
		if (!(access & wp->attr.type))
			continue;

		/* Check if the watchpoint value and byte select match. */
		val = hw_read_bp_reg(AARCH64_DBG_REG_WVR, i);
		ctrl_reg = hw_read_bp_reg(AARCH64_DBG_REG_WCR, i);
		hw_decode_ctrl_reg(ctrl_reg, &ctrl);
		dist = hw_get_distance_from_wp(addr, wp->attr.addr, &ctrl);
		if (dist < min_dist) {
			min_dist = dist;
			closest_match = i;
		}
		/* Is this an exact match? */
		if (dist != 0)
			continue;
		info = hw_get_vc(wp);
		info->trigger = addr;
		info->access_type = access;
		closest_match = i;
	}
	if (min_dist > 0 && min_dist != -1) {
		/* No exact match found. */
		wp = slots[closest_match];
		info = hw_get_vc(wp);
		info->trigger = addr;
		info->access_type = access;
	}
	rcu_read_unlock();

	/*disable all of wps*/
	hw_toggle_bp_registers(AARCH64_DBG_REG_WCR, DBG_ACTIVE_EL1, 0);
	kernel_step = this_cpu_ptr(&stepping_kernel_bp);

	if (*kernel_step != ARM_KERNEL_STEP_NONE)
		return 0;

	if (HW_SYMS_FUNC(kernel_active_single_step)()) {
		*kernel_step = ARM_KERNEL_STEP_SUSPEND;
	} else {
		*kernel_step = ARM_KERNEL_STEP_ACTIVE;
		/*enable ss exception in cur regs*/
		HW_SYMS_FUNC(kernel_enable_single_step)(regs);
	}

	return 0;
}
NOKPROBE_SYMBOL(hw_wp_handler);

/*resume bp states*/
static int hw_bp_reinstall(struct pt_regs *regs)
{
	// struct debug_info *debug_info = &current->thread.debug;
	int handled_exception = 0, *kernel_step;

	/*get step states*/
	kernel_step = this_cpu_ptr(&stepping_kernel_bp);

	if (*kernel_step != ARM_KERNEL_STEP_NONE) {
		hw_toggle_bp_registers(AARCH64_DBG_REG_BCR, DBG_ACTIVE_EL1, 1);
		hw_toggle_bp_registers(AARCH64_DBG_REG_WCR, DBG_ACTIVE_EL1, 1);

		if (*kernel_step != ARM_KERNEL_STEP_SUSPEND) {
			HW_SYMS_FUNC(kernel_disable_single_step());
			handled_exception = 1;
		} else {
			handled_exception = 0;
		}

		*kernel_step = ARM_KERNEL_STEP_NONE;
	}

	return !handled_exception;
}
NOKPROBE_SYMBOL(hw_bp_reinstall);

/*bp reset when cold boot*/
static int hw_bp_reset(unsigned int cpu)
{
	int i;
	struct hw_bp_info **slots;
	/*
	 * When a CPU goes through cold-boot, it does not have any installed
	 * slot, so it is safe to share the same function for restoring and
	 * resetting breakpoints; when a CPU is hotplugged in, it goes
	 * through the slots, which are all empty, hence it just resets control
	 * and value for debug registers.
	 * When this function is triggered on warm-boot through a CPU PM
	 * notifier some slots might be initialized; if so they are
	 * reprogrammed according to the debug slots content.
	 */
	for (slots = this_cpu_ptr(bp_on_reg), i = 0; i < core_num_brps; ++i) {
		if (slots[i]) {
			hw_bp_control(slots[i], HW_BREAKPOINT_RESTORE);
		} else {
			hw_write_bp_reg(AARCH64_DBG_REG_BCR, i, 0UL);
			hw_write_bp_reg(AARCH64_DBG_REG_BVR, i, 0UL);
		}
	}

	for (slots = this_cpu_ptr(wp_on_reg), i = 0; i < core_num_wrps; ++i) {
		if (slots[i]) {
			hw_bp_control(slots[i], HW_BREAKPOINT_RESTORE);
		} else {
			hw_write_bp_reg(AARCH64_DBG_REG_WCR, i, 0UL);
			hw_write_bp_reg(AARCH64_DBG_REG_WVR, i, 0UL);
		}
	}

	return 0;
}

static void hw_trigger_handler(struct pt_regs *regs)
{
	int i = 0;
	struct hw_bp_info *wp, **slots;
	hw_bp_callback_data report;

	rcu_read_lock();
	slots = this_cpu_ptr(bp_on_reg);
	for (i = 0; i < core_num_brps; ++i) {
		wp = slots[i];
		if (wp == NULL)
			continue;
		if (wp->info.trigger) {
			wp->attr.times.exec++;
			report.type = HW_BREAKPOINT_X;
			report.addr = wp->info.trigger;
			report.times = wp->attr.times;
			report.type = wp->attr.type;
			/*user handler*/
			wp->attr.handler(&report, regs);

			wp->info.trigger = 0;
		}
	}
	slots = this_cpu_ptr(wp_on_reg);
	for (i = 0; i < core_num_wrps; ++i) {
		wp = slots[i];
		if (wp == NULL)
			continue;
		if (!wp->info.trigger) {
			continue;
		}
		if (wp->info.trigger >= wp->attr.addr &&
		    wp->info.trigger < wp->attr.addr + wp->attr.len) {
			/*The user handler only within the range of addresses that are expected to be detected*/
			if (wp->info.access_type & HW_BREAKPOINT_R) {
				wp->attr.times.read++;
			} else if (wp->info.access_type & HW_BREAKPOINT_W) {
				wp->attr.times.write++;
			}
			/*user handler*/
			report.type = wp->info.access_type;
			report.addr = wp->info.trigger;
			report.times = wp->attr.times;
			wp->attr.handler(&report, regs);
		}
		wp->info.trigger = 0;
	}
	rcu_read_unlock();
}

/*ss exception handler, will run user handler*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
static int hw_step_brk_fn(struct pt_regs *regs, unsigned long esr)
#else
static int hw_step_brk_fn(struct pt_regs *regs, unsigned int esr)
#endif
{
	int *kernel_step;

	/*step states*/
	kernel_step = this_cpu_ptr(&stepping_kernel_bp);

	if (user_mode(regs) || !(*kernel_step))
		return DBG_HOOK_ERROR;

	hw_trigger_handler(regs);

	if (hw_bp_reinstall(regs)) {
		return DBG_HOOK_ERROR;
	}
#ifdef CONFIG_KGDB
	kgdb_handle_exception(0, SIGTRAP, 0, regs);
#endif

	return DBG_HOOK_HANDLED;
}
NOKPROBE_SYMBOL(hw_step_brk_fn);

#ifdef CONFIG_CPU_PM
extern void cpu_suspend_set_dbg_restorer(int (*hw_bp_restore)(unsigned int));
#else
static inline void
cpu_suspend_set_dbg_restorer(int (*hw_bp_restore)(unsigned int))
{
}
#endif

static struct step_hook ghw_step_hook = { .fn = hw_step_brk_fn };

/*search symbol addr*/
unsigned long kaddr_lookup_name(const char *fname_raw)
{
	int i;
	unsigned long kaddr;
	char *fname_lookup, *fname;

	fname_lookup = kzalloc(NAME_MAX, GFP_KERNEL);
	if (!fname_lookup)
		return 0;

	fname = kzalloc(strlen(fname_raw) + 4, GFP_KERNEL);
	if (!fname)
		return 0;

	/*
   * We have to add "+0x0" to the end of our function name
   * because that's the format that sprint_symbol() returns
   * to us. If we don't do this, then our search can stop
   * prematurely and give us the wrong function address!
   */
	strcpy(fname, fname_raw);
	strcat(fname, "+0x0");

	/*获取内核代码段基地址*/
	kaddr = (unsigned long)&sprint_symbol;
	kaddr &= 0xffffffffff000000;

	/*内核符号不会超过0x100000*16的大小，所以按4字节偏移，挨个找*/
	for (i = 0x0; i < 0x400000; i++) {
		/*寻找地址对应的符号名称*/
		sprint_symbol(fname_lookup, kaddr);
		/*对比寻找的符号名字*/
		if (strncmp(fname_lookup, fname, strlen(fname)) == 0) {
			/*找到了就返回地址*/
			kfree(fname_lookup);
			kfree(fname);
			return kaddr;
		}
		/*偏移4字节*/
		kaddr += 0x04;
	}
	/*没找到地址就返回0*/
	kfree(fname_lookup);
	kfree(fname);
	return 0;
}

/*get kallsyms_lookup_name*/
static int hw_get_kallsyms_lookup_name(void)
{
	HW_SYMS_FUNC(kallsyms_lookup_name) =
		(void *)kaddr_lookup_name("kallsyms_lookup_name");
	if (!HW_SYMS_FUNC(kallsyms_lookup_name)) {
		printk("get kallsyms_lookup_name fail \n");
		return -1;
	}
	return 0;
}

/*get vars from kernel*/
static int hw_get_kernel_api(void)
{
	memset(&g_kernel_api, 0, sizeof(g_kernel_api));
	if (hw_get_kallsyms_lookup_name()) {
		return -1;
	}
	HW_SYMS_VAL(debug_fault_info) =
		(void *)HW_SYMS_FUNC(kallsyms_lookup_name)("debug_fault_info");
	if (!HW_SYMS_VAL(debug_fault_info)) {
		pr_warn("get debug_fault_info fail\n");
		return -1;
	}
	// pr_warn("debug_fault_info = %llx,name = %s\n", &HW_SYMS_VAL(debug_fault_info)[0],
	//        HW_SYMS_VAL(debug_fault_info)[0].name);
	// pr_warn("debug_fault_info = %llx,name = %s\n", &HW_SYMS_VAL(debug_fault_info)[2],
	//        HW_SYMS_VAL(debug_fault_info)[2].name);
#ifdef CONFIG_CPU_PM
	HW_SYMS_VAL(hw_breakpoint_restore) = (void *)HW_SYMS_FUNC(
		kallsyms_lookup_name)("hw_breakpoint_restore");
	if (!HW_SYMS_VAL(hw_breakpoint_restore)) {
		pr_warn("get hw_breakpoint_restore fail\n");
		return -1;
	}
	// pr_warn("hw_breakpoint_restore = %llx,%llx\n", HW_SYMS_VAL(hw_breakpoint_restore),
	//        *HW_SYMS_VAL(hw_breakpoint_restore));
#endif
	HW_SYMS_FUNC(kernel_active_single_step) = (void *)HW_SYMS_FUNC(
		kallsyms_lookup_name)("kernel_active_single_step");
	if (!HW_SYMS_FUNC(kernel_active_single_step)) {
		pr_warn("get kernel_active_single_step fail\n");
		return -1;
	}
	HW_SYMS_FUNC(kernel_disable_single_step) = (void *)HW_SYMS_FUNC(
		kallsyms_lookup_name)("kernel_disable_single_step");
	if (!HW_SYMS_FUNC(kernel_disable_single_step)) {
		pr_warn("get kernel_disable_single_step fail\n");
		return -1;
	}
	HW_SYMS_FUNC(kernel_enable_single_step) = (void *)HW_SYMS_FUNC(
		kallsyms_lookup_name)("kernel_enable_single_step");
	if (!HW_SYMS_FUNC(kernel_enable_single_step)) {
		pr_warn("get kernel_enable_single_step fail\n");
		return -1;
	}
	HW_SYMS_FUNC(disable_debug_monitors) = (void *)HW_SYMS_FUNC(
		kallsyms_lookup_name)("disable_debug_monitors");
	if (!HW_SYMS_FUNC(disable_debug_monitors)) {
		pr_warn("get disable_debug_monitors fail\n");
		return -1;
	}
	HW_SYMS_FUNC(do_bad) =
		(void *)HW_SYMS_FUNC(kallsyms_lookup_name)("do_bad");
	if (!HW_SYMS_FUNC(do_bad)) {
		pr_warn("get do_bad fail\n");
		return -1;
	}
	HW_SYMS_FUNC(enable_debug_monitors) = (void *)HW_SYMS_FUNC(
		kallsyms_lookup_name)("enable_debug_monitors");
	if (!HW_SYMS_FUNC(enable_debug_monitors)) {
		pr_warn("get enable_debug_monitors fail\n");
		return -1;
	}
	HW_SYMS_FUNC(read_sanitised_ftr_reg) = (void *)HW_SYMS_FUNC(
		kallsyms_lookup_name)("read_sanitised_ftr_reg");
	if (!HW_SYMS_FUNC(read_sanitised_ftr_reg)) {
		pr_warn("get read_sanitised_ftr_reg fail\n");
		return -1;
	}
	HW_SYMS_FUNC(show_regs) =
		(void *)HW_SYMS_FUNC(kallsyms_lookup_name)("show_regs");
	if (!HW_SYMS_FUNC(show_regs)) {
		pr_warn("get show_regs fail\n");
		return -1;
	}
	HW_SYMS_FUNC(dump_backtrace) =
		(void *)HW_SYMS_FUNC(kallsyms_lookup_name)("dump_backtrace");
	if (!HW_SYMS_FUNC(dump_backtrace)) {
		pr_warn("get dump_backtrace fail\n");
		return -1;
	}
	/*5.0以下内核用的是register_step_hook*/
	HW_SYMS_FUNC(register_step_hook) = (void *)HW_SYMS_FUNC(
		kallsyms_lookup_name)("register_step_hook");
	if (!HW_SYMS_FUNC(register_step_hook)) {
		/*5.0以上内核用的是register_kernel_step_hook*/
		HW_SYMS_FUNC(register_step_hook) = (void *)HW_SYMS_FUNC(
			kallsyms_lookup_name)("register_kernel_step_hook");
		if (!HW_SYMS_FUNC(register_step_hook)) {
			pr_warn("get register_step_hook fail\n");
			return -1;
		}
	}
	HW_SYMS_FUNC(unregister_step_hook) = (void *)HW_SYMS_FUNC(
		kallsyms_lookup_name)("unregister_step_hook");
	if (!HW_SYMS_FUNC(unregister_step_hook)) {
		HW_SYMS_FUNC(unregister_step_hook) = (void *)HW_SYMS_FUNC(
			kallsyms_lookup_name)("unregister_kernel_step_hook");
		if (!HW_SYMS_FUNC(unregister_step_hook)) {
			pr_warn("get unregister_step_hook fail\n");
			return -1;
		}
	}

	/*以下不影响驱动使用，只影响根据io地址查询虚拟地址功能*/
	HW_SYMS_VAL(vmap_area_lock) =
		(void *)HW_SYMS_FUNC(kallsyms_lookup_name)("vmap_area_lock");
	HW_SYMS_VAL(vmap_area_lock) =
		(void *)HW_SYMS_FUNC(kallsyms_lookup_name)("vmap_area_list");
	if ((!HW_SYMS_VAL(vmap_area_lock)) || (!HW_SYMS_VAL(vmap_area_lock))) {
		pr_warn("can not get virt from iophys\n");
	}

	return 0;
}

/*hp init*/
static int __init hw_bp_init(void)
{
	if (hw_get_kernel_api()) {
		return -1;
	}

	core_num_brps = hw_get_num_brps();
	core_num_wrps = hw_get_num_wrps();

	pr_info("found %d breakpoint and %d watchpoint registers.\n",
		core_num_brps, core_num_wrps);

	/* register dbg exception hook */
	/*bp*/
	/*save pre vars*/
	HW_SYMS_VAL(default_fault_info)
	[0].fn = HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWBP].fn;
	HW_SYMS_VAL(default_fault_info)
	[0].sig = HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWBP].sig;
	HW_SYMS_VAL(default_fault_info)
	[0].code = HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWBP].code;
	HW_SYMS_VAL(default_fault_info)
	[0].name = HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWBP].name;

	/*new*/
	HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWBP].fn = hw_bp_handler;
	HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWBP].sig = SIGTRAP;
	HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWBP].code = TRAP_HWBKPT;
	HW_SYMS_VAL(debug_fault_info)
	[DBG_ESR_EVT_HWBP].name = "hw-breakpoint handler";
	/*wp*/
	/*save pre vars*/
	HW_SYMS_VAL(default_fault_info)
	[1].fn = HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWWP].fn;
	HW_SYMS_VAL(default_fault_info)
	[1].sig = HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWWP].sig;
	HW_SYMS_VAL(default_fault_info)
	[1].code = HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWWP].code;
	HW_SYMS_VAL(default_fault_info)
	[1].name = HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWWP].name;
	/*new*/
	HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWWP].fn = hw_wp_handler;
	HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWWP].sig = SIGTRAP;
	HW_SYMS_VAL(debug_fault_info)[DBG_ESR_EVT_HWWP].code = TRAP_HWBKPT;
	HW_SYMS_VAL(debug_fault_info)
	[DBG_ESR_EVT_HWWP].name = "hw-watchpoint handler";
	HW_SYMS_FUNC(register_step_hook)(&ghw_step_hook);
#ifdef CONFIG_CPU_PM
	HW_SYMS_VAL(default_hw_breakpoint_restore) =
		*HW_SYMS_VAL(hw_breakpoint_restore);
	*HW_SYMS_VAL(hw_breakpoint_restore) = (u64)hw_bp_reset;
#endif
	hw_bp_manage_init();
	hw_proc_init();

	pr_info("zwf 11111111111111111111111111111 %s ok\n", __FUNCTION__);
	return 0;
}

static void __exit hw_bp_exit(void)
{
	hw_proc_exit();
	hw_bp_manage_deinit();
#ifdef CONFIG_CPU_PM
	*HW_SYMS_VAL(hw_breakpoint_restore) =
		HW_SYMS_VAL(default_hw_breakpoint_restore);
#endif
	HW_SYMS_FUNC(unregister_step_hook)(&ghw_step_hook);
	/*wp*/
	HW_SYMS_VAL(debug_fault_info)
	[DBG_ESR_EVT_HWWP].fn = HW_SYMS_VAL(default_fault_info)[1].fn;
	HW_SYMS_VAL(debug_fault_info)
	[DBG_ESR_EVT_HWWP].sig = HW_SYMS_VAL(default_fault_info)[1].sig;
	HW_SYMS_VAL(debug_fault_info)
	[DBG_ESR_EVT_HWWP].code = HW_SYMS_VAL(default_fault_info)[1].code;
	HW_SYMS_VAL(debug_fault_info)
	[DBG_ESR_EVT_HWWP].name = HW_SYMS_VAL(default_fault_info)[1].name;
	/*bp*/
	HW_SYMS_VAL(debug_fault_info)
	[DBG_ESR_EVT_HWBP].fn = HW_SYMS_VAL(default_fault_info)[0].fn;
	HW_SYMS_VAL(debug_fault_info)
	[DBG_ESR_EVT_HWBP].sig = HW_SYMS_VAL(default_fault_info)[0].sig;
	HW_SYMS_VAL(debug_fault_info)
	[DBG_ESR_EVT_HWBP].code = HW_SYMS_VAL(default_fault_info)[0].code;
	HW_SYMS_VAL(debug_fault_info)
	[DBG_ESR_EVT_HWBP].name = HW_SYMS_VAL(default_fault_info)[0].name;
	printk(" hw_bp_exit\n");
}

module_init(hw_bp_init);
module_exit(hw_bp_exit);

MODULE_AUTHOR("Vimoon Zheng <Vimoon.Zheng@cixtech.com>");
MODULE_DESCRIPTION("hardware breakpoint for SKY1 and later");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform: sky1-bp");
