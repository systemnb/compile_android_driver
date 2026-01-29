#ifndef __EXT_HW_BREAKPOINT_H
#define __EXT_HW_BREAKPOINT_H

#include <asm/hw_breakpoint.h>
#include <linux/hw_breakpoint.h>
#include <asm/debug-monitors.h>

#define HW_SYMS_FUNC(x) g_kernel_api.fun.x
#define HW_SYMS_VAL(x) g_kernel_api.val.x

typedef struct hw_trigger_times {
	u64 read;
	u64 write;
	u64 exec;
} hw_trigger_times;

typedef struct hw_bp_callback_data {
	u32 type;
	u64 addr;
	hw_trigger_times times;
} hw_bp_callback_data;

typedef void (*hw_bp_callback)(const hw_bp_callback_data *attr,
			       const struct pt_regs *regs);

typedef struct hw_bp_attr {
	u32 type; /*bp type*/
	u64 addr; /*The addr of the bp expected to be monitored*/
	u64 start_addr; /*The starting address of the actual monitoring*/
	u64 end_addr; /*The end address of the actual monitoring*/
	u64 len; /*The length of the bp expected to be monitored*/
	u64 real_len; /*LBN len*/
	u32 mask; /*addr mask*/
	hw_trigger_times times; /*trigger times*/
	hw_bp_callback handler; /*user handler*/
	u64 disabled : 1, //63bit
		reserved : 63; //0~62bit
} hw_bp_attr;

/*struct of get info*/
typedef struct hw_bp_report {
	u32 type; /*bp type*/
	u64 addr; /*The addr of the bp expected to be monitored*/
	u64 len; /*The length of the bp expected to be monitored*/
	u32 mask;
	hw_trigger_times times; /*trigger times*/
} hw_bp_report;
typedef struct hw_bp_info_list {
	struct list_head list; /*list*/
	hw_bp_report *attr; /*bp attr. attr[cpu_id]*/
	int cpu_mask; /*success install of cpu*/
	int cpu_num; /*total cpu num*/
} hw_bp_info_list;

typedef struct hw_bp_ctrl_reg {
	u32 reserved2 : 3, //29~31bit,
		mask : 5, //24~28bit, addr mask，mask=0b11111: (mask2^0b11111 the low bit addr), support 8~2G range
		reserved1 : 3, //21~23bit,
		wt : 1, //20bit, watchpoint type, Unlinked(0)/linked(1) data address match.
		lbn : 4, //16~19bit, WT is only required to be set when setting, which is related to link breakpoints
		ssc : 2, //14,15bit, Security state control, which controls what state will listen for breakpoint events
		hmc : 1, //13bit, Use in conjunction with the above fields
		len : 8, //5~12bit, LBN of len, Each bit represents 1 byte and a maximum of 8 bytes
		type : 2, //3~4bit， bp type wp/bp
		privilege : 2, //1~2bit, The EL level at the time of the last breakpoint setting is used with SSC and HMC
		enabled : 1; //0bit, bp enable
} hw_bp_ctrl_reg;

typedef struct hw_bp_vc {
	u64 address;
	hw_bp_ctrl_reg ctrl;
	u64 trigger;
	u8 access_type;
} hw_bp_vc;

struct hw_bp_info {
	int cpu;
	hw_bp_attr attr;
	hw_bp_vc info;
};

struct fault_info {
	int (*fn)(unsigned long addr, unsigned int esr, struct pt_regs *regs);
	int sig;
	int code;
	const char *name;
};
typedef struct hw_kernel_api {
	struct {
		unsigned long (*kallsyms_lookup_name)(
			const char *name); /*search symbols func*/
		void (*register_step_hook)(struct step_hook *hook);
		void (*unregister_step_hook)(struct step_hook *hook);
		void (*enable_debug_monitors)(enum dbg_active_el el);
		void (*disable_debug_monitors)(enum dbg_active_el el);
		int (*kernel_active_single_step)(void);
		void (*kernel_enable_single_step)(struct pt_regs *regs);
		void (*kernel_disable_single_step)(void);
		u64 (*read_sanitised_ftr_reg)(u32 id);
		void (*show_regs)(struct pt_regs *);
		void (*dump_backtrace)(struct pt_regs *regs,
				       struct task_struct *tsk);
		void (*do_bad)(unsigned long addr, unsigned int esr,
			       struct pt_regs *regs);
	} __aligned(128) fun;
	struct {
#ifdef CONFIG_CPU_PM
		u64 *hw_breakpoint_restore;
		u64 default_hw_breakpoint_restore;
#endif
		struct fault_info *debug_fault_info;
		struct fault_info default_fault_info[2];
		spinlock_t *vmap_area_lock; /*kernel vm spinlock*/
		struct list_head *vmap_area_list; /*kernel vm list*/
	} __aligned(128) val;

} hw_kernel_api;

extern hw_kernel_api g_kernel_api;

/*encode reg*/
static inline u32 hw_encode_ctrl_reg(hw_bp_ctrl_reg ctrl)
{
	u32 val = (ctrl.mask << 24) | (ctrl.len << 5) | (ctrl.type << 3) |
		  (ctrl.privilege << 1) | ctrl.enabled;

	if (is_kernel_in_hyp_mode() && ctrl.privilege == AARCH64_BREAKPOINT_EL1)
		val |= DBG_HMC_HYP;

	return val;
}

/*decode reg*/
static inline void hw_decode_ctrl_reg(u32 reg, hw_bp_ctrl_reg *ctrl)
{
	ctrl->enabled = reg & 0x1;
	reg >>= 1;
	ctrl->privilege = reg & 0x3;
	reg >>= 2;
	ctrl->type = reg & 0x3;
	reg >>= 2;
	ctrl->len = reg & 0xff;
	reg >>= 19;
	ctrl->mask = reg & 0x1f;
}

static inline hw_bp_vc *hw_get_vc(struct hw_bp_info *bp)
{
	return &bp->info;
}

/* Determine number of BRP registers available. */
static inline int hw_get_num_brps(void)
{
    u64 dfr0 = HW_SYMS_FUNC(read_sanitised_ftr_reg)(SYS_ID_AA64DFR0_EL1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    return 1 + cpuid_feature_extract_unsigned_field(dfr0, ID_AA64DFR0_EL1_BRPs_SHIFT);
#else
    return 1 + cpuid_feature_extract_unsigned_field(dfr0, ID_AA64DFR0_BRPS_SHIFT);
#endif
}

/* Determine number of WRP registers available. */
static inline int hw_get_num_wrps(void)
{
    u64 dfr0 = HW_SYMS_FUNC(read_sanitised_ftr_reg)(SYS_ID_AA64DFR0_EL1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    return 1 + cpuid_feature_extract_unsigned_field(dfr0, ID_AA64DFR0_EL1_WRPs_SHIFT);
#else
    return 1 + cpuid_feature_extract_unsigned_field(dfr0, ID_AA64DFR0_WRPS_SHIFT);
#endif
}

int hw_get_bp_num(int type);
void hw_proc_exit(void);
void hw_bp_manage_deinit(void);

/*user handler*/
/*install/uninstall*/
int hw_bp_install_from_addr(u64 addr, int len, int type,
			    hw_bp_callback handler);
void hw_bp_uninstall_from_addr(u64 addr);
int hw_bp_install_from_symbol(char *name, int len, int type,
			      hw_bp_callback handler);
void hw_bp_uninstall_from_symbol(char *name);
/*get install bp info*/
hw_bp_info_list *hw_get_bp_infos(void);
void hw_free_bp_infos(hw_bp_info_list *info);

#endif