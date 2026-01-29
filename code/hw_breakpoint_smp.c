#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/version.h>
#include "ext_hw_breakpoint.h"

typedef int (*hw_remote_func_f)(void *);

/*func extern*/
extern int hw_bp_arch_parse(struct hw_bp_info *bp, const hw_bp_attr *attr,
			    hw_bp_vc *hw);
extern int hw_bp_install(struct hw_bp_info *bp);
extern int hw_bp_uninstall(struct hw_bp_info *bp);
extern int hw_arch_check_bp_in_kspace(hw_bp_vc *hw);

struct hw_remote_func_call {
	struct hw_bp_info *p;
	hw_remote_func_f func;
	void *info;
	int ret;
};

static void hw_remote_func(void *data)
{
	struct hw_remote_func_call *tfc = data;

	/*callback*/
	tfc->ret = tfc->func(tfc->info);
}

static int hw_cpu_func_call(int cpu, hw_remote_func_f func, void *info)
{
	struct hw_remote_func_call data = {
		.p = NULL,
		.func = func,
		.info = info,
		.ret = -ENXIO, /* No such CPU */
	};

	preempt_disable();
	if (cpu != smp_processor_id()) {
		smp_call_function_single(cpu, hw_remote_func, &data, 1);
		goto out;
	}

	data.ret = func(info);

out:
	preempt_enable();
	return data.ret;
}

static int hw_bp_parse(struct hw_bp_info *bp, const hw_bp_attr *attr,
		       hw_bp_vc *hw)
{
	int err;

	err = hw_bp_arch_parse(bp, attr, hw);
	if (err)
		return err;

	if (hw_arch_check_bp_in_kspace(hw)) {
		/*Don't let unprivileged users set a breakpoint in the trappath to avoid trap recursion attacks.*/
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
	}

	return 0;
}

static int hw_bp_info_del(void *p)
{
	struct hw_bp_info *bp = (struct hw_bp_info *)p;
	return hw_bp_uninstall(bp);
}

static int hw_bp_info_add(void *p)
{
	struct hw_bp_info *bp = (struct hw_bp_info *)p;
	return hw_bp_install(bp);
}

static int hw_bp_info_init(struct hw_bp_info *bp)
{
	int err;
	hw_bp_vc hw = {};

	/*parse*/
	err = hw_bp_parse(bp, &bp->attr, &hw);
	if (err)
		return err;

	bp->info = hw;

	return 0;
}

static struct hw_bp_info *hw_bp_info_alloc(const hw_bp_attr *attr, int cpu)
{
	struct hw_bp_info *bp = NULL;
	int err;

	bp = kzalloc(sizeof(*bp), GFP_KERNEL);
	if (!bp) {
		pr_info("bp alloc fail\n");
		return ERR_PTR(-ENOMEM);
	}

	bp->cpu = cpu;
	bp->attr = *attr;

	/*bp info init*/
	err = hw_bp_info_init(bp);
	if (err) {
		pr_info("hw_bp_info_init fail\n");
		return ERR_PTR(err);
	}
	/*smp_call_function_single in kgdb is error?*/
	err = hw_cpu_func_call(cpu, hw_bp_info_add, bp);
	if (err) {
		pr_info("hw_bp_info_add fail\n");
		return ERR_PTR(err);
	}

	return bp;
}

static void hw_bp_info_free(struct hw_bp_info *bp, int cpu)
{
	hw_cpu_func_call(cpu, hw_bp_info_del, bp);
	kfree(bp);
}

void hw_bp_unregister(struct hw_bp_info *__percpu *bp, int state)
{
	int cpu;

	if (bp == NULL) {
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	cpus_read_lock();
#else
	get_online_cpus();
#endif
	for_each_possible_cpu(cpu) {
		if (state & 1 << cpu) {
			hw_bp_info_free(per_cpu(*bp, cpu), cpu);
		}
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	cpus_read_unlock();
#else
	put_online_cpus();
#endif
}

int hw_bp_register(struct hw_bp_info *__percpu *cpu_events, hw_bp_attr *attr,
		   int *state)
{
	struct hw_bp_info *bp;
	int cpu;

	if (cpu_events == NULL || attr == NULL || state == NULL) {
		pr_info("hw_bp_register para is NULL\n");
		return -1;
	}

	*state = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	cpus_read_lock();
#else
	get_online_cpus();
#endif
	for_each_online_cpu(cpu) {
		bp = hw_bp_info_alloc(attr, cpu);
		if (IS_ERR(bp)) {
			pr_info("hw_bp_info_alloc error at CPU[%d]\n", cpu);
		}
		/*cpu success mask*/
		*state |= 1 << cpu;
		/*percpu bp*/
		per_cpu(*cpu_events, cpu) = bp;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	cpus_read_unlock();
#else
	put_online_cpus();
#endif

	return 0;
}
