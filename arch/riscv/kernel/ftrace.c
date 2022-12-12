// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2013 Linaro Limited
 * Author: AKASHI Takahiro <takahiro.akashi@linaro.org>
 * Copyright (C) 2017 Andes Technology Corporation
 */

#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/memory.h>
#include <asm/cacheflush.h>
#include <asm/patch.h>
#include <asm/set_memory.h>

#ifdef CONFIG_DYNAMIC_FTRACE

#ifdef CONFIG_MODULES
#include <linux/moduleloader.h>

static inline void *alloc_tramp(unsigned long size)
{
	return module_alloc(size);
}

static inline void tramp_free(void *tramp)
{
	module_memfree(tramp);
}
#else

static inline void *alloc_tramp(unsigned long size)
{
	return NULL;
}

static inline void tramp_free(void *tramp) { }
#endif

static unsigned long calc_trampoline_call_offset(bool save_regs)
{
	unsigned long start_offset;
	unsigned long call_offset;

	if (save_regs) {
		start_offset = (unsigned long)ftrace_regs_caller_start;
		call_offset = (unsigned long)ftrace_regs_call;
	} else {
		start_offset = (unsigned long)ftrace_caller_start;
		call_offset = (unsigned long)ftrace_call;
	}

	return call_offset - start_offset;
}

static int __ftrace_modify_call(unsigned long hook_pos, unsigned long target,
				bool enable, bool ra);
#define JR_T0_C	(0x8282)
#define JR_T0_I	(0x00028067)
#define NOP2	(0x0001)

static unsigned long
create_trampoline(struct ftrace_ops *ops, unsigned int *tramp_size)
{
	unsigned long start_offset;
	unsigned long end_offset;
	unsigned long op_offset;
	unsigned long call_offset;
	unsigned long npages;
	unsigned long size;
	unsigned long ip;
	void *trampoline;
	unsigned int call[2];
	unsigned int ops_inst[2];
#ifdef CONFIG_RISCV_ISA_C
	unsigned short nop[1] = {NOP2};
	unsigned short jr_t0[1] = {JR_T0_C};
#else
	unsigned int nop[1] = {NOP4};
	unsigned int jr_t0[1] = {JR_T0_I};
#endif
	int ret;

	if (ops->flags & FTRACE_OPS_FL_SAVE_REGS) {
		start_offset = (unsigned long)ftrace_regs_caller_start;
		end_offset = (unsigned long)ftrace_regs_caller_end;
		op_offset = (unsigned long)ftrace_regs_caller_op_ptr;
		call_offset = (unsigned long)ftrace_regs_call;
	} else {
		start_offset = (unsigned long)ftrace_caller_start;
		end_offset = (unsigned long)ftrace_caller_end;
		op_offset = (unsigned long)ftrace_caller_op_ptr;
		call_offset = (unsigned long)ftrace_call;
	}

	size = end_offset - start_offset;

	*tramp_size = size + sizeof(jr_t0);

	trampoline = alloc_tramp(*tramp_size);
	if (!trampoline)
		return 0;

	// copy start_offset -- end_offset
	ret = copy_from_kernel_nofault(trampoline, (void *)start_offset, size);
	if (WARN_ON(ret < 0))
		goto fail;

	// copy jr t0
	ip = (unsigned long)trampoline + size;
	mutex_lock(&text_mutex);
	memcpy((void *)ip, jr_t0, sizeof(jr_t0));
	mutex_unlock(&text_mutex);

	// replace function_trace_op with ops
	op_offset -= start_offset;
	ip = (unsigned long)trampoline + op_offset + sizeof(unsigned int);
	make_li_a2((unsigned long)ops, ops_inst);

	mutex_lock(&text_mutex);
	memcpy((void *)ip, ops_inst, sizeof(ops_inst));
	mutex_unlock(&text_mutex);

	// replace `ld a2,0(a1)` with nop
	ip += sizeof(ops_inst);

	mutex_lock(&text_mutex);
	memcpy((void *)ip, nop, sizeof(nop));
	mutex_unlock(&text_mutex);

	// replace ops->func
	call_offset -= start_offset;
	ip = (unsigned long)trampoline + call_offset;
	make_call_ra(ip, (unsigned long)(ftrace_ops_get_func(ops)), call);

	mutex_lock(&text_mutex);
	memcpy((void *)ip, call, sizeof(call));
	mutex_unlock(&text_mutex);

	ops->flags |= FTRACE_OPS_FL_ALLOC_TRAMP;

	npages = DIV_ROUND_UP(*tramp_size, PAGE_SIZE);

	set_vm_flush_reset_perms(trampoline);

	if (likely(system_state != SYSTEM_BOOTING))
		set_memory_ro((unsigned long)trampoline, npages);
	set_memory_x((unsigned long)trampoline, npages);

	return (unsigned long)trampoline;

fail:
	tramp_free(trampoline);
	return 0;
}

void arch_ftrace_update_trampoline(struct ftrace_ops *ops)
{
	ftrace_func_t func;
	unsigned long offset;
	unsigned long ip;
	unsigned int size;

	if (!ops->trampoline) {
		ops->trampoline = create_trampoline(ops, &size);
		if (!ops->trampoline)
			return;
		ops->trampoline_size = size;
		return;
	}

	/*
	 * The ftrace_ops caller may set up its own trampoline.
	 * In such a case, this code must not modify it.
	 */
	if (!(ops->flags & FTRACE_OPS_FL_ALLOC_TRAMP))
		return;

	offset = calc_trampoline_call_offset(ops->flags & FTRACE_OPS_FL_SAVE_REGS);
	ip = ops->trampoline + offset;
	func = ftrace_ops_get_func(ops);

	mutex_lock(&text_mutex);

	__ftrace_modify_call(ip, (unsigned long)func, true, true);

	mutex_unlock(&text_mutex);
}

static void *addr_from_call(void *ptr)
{
	unsigned int call[2];
	unsigned long pc = (unsigned long)ptr;
	int low_12;
	int ret;

	ret = copy_from_kernel_nofault(call, ptr, MCOUNT_INSN_SIZE);
	if (WARN_ON_ONCE(ret < 0))
		return NULL;

	if ((call[0] & U_TYPE_BASE_MASK) != AUIPC_RA ||
	    (call[1] & I_TYPE_BASE_MASK)  != JALR_RA)
		return NULL;

	pc += (call[0] & (~U_TYPE_BASE_MASK));

	low_12 = (call[1] & (~I_TYPE_BASE_MASK)) >> I_TYPE_SHIFT;

	low_12 = (low_12 & I_TYPE_SIGN_MASK) ? -(U_TYPE_PAD - low_12) : low_12;

	pc += low_12;
	pc &= ~(1 << 0);
	return (void *)pc;
}

void *arch_ftrace_trampoline_func(struct ftrace_ops *ops, struct dyn_ftrace *rec)
{
	unsigned long offset;

	offset = calc_trampoline_call_offset(ops->flags & FTRACE_OPS_FL_SAVE_REGS);
	return addr_from_call((void *)ops->trampoline + offset);
}

void arch_ftrace_trampoline_free(struct ftrace_ops *ops)
{
	if (!ops || !(ops->flags & FTRACE_OPS_FL_ALLOC_TRAMP))
		return;

	tramp_free((void *)ops->trampoline);
	ops->trampoline = 0;
}

void ftrace_arch_code_modify_prepare(void) __acquires(&text_mutex)
{
	mutex_lock(&text_mutex);
}

void ftrace_arch_code_modify_post_process(void) __releases(&text_mutex)
{
	mutex_unlock(&text_mutex);
}

static int ftrace_check_current_call(unsigned long hook_pos,
				     unsigned int *expected)
{
	unsigned int replaced[2];
	unsigned int nops[2] = {NOP4, NOP4};

	/* we expect nops at the hook position */
	if (!expected)
		expected = nops;

	/*
	 * Read the text we want to modify;
	 * return must be -EFAULT on read error
	 */
	if (copy_from_kernel_nofault(replaced, (void *)hook_pos,
			MCOUNT_INSN_SIZE))
		return -EFAULT;

	/*
	 * Make sure it is what we expect it to be;
	 * return must be -EINVAL on failed comparison
	 */
	if (memcmp(expected, replaced, sizeof(replaced))) {
		pr_err("%p: expected (%08x %08x) but got (%08x %08x)\n",
		       (void *)hook_pos, expected[0], expected[1], replaced[0],
		       replaced[1]);
		return -EINVAL;
	}

	return 0;
}

static int __ftrace_modify_call(unsigned long hook_pos, unsigned long target,
				bool enable, bool ra)
{
	unsigned int call[2];
	unsigned int nops[2] = {NOP4, NOP4};

	if (ra)
		make_call_ra(hook_pos, target, call);
	else
		make_call_t0(hook_pos, target, call);

	/* Replace the auipc-jalr pair at once. Return -EPERM on write error. */
	if (patch_text_nosync
	    ((void *)hook_pos, enable ? call : nops, MCOUNT_INSN_SIZE))
		return -EPERM;

	return 0;
}

int ftrace_make_call(struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned int call[2];

	make_call_t0(rec->ip, addr, call);

	if (patch_text_nosync((void *)rec->ip, call, 8))
		return -EPERM;

	return 0;
}

int ftrace_make_nop(struct module *mod, struct dyn_ftrace *rec,
		    unsigned long addr)
{
	unsigned int nops[2] = {NOP4, NOP4};

	if (patch_text_nosync((void *)rec->ip, nops, MCOUNT_INSN_SIZE))
		return -EPERM;

	return 0;
}

/*
 * This is called early on, and isn't wrapped by
 * ftrace_arch_code_modify_{prepare,post_process}() and therefor doesn't hold
 * text_mutex, which triggers a lockdep failure.  SMP isn't running so we could
 * just directly poke the text, but it's simpler to just take the lock
 * ourselves.
 */
int ftrace_init_nop(struct module *mod, struct dyn_ftrace *rec)
{
	int out;

	ftrace_arch_code_modify_prepare();
	out = ftrace_make_nop(mod, rec, MCOUNT_ADDR);
	ftrace_arch_code_modify_post_process();

	return out;
}

int ftrace_update_ftrace_func(ftrace_func_t func)
{
	int ret = __ftrace_modify_call((unsigned long)&ftrace_call,
				       (unsigned long)func, true, true);
	if (!ret) {
		ret = __ftrace_modify_call((unsigned long)&ftrace_regs_call,
					   (unsigned long)func, true, true);
	}

	return ret;
}
#endif

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
int ftrace_modify_call(struct dyn_ftrace *rec, unsigned long old_addr,
		       unsigned long addr)
{
	unsigned int call[2];
	unsigned long caller = rec->ip;
	int ret;

	make_call_t0(caller, old_addr, call);
	ret = ftrace_check_current_call(caller, call);

	if (ret)
		return ret;

	return __ftrace_modify_call(caller, addr, true, false);
}
#endif

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
/*
 * Most of this function is copied from arm64.
 */
void prepare_ftrace_return(unsigned long *parent, unsigned long self_addr,
			   unsigned long frame_pointer)
{
	unsigned long return_hooker = (unsigned long)&return_to_handler;
	unsigned long old;

	if (unlikely(atomic_read(&current->tracing_graph_pause)))
		return;

	/*
	 * We don't suffer access faults, so no extra fault-recovery assembly
	 * is needed here.
	 */
	old = *parent;

	if (!function_graph_enter(old, self_addr, frame_pointer, parent))
		*parent = return_hooker;
}

#ifdef CONFIG_DYNAMIC_FTRACE
#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
void ftrace_graph_func(unsigned long ip, unsigned long parent_ip,
		       struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = arch_ftrace_get_regs(fregs);
	unsigned long *parent = (unsigned long *)&regs->ra;

	prepare_ftrace_return(parent, ip, frame_pointer(regs));
}
#else /* CONFIG_DYNAMIC_FTRACE_WITH_REGS */
extern void ftrace_graph_call(void);
int ftrace_enable_ftrace_graph_caller(void)
{
	return __ftrace_modify_call((unsigned long)&ftrace_graph_call,
				    (unsigned long)&prepare_ftrace_return, true, true);
}

int ftrace_disable_ftrace_graph_caller(void)
{
	return __ftrace_modify_call((unsigned long)&ftrace_graph_call,
				    (unsigned long)&prepare_ftrace_return, false, true);
}
#endif /* CONFIG_DYNAMIC_FTRACE_WITH_REGS */
#endif /* CONFIG_DYNAMIC_FTRACE */
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */
