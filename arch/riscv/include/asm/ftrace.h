/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2017 Andes Technology Corporation */

#ifndef _ASM_RISCV_FTRACE_H
#define _ASM_RISCV_FTRACE_H

/*
 * The graph frame test is not possible if CONFIG_FRAME_POINTER is not enabled.
 * Check arch/riscv/kernel/mcount.S for detail.
 */
#if defined(CONFIG_FUNCTION_GRAPH_TRACER) && defined(CONFIG_FRAME_POINTER)
#define HAVE_FUNCTION_GRAPH_FP_TEST
#endif
#define HAVE_FUNCTION_GRAPH_RET_ADDR_PTR

/*
 * Clang prior to 13 had "mcount" instead of "_mcount":
 * https://reviews.llvm.org/D98881
 */
#if defined(CONFIG_CC_IS_GCC) || CONFIG_CLANG_VERSION >= 130000
#define MCOUNT_NAME _mcount
#else
#define MCOUNT_NAME mcount
#endif

#define ARCH_SUPPORTS_FTRACE_OPS 1
#ifndef __ASSEMBLY__
void MCOUNT_NAME(void);
static inline unsigned long ftrace_call_adjust(unsigned long addr)
{
	return addr;
}

struct dyn_arch_ftrace {
};
#endif

#ifdef CONFIG_DYNAMIC_FTRACE
/*
 * A general call in RISC-V is a pair of insts:
 * 1) auipc: setting high-20 pc-related bits to ra register
 * 2) jalr: setting low-12 offset to ra, jump to ra, and set ra to
 *          return address (original pc + 4)
 *
 *<ftrace enable>:
 * 0: auipc  t0/ra, 0x?
 * 4: jalr   t0/ra, ?(t0/ra)
 *
 *<ftrace disable>:
 * 0: nop
 * 4: nop
 *
 * Dynamic ftrace generates probes to call sites, so we must deal with
 * both auipc and jalr at the same time.
 */

#define MCOUNT_ADDR		((unsigned long)MCOUNT_NAME)
#define I_TYPE_SIGN_MASK	(0x00000800)
#define I_TYPE_OFFSET_MASK	(0x00000fff)
#define I_TYPE_BASE_MASK	(0x000fffff)
#define U_TYPE_OFFSET_MASK	(0xfffff000)
#define U_TYPE_BASE_MASK	(0x00000fff)
#define U_TYPE_PAD		(0x00001000)
#define I_TYPE_SHIFT		20
#define JALR_RA			(0x000080e7)
#define AUIPC_RA		(0x00000097)
#define JALR_T0			(0x000282e7)
#define AUIPC_T0		(0x00000297)
#define NOP4			(0x00000013)
#define LUI_A2			(0x00000637)
#define ADDI_A2			(0x00060613)

#define to_addi_a2(addr)						\
	(((addr & I_TYPE_OFFSET_MASK) << I_TYPE_SHIFT) | ADDI_A2)

#define to_lui_a2(addr)							\
	((addr & I_TYPE_SIGN_MASK) ?					\
	(((addr & U_TYPE_OFFSET_MASK) + U_TYPE_PAD) | LUI_A2) :		\
	((addr & U_TYPE_OFFSET_MASK) | LUI_A2))

#define make_li_a2(addr, call)						\
do {									\
	call[0] = to_lui_a2(addr);					\
	call[1] = to_addi_a2(addr);					\
} while (0)

#define to_jalr_t0(offset)						\
	(((offset & I_TYPE_OFFSET_MASK) << I_TYPE_SHIFT) | JALR_T0)

#define to_auipc_t0(offset)						\
	((offset & I_TYPE_SIGN_MASK) ?					\
	(((offset & U_TYPE_OFFSET_MASK) + U_TYPE_PAD) | AUIPC_T0) :	\
	((offset & U_TYPE_OFFSET_MASK) | AUIPC_T0))

#define make_call_t0(caller, callee, call)				\
do {									\
	unsigned int offset =						\
		(unsigned long) callee - (unsigned long) caller;	\
	call[0] = to_auipc_t0(offset);					\
	call[1] = to_jalr_t0(offset);					\
} while (0)

#define to_jalr_ra(offset)						\
	(((offset & I_TYPE_OFFSET_MASK) << I_TYPE_SHIFT) | JALR_RA)

#define to_auipc_ra(offset)						\
	((offset & I_TYPE_SIGN_MASK) ?					\
	(((offset & U_TYPE_OFFSET_MASK) + U_TYPE_PAD) | AUIPC_RA) :	\
	((offset & U_TYPE_OFFSET_MASK) | AUIPC_RA))

#define make_call_ra(caller, callee, call)				\
do {									\
	unsigned int offset =						\
		(unsigned long) callee - (unsigned long) caller;	\
	call[0] = to_auipc_ra(offset);					\
	call[1] = to_jalr_ra(offset);					\
} while (0)

/*
 * Let auipc+jalr be the basic *mcount unit*, so we make it 8 bytes here.
 */
#define MCOUNT_INSN_SIZE 8

#ifndef __ASSEMBLY__
struct dyn_ftrace;
int ftrace_init_nop(struct module *mod, struct dyn_ftrace *rec);
#define ftrace_init_nop ftrace_init_nop

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
struct ftrace_ops;
struct ftrace_regs;
void ftrace_graph_func(unsigned long ip, unsigned long parent_ip,
		       struct ftrace_ops *op, struct ftrace_regs *fregs);
#define ftrace_graph_func ftrace_graph_func

static inline void arch_ftrace_set_direct_caller(struct pt_regs *regs, unsigned long addr)
{
		regs->t1 = addr;
}

#endif /* CONFIG_DYNAMIC_FTRACE_WITH_REGS */

extern void ftrace_caller_start(void);
extern void ftrace_caller_op_ptr(void);
extern void ftrace_caller_end(void);
extern void ftrace_regs_caller_start(void);
extern void ftrace_regs_caller_op_ptr(void);
extern void ftrace_regs_caller_end(void);

#endif /* __ASSEMBLY__ */

#endif /* CONFIG_DYNAMIC_FTRACE */

#endif /* _ASM_RISCV_FTRACE_H */
