/* SPDX-License-Identifier: GPL-2.0 */
// Copied from arch/arm64/include/asm/vmap_stack.h.
#ifndef _ASM_RISCV_VMAP_STACK_H
#define _ASM_RISCV_VMAP_STACK_H

#include <linux/bug.h>
#include <linux/gfp.h>
#include <linux/kconfig.h>
#include <linux/vmalloc.h>
#include <linux/pgtable.h>
#include <asm/thread_info.h>

/*
 * To ensure that VMAP'd stack overflow detection works correctly, all VMAP'd
 * stacks need to have the same alignment.
 */
static inline unsigned long *arch_alloc_vmap_stack(size_t stack_size, int node)
{
	void *p;

	BUILD_BUG_ON(!IS_ENABLED(CONFIG_VMAP_STACK));

	p = __vmalloc_node(stack_size, THREAD_ALIGN, THREADINFO_GFP, node,
			__builtin_return_address(0));
	return kasan_reset_tag(p);
}

#endif /* _ASM_RISCV_VMAP_STACK_H */
