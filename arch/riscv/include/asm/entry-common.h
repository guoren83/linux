/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_RISCV_ENTRY_COMMON_H
#define _ASM_RISCV_ENTRY_COMMON_H

#include <asm/stacktrace.h>

extern void handle_page_fault(struct pt_regs *regs);

#endif /* _ASM_RISCV_ENTRY_COMMON_H */
