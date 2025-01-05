/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2015 Regents of the University of California
 */

#ifndef _UAPI_ASM_RISCV_BITSPERLONG_H
#define _UAPI_ASM_RISCV_BITSPERLONG_H

#define __BITS_PER_LONG (__SIZEOF_POINTER__ * 8)

#if __BITS_PER_LONG == 64
#define BITS_PER_LONG 64
#else
#define BITS_PER_LONG 32
#endif

#include <asm-generic/bitsperlong.h>

#endif /* _UAPI_ASM_RISCV_BITSPERLONG_H */
