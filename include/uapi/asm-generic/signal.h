/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__ASM_GENERIC_SIGNAL_H
#define _UAPI__ASM_GENERIC_SIGNAL_H

#include <linux/types.h>

#define _NSIG		64
#define _NSIG_BPW	__BITS_PER_LONG
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

#define SIGHUP		 1
#define SIGINT		 2
#define SIGQUIT		 3
#define SIGILL		 4
#define SIGTRAP		 5
#define SIGABRT		 6
#define SIGIOT		 6
#define SIGBUS		 7
#define SIGFPE		 8
#define SIGKILL		 9
#define SIGUSR1		10
#define SIGSEGV		11
#define SIGUSR2		12
#define SIGPIPE		13
#define SIGALRM		14
#define SIGTERM		15
#define SIGSTKFLT	16
#define SIGCHLD		17
#define SIGCONT		18
#define SIGSTOP		19
#define SIGTSTP		20
#define SIGTTIN		21
#define SIGTTOU		22
#define SIGURG		23
#define SIGXCPU		24
#define SIGXFSZ		25
#define SIGVTALRM	26
#define SIGPROF		27
#define SIGWINCH	28
#define SIGIO		29
#define SIGPOLL		SIGIO
/*
#define SIGLOST		29
*/
#define SIGPWR		30
#define SIGSYS		31
#define	SIGUNUSED	31

/* These should not be considered constants from userland.  */
#define SIGRTMIN	32
#ifndef SIGRTMAX
#define SIGRTMAX	_NSIG
#endif

#if !defined MINSIGSTKSZ || !defined SIGSTKSZ
#define MINSIGSTKSZ	2048
#define SIGSTKSZ	8192
#endif

#ifndef __ASSEMBLY__
typedef struct {
	unsigned long sig[_NSIG_WORDS];
} sigset_t;

/* not actually used, but required for linux/syscalls.h */
typedef unsigned long old_sigset_t;

#include <asm-generic/signal-defs.h>

#ifdef SA_RESTORER
#define __ARCH_HAS_SA_RESTORER
#endif

#ifndef __KERNEL__
struct sigaction {
#if __riscv_xlen == 64
	union {
		__sighandler_t sa_handler;
		__u64 __sa_handler;
	};
#else
	__sighandler_t sa_handler;
#endif
#if __riscv_xlen == 64
	union {
		unsigned long sa_flags;
		__u64 __sa_flags;
	};
#else
	unsigned long sa_flags;
#endif
#ifdef SA_RESTORER
#if __riscv_xlen == 64
	union {
		__sigrestore_t sa_restorer;
		__u64 __sa_restorer;
	};
#else
	__sigrestore_t sa_restorer;
#endif
#endif
	sigset_t sa_mask;		/* mask last for extensibility */
};
#endif

typedef struct sigaltstack {
#if __riscv_xlen == 64
	union {
		void __user *ss_sp;
		__u64 __ss_sp;
	};
#else
	void __user *ss_sp;
#endif
	int ss_flags;
#if __riscv_xlen == 64
	union {
		__kernel_size_t ss_size;
		__u64 __ss_size;
	};
#else
	__kernel_size_t ss_size;
#endif
} stack_t;

#endif /* __ASSEMBLY__ */

#endif /* _UAPI__ASM_GENERIC_SIGNAL_H */
