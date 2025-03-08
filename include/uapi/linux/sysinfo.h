/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_SYSINFO_H
#define _LINUX_SYSINFO_H

#include <linux/types.h>

#define SI_LOAD_SHIFT	16

#if (__riscv_xlen == 64) && (__BITS_PER_LONG == 32)
struct sysinfo {
	__s64 uptime;		/* Seconds since boot */
	__u64 loads[3];		/* 1, 5, and 15 minute load averages */
	__u64 totalram;		/* Total usable main memory size */
	__u64 freeram;		/* Available memory size */
	__u64 sharedram;	/* Amount of shared memory */
	__u64 bufferram;	/* Memory used by buffers */
	__u64 totalswap;	/* Total swap space size */
	__u64 freeswap;		/* swap space still available */
	__u16 procs;	   	/* Number of current processes */
	__u16 pad;	   	/* Explicit padding for m68k */
	__u64 totalhigh;	/* Total high memory size */
	__u64 freehigh;		/* Available high memory size */
	__u32 mem_unit;		/* Memory unit size in bytes */
	char _f[20-2*sizeof(__u64)-sizeof(__u32)];	/* Padding: libc5 uses this.. */
};
#else
struct sysinfo {
	__kernel_long_t uptime;		/* Seconds since boot */
	__kernel_ulong_t loads[3];	/* 1, 5, and 15 minute load averages */
	__kernel_ulong_t totalram;	/* Total usable main memory size */
	__kernel_ulong_t freeram;	/* Available memory size */
	__kernel_ulong_t sharedram;	/* Amount of shared memory */
	__kernel_ulong_t bufferram;	/* Memory used by buffers */
	__kernel_ulong_t totalswap;	/* Total swap space size */
	__kernel_ulong_t freeswap;	/* swap space still available */
	__u16 procs;		   	/* Number of current processes */
	__u16 pad;		   	/* Explicit padding for m68k */
	__kernel_ulong_t totalhigh;	/* Total high memory size */
	__kernel_ulong_t freehigh;	/* Available high memory size */
	__u32 mem_unit;			/* Memory unit size in bytes */
	char _f[20-2*sizeof(__kernel_ulong_t)-sizeof(__u32)];	/* Padding: libc5 uses this.. */
};
#endif

#endif /* _LINUX_SYSINFO_H */
