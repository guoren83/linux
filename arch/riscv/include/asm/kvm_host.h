/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *     Anup Patel <anup.patel@wdc.com>
 */

#ifndef __RISCV_KVM_HOST_H__
#define __RISCV_KVM_HOST_H__

#include <linux/types.h>
#include <linux/kvm.h>
#include <linux/kvm_types.h>
#include <linux/spinlock.h>
#include <asm/hwcap.h>
#include <asm/kvm_aia.h>
#include <asm/ptrace.h>
#include <asm/kvm_vcpu_fp.h>
#include <asm/kvm_vcpu_insn.h>
#include <asm/kvm_vcpu_sbi.h>
#include <asm/kvm_vcpu_timer.h>
#include <asm/kvm_vcpu_pmu.h>

#define KVM_MAX_VCPUS			1024

#define KVM_HALT_POLL_NS_DEFAULT	500000

#define KVM_VCPU_MAX_FEATURES		0

#define KVM_IRQCHIP_NUM_PINS		1024

#define KVM_REQ_SLEEP \
	KVM_ARCH_REQ_FLAGS(0, KVM_REQUEST_WAIT | KVM_REQUEST_NO_WAKEUP)
#define KVM_REQ_VCPU_RESET		KVM_ARCH_REQ(1)
#define KVM_REQ_UPDATE_HGATP		KVM_ARCH_REQ(2)
#define KVM_REQ_FENCE_I			\
	KVM_ARCH_REQ_FLAGS(3, KVM_REQUEST_WAIT | KVM_REQUEST_NO_WAKEUP)
#define KVM_REQ_HFENCE_GVMA_VMID_ALL	KVM_REQ_TLB_FLUSH
#define KVM_REQ_HFENCE_VVMA_ALL		\
	KVM_ARCH_REQ_FLAGS(4, KVM_REQUEST_WAIT | KVM_REQUEST_NO_WAKEUP)
#define KVM_REQ_HFENCE			\
	KVM_ARCH_REQ_FLAGS(5, KVM_REQUEST_WAIT | KVM_REQUEST_NO_WAKEUP)
#define KVM_REQ_STEAL_UPDATE		KVM_ARCH_REQ(6)

#define KVM_HEDELEG_DEFAULT		(BIT(EXC_INST_MISALIGNED) | \
					 BIT(EXC_BREAKPOINT)      | \
					 BIT(EXC_SYSCALL)         | \
					 BIT(EXC_INST_PAGE_FAULT) | \
					 BIT(EXC_LOAD_PAGE_FAULT) | \
					 BIT(EXC_STORE_PAGE_FAULT))

#define KVM_HIDELEG_DEFAULT		(BIT(IRQ_VS_SOFT)  | \
					 BIT(IRQ_VS_TIMER) | \
					 BIT(IRQ_VS_EXT))

enum kvm_riscv_hfence_type {
	KVM_RISCV_HFENCE_UNKNOWN = 0,
	KVM_RISCV_HFENCE_GVMA_VMID_GPA,
	KVM_RISCV_HFENCE_VVMA_ASID_GVA,
	KVM_RISCV_HFENCE_VVMA_ASID_ALL,
	KVM_RISCV_HFENCE_VVMA_GVA,
};

struct kvm_riscv_hfence {
	enum kvm_riscv_hfence_type type;
	xlen_t asid;
	xlen_t order;
	gpa_t addr;
	gpa_t size;
};

#define KVM_RISCV_VCPU_MAX_HFENCE	64

struct kvm_vm_stat {
	struct kvm_vm_stat_generic generic;
};

struct kvm_vcpu_stat {
	struct kvm_vcpu_stat_generic generic;
	u64 ecall_exit_stat;
	u64 wfi_exit_stat;
	u64 wrs_exit_stat;
	u64 mmio_exit_user;
	u64 mmio_exit_kernel;
	u64 csr_exit_user;
	u64 csr_exit_kernel;
	u64 signal_exits;
	u64 exits;
	u64 instr_illegal_exits;
	u64 load_misaligned_exits;
	u64 store_misaligned_exits;
	u64 load_access_exits;
	u64 store_access_exits;
};

struct kvm_arch_memory_slot {
};

struct kvm_vmid {
	/*
	 * Writes to vmid_version and vmid happen with vmid_lock held
	 * whereas reads happen without any lock held.
	 */
	xlen_t vmid_version;
	xlen_t vmid;
};

struct kvm_arch {
	/* G-stage vmid */
	struct kvm_vmid vmid;

	/* G-stage page table */
	pgd_t *pgd;
	phys_addr_t pgd_phys;

	/* Guest Timer */
	struct kvm_guest_timer timer;

	/* AIA Guest/VM context */
	struct kvm_aia aia;
};

struct kvm_cpu_trap {
	xlen_t sepc;
	xlen_t scause;
	xlen_t stval;
	xlen_t htval;
	xlen_t htinst;
};

struct kvm_cpu_context {
	xlen_t zero;
	xlen_t ra;
	xlen_t sp;
	xlen_t gp;
	xlen_t tp;
	xlen_t t0;
	xlen_t t1;
	xlen_t t2;
	xlen_t s0;
	xlen_t s1;
	xlen_t a0;
	xlen_t a1;
	xlen_t a2;
	xlen_t a3;
	xlen_t a4;
	xlen_t a5;
	xlen_t a6;
	xlen_t a7;
	xlen_t s2;
	xlen_t s3;
	xlen_t s4;
	xlen_t s5;
	xlen_t s6;
	xlen_t s7;
	xlen_t s8;
	xlen_t s9;
	xlen_t s10;
	xlen_t s11;
	xlen_t t3;
	xlen_t t4;
	xlen_t t5;
	xlen_t t6;
	xlen_t sepc;
	xlen_t sstatus;
	xlen_t hstatus;
	union __riscv_fp_state fp;
	struct __riscv_v_ext_state vector;
};

struct kvm_vcpu_csr {
	xlen_t vsstatus;
	xlen_t vsie;
	xlen_t vstvec;
	xlen_t vsscratch;
	xlen_t vsepc;
	xlen_t vscause;
	xlen_t vstval;
	xlen_t hvip;
	xlen_t vsatp;
	xlen_t scounteren;
	xlen_t senvcfg;
};

struct kvm_vcpu_config {
	u64 henvcfg;
	u64 hstateen0;
	xlen_t hedeleg;
};

struct kvm_vcpu_smstateen_csr {
	xlen_t sstateen0;
};

struct kvm_vcpu_arch {
	/* VCPU ran at least once */
	bool ran_atleast_once;

	/* Last Host CPU on which Guest VCPU exited */
	int last_exit_cpu;

	/* ISA feature bits (similar to MISA) */
	DECLARE_BITMAP(isa, RISCV_ISA_EXT_MAX);

	/* Vendor, Arch, and Implementation details */
	xlen_t mvendorid;
	xlen_t marchid;
	xlen_t mimpid;

	/* SSCRATCH, STVEC, and SCOUNTEREN of Host */
	xlen_t host_sscratch;
	xlen_t host_stvec;
	xlen_t host_scounteren;
	xlen_t host_senvcfg;
	xlen_t host_sstateen0;

	/* CPU context of Host */
	struct kvm_cpu_context host_context;

	/* CPU context of Guest VCPU */
	struct kvm_cpu_context guest_context;

	/* CPU CSR context of Guest VCPU */
	struct kvm_vcpu_csr guest_csr;

	/* CPU Smstateen CSR context of Guest VCPU */
	struct kvm_vcpu_smstateen_csr smstateen_csr;

	/* CPU context upon Guest VCPU reset */
	struct kvm_cpu_context guest_reset_context;
	spinlock_t reset_cntx_lock;

	/* CPU CSR context upon Guest VCPU reset */
	struct kvm_vcpu_csr guest_reset_csr;

	/*
	 * VCPU interrupts
	 *
	 * We have a lockless approach for tracking pending VCPU interrupts
	 * implemented using atomic bitops. The irqs_pending bitmap represent
	 * pending interrupts whereas irqs_pending_mask represent bits changed
	 * in irqs_pending. Our approach is modeled around multiple producer
	 * and single consumer problem where the consumer is the VCPU itself.
	 */
#define KVM_RISCV_VCPU_NR_IRQS	64
	DECLARE_BITMAP(irqs_pending, KVM_RISCV_VCPU_NR_IRQS);
	DECLARE_BITMAP(irqs_pending_mask, KVM_RISCV_VCPU_NR_IRQS);

	/* VCPU Timer */
	struct kvm_vcpu_timer timer;

	/* HFENCE request queue */
	spinlock_t hfence_lock;
	xlen_t hfence_head;
	xlen_t hfence_tail;
	struct kvm_riscv_hfence hfence_queue[KVM_RISCV_VCPU_MAX_HFENCE];

	/* MMIO instruction details */
	struct kvm_mmio_decode mmio_decode;

	/* CSR instruction details */
	struct kvm_csr_decode csr_decode;

	/* SBI context */
	struct kvm_vcpu_sbi_context sbi_context;

	/* AIA VCPU context */
	struct kvm_vcpu_aia aia_context;

	/* Cache pages needed to program page tables with spinlock held */
	struct kvm_mmu_memory_cache mmu_page_cache;

	/* VCPU power state */
	struct kvm_mp_state mp_state;
	spinlock_t mp_state_lock;

	/* Don't run the VCPU (blocked) */
	bool pause;

	/* Performance monitoring context */
	struct kvm_pmu pmu_context;

	/* 'static' configurations which are set only once */
	struct kvm_vcpu_config cfg;

	/* SBI steal-time accounting */
	struct {
		gpa_t shmem;
		u64 last_steal;
	} sta;
};

/*
 * Returns true if a Performance Monitoring Interrupt (PMI), a.k.a. perf event,
 * arrived in guest context.  For riscv, any event that arrives while a vCPU is
 * loaded is considered to be "in guest".
 */
static inline bool kvm_arch_pmi_in_guest(struct kvm_vcpu *vcpu)
{
	return IS_ENABLED(CONFIG_GUEST_PERF_EVENTS) && !!vcpu;
}

static inline void kvm_arch_sync_events(struct kvm *kvm) {}

#define KVM_RISCV_GSTAGE_TLB_MIN_ORDER		12

void kvm_riscv_local_hfence_gvma_vmid_gpa(xlen_t vmid,
					  gpa_t gpa, gpa_t gpsz,
					  xlen_t order);
void kvm_riscv_local_hfence_gvma_vmid_all(xlen_t vmid);
void kvm_riscv_local_hfence_gvma_gpa(gpa_t gpa, gpa_t gpsz,
				     xlen_t order);
void kvm_riscv_local_hfence_gvma_all(void);
void kvm_riscv_local_hfence_vvma_asid_gva(xlen_t vmid,
					  xlen_t asid,
					  xlen_t gva,
					  xlen_t gvsz,
					  xlen_t order);
void kvm_riscv_local_hfence_vvma_asid_all(xlen_t vmid,
					  xlen_t asid);
void kvm_riscv_local_hfence_vvma_gva(xlen_t vmid,
				     xlen_t gva, xlen_t gvsz,
				     xlen_t order);
void kvm_riscv_local_hfence_vvma_all(xlen_t vmid);

void kvm_riscv_local_tlb_sanitize(struct kvm_vcpu *vcpu);

void kvm_riscv_fence_i_process(struct kvm_vcpu *vcpu);
void kvm_riscv_hfence_gvma_vmid_all_process(struct kvm_vcpu *vcpu);
void kvm_riscv_hfence_vvma_all_process(struct kvm_vcpu *vcpu);
void kvm_riscv_hfence_process(struct kvm_vcpu *vcpu);

void kvm_riscv_fence_i(struct kvm *kvm,
		       xlen_t hbase, xlen_t hmask);
void kvm_riscv_hfence_gvma_vmid_gpa(struct kvm *kvm,
				    xlen_t hbase, xlen_t hmask,
				    gpa_t gpa, gpa_t gpsz,
				    xlen_t order);
void kvm_riscv_hfence_gvma_vmid_all(struct kvm *kvm,
				    xlen_t hbase, xlen_t hmask);
void kvm_riscv_hfence_vvma_asid_gva(struct kvm *kvm,
				    xlen_t hbase, xlen_t hmask,
				    xlen_t gva, xlen_t gvsz,
				    xlen_t order, xlen_t asid);
void kvm_riscv_hfence_vvma_asid_all(struct kvm *kvm,
				    xlen_t hbase, xlen_t hmask,
				    xlen_t asid);
void kvm_riscv_hfence_vvma_gva(struct kvm *kvm,
			       xlen_t hbase, xlen_t hmask,
			       xlen_t gva, xlen_t gvsz,
			       xlen_t order);
void kvm_riscv_hfence_vvma_all(struct kvm *kvm,
			       xlen_t hbase, xlen_t hmask);

int kvm_riscv_gstage_ioremap(struct kvm *kvm, gpa_t gpa,
			     phys_addr_t hpa, unsigned long size,
			     bool writable, bool in_atomic);
void kvm_riscv_gstage_iounmap(struct kvm *kvm, gpa_t gpa,
			      unsigned long size);
int kvm_riscv_gstage_map(struct kvm_vcpu *vcpu,
			 struct kvm_memory_slot *memslot,
			 gpa_t gpa, unsigned long hva, bool is_write);
int kvm_riscv_gstage_alloc_pgd(struct kvm *kvm);
void kvm_riscv_gstage_free_pgd(struct kvm *kvm);
void kvm_riscv_gstage_update_hgatp(struct kvm_vcpu *vcpu);
void __init kvm_riscv_gstage_mode_detect(void);
unsigned long __init kvm_riscv_gstage_mode(void);
int kvm_riscv_gstage_gpa_bits(void);

void __init kvm_riscv_gstage_vmid_detect(void);
xlen_t kvm_riscv_gstage_vmid_bits(void);
int kvm_riscv_gstage_vmid_init(struct kvm *kvm);
bool kvm_riscv_gstage_vmid_ver_changed(struct kvm_vmid *vmid);
void kvm_riscv_gstage_vmid_update(struct kvm_vcpu *vcpu);

int kvm_riscv_setup_default_irq_routing(struct kvm *kvm, u32 lines);

void __kvm_riscv_unpriv_trap(void);

unsigned long kvm_riscv_vcpu_unpriv_read(struct kvm_vcpu *vcpu,
					 bool read_insn,
					 unsigned long guest_addr,
					 struct kvm_cpu_trap *trap);
void kvm_riscv_vcpu_trap_redirect(struct kvm_vcpu *vcpu,
				  struct kvm_cpu_trap *trap);
int kvm_riscv_vcpu_exit(struct kvm_vcpu *vcpu, struct kvm_run *run,
			struct kvm_cpu_trap *trap);

void __kvm_riscv_switch_to(struct kvm_vcpu_arch *vcpu_arch);

void kvm_riscv_vcpu_setup_isa(struct kvm_vcpu *vcpu);
unsigned long kvm_riscv_vcpu_num_regs(struct kvm_vcpu *vcpu);
int kvm_riscv_vcpu_copy_reg_indices(struct kvm_vcpu *vcpu,
				    u64 __user *uindices);
int kvm_riscv_vcpu_get_reg(struct kvm_vcpu *vcpu,
			   const struct kvm_one_reg *reg);
int kvm_riscv_vcpu_set_reg(struct kvm_vcpu *vcpu,
			   const struct kvm_one_reg *reg);

int kvm_riscv_vcpu_set_interrupt(struct kvm_vcpu *vcpu, unsigned int irq);
int kvm_riscv_vcpu_unset_interrupt(struct kvm_vcpu *vcpu, unsigned int irq);
void kvm_riscv_vcpu_flush_interrupts(struct kvm_vcpu *vcpu);
void kvm_riscv_vcpu_sync_interrupts(struct kvm_vcpu *vcpu);
bool kvm_riscv_vcpu_has_interrupts(struct kvm_vcpu *vcpu, u64 mask);
void __kvm_riscv_vcpu_power_off(struct kvm_vcpu *vcpu);
void kvm_riscv_vcpu_power_off(struct kvm_vcpu *vcpu);
void __kvm_riscv_vcpu_power_on(struct kvm_vcpu *vcpu);
void kvm_riscv_vcpu_power_on(struct kvm_vcpu *vcpu);
bool kvm_riscv_vcpu_stopped(struct kvm_vcpu *vcpu);

void kvm_riscv_vcpu_sbi_sta_reset(struct kvm_vcpu *vcpu);
void kvm_riscv_vcpu_record_steal_time(struct kvm_vcpu *vcpu);

#endif /* __RISCV_KVM_HOST_H__ */
