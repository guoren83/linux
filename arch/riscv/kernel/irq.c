// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 * Copyright (C) 2018 Christoph Hellwig
 */

#include <linux/entry-common.h>
#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/seq_file.h>
#include <asm/smp.h>

int arch_show_interrupts(struct seq_file *p, int prec)
{
	show_ipi_stats(p, prec);
	return 0;
}

void __init init_IRQ(void)
{
	irqchip_init();
	if (!handle_arch_irq)
		panic("No interrupt controller found.");
}

asmlinkage void noinstr do_riscv_irq(struct pt_regs *regs)
{
	struct pt_regs *old_regs;
	irqentry_state_t state = irqentry_enter(regs);

	irq_enter_rcu();
	old_regs = set_irq_regs(regs);
	handle_arch_irq(regs);
	set_irq_regs(old_regs);
	irq_exit_rcu();

	irqentry_exit(regs, state);
}
