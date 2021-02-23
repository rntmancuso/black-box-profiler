#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/irq_work.h>
#include <linux/hardirq.h>
#include <linux/perf_event.h>
#include <linux/perf_event.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <asm/atomic.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/printk.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/smp.h> /* IPI calls */
#include <linux/migrate.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <asm-generic/getorder.h>
#include <asm/tlbflush.h>
#include <asm/page.h>
#include <linux/hash.h>
#include <linux/ioport.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <linux/proc_fs.h>
#include <linux/sched/mm.h>
#include <asm/pgtable.h>

#ifdef __arm__
#include <asm/cacheflush.h> /*for processor L1 cache flushing*/
#include <asm/outercache.h>
#include <asm/hardware/cache-l2x0.h>
#endif

#include <asm/mman.h>
#include <linux/smp.h>   /* for on_each_cpu */
#include <linux/kallsyms.h>
#include <linux/genalloc.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 13, 0)
#  include <linux/sched/types.h>
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 8, 0)
#  include <linux/sched/rt.h>
#endif
#include <linux/sched.h>

#undef pr_info
#define pr_info(fmt, ...) {}

void rec_migrate_pgtables(struct vm_area_struct *vma, new_page_t get_new_page,
			  unsigned long private);

struct mm_struct * __init_mm = NULL;

static inline bool is_in_swapper_pgdir(void *addr)
{
	return ((unsigned long)addr & PAGE_MASK) ==
	        ((unsigned long)__init_mm->pgd & PAGE_MASK);
}

static void migrate_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
			      new_page_t get_new_page, unsigned long private)
{
	pte_t * pte = pte_offset_map(pmd, addr);
	pte_t new_pte_val;

	do {
		struct page * old_pte;
		struct page * new_pte;
		void * new_kva, * old_kva;

		pte_t ptent = *pte;

		pr_info("PTE PTR = 0x%lx, VAL = 0x%lx\n",
			(unsigned long)pte, pte_val(ptent));

		if (pte_none(ptent))
			continue;

		if (!pte_present(ptent))
			continue;

		pr_info("...migrating\n");

		old_pte = pte_page(*pte);
		new_pte = get_new_page(old_pte, private);

		if (new_pte != old_pte) {
			old_kva = page_to_virt(old_pte);
			new_kva = page_to_virt(new_pte);

			memcpy(new_kva, old_kva, PAGE_SIZE);
			new_pte_val = __pte(page_to_phys(new_pte) |
					    (pte_val(*pte) & (~PTE_ADDR_MASK)));

			pr_info("New PMD VAL = 0x%lx\n\n", new_pte_val);

			WRITE_ONCE(*pte, new_pte_val);

			if (pte_valid(new_pte_val)) {
				dsb(ishst);
				isb();
			}
			put_page(old_pte);
		}
		/* MIGRATION --- END */

	} while (pte++, addr += PAGE_SIZE, addr != end);
}

static inline void migrate_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
				     new_page_t get_new_page, unsigned long private)

{
	pmd_t *pmd, new_pmd_val;
	unsigned long next;
	unsigned long start;
	struct page * old_pmd;
	struct page * new_pmd;
	void * new_kva, * old_kva;

	start = addr;
	pmd = pmd_offset(pud, addr);

	if (is_in_swapper_pgdir(pmd))
		return;

	/* MIGRATION */
	pr_info("\n\nPMD PTR = 0x%lx, VAL = 0x%lx\n\n",
		(unsigned long)pmd, pmd_val(*pmd));

	pr_info("...migrating\n");

	old_pmd = pmd_page(*pmd);
	new_pmd = get_new_page(old_pmd, private);

	if (new_pmd != old_pmd) {
		old_kva = page_to_virt(old_pmd);
		new_kva = page_to_virt(new_pmd);

		memcpy(new_kva, old_kva, PAGE_SIZE);
		memcpy(new_pmd, old_pmd, sizeof(struct page));

		new_pmd_val = __pmd(page_to_phys(new_pmd) |
				    (pmd_val(*pmd) & (PMD_TYPE_MASK)));

		pr_info("New PMD VAL = 0x%lx\n\n", new_pmd_val);

		WRITE_ONCE(*pmd, new_pmd_val);

		if (pmd_valid(new_pmd_val)) {
			dsb(ishst);
			isb();
		}
	}
	/* MIGRATION --- END */

	return;

	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none(*pmd))
			continue;
		migrate_pte_range(pmd, addr, next, get_new_page, private);
	} while (pmd++, addr = next, addr != end);


}

static inline void migrate_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end,
				     new_page_t get_new_page, unsigned long private)
{
	pud_t *pud, new_pud_val;
	unsigned long next;
	unsigned long start;
	struct page * old_pud;
	struct page * new_pud;
	void * new_kva, * old_kva;

	start = addr;
	pud = pud_offset(p4d, addr);

	if (is_in_swapper_pgdir(pud))
		return;

	/* MIGRATION */
	pr_info("\n\nPUD PTR = 0x%lx, VAL = 0x%lx\n\n",
		(unsigned long)p4d, p4d_val(*p4d));

	pr_info("...migrating\n");

	old_pud = pud_page(*pud);
	new_pud = get_new_page(old_pud, private);

	if (new_pud != old_pud) {
		old_kva = page_to_virt(old_pud);
		new_kva = page_to_virt(new_pud);

		memcpy(new_kva, old_kva, PAGE_SIZE);
		memcpy(new_pud, old_pud, sizeof(struct page));

		new_pud_val = __pud(page_to_phys(new_pud) |
				    (pud_val(*pud) & (PUD_TYPE_MASK)));

		pr_info("New PUD VAL = 0x%lx\n\n", new_pud_val);

		WRITE_ONCE(*pud, new_pud_val);

		if (pud_valid(new_pud_val)) {
			dsb(ishst);
			isb();
		}
	}
	/* MIGRATION --- END */

	do {
		next = pud_addr_end(addr, end);
		if (pud_none(*pud))
			continue;
		migrate_pmd_range(pud, addr, next, get_new_page, private);
	} while (pud++, addr = next, addr != end);

}

static inline void migrate_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
				     new_page_t get_new_page, unsigned long private)
{
	p4d_t *p4d;
	unsigned long next;
	unsigned long start;

	start = addr;
	p4d = p4d_offset(pgd, addr);

	pr_info("\n\nP4D PTR = 0x%lx, VAL = 0x%lx\n\n",
		(unsigned long)p4d, p4d_val(*p4d));

	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(p4d))
			continue;
		migrate_pud_range(p4d, addr, next, get_new_page, private);
	} while (p4d++, addr = next, addr != end);

}

/*
 * This function frees user-level page tables of a process.
 */
static inline void migrate_pgd_range(struct mm_struct * mm, unsigned long addr, unsigned long end,
		       new_page_t get_new_page, unsigned long private)
{
	pgd_t *pgd;
	unsigned long next;

	addr &= PMD_MASK;
	/*
	 * We add page table cache pages with PAGE_SIZE,
	 * (see pte_free_tlb()), flush the tlb if we need
	 */
	//tlb_change_page_size(tlb, PAGE_SIZE);
	pgd = pgd_offset(mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		migrate_p4d_range(pgd, addr, next, get_new_page, private);
	} while (pgd++, addr = next, addr != end);
}

void rec_migrate_pgtables(struct vm_area_struct * vma, new_page_t get_new_page,
		      unsigned long private)
{
	if(!__init_mm) {
		__init_mm = (struct mm_struct *)kallsyms_lookup_name("init_mm");
	}

	if (!__init_mm) {
		pr_err("Unable to locate swapper pgdir.\n");
		return;
	}

	migrate_pgd_range(vma->vm_mm, vma->vm_start, vma->vm_end, get_new_page, private);

	flush_tlb_mm(vma->vm_mm);
}
