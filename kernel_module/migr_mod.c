/**
 * Memory Hotplug Test
 *
 * Copyright (C) 2020  Renato Mancuso (BU)
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See LICENSE.TXT for details.
 *
 */

/**************************************************************************
 * Conditional Compilation Options
 **************************************************************************/
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt


/**************************************************************************
 * Included Files
 **************************************************************************/
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/smp.h> /* IPI calls */
#include <linux/irq_work.h>
#include <linux/hardirq.h>
#include <linux/perf_event.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <asm/atomic.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/printk.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/genalloc.h>
#include <linux/migrate.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 13, 0)
#  include <linux/sched/types.h>
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 8, 0)
#  include <linux/sched/rt.h>
#endif
#include <linux/sched.h>

/**********************************************************************
 * The following needs to be addded was added to the DTS for this     *
 * code to work as expected                                           *
 * NOTE: the root-node of this system uses two cells for both         *
 *       address and size fields. So we stay consistent.              *
 **********************************************************************
/ {

	reserved-memory {
		#address-cells = <2>;
		#size-cells = <2>;
		ranges;

		jailhouse_mem: jailhouse_mem@87d000000 {
			 no-map;
		         reg = <0x8 0x7d000000 0x0 0x03000000>;
		};

		private_hi: privatehi@85dc00000 {
		         reg = <0x8 0x5dc00000 0x0 0x1f400000>;
		};

		private_lo: privatelo@60000000 {
		         reg = <0x0 0x60000000 0x0 0x20000000>;
		};

	};
};
**********************************************************************/

/* TODO: retrieve physical memory aperture from device tree */
#define MEM_START_HI      0x85dc00000UL
#define MEM_SIZE_HI       0x01f400000UL

#define MEM_START_LO      0x060000000UL
/* NOTE: we do not actually have up until +0x20000000 because the last
   0x100000 is not visible/reserved to Linux */
#define MEM_SIZE_LO       0x01ff00000UL

#define NUMA_NODE_THIS    -1

/* Handle for remapped memory */
static void * __pool_kva_hi;
static void * __pool_kva_lo;

/* This is just a hack: keep track of the (single) allocated page so
 * that we can deallocate it upon module cleanup */
static void ** __allocd_pages = NULL;
static unsigned int __allocd_count = 0;
#define MAX_PAGES         1000

struct gen_pool * mem_pool = NULL;

/* The kernel was modified to invoke an implementable function with
 * the following prototype before returning any page to the per-CPU
 * page cache (PCP) in free_unref_page_commit. The page should return
 * 0 if the function was able to correctly return the page to the
 * custom allocator, and 1 if the page does not belong to the pool and
 * the normal deallocation route needs to be followed instead. */
extern int (*free_pvtpool_page) (struct page *page);


struct page * alloc_pool_page(struct page * page, unsigned long track_page)
{
	void * page_va;

	if (!mem_pool)
		return NULL;

	page_va = (void *)gen_pool_alloc(mem_pool, PAGE_SIZE);

	pr_info("POOL: Allocating VA: 0x%08lx\n", (unsigned long)page_va);

	if (!page_va) {
		pr_err("Unable to allocate page from colored pool.\n");
		return NULL;
	}

	dump_page(virt_to_page(page_va), "pool alloc debug");

	/* If this page is allocated by a profiler and needs to be
	 * manually reclaimed at module teardown */
	if (track_page)
		__allocd_pages[__allocd_count++] = page_va;

	return virt_to_page(page_va);

}

static void free_migrated_page(struct page * page, unsigned long private)
{
	pr_info("MIGR: Freeing page 0x%08lx VA: 0x%08lx\n",
		(unsigned long)page, (unsigned long)page_to_virt(page));

	__free_pages(page, 0);
}


void free_pool_page(struct page * to_free)
{
	void * page_va;

	if (!mem_pool || !to_free)
		return;

	page_va = page_to_virt(to_free);

	gen_pool_free(mem_pool, (unsigned long)page_va, PAGE_SIZE);
}

static bool __addr_in_gen_pool(struct gen_pool *pool, unsigned long start,
			size_t size)
{
	bool found = false;
	unsigned long end = start + size - 1;
	struct gen_pool_chunk *chunk;

	rcu_read_lock();
	list_for_each_entry_rcu(chunk, &(pool)->chunks, next_chunk) {
		if (start >= chunk->start_addr && start <= chunk->end_addr) {
			if (end <= chunk->end_addr) {
				found = true;
				break;
			}
		}
	}
	rcu_read_unlock();
	return found;
}

int __my_free_pvtpool_page (struct page * page)
{
	void * page_va;

	if (!mem_pool || !page)
		return 1;

	page_va = page_to_virt(page);

	if(__addr_in_gen_pool(mem_pool, (unsigned long)page_va, PAGE_SIZE)) {
		pr_info("Dynamic de-allocation for phys page 0x%08llx\n",
			page_to_phys(page));


		set_page_count(page, 1);
		dump_page(page, "pool dealloc debug");

		gen_pool_free(mem_pool, (unsigned long)page_va, PAGE_SIZE);
		return 0;
	}

	return 1;

}

static struct task_struct * task_by_name(char * name) {
	struct task_struct * retval = NULL;
	struct task_struct * task;
	char task_name[TASK_COMM_LEN];

	for_each_process(task) {
		get_task_comm(task_name, task);
		if(strncmp(name, task_name, TASK_COMM_LEN) == 0) {
			retval = task;
			return retval;
		}
	}

	return retval;
}

/* Print out physical address of a given process page. */
static int test_process_page(struct task_struct * target, int vm_target, int pg_target)
{
	int err = -1;
	struct vm_area_struct * tgt_vma = NULL, *vma;
	struct mm_struct * mm;
	struct page * tgt_page = NULL;
	unsigned int gup_flags = FOLL_FORCE | FOLL_POPULATE;
	unsigned long start_addr;
	struct address_space * mapping;

	int i, res;

	if (!target)
		goto exit;

	mm = target->mm;

	/* Find the target VMA */
	for (vma = mm->mmap, i = 0; vma; vma = vma->vm_next, ++i) {
		if (i == vm_target) {
			tgt_vma = vma;
			break;
		}
	}

	if (!tgt_vma)
		goto exit;

	start_addr = tgt_vma->vm_start + (pg_target << PAGE_SHIFT);

	/* Resolve page struct -- making sure it is faulted in */
	down_read(&mm->mmap_sem);
	res = get_user_pages_remote(target, mm, start_addr, 1,
				    gup_flags, &tgt_page, NULL, NULL);

	/* NOTE: We need to call put page, but this might not be the best
	 * place to do it. */
	put_page(tgt_page);
	up_read(&mm->mmap_sem);

	if (!tgt_page || res < 1) {
		pr_err("Unable to get user pages to migrate.\n");
		goto exit;
	}

	pr_info("Process page (0x%08lx): VA = 0x%08lx, PA = 0x%08llx (res = %d)\n",
		(unsigned long)tgt_page, start_addr, page_to_phys(tgt_page), res);

	mapping = page_mapping(tgt_page);
	if (mapping) {
		pr_info("Mapping: 0x%08lx, isolate: 0x%08lx\n",
			(long unsigned)mapping,
			(long unsigned)mapping->a_ops->isolate_page);
	} else {
		pr_info("No mapping!\n");
	}

	return (res == 1);
exit:
	return err;
}

static int migrate_page_list(struct page ** pages, int nr_pages,
			     new_page_t get_new_page,
			     enum migrate_mode mode)
{
	int res;
	int nr_failed = 0;
	int nr_succeeded = 0;
	int i;

	int swapwrite = current->flags & PF_SWAPWRITE;

	if (!swapwrite)
		current->flags |= PF_SWAPWRITE;

	for (i = 0; i < nr_pages; ++i) {
		struct page * page = pages[i];
		cond_resched();

		if(PageHuge(page)) {
			res = unmap_and_move_huge_page(get_new_page,
					 NULL, 0, page, 1, mode, 0);
		} else {
			res = unmap_and_move(get_new_page, NULL, 0,
					     page, 1, mode, 0);
		}

		if (res != MIGRATEPAGE_SUCCESS) {
			pr_info("Migration for PA 0x%llx failed: res = %d\n",
				page_to_phys(page), res);
		}

		switch(res) {
		case -ENOMEM:
		case -EAGAIN:
			nr_failed++;
			break;
		case MIGRATEPAGE_SUCCESS:
			nr_succeeded++;
			break;
		default:
			nr_failed++;
			break;
		}

	}

	if (!swapwrite)
		current->flags &= ~PF_SWAPWRITE;

	if (nr_succeeded)
		count_vm_events(PGMIGRATE_SUCCESS, nr_succeeded);
	if (nr_failed)
		count_vm_events(PGMIGRATE_FAIL, nr_failed);

	return nr_failed;

}

/* Attempt to migrate a single page in the target. NEW IMPLEMENTATION!  */
static int migrate_to_pool(struct task_struct * target, int vm_target,
			   int pg_target_start, int pg_target_end)
{
	int err = -1;
	struct vm_area_struct * tgt_vma = NULL, *vma;
	struct mm_struct * mm;
	unsigned long * vaddrs = NULL;
	unsigned long start_addr, end_addr;
	unsigned long pages = pg_target_end - pg_target_start;

	int i;

	pr_info("--- Migration for VMA %d started ---\n", vm_target);

	if (!target)
		goto exit;

	mm = target->mm;

	/* Find the target VMA */
	for (vma = mm->mmap, i = 0; vma; vma = vma->vm_next, ++i) {
		if (i == vm_target) {
			tgt_vma = vma;
			break;
		}
	}

	if (!tgt_vma)
		goto exit;

	start_addr = tgt_vma->vm_start + (pg_target_start << PAGE_SHIFT);
	end_addr = start_addr + (pages << PAGE_SHIFT);

	if (end_addr > tgt_vma->vm_end) {
		pr_err("Tried to migrate too many pages from target VMA.\n");
		goto exit;
	}

	/* Allocate space for our pages array */
	vaddrs = (unsigned long *)kmalloc(sizeof(unsigned long) * pages, GFP_KERNEL);

	for (i = 0; i < pages; ++i)
		vaddrs[i] = start_addr + (i << PAGE_SHIFT);

	err = move_pages_to_pvtpool(mm, pages, vaddrs, alloc_pool_page, 0);
	pr_info("Migrating selected pages, ret = %d\n", err);

	/* All done, folks! */
	kfree(vaddrs);
exit:
	pr_info("------------------------------------");

	return err;
}

#if 0
/* Attempt to migrate a single page in the target */
static int migrate_to_pool(struct task_struct * target, int vm_target,
			   int pg_target_start, int pg_target_end)
{
	int err = -1;
	struct vm_area_struct * tgt_vma = NULL, *vma;
	struct mm_struct * mm;
	struct page ** tgt_page = NULL;
	unsigned int gup_flags = FOLL_FORCE | FOLL_POPULATE;
	unsigned long start_addr, end_addr;
	unsigned long pages = pg_target_end - pg_target_start;

	LIST_HEAD(move_pages);

	int i, res;

	pr_info("--- Migration for VMA %d started ---", vm_target);

	if (!target)
		goto exit;

	mm = target->mm;

	/* Find the target VMA */
	for (vma = mm->mmap, i = 0; vma; vma = vma->vm_next, ++i) {
		if (i == vm_target) {
			tgt_vma = vma;
			break;
		}
	}

	if (!tgt_vma)
		goto exit;

	start_addr = tgt_vma->vm_start + (pg_target_start << PAGE_SHIFT);
	end_addr = start_addr + (pages << PAGE_SHIFT);

	if (end_addr > tgt_vma->vm_end) {
		pr_err("Tried to migrate too many pages from target VMA.\n");
		goto exit;
	}

	/* Allocate space for our pages array */
	tgt_page = (struct page **)kmalloc(sizeof(struct page *) * pages, GFP_KERNEL);

	/* Resolve page struct -- making sure it is faulted in */
	down_read(&mm->mmap_sem);
	res = get_user_pages_remote(target, mm, start_addr, pages,
				    gup_flags, tgt_page, NULL, NULL);

	if (res < pages)
		pr_info("WARNING: Unable to get all the requested pages.\n");

	err = 0;

	for (i = 0; i < pages; ++i) {
		struct page * cur_page = tgt_page[i];

		if (!cur_page) {
			pr_err("WARNING: Unable to get user page +0x%x for migration.\n", i);
			continue;
		}

		/* NOTE: We need to call put page, but this might not be the best
		 * place to do it. */
		put_page(cur_page);

		if (PageAnon(cur_page)) {
			list_add(&cur_page->lru, &move_pages);
		} else {

#if 1
			err = migrate_page_range(page_to_pfn(cur_page),
						 page_to_pfn(cur_page)+1,
						 alloc_pool_page);
#endif

		}

		dump_page(cur_page, "page selection debug");
		pr_info("Page Attributes: Movable = %d, Isolated = %d, LRU = %d\n"
			"\tAnon = %d, SwapBacked = %d, Count = %d\n",
			PageMovable(cur_page), PageIsolated(cur_page),
			PageLRU(cur_page), PageAnon(cur_page),
			PageSwapBacked(cur_page), page_count(cur_page));

		pr_info("Migrating mapped page %x, ret = %d\n", i, err);


	}

	up_read(&mm->mmap_sem);

	if (!list_empty(&move_pages)) {
		err = 0;
		err = migrate_pages(&move_pages, alloc_pool_page, free_migrated_page,
				    0, MIGRATE_SYNC, MR_NUMA_MISPLACED);


		pr_info("Migrating anon pages, ret = %d\n", err);
	}

	kfree(tgt_page);

exit:
	pr_info("------------------------------------");

	return err;
}
#endif

static void test_page_structs(void)
{
	struct page * the_page_struct = virt_to_page(__pool_kva_lo);
	unsigned long phys_start;

	/* Get page struct */
	pr_info("Page struct address of pool kernel VA (LO): 0x%08lx\n",
		(long unsigned)the_page_struct);

	/* Now try to get physical address ;) */
	phys_start = page_to_phys(the_page_struct);
	pr_info("Physical address of pool (LO): 0x%08lx\n", phys_start);


	/* Get page struct */
	the_page_struct = virt_to_page(__pool_kva_hi);
	pr_info("Page struct address of pool kernel VA (HI): 0x%08lx\n",
		(long unsigned)the_page_struct);

	/* Now try to get physical address ;) */
	phys_start = page_to_phys(the_page_struct);
	pr_info("Physical address of pool (HI): 0x%08lx\n", phys_start);


	/* Let's test with a normal kernel address in high zone */
	the_page_struct = phys_to_page(0x830000000UL);
	pr_info("Page struct address of known kernel PA: 0x%08lx\n",
		(long unsigned)the_page_struct);

	/* Now try to get physical address ;) */
	phys_start = page_to_phys(the_page_struct);
	pr_info("Physical address of known address: 0x%08lx\n", phys_start);
}

#define ATTEMPT_MEM_REQUEST 0

int init_module( void )
{
	struct task_struct * target;
	int ret;

#if ATTEMPT_MEM_REQUEST
	struct resource * res;

	/* First off, request a new memory region */
	res = request_mem_region(MEM_START_LO, MEM_SIZE_LO, "Profiler Pool LO");

	if (res == NULL) {
		pr_err("Unable to request memory region @ 0x%08lx. Exiting.\n", MEM_START_LO);
		return -1;
	}

	res = request_mem_region(MEM_START_HI, MEM_SIZE_HI, "Profiler Pool HI");

	if (res == NULL) {
		pr_err("Unable to request memory region @ 0x%08lx. Exiting.\n", MEM_START_HI);
		goto release;
	}

#endif

	/* Now try to remap memory at a known physical address. For both LO and HI range */
	pr_info("Remapping PRIVATE_LO reserved memory area\n");

	/* Setup pagemap structure to guide memremap_pages operation */
	__pool_kva_lo = memremap(MEM_START_LO, MEM_SIZE_LO, MEMREMAP_WB);

	if (__pool_kva_lo == NULL) {
		pr_err("Unable to request memory region @ 0x%08lx. Exiting.\n", MEM_START_LO);
		goto release;
	}

	pr_info("Remapping PRIVATE_LO reserved memory area\n");

	/* Setup pagemap structure to guide memremap_pages operation */
	__pool_kva_hi = memremap(MEM_START_HI, MEM_SIZE_HI, MEMREMAP_WB);

	if (__pool_kva_hi == NULL) {
		pr_err("Unable to request memory region @ 0x%08lx. Exiting.\n", MEM_START_HI);
		goto unmap_lo;
	}

	/* Instantiate an allocation pool using the genpool subsystem */
	mem_pool = gen_pool_create(PAGE_SHIFT, NUMA_NODE_THIS);
	ret = gen_pool_add(mem_pool, (unsigned long)__pool_kva_lo, MEM_SIZE_LO, NUMA_NODE_THIS);
	ret |= gen_pool_add(mem_pool, (unsigned long)__pool_kva_hi, MEM_SIZE_HI, NUMA_NODE_THIS);

	if (ret != 0) {
		pr_err("Unable to initialize genalloc memory pool.\n");
		goto unmap;
	}

	/* Allocate space to keep track of allocated pages so that we
	 * can appropriately cleanup at module teardown. */
	__allocd_pages = (void **)kmalloc(sizeof(void *) * MAX_PAGES, GFP_KERNEL);
	memset(__allocd_pages, 0, sizeof(void *) * MAX_PAGES);

	/* Install handler for pages released by the kernel at task completion */
	free_pvtpool_page = __my_free_pvtpool_page;

	/* Run a quick sanity check on the existance of page structs
	 * for pool area */
	test_page_structs();

	/* Now locate a process and attempt a VMA migration */
	target = task_by_name("migrate");

	if (!target) {
		pr_err("Unable to locate target task.\n");
	} else {
		pr_info("Target task located!\n");
#define TEST_HEAP
#ifdef TEST_TEXT
		test_process_page(target, 0, 0);
		ret = migrate_to_pool(target, 0, 0, 0x41);
		pr_info("Page migration returned: %d\n", ret);
		test_process_page(target, 0, 0);
#endif
#ifdef TEST_HEAP
		test_process_page(target, 2, 0);
		test_process_page(target, 2, 1);
		ret = migrate_to_pool(target, 2, 0, 2);
		pr_info("Page migration returned: %d\n", ret);
		test_process_page(target, 2, 0);
		test_process_page(target, 2, 1);
#endif
		pr_info("Migration of task pages migration completed.\n");
	}

	return 0;

unmap:
	memunmap(__pool_kva_hi);
unmap_lo:
	memunmap(__pool_kva_lo);
release:
#if ATTEMPT_MEM_REQUEST
	release_mem_region(MEM_START_LO, MEM_SIZE_LO);
	release_mem_region(MEM_START_HI, MEM_SIZE_HI);
#endif
	return -1;
}

void cleanup_module( void )
{
	/* Return allocated page to the pool. */
	if (mem_pool && __allocd_pages) {
		int i;
		for (i = 0; i < __allocd_count; ++i) {
			gen_pool_free(mem_pool, (unsigned long)__allocd_pages[i],
				      PAGE_SIZE);
		}

		kfree(__allocd_pages);
	}

	/* destroy genalloc memory pool */
	if (mem_pool)
		gen_pool_destroy(mem_pool);

	/* Unmap & release memory regions */
	if (__pool_kva_lo)
		memunmap(__pool_kva_lo);
	if (__pool_kva_hi)
		memunmap(__pool_kva_hi);

#if ATTEMPT_MEM_REQUEST
	release_mem_region(MEM_START_LO, MEM_SIZE_LO);
	release_mem_region(MEM_START_HI, MEM_SIZE_HI);
#endif

	/* Release handler of page deallocations */
	free_pvtpool_page = NULL;

	pr_info("Migration test module uninstalled successfully.\n");
	return;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Renato Mancus <rmancuso@bu.edu>");
