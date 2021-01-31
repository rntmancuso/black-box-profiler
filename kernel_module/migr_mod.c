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

struct page * alloc_pool_page(struct page * page, unsigned long private)
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

	__allocd_pages[__allocd_count++] = page_va;
	return virt_to_page(page_va);
	
}

void free_pool_page(struct page * to_free)
{
	void * page_va;
	
	if (!mem_pool || !to_free)
		return;	
	
	page_va = page_to_virt(to_free);

	gen_pool_free(mem_pool, (unsigned long)page_va, PAGE_SIZE);
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

	pr_info("Process page: VA = 0x%08lx, PA = 0x%08llx (res = %d)\n",
		start_addr, page_to_phys(tgt_page), res);

	return (res == 1);
exit:
	return err;	
}

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
	LIST_HEAD(source);
	
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

	up_read(&mm->mmap_sem);

	if (res < pages) 
		pr_info("WARNING: Unable to get all the requested pages.\n");

	err = 0;
	
	for (i = 0; i < pages; ++i) {
		struct page * cur_page = tgt_page[i];

		/* NOTE: We need to call put page, but this might not be the best
		 * place to do it. */
		put_page(cur_page);
		
		if (!cur_page) {
			pr_err("WARNING: Unable to get user page +0x%x for migration.\n", i);
			continue;
		}
						
		err |= migrate_page_range(page_to_pfn(cur_page),
					  page_to_pfn(cur_page)+1, alloc_pool_page);

		pr_info("Migrating page %x, ret = %d\n", i, err);
		
	}

	kfree(tgt_page);

exit:	
	return err;
}

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
	
	/* Run a quick sanity check on the existance of page structs
	 * for pool area */
	test_page_structs();
	
	/* Now locate a process and attempt a VMA migration */
	target = task_by_name("migrate");
	
	if (!target) {
		pr_err("Unable to locate target task.\n");
	} else {
		pr_info("Target task located!\n");
		test_process_page(target, 0, 0);
		ret = migrate_to_pool(target, 0, 0, 0x41);
		pr_info("Page migration returned: %d\n", ret);
		test_process_page(target, 0, 0);
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
	
	pr_info("Migration test module uninstalled successfully.\n");
	return;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Renato Mancus <rmancuso@bu.edu>");
