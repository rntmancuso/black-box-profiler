//kernel module for printing a process vma and pte

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
#include <asm-generic/pgalloc.h>
#include <asm/io.h>
#include <linux/proc_fs.h>
#include <linux/sched/mm.h>


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

/* At insert time, decide if we are gonna use both pools or disable
 * them selectively */
/* int use_lopool = 1; */
/* module_param(use_lopool, int, 0660); */

/* int use_hipool = 1; */
/* module_param(use_hipool, int, 0660); */

/*****************************************************************
 *
 ****************************************************************/
/* Helper macro to prefix any print statement produced by the host *
 * process. */
#ifndef _SILENT_
int verbose = 0;
module_param(verbose, int, 0660);

#define DBG_PRINT(format, ...)                                          \
        do {                                                            \
		if (verbose)						\
                        pr_info("[KPROF] " format, ##__VA_ARGS__);	\
        } while (0)
#else
#define DBG_PRINT(format, ...)                          \
        {}
#endif

#define DBG_INFO(format, ...)						\
        do {                                                            \
		pr_info("[KPROF] " format, ##__VA_ARGS__);		\
        } while (0)

/* TODO: retrieve physical memory aperture from device tree */
/* #define MEM_START_HI      0x85dc00000UL */
/* #define MEM_SIZE_HI       0x01f400000UL */

/* #define MEM_START_LO      0x060000000UL */
/* /\* NOTE: we do not actually have up until +0x20000000 because the last */
/*    0x100000 is not visible/reserved to Linux *\/ */
/* #define MEM_SIZE_LO       0x01ff00000UL */
#define MEM_START_LO0      0x00000000UL

#define MEM_START_LO1      0x20000000UL

#define MEM_START_LO2      0x40000000UL

#define MEM_START_LO3      0x60000000UL

#define MEM_SIZE           0x20000000UL

#define NUMA_NODE_THIS    -1

/* Handle for remapped memory */
static void * __pool_kva_lo_0 = NULL;
static void * __pool_kva_lo_1 = NULL;
static void * __pool_kva_lo_2 = NULL;
static void * __pool_kva_lo_3 = NULL;
unsigned long  __pool_kva_lo[4];
/* This is just a hack: keep track of the (single) allocated page so *
 * that we can deallocate it upon module cleanup */
static unsigned int __in_pool = 0;

struct gen_pool * mem_pool[4] = kmalloc(4*sizeof(struct gen_pool),GFP_KERNEL);
struct gen_pool mem_pool[0] = kmalloc(sizeof(struct gen_pool),GFP_KERNEL); 
struct gen_pool * mem_pool_0 = NULL;
struct gen_pool * mem_pool_1 = NULL;
struct gen_pool * mem_pool_2 = NULL;
struct gen_pool * mem_pool_3 = NULL;
/* The kernel was modified to invoke an implementable function with *
 * the following prototype before returning any page to the per-CPU *
 * page cache (PCP) in free_unref_page_commit. The page should return
 * * 0 if the function was able to correctly return the page to the *
 * custom allocator, and 1 if the page does not belong to the pool and
 * * the normal deallocation route needs to be followed instead. */

extern struct page * (*alloc_pvtpool_page) (struct page *, unsigned long);
extern int (*free_pvtpool_page) (struct page *);



static inline void prefetch_page(void * page_va) {
	int i;
	for (i = 0; i < PAGE_SIZE; i += 64) {
		prefetch(page_va + i);
	}
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

struct page * alloc_pool_page(struct page * page, unsigned long private)
{
 	void * page_va;
	struct pvtpool_params * params;

	if (!mem_pool[0])
                return NULL;

	if (private == PVTPOOL_ALLOC_NOREPLACE) {
		void * old_page_va = page_va = page_to_virt(page);
		if(__addr_in_gen_pool(mem_pool[0], (unsigned long)old_page_va, PAGE_SIZE)) {
			return page;
		}
	} else if (private == IS_PVTPOOL_PARAMS) {
		params = (struct pvtpool_params *)page;
		if ((params->vma->vm_flags & VM_ALLOC_PVT_CORE) == 0)
			return NULL;
	}

	page_va = (void *)gen_pool_alloc(mem_pool[0], PAGE_SIZE);

        printk("POOL: Allocating VA: 0x%08lx\n", (unsigned long)page_va);

	if (!page_va) {
                pr_err("Unable to allocate page from colored pool.\n");
		return NULL;
	}

	if (verbose)
		dump_page(virt_to_page(page_va), "pool alloc debug");

	++__in_pool;

	printk("POOL: [ALLOC] Current allocation: %d pages\n", __in_pool);
	printk("in alloc of kmod, current->mm->cpu_id is:%d\n",current->mm->cpu_id);
	prefetch_page(page_va);

	return virt_to_page(page_va);

}

int __my_free_pvtpool_page (struct page * page)
{
 	void * page_va;

        if (!mem_pool[0] || !page)
                return 1;

        page_va = page_to_virt(page);

	if(__addr_in_gen_pool(mem_pool[0], (unsigned long)page_va, PAGE_SIZE)) {
                printk("Dynamic de-allocation for phys page 0x%08llx\n",
			page_to_phys(page));


	        set_page_count(page, 1);
		if (verbose)
			dump_page(page, "pool dealloc debug");

                gen_pool_free(mem_pool[0], (unsigned long)page_va, PAGE_SIZE);

		--__in_pool;

		printk("POOL: [FREE] Current allocation: %d pages\n", __in_pool);

		return 0;
        }

        return 1;

}



static int mm_exp_load(void){

	int ret[4] = {-1,-1,-1,-1};




	/* Now try to remap memory at a known physical address. For both LO and HI range */
        printk("Remapping PRIVATE_LO reserved memory area\n");

        /* Setup pagemap structure to guide memremap_pages operation */
	/* for (  i = 0; i < 4; i++) */
	/* { */
	/* 	__pool_kva_lo[i] = (unsigned long)memremap(MEM_START_LO[i], MEM_SIZE, MEMREMAP_WB); */

	/* 	if (__pool_kva_lo[i] == 0) { */
	/* 		pr_err("Unable to request memory region @ 0x%08lx. Exiting.\n", */
	/* 		       MEM_START_LO[i]); */
	/* 		goto unmap; */
	/* 	} */

	/* 	ret[i] = 0; */
	/* } */
	
	__pool_kva_lo[0] = (unsigned long)memremap(MEM_START_LO0, MEM_SIZE, MEMREMAP_WB);

	if (__pool_kva_lo[0] == 0) {
		pr_err("Unable to request memory region @ 0x%08lx. Exiting.\n",
		       MEM_START_LO0);
		goto unmap;
	}

	ret[0] = 0;

	__pool_kva_lo[1] = (unsigned long)memremap(MEM_START_LO1, MEM_SIZE, MEMREMAP_WB);

	if (__pool_kva_lo[1] == 0) {
		pr_err("Unable to request memory region @ 0x%08lx. Exiting.\n",
		       MEM_START_LO1);
		goto unmap;
	}

	ret[1] = 0;
	printk("test 2\n");
	/* __pool_kva_lo_2 = memremap(MEM_START_LO2, MEM_SIZE, MEMREMAP_WB); */

	/* if (__pool_kva_lo_2 == NULL) { */
	/* 	pr_err("Unable to request memory region @ 0x%08lx. Exiting.\n", */
	/* 	       MEM_START_LO2); */
	/* 	goto unmap; */
	/* } */

	/* ret[2] = 0; */


	/* __pool_kva_lo_3 = memremap(MEM_START_LO3, MEM_SIZE, MEMREMAP_WB); */

	/* if (__pool_kva_lo_3 == NULL) { */
	/* 	pr_err("Unable to request memory region @ 0x%08lx. Exiting.\n", */
	/* 	       MEM_START_LO3); */
	/* 	goto unmap; */
	/* } */

	/* ret[3] = 0; */
	//}

        /* Setup pagemap structure to guide memremap_pages operation */
	/* if (use_hipool) { */
	/* 	__pool_kva_hi = memremap(MEM_START_HI, MEM_SIZE_HI, MEMREMAP_WB); */

	/* 	if (__pool_kva_hi == NULL) { */
	/* 		pr_err("Unable to request memory region @ 0x%08lx. Exiting.\n", */
	/* 		       MEM_START_HI); */
	/* 		goto unmap_lo; */
	/* 	} */

	/* 	ret = 0; */
	/* } */

	/* Instantiate an allocation pool using the genpool subsystem */
	/* for (i = 0; i < 4; i++) */
        /* { */
	/* 	mem_pool[i] = gen_pool_create(PAGE_SHIFT, NUMA_NODE_THIS); */
	/* 	ret[i] |= gen_pool_add(mem_pool[i], (unsigned long)__pool_kva_lo[i], */
	/* 			       MEM_SIZE, NUMA_NODE_THIS); */

	/* 	if (ret[i] != 0) { */
	/* 		pr_err("Unable to initialize genalloc memory pool.\n"); */
	/* 		goto unmap; */
	/* 	} */
	/* } */
	
        mem_pool[0] = gen_pool_create(PAGE_SHIFT, NUMA_NODE_THIS);

	ret[0] |= gen_pool_add(mem_pool[0], (unsigned long)__pool_kva_lo[0],
			       MEM_SIZE, NUMA_NODE_THIS);

        if (ret[0] != 0) {
                pr_err("Unable to initialize genalloc memory pool.\n");
                goto unmap;
        }

	mem_pool_1 = gen_pool_create(PAGE_SHIFT, NUMA_NODE_THIS);

	ret[1] |= gen_pool_add(mem_pool_1, (unsigned long)__pool_kva_lo[1],
			       MEM_SIZE, NUMA_NODE_THIS);

        if (ret[1] != 0) {
                pr_err("Unable to initialize genalloc memory pool.\n");
                goto unmap;
        }

	/* mem_pool_2 = gen_pool_create(PAGE_SHIFT, NUMA_NODE_THIS); */

	/* ret[2] |= gen_pool_add(mem_pool_2, (unsigned long)__pool_kva_lo_2, */
	/* 		    MEM_SIZE, NUMA_NODE_THIS); */

        /* if (ret[2] != 0) { */
        /*         pr_err("Unable to initialize genalloc memory pool.\n"); */
        /*         goto unmap; */
        /* } */

	/* mem_pool_3 = gen_pool_create(PAGE_SHIFT, NUMA_NODE_THIS); */

	/* ret[3] |= gen_pool_add(mem_pool_3, (unsigned long)__pool_kva_lo_3, */
	/* 		    MEM_SIZE, NUMA_NODE_THIS); */

        /* if (ret[3] != 0) { */
        /*         pr_err("Unable to initialize genalloc memory pool.\n"); */
        /*         goto unmap; */
        /* } */

	/* Install handler for pages released by the kernel at task completion */
        free_pvtpool_page = __my_free_pvtpool_page;
	alloc_pvtpool_page = alloc_pool_page;

	/* Run a quick sanity check on the existance of page structs
	 * for pool area */
	//if(verbose)
	//	test_page_structs();

	pr_info("KPROFILER module installed successfully.\n");


	return 0;

unmap:
	printk("for now: here is unmap!\n");
	//if (use_hipool)
	//	memunmap(__pool_kva_hi);
//unmap_lo:
//	if (use_lopool)
//		memunmap(__pool_kva_lo);
//release:
        return -1;
}

static void mm_exp_unload(void)
{
	int i;
	printk("POOL: [UNLOAD] Current allocation: %d pages\n", __in_pool);

	/* destroy genalloc memory pool */
	/* for i = 0; i < 4; i++) */
	/* { */
	/*   if (mem_pool[i]) */
	/*      gen_pool_destroy(mem_pool[i]); */
	/* } */
	if (mem_pool[0])
		gen_pool_destroy(mem_pool_0);
	if (mem_pool_1)
		gen_pool_destroy(mem_pool_1);
	/* if (mem_pool_2) */
	/*         gen_pool_destroy(mem_pool_2); */
	/* if (mem_pool_3) */
	/*         gen_pool_destroy(mem_pool_3); */

	/* Unmap & release memory regions */
	for (i = 0; i < 4; i++)
	{
		memunmap((void *)__pool_kva_lo[i]);
	}
	/* if (__pool_kva_lo[0]) */
	/*   memunmap((void *)__pool_kva_lo[0]); */
	/* if (__pool_kva_lo_1) */
	/*   memunmap((void *)__pool_kva_lo_1); */
	/* if (__pool_kva_lo_2) */
	/*         memunmap(__pool_kva_lo_2); */
	/* if (__pool_kva_lo_3) */
	/*         memunmap(__pool_kva_lo_3); */

	/* Release handler of page deallocations */
	free_pvtpool_page = NULL;
	alloc_pvtpool_page = NULL;



	pr_info("KPROFILER module uninstalled successfully.\n");
}

module_init(mm_exp_load);
module_exit(mm_exp_unload);

MODULE_AUTHOR ("Golsana Ghaemi, Renato Mancuso");
MODULE_DESCRIPTION ("changin cacheability of mmeory regions");
MODULE_LICENSE("GPL");
