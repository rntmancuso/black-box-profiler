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
#include <asm/io.h>
#include <linux/proc_fs.h>

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

/* This is just a hack: keep track of the (single) allocated page so *
 * that we can deallocate it upon module cleanup */
static void ** __allocd_pages = NULL;
static unsigned int __allocd_count = 0;
#define MAX_PAGES         1000

struct gen_pool * mem_pool = NULL;

/* The kernel was modified to invoke an implementable function with *
 * the following prototype before returning any page to the per-CPU *
 * page cache (PCP) in free_unref_page_commit. The page should return
 * * 0 if the function was able to correctly return the page to the *
 * custom allocator, and 1 if the page does not belong to the pool and
 * * the normal deallocation route needs to be followed instead. */

extern int (*free_pvtpool_page) (struct page *page);

#define PROF_PROCFS_NAME                "memprofile"

static struct proc_dir_entry * memprofile_proc;
/* File oeprations for the  procfile */
struct file_operations  memprof_ops;


/* Forward declaration */
struct vma_descr;

/* Structure of parameters that will be passed to the kernel */
struct profile_params
{
        /* PID of the process to operate on */
        pid_t pid;
        /* Number of VMAs in the vmas array */
        unsigned int vma_count;
        /* Array of VMAs on which to perform operations */
        struct vma_descr * vmas;
};

struct vma_descr
{
        /* Index of VMA in post-init application layout */
        unsigned int vma_index;
        /* Number of pages in a specific VMA */
        unsigned int total_pages;
        /* Number of pages to perform operations on */
        unsigned int page_count;
        /* Command/operation to apply to the pages in this VMA */
        unsigned int operation;
        /* Array of page offsets on which an operation is to be performed */
        unsigned int * page_index;
};


struct profile_params cp;


struct Data// this is for making user virtual address from index in "page_index"
{
	struct vm_area_struct  *vmas;
	unsigned long* page_addr;
	int count_vma;
  //#ifdef __aarch64__
         struct mm_struct *mm;
  //#endif

};

extern void __clean_inval_dcache_area(void * kaddr, size_t size);


#ifdef __arm__
/* Adding 8 to this mask, divides cycle counter by 64 */
#define PERF_DEF_OPTS (1 | 16 | 8)

#define HW_PL310_CL_INV_PA      0x07F0 / 4
/* PL310 Base for iMX.6 Dual/Quad (Wandboard, PICO) */
#define HW_PL310_BASE           0x00A02000

volatile unsigned long __iomem * pl310_area;

//testing for invalidating page
inline void invalidate_page_l1(ulong va_addr)
{
	/* Invalidation procedure -- via coprocessor 15 */
	ulong tmp = 0;

	__asm__ __volatile__
		(
			"mov %0, %1\n"
			"1: \n"
			"MCR p15, 0, %0, c7, c5, 1\n" /* invalidate I-cache line */
			"MCR p15, 0, %0, c7, c14, 1\n" /* invalidate+clean D-cache line */
			"add %0, #32\n"
			"cmp %0, %2\n"
			"bne 1b\n"
			: "=&r"(tmp)
			: "r"(va_addr), "r"(va_addr + PAGE_SIZE) /* Inputs */
			: "memory"
			);


}

inline void invalidate_page_l2(ulong pa_addr)
{
	volatile ulong * inval_reg = &pl310_area[HW_PL310_CL_INV_PA];
	ulong tmp = 0;

	/* Invalidation procedure -- atomic operations */
	__asm__ __volatile__
		(
	                "mov %0, %1\n"
			"1: str %0, [%2]\n"
			"add %0, #32\n"
			"cmp %0, %3\n"
			"bne 1b\n"
			: "=&r"(tmp)
			: "r"(pa_addr), "r"(inval_reg), "r"(pa_addr + PAGE_SIZE) /* Inputs */
			: "memory"
			);
}



#define get_timing(cycleLo) {                                           \
		asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r" (cycleLo) ); \
	}

void enable_cpu_counters(void* data)
{
	/* Enable user-mode access to counters. */
	asm volatile("mcr p15, 0, %0, c9, c14, 0" :: "r"(1));
	/* Program PMU and enable all counters */
	asm volatile("mcr p15, 0, %0, c9, c12, 0" :: "r"(PERF_DEF_OPTS));
	asm volatile("mcr p15, 0, %0, c9, c12, 1" :: "r"(0x8000000f));
}

int init_cpu_counter(void)
{
	DBG_PRINT(KERN_INFO "Now enabling performance counters on all cores.\n");
	on_each_cpu(enable_cpu_counters, NULL, 1);
	DBG_PRINT(KERN_INFO "Done.\n");
	return 0;
}
#endif



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

/* Print out physical address of a given process page. */
static int test_process_page(struct task_struct * target, struct Data* data, int n_page)
{
        int err = -1;
        //struct vm_area_struct * tgt_vma = NULL, *vma;
        struct mm_struct * mm = target->mm;
        struct page * tgt_page = NULL;
        unsigned int gup_flags = FOLL_FORCE | FOLL_POPULATE;
        unsigned long start_addr;
        struct address_space * mapping;

	int i, res;

	for (i = 0; i < n_page; i++)
	{
		start_addr = data->page_addr[i];
		/* Resolve page struct -- making sure it is faulted in */
		down_read(&mm->mmap_sem);
		res = get_user_pages_remote(target, mm, start_addr, 1,
					    gup_flags, &tgt_page, NULL, NULL);
		if (res != 1)
			pr_info("no page for address: 0x%08lx is pinned\n",start_addr);
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
			pr_info("No mapping!\n"); //meaning page is anon
		}
	}
	return 1;
exit:
	return err;
}


static int cacheability_modifier (pte_t *ptep, unsigned long addr,void *data)
{
        int i;
	pte_t *pte = ptep;
	size_t pfn;
	pte_t newpte;
	struct page *page = NULL;
	void *page_v;
	int skip = cp.vmas[((struct Data*)data)->count_vma].operation;
        struct vm_area_struct * vma = ((struct Data*)data)->vmas;

        //DBG_PRINT("skip: %d,page_number:%d\n",skip,cp.vmas[((struct Data*)data)->count_vma].page_count);

        /*check whether current addr is in the list of pages which we want to skip the operation for*/
        for (i=0; i< cp.vmas[((struct Data*)data)->count_vma].page_count; i++)
	{
		if (addr == ((struct Data*)data)->page_addr[i])
		{
			skip =!(cp.vmas[((struct Data*)data)->count_vma].operation);
			break;
		}
	}

	if (skip)
	{
		//DBG_PRINT("we skip (keep cacheable)!, skip is:%d\n",skip);
	}
	else
	{
	        // making new pte
		pfn = pte_pfn(*pte); //with the old pte
		page = pte_page(*pte);
		page_v = kmap(page);

		newpte = pfn_pte(pfn, pgprot_writecombine(vma->vm_page_prot));
		//flush_cache_mm (((struct Data*)data)->mm);
		__clean_inval_dcache_area(page_v, PAGE_SIZE);

		kunmap(page_v);

		/*DBG_PRINT("CM: 0x%llx --> 0x%llx (VA: 0x%lx; PFN = 0x%lx)\n",
                          (long long)pte_val(*pte),
                          (long long)pte_val(newpte), addr, pfn);*/

                set_pte_at(((struct Data*)data)->mm, addr, pte, newpte);

                flush_tlb_page(vma, addr);
		//DBG_PRINT("after flushing\n");

#ifdef __arm__
                //((struct Data*)data)->vmas->vm_page_prot = pgprot_noncached(((struct Data*)data)->vmas->vm_page_prot);
                //making page struct
		pfn = pte_pfn(*pte); //with the old pte
		page = pte_page(*pte);
		DBG_PRINT("after page making\n");
		//phys = page_to_phys(page); //return physical addr, this is needed for invalidate_page_l2
		page_v = kmap(page);//kmap always returns a kernel virtual address that addresses the desired page
		//DBG_PRINT("after kmap\n");
		//calculating pfn
		pfn = pte_pfn(*pte); //with the old pte
		//making new pte
		//changing pgprot for changin cacheability here
		//newpte = pfn_pte(pfn, ((struct Data*)data)->vmas->vm_page_prot);
		newpte = pfn_pte(pfn, ((struct Data*)data)->vmas->vm_page_prot);
		//Perform PA-based invaluidation on L1 and L2
		//invalidate_page_l2(phys);
		invalidate_page_l1((ulong)page_v);//argument used to be addr
		invalidate_page_l2(phys);
		kunmap(page);
                flush_cache_mm (((struct Data*)data)->mm);
		//setting new pte
		set_pte_ext(pte, newpte, 0);
		//flushing TLB for one page
		// each time addr is added by 4KB
		DBG_PRINT("cacheability_modifier on cpu: %d\n",smp_processor_id());
		//flush_tlb_page_m(((struct Data*)data)->vmas,addr); //for using this u should activate defining flush_tlb_page_m on top
		//on_each_cpu(middle_func, &ta, 1);
		__flush_tlb_page(((struct Data*)data)->vmas,addr);
#endif
		}

	return 0;
}

long faultin_vma(struct task_struct * task, struct vm_area_struct * vma)
{
        int locked = 1;
        long retval;
        unsigned long start = vma->vm_start;
        unsigned long end = vma->vm_end;
        unsigned long nr_pages = (end - start) >> PAGE_SHIFT;
        unsigned int gup_flags = 0;

        gup_flags = FOLL_TOUCH | FOLL_POPULATE | FOLL_MLOCK;
        if (vma->vm_flags & VM_LOCKONFAULT)
                gup_flags &= ~FOLL_POPULATE;
	/*
	 * We want to touch writable mappings with a write fault in
	 * order to break COW, except for shared mappings because
	 * these don't COW and we would not want to dirty them for
	 * nothing.
	 */
	 if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == VM_WRITE)
                gup_flags |= FOLL_WRITE;

	 /*
	  * We want mlock to succeed for regions that have any
	  * permissions other than PROT_NONE.
	  */
	 if (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC))
		 gup_flags |= FOLL_FORCE;

	 down_read(&task->mm->mmap_sem);
	 retval = get_user_pages_remote(task, task->mm, start, nr_pages,
                                         gup_flags, NULL, NULL, &locked);

	 if (locked)
		 up_read(&task->mm->mmap_sem);

	 return retval;
}

void which_operation(struct task_struct *task,unsigned long operation,
		     struct Data* data,int page_count)
{
	int err;
	struct vm_area_struct  *vma = data->vmas;
	DBG_PRINT("operation : %ld\n", operation);

	/* All non-cacheable except pages in page_index array-for
	   profiling phase is one page at a time*/
	if (operation == 0) {
		DBG_PRINT("inside operation == 0\n");
		apply_to_page_range(vma->vm_mm, vma->vm_start,
				    vma->vm_end - vma->vm_start,
				    cacheability_modifier, data);
	}

	/* All cacheable except pages in page_index array-for
	   profiling phase is one page at a time */
	else if (operation == 1) {
		apply_to_page_range(vma->vm_mm, vma->vm_start,
				    vma->vm_end - vma->vm_start,
				    cacheability_modifier, data);
	}

	/* Pages in the page_index array will be selected for
	 * migration to the private pool */
	else if (operation == 2) {
	      DBG_PRINT("before test_process_page\n");

	      /* data was created for extra info for
	       * apply_to_page_range(), but is usable here too */
	      test_process_page(task,data,page_count);
	      DBG_PRINT("before move_pages_to_pvtpool\n");
	      err = move_pages_to_pvtpool(data->mm,page_count,data->page_addr,alloc_pool_page, 0);
	      DBG_PRINT("Migrating selected pages, ret = %d\n", err);
	      test_process_page(task,data,page_count);
	}
}

void vaddr_maker(struct task_struct *task,struct Data *data)
{
	int j;
	int i = data->count_vma;
	/* Make sure the pages we need are faulted in! (mm_populate) */
	faultin_vma(task, data->vmas);

	if (cp.vmas[i].page_count)
		data->page_addr = kmalloc(cp.vmas[i].page_count *
					  sizeof(unsigned long), GFP_KERNEL);
	else
		data->page_addr = NULL;

	if (!data->page_addr) {
		pr_err("[KPROF] Unable to allocate memory.\n");
		return;
	}

	for (j = 0; j < cp.vmas[i].page_count; j++)
	{
		data->page_addr[j] = data->vmas->vm_start +
			((cp.vmas[i].page_index[j])*PAGE_SIZE);
		DBG_PRINT("cp.vmas[%d].page_index[%d]:%d\n", i, j,
			  cp.vmas[i].page_index[j]);
	}
}

/* NOTE: we can get mm from task. There might not be a need to pass it
 * here explicitly. */
void vma_finder (struct mm_struct *mm, struct Data *data, struct task_struct *task) 
{
	int i = 0; /*vma_len*/
	/*for walking on list of vmas of the process sent by user*/
	int process_vma = 0;
	data->mm = mm;
	data->vmas = mm->mmap;
	//vma_len = (data->vmas->vm_end - data->vmas->vm_start)/PAGE_SIZE;
	DBG_PRINT("vma_numbers: %d\n",cp.vma_count);
	/*for walking on vma arrays (cp.vmas) sent by user*/
	for (i = 0; i < cp.vma_count ; i++)
	{
                data->count_vma = i;
		for (; process_vma < mm->map_count; process_vma++)
		{
			//DBG_PRINT("user's VMA is: %d\n",cp.vmas[i].vma_index);
                        if (cp.vmas[i].vma_index == process_vma)
			{
				//DBG_PRINT("cp.vmas[i].vma_index:%d, process_vma:%d\n",cp.vmas[i].vma_index,process_vma);
				//DBG_PRINT("Len of vma %d is:%d\n",process_vma,(data->vmas->vm_end - data->vmas->vm_start)/PAGE_SIZE);
				/*checking the consistency*/
				if (cp.vmas[i].total_pages == (data->vmas->vm_end - data->vmas->vm_start)/PAGE_SIZE)
		        	{
					// DBG_PRINT("VMA[%d] is: %d and its start: %lx\n",i,cp.vmas[i].vma_index, data->vmas->vm_start);
					/*making user virtual adddresses for this VMA*/
					vaddr_maker(task,data);
					//DBG_PRINT("after making user vaddr, operation: %d\n",cp.vmas[i].operation);

                                        /*decide which operation to do*/
					which_operation(task, cp.vmas[i].operation,
							data, cp.vmas[i].page_count);

					if (cp.vmas[i].page_count)
						kfree(data->page_addr);

					data->vmas = data->vmas->vm_next;
					process_vma++;
					break;
				} else {
					pr_err("KPROFILER: VM size mismatch!");
				}
			}
			else
			{
				data->vmas = data->vmas->vm_next;
				DBG_PRINT("VMA %d: not in the list of user's VMA\n", process_vma);
			}

		}
	}
}


void get_vma (void)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct Data *data = kmalloc (sizeof(struct Data), GFP_KERNEL);
	char task_name [TASK_COMM_LEN];
	//DBG_PRINT("start of get_vma\n");
	for_each_process(task)
	{
		get_task_comm(task_name,task);

		if(task->pid == cp.pid)
		{
			//DBG_PRINT("\n%s[%d]\n", task->comm, task->pid);
			mm = task->mm;
			DBG_PRINT("cp.vmas[0].page_count:%d\n",cp.vmas[0].page_count);
			DBG_PRINT("cp.vmas[0].vma_index:%d,cp.page_index[0]:%d\n", cp.vmas[0].vma_index,cp.vmas[0].page_index[0]);
			data->vmas = mm->mmap;
			//DBG_PRINT("before vma_finder\n");
			vma_finder(mm,data,task);
		}
	}
	kfree(data);
}

int filling_params(void)
{
	int i;
	unsigned int * temp_page_index;
	struct vma_descr * temp_vmas;

        /* cp has a field size with useful data and cp.vmas which so
	 * far has a user ptr which is useless in kernel we don't need
	 * to care about this stuff for fields like cp.pid or
	 * cp.vma_count which are not array. Just pointers (arrays)
	 * need allocation in kernel address space(with kmalloc here)
	 * putting user pointer of cp.touched_vmas in a temp var and
	 * later use as src in cpy_from_user*/
	temp_vmas = cp.vmas;
	cp.vmas = kmalloc(cp.vma_count * sizeof(struct vma_descr), GFP_KERNEL);

	/* cp.vmas is a kernel pointer (address) now, can be used as
	 * dst in cpy_from_usr and src should be usr pointer
	 * (temp_vmas) */
	if(copy_from_user(cp.vmas,temp_vmas, cp.vma_count*sizeof(struct vma_descr)))
		return -EFAULT;

	for (i = 0; i < cp.vma_count; i++) {
		temp_page_index = cp.vmas[i].page_index;
		cp.vmas[i].page_index = kmalloc(cp.vmas[i].page_count *
						sizeof(unsigned int),GFP_KERNEL);

		if(copy_from_user(cp.vmas[i].page_index, temp_page_index,
				  cp.vmas[i].page_count*sizeof(unsigned int)))
			return -EFAULT;

	}

	return 0;
}


ssize_t memprofile_proc_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *data)
{       int i;
	DBG_PRINT(KERN_ALERT "memprofile_proc_write\n");
	if(copy_from_user(&cp, buffer, sizeof(struct profile_params)))
		return -EFAULT;
	else {
		filling_params();
		get_vma();
	}

	for(i = 0; i< cp.vma_count; i++) {
		if (cp.vmas[i].page_count)
			kfree(cp.vmas[i].page_index);
	}
	kfree(cp.vmas);
        return 0;
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



static int mm_exp_load(void){

        int ret;
#ifdef __arm__
	/* Init PMCs on all the cores */
	init_cpu_counter();

	/*PL310 L2 cache for using those clean,invalidate funcs*/
	//Setup the I/O memory for the PL310 cache controller
	pl310_area = ioremap_nocache(HW_PL310_BASE, PAGE_SIZE);
	DBG_PRINT(KERN_INFO "PL310 area @ 0x%p\n", pl310_area);

	if (!pl310_area) {
		pr_err("Unable to perform ioremap.");
		return 1;
	}
#endif


	/* Initialize file operations */
	memprof_ops.write = memprofile_proc_write;
	memprof_ops.owner = THIS_MODULE;


	/* create proc entry */
	memprofile_proc = proc_create(PROF_PROCFS_NAME, 0666, NULL, &memprof_ops);

	if (memprofile_proc == NULL) {
		remove_proc_entry(PROF_PROCFS_NAME, NULL);
		pr_err("Error: Could not initialize /proc/%s\n", PROF_PROCFS_NAME);
		return -ENOMEM;
	}


	/* Now try to remap memory at a known physical address. For both LO and HI range */
        DBG_PRINT("Remapping PRIVATE_LO reserved memory area\n");

        /* Setup pagemap structure to guide memremap_pages operation */
        __pool_kva_lo = memremap(MEM_START_LO, MEM_SIZE_LO, MEMREMAP_WB);

        if (__pool_kva_lo == NULL) {
                pr_err("Unable to request memory region @ 0x%08lx. Exiting.\n", MEM_START_LO);
                goto release;
        }

        DBG_PRINT("Remapping PRIVATE_LO reserved memory area\n");

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
	if(verbose)
		test_page_structs();

	pr_info("KPROFILER module installed successfully.\n");


	return 0;

	unmap:
        memunmap(__pool_kva_hi);
unmap_lo:
        memunmap(__pool_kva_lo);
release:
        return -1;
}

static void mm_exp_unload(void)
{

#ifdef __arm__
	//Release PL310 I/O memory area
	iounmap(pl310_area);
#endif

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

	/* Release handler of page deallocations */
        free_pvtpool_page = NULL;

        remove_proc_entry(PROF_PROCFS_NAME, NULL);


	pr_info("KPROFILER module uninstalled successfully.\n");
}

module_init(mm_exp_load);
module_exit(mm_exp_unload);

MODULE_AUTHOR ("Golsana Ghaemi, Renato Mancuso");
MODULE_DESCRIPTION ("changin cacheability of mmeory regions");
MODULE_LICENSE("GPL");
