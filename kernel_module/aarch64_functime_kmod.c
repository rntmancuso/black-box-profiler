//kernel module for printing a process vma and pte


#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/migrate.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <asm-generic/getorder.h>
#include <asm/io.h>
//#include <asm/cp15.h>
#include <asm/tlbflush.h>
#include <asm/page.h>
#include <linux/hash.h>
#include <linux/ioport.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <linux/proc_fs.h>
//#include <asm/cacheflush.h> /*for processor L1 cache flushing*/
//#include <asm/outercache.h>
//#include <asm/hardware/cache-l2x0.h>
#include <asm/mman.h>
#include <linux/smp.h>   // for on_each_cpu
//#include "flush_tlb.c"
#include <linux/kallsyms.h>
#include <linux/genalloc.h>


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

/*for using function ( populate_vma_page_range)  which is not exported*/
static long (*populate_vma_page_range_ptr)(struct vm_area_struct *vma,
		unsigned long start, unsigned long end, int *locked) = NULL;

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
	printk(KERN_INFO "Now enabling performance counters on all cores.\n");
	on_each_cpu(enable_cpu_counters, NULL, 1);
	printk(KERN_INFO "Done.\n");
	return 0;
}
#endif

/*inline void invalidate_cache(start,end)
{
  __dma_inv_area:
	add	x1, x1, x0
	dcache_line_size x2, x3
	sub	x3, x2, #1
	tst	x1, x3				// end cache line aligned?
	bic	x1, x1, x3
	b.eq	1f
	dc	civac, x1			// clean & invalidate D / U line
1:	tst	x0, x3				// start cache line aligned?
	bic	x0, x0, x3
	b.eq	2f
	dc	civac, x0			// clean & invalidate D / U line
	b	3f
2:	dc	civac, x0			// clean & invalidate D / U line
3:	add	x0, x0, x2
	cmp	x0, x1
	b.lo	2b
	dsb	sy
	ret
	}*/

static int __mm_populate_mod(unsigned long start, unsigned long len, int ignore_errors, struct task_struct *task)
{
        struct mm_struct *mm = task->mm/*current->mm*/;
        unsigned long end, nstart, nend;
        struct vm_area_struct *vma = NULL;
        int locked = 0;
        long ret = 0;

        VM_BUG_ON(start & ~PAGE_MASK);
        VM_BUG_ON(len != PAGE_ALIGN(len));
        end = start + len;

        for (nstart = start; nstart < end; nstart = nend) {
		/* 
		 * We want to fault in pages for [nstart; end) address range.                                                                                                 * Find first corresponding VMA.
		 */
		if (!locked) {
                        locked = 1;
                        down_read(&mm->mmap_sem);
                        vma = find_vma(mm, nstart);
                } else if (nstart >= vma->vm_end)
                        vma = vma->vm_next;
                if (!vma || vma->vm_start >= end)
                        break;
		/*
		 *Set [nstart; nend) to intersection of desired address  
		 *range with the first VMA. Also, skip undesirable VMA types. 
		 */
		nend = min(end, vma->vm_end);
                if (vma->vm_flags & (VM_IO | VM_PFNMAP))
                        continue;
                if (nstart < vma->vm_start)
                        nstart = vma->vm_start;
		/*
		 *Now fault in a range of pages. populate_vma_page_range() 
		 * double checks the vma flags, so that it won't mlock pages 
		 * if the vma was already munlocked.
		 */
		ret = populate_vma_page_range_ptr(vma, nstart, nend, &locked);
		if (ret < 0) {
                        if (ignore_errors) {
                                ret = 0;
                                continue;/* continue at next VMA */
                        }
                        break;
                }
		nend = nstart + ret * PAGE_SIZE;
                ret = 0;
        }
        if (locked)
                up_read(&mm->mmap_sem);
        return ret;/* 0 or negative error code */
}

		
static int cacheability_modifier (pte_t *ptep, unsigned long addr,void *data)
{
        int i;
	pte_t *pte = ptep;
	size_t pfn;
	pte_t newpte;
	/*Later should be seperate for each VMA : cp.vmas[((struct Data*)data)->count_vma].operation*/
	int skip = cp.vmas->operation;
#ifdef __arm__
	struct page *page = NULL; /*for making page and finding physical address */
	unsigned long phys; /*physical addr*/
	/*char * page_v*/unsigned long *page_v;
#endif
	
	printk("skip: %d,page_number:%d\n",skip,cp.vmas[((struct Data*)data)->count_vma].page_count);
	/*check whether current addr is in the list of pages which we want to skip the operation for*/
	for (i=0; i< cp.vmas[((struct Data*)data)->count_vma].page_count; i++) 
	{
		if (addr == ((struct Data*)data)->page_addr[i])
		{
			//Later: cp.vmas[((struct Data*)data)->count_vma].operation
			skip =!(cp.vmas->operation);
			break;
		}  
	}
   
	if (skip) // this block keeps the page cacheable
	{
		//printk("we skip (keep cacheable)!, skip is:%d\n",skip);
	}
	else //this block makes page noncacheable
	{
	  
		//changing prot bits of vma to make it noncacheable
		((struct Data*)data)->vmas->vm_page_prot = pgprot_noncached(((struct Data*)data)->vmas->vm_page_prot);
		//printk("after page_prot changing\n");

		// making new pte
		pfn = pte_pfn(*pte); //with the old pte 
		newpte = pfn_pte(pfn, ((struct Data*)data)->vmas->vm_page_prot);
		//newpte = pfn_pte(pfn,pgprot_noncached(((struct Data*)data)->vmas->vm_page_prot));
		//newpte = mk_pte(newpage, vma->vm_page_prot);

		flush_cache_mm (((struct Data*)data)->mm);

		set_pte_at(((struct Data*)data)->mm,addr,pte, newpte);

		printk("cacheability_modifier on cpu: %d\n",smp_processor_id());

		flush_tlb_page(((struct Data*)data)->vmas,addr);
		printk("after flushing tlb\n");

#ifdef __arm__
		//making page struct
		page = pte_page(*pte);
		printk("after page making\n");
		//phys = page_to_phys(page); //return physical addr, this is needed for invalidate_page_l2
		page_v = kmap(page);//kmap always returns a kernel virtual address that addresses the desired page
		//printk("after kmap\n");
		//calculating pfn
		pfn = pte_pfn(*pte); //with the old pte
		//making new pte
		 newpte = pfn_pte(pfn,pgprot_noncached(((struct Data*)data)->vmas->vm_page_prot));
		//Perform PA-based invaluidation on L1 and L2 
		//invalidate_page_l2(phys);
		invalidate_page_l1((ulong)page_v);//argument used to be addr
		invalidate_page_l2(phys);
		kunmap(page);
                   
		//setting new pte
		set_pte_ext(pte, newpte, 0);
		//flushing TLB for one page
		// each time addr is added by 4KB
		printk("cacheability_modifier on cpu: %d\n",smp_processor_id());
		//flush_tlb_page_m(((struct Data*)data)->vmas,addr); //for using this u should activate defining flush_tlb_page_m on top
		//on_each_cpu(middle_func, &ta, 1);
		__flush_tlb_page(((struct Data*)data)->vmas,addr);
#endif
		
	}
       
	return 0;
}

void vma_finder (struct mm_struct *mm, struct Data *data, struct task_struct *task)
{
 
	int locked;
	int i = 0,j;
	int process_vma = 0; //for walking on list of vmas of the process sent by user
	data->mm = mm;
	data->vmas = mm->mmap; //first vma of the process
	printk("vma_numbers: %d\n",cp.vma_count);

	locked = 1;
	down_read(&mm->mmap_sem);
	for (i = 0; i < cp.vma_count ; i++) //for walking on cp.vmas
	{

	        data->count_vma = i; // for keeping track of the vma we are wroking on, in apply_to_page_range

		for (; process_vma < mm->map_count; process_vma++) //mm->map_count is the number of VMAs for process with pid cp.pid
		{
			printk("vma is: %d\n",process_vma);
			//	printk("vm_start is:%x\n",data->vmas->vm_start);

			if (cp.vmas[i].vma_index == process_vma)
			{
				printk("Len of vma %d is:%d\n",process_vma,(data->vmas->vm_end - data->vmas->vm_start)/PAGE_SIZE);
			 
				if (cp.vmas[i].total_pages == (data->vmas->vm_end - data->vmas->vm_start)/PAGE_SIZE)//for checking the consistency
				
			      	{
	                                printk("before mm_populate_ptr, VMA[%d] is: %d and data->vmas->vm_start: %lx\n",i,cp.vmas[i].vma_index, data->vmas->vm_start);
				    
					__mm_populate_mod(data->vmas->vm_start, data->vmas->vm_end - data->vmas->vm_start,1,task);

					data->page_addr = kmalloc(cp.vmas[i].page_count*sizeof(int),GFP_KERNEL);
			
					for (j=0; j < cp.vmas[i].page_count; j++)//making adresses from page_indexes sent by user
					{
						data->page_addr[j] = data->vmas->vm_start+((cp.vmas[i].page_index[j])*PAGE_SIZE);
						printk("cp.vmas[%d].page_index[%d]:%d\n",i,j,cp.vmas[i].page_index[j]);
		    
					}
					apply_to_page_range(data->vmas->vm_mm, data->vmas->vm_start, data->vmas->vm_end - data->vmas->vm_start,cacheability_modifier,data);
			         



					kfree(data->page_addr);//later if we wanna do all vmas at the same time, should we free here?or at //*
					data->vmas = data->vmas->vm_next;
					process_vma++;
					break;
				}
			}
			else
			{
				data->vmas = data->vmas->vm_next;
				printk("this VMA (%d) is not in cp.vmas\n",cp.vmas[i].vma_index);
			}
	  
		}
	} //*
	if(locked)
		up_read(&mm->mmap_sem);
}


void get_vma (void)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct Data *data = kmalloc (sizeof(struct Data), GFP_KERNEL);
	char task_name [TASK_COMM_LEN];
	printk("start of get_vma\n");
	for_each_process(task)
	{
		get_task_comm(task_name,task);
		//printk("before checking cp.pid:%d and task->pid:%d\n",cp.pid,task->pid);
		if(task->pid == cp.pid)
		{
			//printk("after checking pid %d\n",cp.pid);
			printk("\n%s[%d]\n", task->comm, task->pid);
			mm = task->mm;
			printk("cp.vmas[0].page_count:%d\n",cp.vmas[0].page_count);
			printk("cp.vmas[0].vma_index:%d, cp.page_index[0]:%d\n", cp.vmas[0].vma_index,cp.vmas[0].page_index[0]);
		       
			data->vmas = mm->mmap; //not data.vms bc data is pointer // this is vma0
			//printk("data->vmas->vm_start (vma 0) : %x\n", data->vmas->vm_start);
			vma_finder(mm,data,task); //
		}
	
	}
	kfree(data);
}

int filling_params(void)
{
        unsigned int* temp_page_index;
	struct vma_descr *temp_vmas;
	/*cp has a field size with useful data and cp.vmas which so far has a user ptr which is useless in kernel
	 *we don't need to care about this stuff for fields like cp.pid or cp.vma_count which are not array. 
	 *Just pointers (arrays)  need allocation in kernel address space(with kmalloc here)*/
	//int* temp_size = cp.size;

	temp_vmas = cp.vmas;// putting user pointer of cp.vmas in a temp var and later use as src in cpy_from_user
	cp.vmas = kmalloc(cp.vma_count*sizeof(struct vma_descr),GFP_KERNEL);
	/* cp.vmas is a kernel pointer (address) now, can be used as dst in cpy_from_usr
	 *and src should be usr pointer (temp_vmas) */
	if(copy_from_user(cp.vmas,temp_vmas, cp.vma_count*sizeof(struct vma_descr))) return -EFAULT;

	
	temp_page_index = cp.vmas->page_index;
	cp.vmas->page_index = kmalloc(cp.vmas->page_count*sizeof(unsigned int),GFP_KERNEL);
	if(copy_from_user(cp.vmas->page_index,temp_page_index, cp.vmas->page_count*sizeof(unsigned int))) return -EFAULT;
    

	return 0;
}


ssize_t memprofile_proc_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *data)
{
	printk(KERN_ALERT "memprofile_proc_write\n");
	if(copy_from_user(&cp, buffer, sizeof(struct profile_params))) return -EFAULT;
	else
	{
		filling_params();
		//printk("\ncp.vmas[0].vma_index: %d\n",cp.vmas[0].vma_index);
		get_vma(); 
	}
	
	kfree(cp.vmas->page_index);
	kfree(cp.vmas);
	//kfree(cp.size);

	return 0;
}

static int mm_exp_load(void){

#ifdef __arm__
	/* Init PMCs on all the cores */
	init_cpu_counter();

	printk("test for PL310");
	
	pl310_area = ioremap_nocache(HW_PL310_BASE, PAGE_SIZE);
	printk(KERN_INFO "PL310 area @ 0x%p\n", pl310_area);

	if (!pl310_area) {
		printk(KERN_INFO "Unable to perform ioremap.");
		return 1;
	}
#endif

	/* Attempt to find symbol(populate_vma_page_range) */
	if (!populate_vma_page_range_ptr)
	{
		preempt_disable();
		mutex_lock(&module_mutex);
		populate_vma_page_range_ptr = (void*)kallsyms_lookup_name("populate_vma_page_range");
		mutex_unlock(&module_mutex);
		preempt_enable();

		//Have we found a valid symbol?
		if (!populate_vma_page_range_ptr) {
			pr_err("Unable to find populate_vma_page_range symbol. Aborting.\n");
			return -ENOSYS;
		}
	}
	
	/* Initialize file operations */
	memprof_ops.write = memprofile_proc_write;
	memprof_ops.owner = THIS_MODULE;

	//printk("after symbol lookup\n");
	/* Now create proc entry */
	memprofile_proc = proc_create(PROF_PROCFS_NAME, 0666, NULL, &memprof_ops);

	if (memprofile_proc == NULL) {
		remove_proc_entry(PROF_PROCFS_NAME, NULL);
		printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROF_PROCFS_NAME);
		return ;
	}


	return 0;
}

static void mm_exp_unload(void)
{
#ifdef __arm__
	//Release PL310 I/O memory area
	iounmap(pl310_area);
#endif
	
        remove_proc_entry(PROF_PROCFS_NAME, NULL);
	printk("\nPrint segment information module exiting.\n");
	
}

module_init(mm_exp_load);
module_exit(mm_exp_unload);
//module_param(myflag, int, 0);
//MODULE_LICENSE("GPL");

MODULE_AUTHOR ("Golsana Ghaemi, Renato Mancuso");
MODULE_DESCRIPTION ("changin cacheability of mmeory regions");
MODULE_LICENSE("GPL");


