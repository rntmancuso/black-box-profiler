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
#include <asm/cp15.h>
#include <asm/tlbflush.h>
#include <asm/page.h>
#include <linux/hash.h>
#include <linux/ioport.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <linux/proc_fs.h>
#include <asm/cacheflush.h> /*for processor L1 cache flushing*/
#include <asm/outercache.h>
#include <asm/hardware/cache-l2x0.h>
#include <asm/mman.h>


/*#include "/media/disk/linux-4.1.15_2.0.0/mm/internal.h"

  #include <linux/mman.h>
  #include <linux/pagemap.h>
  #include <linux/syscalls.h>
  #include <linux/mempolicy.h>
  #include <linux/page-isolation.h>
  #include <linux/hugetlb.h>
  #include <linux/falloc.h>
  #include <linux/sched.h>
  #include <linux/ksm.h>
  #include <linux/fs.h>
  #include <linux/file.h>
  #include <linux/blkdev.h>
  #include <linux/swap.h>
  #include <linux/swapops.h>*/
//#include <linux/fs.h>

#define PROF_PROCFS_NAME                "memprofile"

static struct proc_dir_entry * memprofile_proc;
/* File oeprations for the  procfile */
struct file_operations  memprof_ops;

//long p = 0;
//char *p;

/*interacting between user and kernel for sending page index:
  we store number of pages in "size" field and page indices in buff field  of "params" struct
  user is sending them  (using write()) in buff.
  we need cp to have p (page index) in kernel side and later by  using p we can fill
  page_addr field of struct Data*/
struct params
{
	int size;
	int *buff;
	bool shouldSkip;
	pid_t pid;
};
struct params cp;
//long *p;

struct Data
{
	struct vm_area_struct  *vmas;
	unsigned long* page_addr;

};
/*
  typedef struct Data
  {
  struct vm_area_struct  *vmas;
  unsigned long page_addr;

  }myData;
  wuth this format instead of using struct Data ... you should use myData .... for ex in casting instead of
  (struct Data*)... we write (myData*)...
*/

/* Adding 8 to this mask, divides cycle counter by 64 */
#define PERF_DEF_OPTS (1 | 16 | 8)

#define HW_PL310_CL_INV_PA      0x07F0 / 4
/* PL310 Base for iMX.6 Dual/Quad (Wandboard, PICO) */
#define HW_PL310_BASE           0x00A02000

volatile unsigned long __iomem * pl310_area;
//static int mm_populate(unsigned long start, unsigned long len,int ignore_errors,struct task_struct *task);

static long populate_vma_page_range(struct vm_area_struct *vma,
				    unsigned long start, unsigned long end, int *nonblocking,struct task_struct *task)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long nr_pages = (end - start) / PAGE_SIZE;
	int gup_flags;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(end   & ~PAGE_MASK);
	VM_BUG_ON_VMA(start < vma->vm_start, vma);
	VM_BUG_ON_VMA(end   > vma->vm_end, vma);
	VM_BUG_ON_MM(!rwsem_is_locked(&mm->mmap_sem), mm);

	gup_flags = FOLL_TOUCH | FOLL_POPULATE;
	/*
	 * We want to touch writable mappings with a write fault in order
	 * to break COW, except for shared mappings because these don't COW
	 * and we would not want to dirty them for nothing.
	 */
	if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == VM_WRITE)
		gup_flags |= FOLL_WRITE;

	/*
	 * We want mlock to succeed for regions that have any permissions
	 * other than PROT_NONE.
	 */
	if (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC))
		gup_flags |= FOLL_FORCE;

	/*
	 * We made sure addr is within a VMA, so the following will
	 * not result in a stack expansion that recurses back here.
	 */
	return __get_user_pages(task/*current*/, mm, start, nr_pages, gup_flags,
				NULL, NULL, nonblocking);
}

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
		 * We want to fault in pages for [nstart; end) address range.
		 * Find first corresponding VMA.
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
		 * Set [nstart; nend) to intersection of desired address
		 * range with the first VMA. Also, skip undesirable VMA types.
		 */
		nend = min(end, vma->vm_end);
		if (vma->vm_flags & (VM_IO | VM_PFNMAP))
			continue;
		if (nstart < vma->vm_start)
			nstart = vma->vm_start;
		/*
		 * Now fault in a range of pages. populate_vma_page_range()
		 * double checks the vma flags, so that it won't mlock pages
		 * if the vma was already munlocked.
		 */
		ret = populate_vma_page_range(vma, nstart, nend, &locked,task);
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




//for debugging
void print_debug(bool enable, const char* statement, unsigned long variable)
{
	if (enable)
	{
		if (variable == 0)
			printk(statement);
		else
			printk(statement,variable);
	}

}

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
//end of testing


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

/*bool isAdress()
  {
  
  }*/

static int print_mem (pte_t *ptep, pgtable_t token ,  unsigned long addr,void *data)
{
	///struct Data *cdata = data;
	pte_t *pte = ptep;
	size_t pfn;
	pte_t newpte;
	bool skip = cp.shouldSkip;
	struct page *page = NULL; /*for making page and finding physical address */
	unsigned long phys; /*physical addr*/
	/*char * page_v*/unsigned long *page_v;
        int i;
	//printk ("\naddr is:%lu and skip is:%d\n", addr,skip);
        for (i=0; i<cp.size; i++) //check whether current addr is in the list pf pages we want to skip
	{
	  //printk("\naddr is:%lu and page_addr[%d] is:%lu\n",addr,i,((struct Data*)data)->page_addr[i]);
		if (addr == ((struct Data*)data)->page_addr[i])
		{
		  //printk("skip is zero here\n");
			skip =!(cp.shouldSkip);
			break;
		}  
	}
	//for (i=0; i<cp.size; i++)
	//{
	if (skip) // this block keeps the page cacheable
	{
	  //printk("we skip (keep cacheable)!, skip is:%d\n",skip);
	}
	else //this block makes page noncacheable
	{
	  //    printk("we don't skip (noncacheable) and skip is:%d\n",skip);
		print_debug(0,"\n\nbeginning of the else print_mem() with print_debug()",0);
		//changing prot bits of vma to make it noncacheable
		//cdata->vmas->vm_page_prot = pgprot_noncached(cdata->vmas->vm_page_prot);
		((struct Data*)data)->vmas->vm_page_prot = pgprot_noncached(((struct Data*)data)->vmas->vm_page_prot);
		//print_debug(0,"\nvm_page_prot after: cvma->vm_page_prot: %x", cdata->vmas->vm_page_prot);
		//making page struct
		page = pte_page(*pte);
		phys = page_to_phys(page); //return physical addr
		page_v = kmap(page);//kmap always returns a virtual address that addresses the desired page
		//calculating pfn
		pfn = pte_pfn(*pte); //with the old pte
		//making new pte
		//newpte = pfn_pte(pfn, cdata->vmas->vm_page_prot);
		newpte = pfn_pte(pfn, ((struct Data*)data)->vmas->vm_page_prot);
		/*//flushing L1 cache
		  __cpuc_flush_user_range(addr,addr+PAGE_SIZE,cdata->vmas->vm_flags);
		  printk("\nafter flush_cache_page\n");
		  //flushing L 2 cache
		  outer_cache.clean_range(phys,phys+PAGE_SIZE);//PHYSICAL ADDR
		  // outer_clean_range(phys,phys+PAGE_SIZE);*/
			
		/* Perform PA-based invaluidation on L1 and L2 */
		//invalidate_page_l2(phys);
		invalidate_page_l1((ulong)page_v/*addr*/);
		invalidate_page_l2(phys);
		kunmap(page);
		//setting new pte
		set_pte_ext(pte, newpte, 0);
		//flushing TLB for one page
		// each time addr is added by 4KB 
		__flush_tlb_page(((struct Data*)data)->vmas,addr);
		//kunmap(page);
		//printk("after flush tlb\n");
	}
	// }
	return 0;
}

ssize_t memprofile_proc_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *data)
{
	printk(KERN_ALERT "memprofile_proc_write");
	int i;

	if(copy_from_user(&cp, buffer, sizeof(struct params))) return -EFAULT;
	else {
		/*cp has a field size with useful data and cp.buff which so far has a user ptr which is useless in kernel
		  we don't need to care about this stuff for cp.size and cp.shouldSkip. Those are not pointers*/
		int* temp_buff = cp.buff; //adress of user level
		cp.buff = kmalloc(cp.size*sizeof(long),GFP_KERNEL);//now cp.buff has kernel pointer


		if(copy_from_user(cp.buff,temp_buff, cp.size*sizeof(long))) return -EFAULT; /*src should be a user pointer and it is (temp_buff is user ptr)
											      and dst is kernel ptr*/
		else
		{
			printk("\nsize is %d\n",cp.size);
			struct task_struct *task;
	                struct mm_struct *mm;
		        //struct vm_area_struct *data;
			//struct vm_area_struct *prev = NULL;
			//vm_flags_t newflags;
		        struct Data *data = kmalloc (sizeof(struct Data), GFP_KERNEL);
		        // myData *data = kmalloc (sizeof(myData), GFP_KERNEL);
		        //struct vma_srea_struct data = vma;
		        char task_name [TASK_COMM_LEN];
			


			for_each_process(task)
		        {
				get_task_comm(task_name,task);
				//printk("task->pid is:%d\n", task->pid);
				//printk("cp.pid is:%d\n", cp.pid);
			    
				if(task->pid == cp.pid)
				  {
					printk("\n%s[%d]\n", task->comm, task->pid);
					mm = task->mm;
					printk("\nThis mm_struct has %d vmas.\n", mm->map_count);
					printk("test1\n");

      					data->vmas = mm->mmap; //not data.vms bc data is pointer
					for (data->vmas = mm->mmap ; data->vmas ; data->vmas = data->vmas->vm_next)
					{
					  printk("mm->brek and start :%lx %lx\n", mm->brk,data->vmas->vm_start);
					  if (data->vmas->vm_start <= mm->brk && data->vmas->vm_end >= mm->start_brk) //finding heap region
						{
							print_debug(1,"\n[heap]",0);
							printk("heap\n");
							//newflags = data->vmas-> vm_flags | VM_LOCKED;
							(void) __mm_populate_mod(data->vmas->vm_start, data->vmas->vm_end - data->vmas->vm_start,1,task);
							printk("done with locking physical memory\n");
							data->page_addr = kmalloc(cp.size*sizeof(long),GFP_KERNEL);
							for (i=0; i<cp.size; i++) //making adresses we want to skip (keeping the cacheable or making noncacheable. debends on shouldSkip)
								{
								data->page_addr[i] = data->vmas->vm_start+((cp.buff[i]-1)*PAGE_SIZE);
								//printk("data->page_addr[%d]=%lu\n",i, data->page_addr[i]);
								}
        
							print_debug(1,"\nnumber of pages in heap:%ld\n",(data->vmas->vm_end-data->vmas->vm_start)/PAGE_SIZE);
				  
							apply_to_page_range(data->vmas->vm_mm, data->vmas->vm_start, data->vmas->vm_end - data->vmas->vm_start,print_mem, data);
							kfree(data->page_addr);
                                                        break;

							   }
					  
					                 }

					}
			      	}
                        kfree(data);
	        	}
		//	kfree(data);
		}
	kfree(cp.buff);
	//kfree(data->page_addr);
	//kfree(data);
	//	}
	//kfree(data);
	return 0;
}

static int mm_exp_load(void){

	/* Init PMCs on all the cores */
	init_cpu_counter();

	
	/*PL310 L2 cache for using those clean,invalidate funcs*/
	/*struct resource * pl310_res = NULL;
	//Setup the I/O memory for the PL310 cache controller
	pl310_res = request_mem_region(HW_PL310_BASE, PAGE_SIZE, "PL310 Area");
	printk(KERN_INFO "PL310 area @ 0x%p\n", pl310_area);
	if (!pl310_res) {
	printk(KERN_INFO "Unable to request mem region. Is it already mapped?");
	return 1;
	}
	*/

	printk("test for PL310");
	
	pl310_area = ioremap_nocache(HW_PL310_BASE, PAGE_SIZE);
	printk(KERN_INFO "PL310 area @ 0x%p\n", pl310_area);

	if (!pl310_area) {
		printk(KERN_INFO "Unable to perform ioremap.");
		return 1;
	}

	
	/* Initialize file operations */
	memprof_ops.write = memprofile_proc_write;
	memprof_ops.owner = THIS_MODULE;


	/* Now create proc entry */
	memprofile_proc = proc_create(PROF_PROCFS_NAME, 0666, NULL, &memprof_ops);

	if (memprofile_proc == NULL) {
		remove_proc_entry(PROF_PROCFS_NAME, NULL);
		printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROF_PROCFS_NAME);
		return ;
	}


	/*	struct task_struct *task;
		struct mm_struct *mm;
		//struct vm_area_struct *vma;
		struct vm_area_struct *data;
		//struct vma_srea_struct data = vma;  
		char task_name [TASK_COMM_LEN];
		// if (myflag == 1) {
		printk("\nwith changing the cacheability"); 
		for_each_process(task){
		get_task_comm(task_name,task);
		if(strncmp(task_name,"hello",TASK_COMM_LEN) == 0) {
		printk("%s[%d]\n", task->comm, task->pid);
		mm = task->mm;
		printk("\nThis mm_struct has %d vmas.\n", mm->map_count);
		data = mm->mmap;
		printk ("\ndata->vm_page_prot: %x\n", data->vm_page_prot);
		for (data = mm->mmap ; data ; data = data->vm_next){
		if (data->vm_start <= mm->brk && data->vm_end >= mm->start_brk){
		printk("\n[heap]");
		printk ("\ndata->vm_page_prot: %x\n", data->vm_page_prot);
		//print_mem(task);
		apply_to_page_range(data->vm_mm, data->vm_start, data->vm_end - data->vm_start,print_mem, data);
		}
		}
		}
		//}
		}*/
	return 0;
}

static void mm_exp_unload(void)
{
        remove_proc_entry(PROF_PROCFS_NAME, NULL);
	printk("\nPrint segment information module exiting.\n");
	
}

module_init(mm_exp_load);
module_exit(mm_exp_unload);
//module_param(myflag, int, 0);
//MODULE_LICENSE("GPL");

MODULE_AUTHOR ("Golsana Ghaemi");
MODULE_DESCRIPTION ("make pages of a vma noncacheable");
MODULE_LICENSE("GPL");


