/*memory profiler: reads different memory infrastructures from the dtb of the kernel,
  generates memory pools from those mem infrastructures, benchmarks these different memories
  for modeling them by collecting peak bw,...., and presents it (memory profiler's output) as
  ...*/
#include <linux/timex.h> //using get_cycles 

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
#include <linux/of.h>

#include <asm/mman.h>
#include <linux/smp.h>   /* for on_each_cpu */
#include <linux/kallsyms.h>
#include <linux/genalloc.h>
#include <linux/timekeeping.h>
#include <linux/delay.h> /*for msleeo() using as test*/
#include <linux/cpumask.h>


#ifdef __arm__
#include <asm/cacheflush.h> /*for processor L1 cache flushing*/
#include <asm/outercache.h>
#include <asm/hardware/cache-l2x0.h>
#endif


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

//extern int (*profile_decomposer) (int);


#ifndef _SILENT_
int verbose = 0;
module_param(verbose, int, 0660);

#define DBG_PRINT(format, ...)                                          \
        do {                                                            \
		if (verbose)						\
                        pr_info("[KPROF] " format, ##__VA_ARGS__);	\
        } while (0)
#else
#define DBG_PRINT(format, ...)			\
        {}
#endif

#define DBG_INFO(format, ...)					\
        do {							\
		pr_info("[KPROF] " format, ##__VA_ARGS__);	\
        } while (0)



/**************for physical memory based on dtb 
memory type, MEM_START, MEM_SIZE
BRAM         
FPGA-DRAM           0xfffc0000UL 
OCM
DRAM
***************/

int mem_no = 0; //for now, but I think is better to pass it rather than having as general

#define NUMA_NODE_THIS    -1

#define THRESHOLD /*19630000*/112927923

#define CACHE_LINE  64
//#define BUFFER_SIZE 16*1024*1024            /*size of buffer we read from/write to for benchmarking*/
#define MY_TYPE int                        /*type of data in allocated buffer which we read/write*/
volatile unsigned int g_start;		   /* starting time */
volatile unsigned int g_end;               /* ending time */
volatile int mywait = 1;                               //global var to tell activities on other core to start/stop

extern void __clean_inval_dcache_area(void * kaddr, size_t size);

/* Handle for remapped memory */
unsigned long  __pool_kva_lo[4];
//static void * __pool_kva_lo = NULL


struct gen_pool ** mem_pool;
//struct gen_pool * mem_pool[4];

/* This is just a hack: keep track of the (single) allocated page so *
 * that we can deallocate it upon module cleanup */
static unsigned int __in_pool = 0;

struct MemRange
{
	unsigned long start;
	unsigned long size;
};


//for keeping reg property of memory device node in dtb
//struct MemRange mem[4]; 
struct MemRange *mem;

extern struct page * (*alloc_pvtpool_page) (struct page *, unsigned long);
extern int (*free_pvtpool_page) (struct page *);
extern struct profile* (*profile_decomposer) (char* profile);




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


/*int*/struct profile*  my_profile_decomposer(char* profile)
{
  // struct mm_struct *mm;
  //struct vm_area_struct *vma;
	//	struct file *file;
	//dev_t dev = 0;
	//vm_flags_t flags;
	//unsigned long ino = 0;
	char* src_pos = profile;
	int i;
	//unsigned long long pgoff = 0;
	unsigned int vma_count, profile_len;
	//const char *name = NULL;
	//unsigned int vma_count = *(unsigned int*)(src_pos);
	//unsigned int* vma_count_ptr = kmalloc(sizeof(unsigned int));
	struct profile *myprofile = kmalloc(sizeof(struct profile), GFP_KERNEL);
	//TODO error checking for kmalloc
	//printk("we are inside the __profile_decomposer()\n");

  
	//Make sure we start with a clean struct profile
	memset(myprofile, 0, sizeof(struct profile));

	/*deserializing the profile information to profile struct*/
	//memcpy(vma_count_ptr, src_pos ,sizeof(unsigned int)); 
	//reading number of VMAs in this layout
	memcpy((void *)&vma_count, src_pos,sizeof(unsigned int)); //(void* or &vma_count?
	//printk("test after the first memcpy\n");
	src_pos += sizeof(unsigned int);
	//printk("number of VMAs in the layout of this process is:%d\n",vma_count);

	//going forward as much as application layout
	src_pos += vma_count*sizeof(struct vma_descr);

	//reading the actual profile (header), reading all first three elements in one shot
	memcpy((void*)&myprofile->profile_len, src_pos, 3*sizeof(unsigned int));
	src_pos += 3*sizeof(unsigned int); // position now is at profiled_vma* 
	profile_len = myprofile->profile_len; //I think # VMAs have been profiled
	//printk("profile_len is: %d\n",myprofile->profile_len);

	//should we kmalloc this?
	myprofile->vmas = kmalloc(profile_len*sizeof(struct profiled_vma),GFP_KERNEL);
	//TODO error checking for kmalloc

	for (i = 0; i < profile_len; ++i) { //profile_len is number of profiled VMA
		struct profiled_vma *vma = &myprofile->vmas[i];// putting address of field vmas[i] of myprofile which we kmalloced above
		/*address of first element of myprofile->vmas (which is a vma that is included
		  in the profile meaning that it has at least one imp page, is in vma in each round.
		  in this memcpy we read from right src_pos in each i and put in right place
		  we read both vma_index and page_count in one shot*/
		memcpy((void *)&vma->vma_id, src_pos, 2*sizeof(unsigned int));
		src_pos += 2*sizeof(unsigned int);
		/* if (i == 0) //heap is 20 */
		/*   vma->vma_id = 20; */
		/* if (i == 1) //stack is zero */
		/*   vma->vma_id = 0; */
		//	printk("VMA %d (idx: %d) has %d pages.\n", i, vma->vma_id, vma->page_count);

		if (vma->page_count) {
		       
			ssize_t pg_size = vma->page_count*sizeof(struct profiled_vma_page);
			vma->pages = (struct profiled_vma_page *)kmalloc(pg_size,GFP_KERNEL);
			memcpy(vma->pages, src_pos, pg_size /*sizeof(struct profiled_vma_page)*/);
			src_pos += pg_size /*sizeof(struct profiled_vma_page)*/;
		}
		else {
			vma->pages = NULL;
		}
    
	}



	return myprofile;

  
}


///*static int*/ void pool_range(void)// why static int? //designing error handling path
void pool_range(void){
  
	struct device_node **mem_type;
	struct device_node *node_count;
	u64 regs[2];//regs[0] = start and regs[1] = size 
	int rc,i,j;
	
	//printk("inside pool_range()\n");

        /*scanning nodes in the first round for realizing the number of nodes with compatible = genpool*/
	node_count = NULL;
	do
	{
		node_count = of_find_compatible_node(node_count, "memory","genpool");
		if (node_count)
			mem_no++;
	}
	while(node_count != NULL);

	mem_type = kmalloc(mem_no*sizeof(struct device_node*), GFP_KERNEL);
  	mem = kmalloc(mem_no*sizeof(struct MemRange),GFP_KERNEL);

	/*second round is for actually reading nodes of dtb with compatible = genpool and reading
	  the start addr and the size of each type of memory node to make memory pool with*/
	
	//for reading the start and size of the first desired  memory node
	mem_type[0] = of_find_compatible_node(NULL,"memory","genpool");

	if (!mem_type){
		printk("mem_type is NULL!\n");
	}
	
	for (i = 0; i < 2; i++)
	{
		rc = of_property_read_u64_index(mem_type[0],"reg",
						i, &regs[i]);
		if (rc){
			printk("didn't catch the regs<mem_start> correctly\n");
		}
	}
        //printk("mem[0].start : %llx, mem[0].size = %llx \n",regs[0], regs[1]);
        mem[0].start = regs[0];
        mem[0].size = regs[1];

	//for reading the start and size of rest of desired memory nodes
	for (i = 1; i <= mem_no; i++){
		mem_type[i] = of_find_compatible_node(mem_type[i-1],"memory","genpool");

		if (!mem_type[i]){
		  //printk("END of memory nodes\n");
			break;
		}

		
		for (j = 0; j < 2; j++)
		{
		
			rc = of_property_read_u64_index(mem_type[i],"reg",
							j, &regs[j]);
			if (rc){
				printk("didn't catch the regs<mem_start> correctly\n");
			}
		} 

		//	printk("mem[%d].start: %llx and mem[%d].size: %llx\n",i,regs[0],i,regs[1]);
		
		mem[i].start = regs[0];
		mem[i].size = regs[1];
	}
  

}

static int initializer(int* ret)
{
	int i;
	//printk("mem_no is : %d\n",mem_no);
	for (i = 0; i < mem_no; i++)
        {
                ret[i] = -1;
        }
	//two-dimension array kmallocing
	mem_pool = kmalloc(mem_no*sizeof(struct gen_pool*),GFP_KERNEL);
        for (i = 0; i < mem_no; i++)
        {
                mem_pool[i] = kmalloc(sizeof(struct gen_pool),GFP_KERNEL);
        }

	//printk("Remapping reserved memory area\n");

	for (i = 0; i < mem_no; i++)
        {
         	__pool_kva_lo[i] = (unsigned long)memremap(mem[i].start, mem[i].size, MEMREMAP_WB);

                if (__pool_kva_lo[i] == 0) {
                        pr_err("Unable to request memory region @ 0x%08lx. Exiting.\n",mem[i].start);
                        goto unmap;
                }

		ret[i] = 0;
        }
	/*creating memory pools for different memory technologies*/
	for (i = 0; i < mem_no; i++)
        {
                mem_pool[i] = gen_pool_create(PAGE_SHIFT, NUMA_NODE_THIS);
                ret[i] |= gen_pool_add(mem_pool[i], (unsigned long)__pool_kva_lo[i],
                                       mem[i].size, NUMA_NODE_THIS);

                if (ret[i] != 0) {
			pr_err("Unable to initialize genalloc memory pool.\n");
                        goto unmap;
                }
        }

        kfree(mem);

        return 0;

unmap:
	printk("for now: here is unmap!\n");
	return -1;
	
}





/* static int cacheability_mod (pte_t *ptep, unsigned long addr,void *data) */
/* { */

/*         pte_t *pte = ptep; */
/*         size_t pfn; */
/*         pte_t newpte; */
/*         struct page *page = NULL; */
/*         void *page_v; */

/* //making new pte */
/* 	pfn = pte_pfn(*pte); //with the old pte                                                                                */
/* 	page = pte_page(*pte); */
/* 	page_v = kmap(page); */
	
/*        	newpte = pfn_pte(pfn, pgprot_writecombine(((struct Data*)data)->vmas->vm_page_prot)); */
                                                                                 
/* 	__clean_inval_dcache_area(page_v, PAGE_SIZE); */
		 
/* 	kunmap(page_v); */

/* 	/\*DBG_PRINT("CM: 0x%llx --> 0x%llx (VA: 0x%lx; PFN = 0x%lx)\n",                                                        */
/* 	  (long long)pte_val(*pte),                                                                                           */
/* 	  (long long)pte_val(newpte), addr, pfn);*\/ */

/* 	set_pte_at(current->mm, addr, pte, newpte);// each process has only one mm */
/* 	flush_tlb_page(((struct Data*)data)->vmas, addr); */

/* 	return 0; */
/* } */

/* this is for each page, it is applied to the length of just one page
   length = page_size*/
/* void __cacheability_modifier(unsigned long int user_vaddr, struct vm_area_struct *vma/\*,pte_t *pte*\/) */
/* { */
/* 	//struct Data data;// is not array, does not need kmalloc */
/* 	struct Data *data = kmalloc (sizeof(struct Data), GFP_KERNEL); */
/* 	data->vmas = vma; */
/* 	data->vaddr = user_vaddr; */
  
/* 	apply_to_page_range(data->vmas->vm_mm, data->vaddr,PAGE_SIZE,cacheability_mod, data); */
 
/* } */

void *pool_alloc(int pool_id, struct page *page, unsigned long private, struct vm_area_struct *vma)
{
	void *page_va;
	//printk("beginning of the allocation in the pool_alloc\n");

	if (!mem_pool[pool_id])
		return NULL;
	
	if (private == PVTPOOL_ALLOC_NOREPLACE) {
		void * old_page_va = page_va = page_to_virt(page);
		if(__addr_in_gen_pool(mem_pool[pool_id], (unsigned long)old_page_va, PAGE_SIZE)) {
			return page;
		}
	} else if (private == IS_PVTPOOL_PARAMS) {
		//params = (struct pvtpool_params *)page;
		if ((/*params->*/vma->vm_flags & VM_ALLOC_PVT_CORE) == 0)
			return NULL;
	}
	
	page_va = (void *)gen_pool_alloc(mem_pool[pool_id], PAGE_SIZE);

        //printk("POOL: Allocating VA: 0x%08lx\n", (unsigned long)page_va);

	if (!page_va) {
		pr_err("Unable to allocate page from colored pool.\n");
		return NULL;
	}

        set_page_count(virt_to_page(page_va), 1);

	if (verbose)
		dump_page(virt_to_page(page_va), "pool alloc debug");

	++__in_pool;

	///printk("POOL: [ALLOC] Current allocation: %d pages\n", __in_pool);

	return page_va ;
}

struct page * alloc_pool_page(struct page * page, unsigned long private)
{
 	void * page_va;
	int i, j;
	struct pvtpool_params * params;
	struct profile *myprofile = kmalloc(sizeof(struct profile), GFP_KERNEL);

	//printk("in allocation func of kernel module!\n");
	
	if (!current || !current->mm || !current->mm->prof_info /*|| !mem_pool[current->mm->prof_info->cpu_id]*/)
                return NULL;//returning NULL means default alloc of the kernel
	
	params = (struct pvtpool_params *)page; //now we have access to vma and addr

	myprofile = current->mm->prof_info;

	//printk("vma id is: %d\n", params->vma->vma_id);

	for (i = 0; i < myprofile->profile_len; i++) //for # of VMAs we have in our profile
	{
		struct profiled_vma *curr_vma = &myprofile->vmas[i];
		
		//printk("curr_vma->vma_id is : %d and difference is: %ld\n",
		//curr_vma->vma_id, (params->vma->vm_end - params->vma->vm_start)/PAGE_SIZE);
		
		if (params->vma->vma_id == curr_vma->vma_id) //just for the VMA we mean
		{
			for (j = 0; j < curr_vma->page_count; j++) //check for each page of VMA
			{

				//printk("IDs eq: params->vaddr: %x\n", params->vaddr);
				struct profiled_vma_page *curr_page = &curr_vma->pages[j];

				unsigned long int curr_addr = params->vma->vm_start +
					curr_page->page_index*PAGE_SIZE;
				
				//printk("curr_addr : %lx and params->vaddr : %lx\n", curr_addr, params->vaddr);
				if(curr_addr == params->vaddr)//if the page belongs to profile
				{
				  //printk("When addresses are equal\n");
                                        //allocate from the pool if the threshold;
					//if (curr_page->avg_cycles > N)
					if(curr_page->max_cycles < THRESHOLD)
					//allocate from this pool (all code below?)
					{
						page_va = pool_alloc(3, page, private, params->vma); //should be OCM
					}
					else
					{
						page_va = pool_alloc (3, page, private, params->vma); //should be DRAM
					}

					break;//break from which for
					
				}
				//else //if addr is not found
				//	return NULL;
			}
			
			break;
		}
	}
	
	kfree(myprofile);
	//check if this address of VMA belongs to profiler
	//params.vaddr
	//params = (struct pvtpool_params *)page;
	//now we have params.vaddr
	//we should check if this params.vaddr ==
	//first make addrr from index (start + myprofile->vmas[i]->pageindex*pagesize)
	//check if these two addresses are equal
	//if not return NULL so it goes to default alloc path
	//if yes, check the threshold for cycles
 	
 	/* printk("beginning of the allocation in the kernel module\n"); */
	/* if (private == PVTPOOL_ALLOC_NOREPLACE) { */
	/* 	void * old_page_va = page_va = page_to_virt(page); */
	/* 	if(__addr_in_gen_pool(mem_pool[2/\*current->mm->prof_info->cpu_id*\/], (unsigned long)old_page_va, PAGE_SIZE)) { */
	/* 		return page; */
	/* 	} */
	/* } else if (private == IS_PVTPOOL_PARAMS) { */
	/* 	params = (struct pvtpool_params *)page; */
	/* 	if ((params->vma->vm_flags & VM_ALLOC_PVT_CORE) == 0) */
	/* 		return NULL; */
	/* } */
	
	/* page_va = (void *)gen_pool_alloc(mem_pool[2 /\*current->mm->prof_info->cpu_id*\/], PAGE_SIZE); */

        /* printk("POOL: Allocating VA: 0x%08lx\n", (unsigned long)page_va); */

	/* if (!page_va) { */
	/* 	//pr_err("Unable to allocate page from colored pool.\n"); */
	/* 	return NULL; */
	/* } */

	/* if (verbose) */
	/* 	dump_page(virt_to_page(page_va), "pool alloc debug"); */

	/* ++__in_pool; */

	/* ///printk("POOL: [ALLOC] Current allocation: %d pages\n", __in_pool); */
	
	prefetch_page(page_va);

	return virt_to_page(page_va);

}
	


int __my_free_pvtpool_page (struct page * page)
{
 	void * page_va;
	int i;
	
	if(!current)
	{
		printk("current is NULL!\n");
		return 1;
	}

	for (i = 0; i < mem_no; i++){
		if (!mem_pool[i] || !page){
			printk("one of mem_pool or/and page are NULL :|\n");
			return 1;
		}
       
		page_va = page_to_virt(page);
       
		if(__addr_in_gen_pool(mem_pool[i], (unsigned long)page_va, PAGE_SIZE)) {
		  //printk("Dynamic de-allocation for phys page 0x%08llx\n",
		  //	       page_to_phys(page));

		
			if (verbose)
				dump_page(page, "pool dealloc debug");

			gen_pool_free(mem_pool[i], (unsigned long)page_va, PAGE_SIZE);

			--__in_pool;

			///		printk("POOL: [FREE] Current allocation: %d pages\n", __in_pool);

			return 0;
		}
	}

        return 1;

}


static int mm_exp_load(void){

	int init;
	int* ret;
	
	//printk(KERN_INFO "Online CPUs: %d, Present CPUs: %d\n", num_online_cpus(),num_present_cpus());
	
	pool_range(); //reading start and size from dtb for making memory pools
	//printk("outside the pool_range() and mem_no is:%d\n",mem_no);
	//int ret[mem_no];
    
        ret = kmalloc(mem_no*sizeof(int),GFP_KERNEL);

	/*initialization of memory pools*/
	init = initializer(ret);
        if (init == 0)
	  // printk("init is %d\n",init);
        //printk("after mem_pool initialization\n");

	//Install handlers (callback function)
	/* Install handler for pages released by the kernel at task completion 
	   and for changing page-level cacheability*/
	free_pvtpool_page = __my_free_pvtpool_page;
        alloc_pvtpool_page = alloc_pool_page;
	profile_decomposer = my_profile_decomposer;

	//pr_info("KPROFILER module installed successfully.\n");

	return 0;

}	
	

static void mm_exp_unload(void)
{
	int i;

	/* destroy genalloc memory pool */
	for (i = 0; i < mem_no; i++)
	{
	
		if (mem_pool[i]){
	                gen_pool_destroy(mem_pool[i]);
			//printk("destroying happened successfully\n");
		}
	}
        

	/* Unmap & release memory regions */
	for (i = 0; i < mem_no; i++)
	{
		memunmap((void *)__pool_kva_lo[i]);
	}

	//release the handler
	free_pvtpool_page = NULL;
	alloc_pvtpool_page = NULL;
	profile_decomposer = NULL;

	//pr_info("KPROFILER module uninstalled successfully.\n");
}

module_init(mm_exp_load);
module_exit(mm_exp_unload);

MODULE_AUTHOR ("Golsana Ghaemi, Renato Mancuso");
MODULE_DESCRIPTION ("memory profiler to characterize different memories in the system");
MODULE_LICENSE("GPL");
