/*memory profiler: reads different memory infrastructures from the dtb of the kernel,
generates memory pools from those mem infrastructures, benchmarks these different memories
for modeling them by collecting peak bw,...., and presents it (memory profiler's output) as
...*/
#include <asm-generic/timex.h>
#include <linux/kasan-checks.h>
#include <asm/arch_timer.h>
#include <clocksource/arm_arch_timer.h>                                                         
#include <asm/barrier.h> //getting counter                                                          
#include <asm/hwcap.h>
#include <asm/sysreg.h>
#include <asm/unistd.h>
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

/* #include <linux/timex.h> //using get_cycles */
/* #include <asm/barrier.h> //getting counter */
/* #include <asm/hwcap.h> */
/* #include <asm/sysreg.h> */


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



/**************for physical memory based on dtb 
memory type, MEM_START, MEM_SIZE
BRAM          
FPGA-DRAM           0xfffc0000UL 
OCM
DRAM
***************/

/* #define aarch_counter_enforce_ordering(val) do {			\ */
/* 	u64 tmp, _val = (val);						\ */
/* 									\ */
/* 	asm volatile(							\ */
/* 	"	eor	%0, %1, %1\n"					\ */
/* 	"	add	%0, sp, %0\n"					\ */
/* 	"	ldr	xzr, [%0]"					\ */
/* 	: "=r" (tmp) : "r" (_val));					\ */
/* } while (0) */

//unsigned long MEM_START[4]; //array for keeping the start address of each memory pool
//unsigned long MEM_SIZE[4];  //size of each memory pool
//TODO? enum for each memory (index for each mem to be used inabove arrays

int mem_no = 0; //for now, but I think is better to pass it rather than having as general

#define NUMA_NODE_THIS    -1

#define CACHE_LINE  64
#define BUFFER_SIZE 5*1024*1024
volatile uint64_t g_nread = 0;	           /* number of bytes read */

extern void __clean_inval_dcache_area(void * kaddr, size_t size);

/* Handle for remapped memory */
unsigned long  __pool_kva_lo[4];
//static void * __pool_kva_lo = NULL

/* This is just a hack: keep track of the (single) allocated page so *
 * that we can deallocate it upon module cleanup */
static unsigned int __in_pool = 0;

struct gen_pool ** mem_pool;
//struct gen_pool * mem_pool[4];
//struct gen_pool * mem_pool = NULL;

struct Data // for neccessary info for cacheability_modifier
{
	struct vm_area_struct  *vmas;
	unsigned long vaddr;
  //int count_vma;
  //#ifdef __aarch64__
  //struct mm_struct *mm;
  //#endif
};

struct MemRange
{
	unsigned long start;
	unsigned long size;
};

//for keeping reg property of memory device node in dtb
//struct MemRange mem[4]; 
struct MemRange *mem;


/* The kernel was modified to invoke an implementable function with *
 * the following prototype before returning any page to the per-CPU *
 * page cache (PCP) in free_unref_page_commit. The page should return
 * * 0 if the function was able to correctly return the page to the *
 * custom allocator, and 1 if the page does not belong to the pool and
 * * the normal deallocation route needs to be followed instead. */

extern struct page * (*alloc_pvtpool_page) (struct page *, unsigned long);
extern int (*free_pvtpool_page) (struct page *);
extern void (*cacheability_modifier)(unsigned long int user_vaddr, struct vm_area_struct *vma/*, pte_t *pte*/);


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

/* static __always_inline u64 get_cntpct(void) */
/* { */

/* 	u64 cnt; */

/* 	asm volatile(ALTERNATIVE("isb\n mrs %0, cntpct_el0", */
/* 				 "nop\n" __mrs_s("%0", SYS_CNTPCTSS_EL0), */
/* 				 ARM64_HAS_ECV) */
/* 		     : "=r" (cnt)); */
/* 	arch_counter_enforce_ordering(cnt); */
/* 	return cnt; */
/* } */

///*static int*/ void pool_range(void)// why static int? //designing error handling path
void pool_range(void){
  
	struct device_node **mem_type;
	struct device_node *node_count;
	u64 regs[2];//regs[0] = start and regs[1] = size 
	int rc,i,j;
	
	printk("inside pool_range()\n");

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
	  the start addr and the size of each type of memory node*/
	
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
        printk("mem[0].start : %llx, mem[0].size = %llx \n",regs[0], regs[1]);
        mem[0].start = regs[0];
        mem[0].size = regs[1];

	//for reading the start and size of rest of desired memory nodes
	for (i = 1; i <= mem_no; i++){
		mem_type[i] = of_find_compatible_node(mem_type[i-1],"memory","genpool");

		if (!mem_type[i]){
			printk("END of memory nodes\n");
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

		printk("mem[%d].start: %llx and mem[%d].size: %llx\n",i,regs[0],i,regs[1]);
		
		mem[i].start = regs[0];
		mem[i].size = regs[1];
	}
  

}

static int initializer(int* ret)
{
	int i;
	
	for (i = 0; i < mem_no; i++)
        {
                ret[i] = -1;
        }

	mem_pool = kmalloc(mem_no*sizeof(struct gen_pool*),GFP_KERNEL);
        for (i = 0; i < mem_no; i++)
        {
                mem_pool[i] = kmalloc(sizeof(struct gen_pool),GFP_KERNEL);
        }

	printk("Remapping reserved memory area\n");

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

/* void test(void) */
/* { */
/*   cycles_t start,end; */
/*   start = get_cycles(); */
/*   printk("for test\n"); */
/*   end = get_cycles(); */
/*   printk("elapsed time is:%ld\n",end-start); */
/* } */
int64_t bench_read(void* buffer_va)
{
	int i;	
	int64_t sum = 0;
	for ( i = 0; i < BUFFER_SIZE/4; i+=(CACHE_LINE/4) ) {
		sum += *(long long int*)(buffer_va + i);
	}
	g_nread += BUFFER_SIZE;
	return sum;
}

/*static int*/void  bandwidth_measurment(void)
{
	unsigned int cpu;
	cycles_t start,end;
	void * buffer_va; // virtual addr of kernel
	int64_t sum_read = 0;
        //volatile uint64_t g_nread = 0;/* number of bytes read */
	printk("before gen_pool_alloc\n");
        //allocating buffer, buffer_va is the beginning addr
	buffer_va = (void *)gen_pool_alloc(mem_pool[2/*current->mm->prof_info->cpu_id*/], BUFFER_SIZE);
        printk("VA of beginning of the buffer: 0x%08lx\n", (unsigned long)buffer_va);

        if (!buffer_va) {
                //pr_err("Unable to allocate page from colored pool.\n");                                                                            
                //return NULL;
		printk("unable to allocate buffer.\n");
        }
	
	//accessing memory
	cpu = get_cpu();
	start = get_cycles();
	
	printk("cpu ID is = %d\n",cpu);

	sum_read = bench_read(buffer_va/*,g_nread*/);
	printk("sum_read is %lld\n",sum_read);
	  /*for i = 0, i < what size? bigger than LLC, i+CACHE_LINE                                                                      
         read from the buffer (dereference the address) [function for read operation]                                                  
        addr + CACHE_LINE*/
	
	
	end = get_cycles();
	printk("elapsed time is: %ld cycles\n", (end-start));
	put_cpu();
}
	
static int cacheability_mod (pte_t *ptep, unsigned long addr,void *data)
{

        pte_t *pte = ptep;
        size_t pfn;
        pte_t newpte;
        struct page *page = NULL;
        void *page_v;

//making new pte
	pfn = pte_pfn(*pte); //with the old pte                                                                               
	page = pte_page(*pte);
	page_v = kmap(page);
	
       	newpte = pfn_pte(pfn, pgprot_writecombine(((struct Data*)data)->vmas->vm_page_prot));
                                                                                 
	__clean_inval_dcache_area(page_v, PAGE_SIZE);
		 
	kunmap(page_v);

	/*DBG_PRINT("CM: 0x%llx --> 0x%llx (VA: 0x%lx; PFN = 0x%lx)\n",                                                       
	  (long long)pte_val(*pte),                                                                                          
	  (long long)pte_val(newpte), addr, pfn);*/

	set_pte_at(current->mm, addr, pte, newpte);// each process has only one mm
	flush_tlb_page(((struct Data*)data)->vmas, addr);

	return 0;
}

/* void __cacheability_modifier(unsigned long int user_vaddr, struct vm_area_struct *vma) */
/* { */
/*   //struct Data data;// is not array, does not need kmalloc */
/*   struct Data *data = kmalloc (sizeof(struct Data), GFP_KERNEL); */
/*   data->vmas = vma; */
/*   data->vaddr = user_vaddr; */
  
/*   apply_to_page_range(data->vmas->vm_mm, data->vaddr,PAGE_SIZE, */
/*   		      cacheability_mod, data); */
/* } */


/* this is for each page, it is applied to the length of just one page
   length = page_size*/
void __cacheability_modifier(unsigned long int user_vaddr, struct vm_area_struct *vma/*,pte_t *pte*/)
{
	//struct Data data;// is not array, does not need kmalloc
	struct Data *data = kmalloc (sizeof(struct Data), GFP_KERNEL);
	data->vmas = vma;
	data->vaddr = user_vaddr;
  
	apply_to_page_range(data->vmas->vm_mm, data->vaddr,PAGE_SIZE,cacheability_mod, data);
 
}


struct page * alloc_pool_page(struct page * page, unsigned long private)
{
 	void * page_va;
	struct pvtpool_params * params;


	if (!current || !current->mm || !current->mm->prof_info || !mem_pool[current->mm->prof_info->cpu_id])
                return NULL;
	
 	printk("beginning of the allocation in the kernel module\n");
	if (private == PVTPOOL_ALLOC_NOREPLACE) {
		void * old_page_va = page_va = page_to_virt(page);
		if(__addr_in_gen_pool(mem_pool[current->mm->prof_info->cpu_id], (unsigned long)old_page_va, PAGE_SIZE)) {
			return page;
		}
	} else if (private == IS_PVTPOOL_PARAMS) {
		params = (struct pvtpool_params *)page;
		if ((params->vma->vm_flags & VM_ALLOC_PVT_CORE) == 0)
			return NULL;
	}
	
	page_va = (void *)gen_pool_alloc(mem_pool[/*1*/current->mm->prof_info->cpu_id], PAGE_SIZE);

        printk("POOL: Allocating VA: 0x%08lx\n", (unsigned long)page_va);

	if (!page_va) {
		//pr_err("Unable to allocate page from colored pool.\n");
		return NULL;
	}

	if (verbose)
		dump_page(virt_to_page(page_va), "pool alloc debug");

	++__in_pool;

	///printk("POOL: [ALLOC] Current allocation: %d pages\n", __in_pool);
	
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
			printk("Dynamic de-allocation for phys page 0x%08llx\n",
			       page_to_phys(page));

			set_page_count(page, 1);
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

	
	pool_range(); //reading start and size from dtb for making memory pools
	printk("outside the pool_range() and mem_no is:%d\n",mem_no);
	//int ret[mem_no];
    
        ret = kmalloc(mem_no*sizeof(int),GFP_KERNEL);

	/*initialization of memory pools*/
	init = initializer(ret);
        if (init == 0)
                printk("init is %d\n",init);
        printk("after mem_pool initialization\n");

	bandwidth_measurment();
	//test();
	
        /* Install handler for pages released by the kernel at task completion 
	   and for changing page-level cacheability*/
	free_pvtpool_page = __my_free_pvtpool_page;
        alloc_pvtpool_page = alloc_pool_page;
        cacheability_modifier = __cacheability_modifier;

	pr_info("KPROFILER module installed successfully.\n");

	return 0;

}	
	

static void mm_exp_unload(void)
{
	int i;
	printk("POOL: [UNLOAD] Current allocation: %d pages\n", __in_pool);

	/* destroy genalloc memory pool */
	for (i = 0; i < mem_no; i++)
	{
		if (mem_pool[i])
			gen_pool_destroy(mem_pool[i]);
	}
        

	/* Unmap & release memory regions */
	for (i = 0; i < mem_no; i++)
	{
		memunmap((void *)__pool_kva_lo[i]);
	}


	/* Release handler of page deallocations */
	free_pvtpool_page = NULL;
	alloc_pvtpool_page = NULL;
	cacheability_modifier = NULL;



	pr_info("KPROFILER module uninstalled successfully.\n");
}

module_init(mm_exp_load);
module_exit(mm_exp_unload);

MODULE_AUTHOR ("Golsana Ghaemi, Renato Mancuso");
MODULE_DESCRIPTION ("memory profiler to characterize different memories in the system");
MODULE_LICENSE("GPL");
