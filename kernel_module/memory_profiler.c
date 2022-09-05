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


//unsigned long MEM_START[4]; //array for keeping the start address of each memory pool
//unsigned long MEM_SIZE[4];  //size of each memory pool
//TODO? enum for each memory (index for each mem to be used inabove arrays

int mem_no = 0; //for now, but I think is better to pass it rather than having as general

#define NUMA_NODE_THIS    -1

#define CACHE_LINE  64
#define BUFFER_SIZE 5*1024*1024            /*size of buffer we read from/write to for benchmarking*/
#define MY_TYPE int                        /*type of data in allocated buffer which we read/write*/
volatile unsigned int g_start;		   /* starting time */
volatile unsigned int g_end;               /* ending time */

/* Handle for remapped memory */
unsigned long  __pool_kva_lo[4];
//static void * __pool_kva_lo = NULL


struct gen_pool ** mem_pool;
//struct gen_pool * mem_pool[4];
//struct gen_pool * mem_pool = NULL;


struct MemRange
{
	unsigned long start;
	unsigned long size;
};

//for keeping reg property of memory device node in dtb
//struct MemRange mem[4]; 
struct MemRange *mem;

unsigned int get_usecs(void)
{
	//ktime_t time;
	struct timeval time; //inclduing sec and ns or us?
	time = ktime_to_timeval(ktime_get_real());
	return (time.tv_sec * 1000000 + time.tv_usec);
  
}

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
	//two-dimension array kmallocing
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

int64_t bench_read(int*  buffer_va, uint64_t* g_nread)
{
	int i;
	int64_t sum = 0;
	//int count = 0;  
	for ( i = 0; i < BUFFER_SIZE/sizeof(MY_TYPE); i+=(CACHE_LINE/sizeof(MY_TYPE)) ) {
	  sum += buffer_va[i];
	  //count++;
	}
	*(g_nread) += BUFFER_SIZE;// here g_nread is adddr, we received as addr 
	//printk("number of iteration in the memory buffer is: %d\n", count);
	return sum;
}

/*static int*/void  bandwidth_measurment(void)
{
	unsigned int cpu;
	//cycles_t start,end;
	unsigned int dur;
	long int bw,i;
	int* buffer_va; // virtual addr of kernel, data we want to read from/wr to our buffer is type of int
	int64_t sum_read = 0;
        volatile uint64_t g_nread = 0;/* number of bytes read */

	/*allocating buffer, buffer_va is the beginning addr*/
	buffer_va = (int *) gen_pool_alloc(mem_pool[2/*current->mm->prof_info->cpu_id*/], BUFFER_SIZE);
        printk("VA of beginning of the buffer: 0x%08lx\n",(unsigned long)buffer_va);

        if (!buffer_va) {
		printk("unable to allocate buffer.\n");
        }

	/*benchmarking operation*/
	cpu = get_cpu();
	printk("cpu ID is = %d\n",cpu);
	//start = get_cycles();
	g_start = get_usecs();
	
	//accessing the memory
	//for (i = 0; i < 10; i++)
	//{
	sum_read = bench_read(buffer_va, &g_nread);// pass ass pointer to keep changes
	//}

	//msleep(10); /*for test*/

	//end = get_cycles();
	g_end = get_usecs();
	
	put_cpu();

	dur = g_end - g_start;
	//printk("elapsed time is: %ld cycles\n", (end-start));
        printk("elapsed = ( %d usec )\n", dur);

	//bandwidth calculation
	printk("g_nread(bytes read) = %lld\n", (long long)g_nread);
	bw = g_nread / dur;
	printk("B/W = %ld B/s", bw);

	/*freeing the buffer*/
	gen_pool_free(mem_pool[2], (unsigned long)buffer_va, BUFFER_SIZE);
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

	bandwidth_measurment(); /*benchmarking the bandwidth*/

	pr_info("KPROFILER module installed successfully.\n");

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
			printk("destroying happened successfully\n");}
	}
        

	/* Unmap & release memory regions */
	for (i = 0; i < mem_no; i++)
	{
		memunmap((void *)__pool_kva_lo[i]);
	}

	pr_info("KPROFILER module uninstalled successfully.\n");
}

module_init(mm_exp_load);
module_exit(mm_exp_unload);

MODULE_AUTHOR ("Golsana Ghaemi, Renato Mancuso");
MODULE_DESCRIPTION ("memory profiler to characterize different memories in the system");
MODULE_LICENSE("GPL");
