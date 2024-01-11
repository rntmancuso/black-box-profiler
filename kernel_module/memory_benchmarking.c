/*memory profiler: reads different memory infrastructures from the dtb of the kernel,
  generates memory pools from those mem infrastructures, benchmarks these different memories
  for modeling them by collecting peak bw,...., and presents it (memory profiler's output) as
  ...*/
#include <linux/timex.h> //using get_cycles 

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/irq_work.h>
#include <linux/hardirq.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <asm/atomic.h>
#include <linux/vmalloc.h>
#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/printk.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/smp.h> /* IPI calls */
#include <linux/syscalls.h>
#include <asm-generic/getorder.h>
#include <linux/ioport.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <linux/of.h>
#include <linux/smp.h>   /* for on_each_cpu */
#include <linux/kallsyms.h>
#include <linux/genalloc.h>
#include <linux/delay.h> /*for msleep() using as test*/
#include <linux/cpumask.h>
#include <linux/random.h>

#define PREFIX                "[MemFiler] "
#define ACTIVITY_BANDWIDTH    (1)
#define ACTIVITY_LATENCY      (2)
#define DEFAULT_ITER          (100) /* Nr. of iterations for the benchmark */ 
#define DEFAULT_BUFFER_SIZE   (1*1024*1024) /* Deafult buffers size */ 
#define NUMA_NODE_THIS        -1
#define CACHE_LINE            64
#define MY_TYPE               int  /* type of data in allocated buffer
				    * which we read/write for BW
				    * benchmarking*/

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 13, 0)
#  include <linux/sched/types.h>
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 8, 0)
#  include <linux/sched/rt.h>
#endif
#include <linux/sched.h>


/* 
   Helper macro to prefix any print statement produced by the host
   process.
*/

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

/* START - Kernel Module Structure Definition */
struct mem_pool {
	struct gen_pool * alloc_pool;
	unsigned long pool_kva; /* start kernel virtual addr of memory pool */
	unsigned long phys_start;  /* start physical addr of memory pool */
	unsigned long size;  /* size of memory pool */	
	unsigned char ready;
};

struct activity_info
{
        volatile uint64_t g_nread; /* number of bytes read for BW benchmarking */
	int* buffer_va; /*kvirt addr of beginning of the buffer for BW benchmarking*/
        long int* lat_buff_va;/*same as buffer_va but for latency benchmark*/
        unsigned long int buffer_size; /*size of buffer we are allocating*/
        int operation; /*latency or BW benchmarking?*/
	struct gen_pool * alloc_pool;
};
/* END - Kernel Module Structure Definition */

/* START - Kernel Module Parameter Definition */
static long param_buffer_size = DEFAULT_BUFFER_SIZE;
module_param(param_buffer_size, long, S_IRUGO);

static int param_activity = ACTIVITY_BANDWIDTH;
module_param(param_activity, int, S_IRUGO);
/* END   - Kernel Module Parameter Definition */

/**************for physical memory based on dtb 
memory type, MEM_START, MEM_SIZE
OCM, 0xfffc0000, 0x40000
BRAM, 0xa0000000, 0x100000         
DRAM, 0x10000000, 0x10000000 
FPGA-DRAM (mig), 0x4 0x00000000, 0x10000000
**********************************************/

/* START - Global variables */

/* Number of pools detected in the system */
unsigned int g_pools_count = 0;

/* Array of pool descriptors of size g_pool_count */
struct mem_pool *g_pools = NULL;
/* END - Global variables */


volatile unsigned int g_start;	  /* starting time */
volatile unsigned int g_end;      /* ending time */
volatile int mywait = 1;          /*global var to tell activities on other core to start/stop*/

/*defining spinlocks this way for dynamic initialization*/
static spinlock_t my_lock[4]; // one lock per core

/* Scan through the device tree to detect memory pools. Returns the
 * number of detected pools to callee. Returns -1 in case of error. */
int detect_mempools(void)
{  
	struct device_node *found_node;
	int i;
	
        /* Scanning nodes in the first round for realizing the number
	 * of nodes with compatible = genpool*/
	found_node = NULL;
	do
	{
		found_node = of_find_compatible_node(found_node, "memory","genpool");
		if (found_node)
			g_pools_count++;
	}
	while(found_node != NULL);

	/* Now allocate the pool descriptors */
  	g_pools = kzalloc(g_pools_count * sizeof(struct mem_pool), GFP_KERNEL);
	
	
	/* Start the second scan round is for actually reading nodes
	  of dtb with compatible = genpool and retrieve the start addr
	  and the size of each type of memory node to make memory pool
	  with */

	found_node = NULL;
	for (i = 0; i <= g_pools_count; i++){
		found_node = of_find_compatible_node(found_node,"memory","genpool");

		if (!found_node){
			pr_err(PREFIX "Detection of memory pools terminated prematurely. "
			       "Expected %d pools, detected %d pools.\n", g_pools_count, (i+1));
			goto dealloc_error;
		}

		/* Read start address */
		of_property_read_u64_index(found_node, "reg", 0, &g_pools[i].phys_start);
		/* Read size */
		of_property_read_u64_index(found_node, "reg", 1, &g_pools[i].size);
	}

	return g_pools_count;
dealloc_error:
	kfree(g_pools);
	return -1;
}

/* Initialize memory pools by mapping them in kernel memory and
 * creating associated gen_pool structures. Returns 0 in case of
 * success and -1 in case of errors. */
int initialize_pools(void)
{
	int i;

	/* Remap all the physical address apertures in kernel memory
	 * as cacheable memory. */
	for (i = 0; i < g_pools_count; ++i)
        {
		struct mem_pool * pool = &g_pools[i];
		pool->pool_kva = (unsigned long) memremap(mem[i].start, mem[i].size, MEMREMAP_WB);

                if (pool->pool_kva == 0) {
                        pr_err(PREFIX "Unable to remap memory region @ 0x%08lx. Exiting.\n",
			       pool->phys_start);
                        goto error_unmap;
                }
        }
	
	/* Create gen_pool allocators for each pool. */
	for (i = 0; i < g_pools_count; i++)
        {
		struct mem_pool * pool = &g_pools[i];
		int res;
                pool->alloc_pool = gen_pool_create(PAGE_SHIFT, NUMA_NODE_THIS);

                if (pool->alloc_pool == NULL) {
			pr_err(PREFIX "Unable to create genalloc memory pool.\n");
                        goto unmap;
                }
		
                res = gen_pool_add(pool->alloc_pool, (unsigned long)pool->pool_kva,
				   pool->size, NUMA_NODE_THIS);
                if (res != 0) {
			pr_err(PREFIX "Unable to initialize genalloc memory pool.\n");
                        goto unmap;
                }

		/* If everything goes well, mark this pool as ready. */
		pool->read = 1;
        }

        return 0;

error_unmap:
	return -1;	
}

uint64_t latency_read(struct activityInfo* myinfo)
{
	int i;
	uint64_t readsum = 0;
	long int* shuffled = myinfo->lat_buff_va;

	long int pos = shuffled[0];
	for (i = 0; i < myinfo->buffer_size/CACHE_LINE; i += (CACHE_LINE/sizeof(long int)))
	{
		readsum += shuffled[pos];
		pos = shuffled[pos];
	}
	return readsum;
	
}

int64_t bandwidth_read(struct activityInfo* myinfo)
{
	int i;
	int64_t readsum = 0;
    
	for ( i = 0; i < myinfo->buffer_size/sizeof(MY_TYPE); i+=(CACHE_LINE/sizeof(MY_TYPE)) ) {

		readsum += myinfo->buffer_va[i];
	 
	}

	myinfo->g_nread += myinfo->buffer_size;// here g_nread is addr, we received as addr 

	return readsum;
}

int BW_buffer_allocation(struct activityInfo* myinfo) 
{ 
	int i;
     
	/*allocating buffer, buffer_va is the beginning addr*/
	myinfo->buffer_va = (int *) gen_pool_alloc(myinfo->alloc_pool, myinfo->buffer_size);
	printk("VA of beginning of the buffer: 0x%08lx\n",(unsigned long)(myinfo->buffer_va));

	if (!(myinfo->buffer_va)) {
		printk("unable to allocate buffer for bandwidth.\n");
		return 1;
	}

	/*filling the buffer/array*/	
	for ( i = 0; i < myinfo->buffer_size/sizeof(MY_TYPE); i++) //or buffer_size/cacheline??
	{
		myinfo->buffer_va[i] = i;
	}

	return 0;
}

int latency_buffer_allocation(struct activityInfo* myinfo)
{
	int i;
	long int temp;
	unsigned long random;
	unsigned long int next;
	long int* perm;
	
	/*allocating buffer, lat_buff_va is the beginning addr*/
	myinfo->lat_buff_va = (long int *) gen_pool_alloc(myinfo->alloc_pool, myinfo->buffer_size);
	printk("VA of beginning of the buffer: 0x%08lx\n",(unsigned long)(myinfo->lat_buff_va));
  
	if (!(myinfo->lat_buff_va)) {
		printk("unable to allocate buffer for latency.\n");
		return 1;
	}
	   

	//fill normally  before permutation
      
	perm = vmalloc (sizeof(long int)*myinfo->buffer_size);
	if(!perm)
	  {
	    printk("there is something wrong with the allocation using vmalloc!\n");
	    return 1;
	  }

	/*we fill cacheline by cacheline (granularity of cacheline*/
	for (i = 0; i < myinfo->buffer_size/CACHE_LINE; i ++)
	{
	  /*perm[0] = 0, perm[8] = 1, perm[16] = 2, ...*/
	  perm[i * (CACHE_LINE/sizeof(long int))] = i;
		
	}
        printk("At line: %s:%d\n", __FILE__, __LINE__);

	//permutation
	  /*this is number of accesses, our granularity is cache line,
	  we walk (access) on cache line not array element*/
	for (i = 0; i < myinfo->buffer_size/CACHE_LINE; i +=  (CACHE_LINE/sizeof(long int)))
	{
		temp = perm[i];
		//int next = rand() % (myinfo->buffer_size/CACHE_LINE);
		get_random_bytes(&random, sizeof(random));
		next = random % (myinfo->buffer_size/CACHE_LINE);
		next *= CACHE_LINE/sizeof(long int); //Do we really need this?
		perm[i] = perm[next];
		perm[next] = temp;
	}
	  
        printk("At line: %s:%d\n", __FILE__, __LINE__);
	printk("BOUNDARY: %ld\n", myinfo->buffer_size/CACHE_LINE);
	
	//shuffling
	//char* shuffled =
	///shuffled = myinfo->lat_buff_va;
	myinfo->lat_buff_va[0] = perm[0];
        for (i = 0; i < (myinfo->buffer_size/CACHE_LINE) - 1; i += CACHE_LINE/sizeof(long int))
	{
		myinfo->lat_buff_va[i+1] = perm[perm[i]];
	}

	printk("At line: %s:%d\n", __FILE__, __LINE__);

	//just for printing
	/* for (i = 0; i < myinfo->buffer_size/CACHE_LINE; i += CACHE_LINE/sizeof(long int)) */
	/* { */
	/* 	printk("shuffled[%d] = %ld\n",i, myinfo->lat_buff_va[i] ); */
	/* } */

	       
	return 0;
}


static void activity_stress(void* myinfo)
{
	struct activityInfo my_info;
	unsigned long flags;
	int i, retval;
	int64_t sum = 0;

	local_irq_save(flags);
	get_cpu();
	printk("we are on cpu: %d\n",smp_processor_id());

	spin_unlock(&my_lock[smp_processor_id()]);

	printk("[STRESS] first lock in STRESS :%d",!!spin_is_locked(&my_lock[smp_processor_id()]));


	/*allocating buffer*/
	//size of buffer for remote stress activities
	my_info.buffer_size = 1*1024*1024; //should we get this from outside?
	my_info.alloc_pool = mem_pool[2];
	printk("STRESS: before buffer_allocation()\n");

        /*for all stress activities no matter BW or latency we do BW stressing*/
	retval = BW_buffer_allocation(&my_info);
	if (retval != 0) {
		printk("BW_buffer_allocation() failed.\n");
		//return;
	}
	
	/*main activity*/
	while(mywait)
	{		
		for ( i = 0; i < my_info.buffer_size/sizeof(MY_TYPE);
		      i+=(CACHE_LINE/sizeof(MY_TYPE)) )
		{
			my_info.buffer_va[i] = i;
		}
	}
	
	spin_unlock(&my_lock[smp_processor_id()]);

	printk("[STRESS] second lock in STRESS :%d %lld",!!spin_is_locked(&my_lock[smp_processor_id()]),sum);


	/*freeing the buffer*/
	gen_pool_free(my_info.alloc_pool, (unsigned long)(my_info.buffer_va),my_info.buffer_size);
        put_cpu();
	local_irq_restore(flags);

}

static void activity_idle(void* myinfo)
{
	unsigned long flags;
	
	local_irq_save(flags);
	get_cpu();
        printk("IDLE: mywait before while is %d\n",mywait);

	spin_unlock(&my_lock[smp_processor_id()]);

	printk("[IDLE] first lock in IDLE :%d",!!spin_is_locked(&my_lock[smp_processor_id()]));

	/*main activity-busy loop*/
	while (mywait)
	{
		//break;
	}
  
	spin_unlock(&my_lock[smp_processor_id()]);

	printk("[IDLE] second lock in IDLE :%d",!!spin_is_locked(&my_lock[smp_processor_id()]));

	put_cpu();
	local_irq_restore(flags);

}

/*static int*/void measurement(struct activityInfo * actInfo)
{
  
	//cycles_t start,end;
	unsigned long flags; // for interrupt state
	unsigned int dur, c;
	long int bandwidth, bandwidth_frac, i;
	long int avglat; 
	int retval, j, k, z, local_core, counter1, counter2;
	struct cpumask mymask1, mymask2;
	uint64_t sum_read = 0;
	//int operation = 2; //for now latency
	int repeat = DEFAULT_ITER;
	
	printk("actInfo.operation is %d\n",actInfo->operation);

	/*allocation and initialization at the same time*/
	if (actInfo->operation == ACTIVITY_BANDWIDTH) //BANDWIDTH
	{
		retval = BW_buffer_allocation(actInfo);//for remote cors I assume
		if (retval != 0) {
			printk("buffer_allocation() for BW failed.\n");
		}
	}

	if (actInfo->operation == ACTIVITY_LATENCY) //LATENCY
	{
		retval = latency_buffer_allocation(actInfo);//for remote cors I assume
		if (retval != 0) {
			printk("buffer_allocation() for latency failed.\n");
		}
	}

	//Initializing locks
	for (i = 0; i < 4; i++)
	{
		spin_lock_init(&my_lock[i]);
		spin_lock(&my_lock[i]);
		//if locked, return value is 1
		printk("lock is :%d",spin_is_locked(&my_lock[i]));
	
	}


	local_core = get_cpu();
	printk("local_core is: %d\n",local_core);

	/*main activity loop*/
	for (j = 0; j < 4; j++)
	{
		/*reset masks at the begining of each iteration*/
		cpumask_clear(&mymask1);
		cpumask_clear(&mymask2);
		actInfo->g_nread = 0;


		//j = 3;
		printk(" j = %d\n",j);
		mywait = 1;
		counter1 = 0;
		counter2 = 0;
		printk("local core is(inside for): %d\n",local_core);
		/*c is # of cores which run the activity*/
		for ( c = 0; c < 4; c++)
		{
	
			if (c == local_core)
				continue;

			if (counter1 < j) //when we want just one core runs f1
			{
				//f1_mask.set(c);
				cpumask_set_cpu(c,&mymask1);
				counter1++;
			}
			else if (counter2 < (4-j))
			{
				cpumask_set_cpu(c,&mymask2);
				counter2++;
			}
		
		
		}

		/*for testing mymask*/
		for (k = 0; k < 4; k++)
		{
			if(cpumask_test_cpu(k,&mymask1))
				printk("mymask1 %d is set\n", k);
			//if(cpumask_test_cpu(k,&mymask2))
			//printk("mymask2 %d is set\n", k);

		}

		for (k = 0; k < 4; k++)
		{
			if(cpumask_test_cpu(k,&mymask2))
				printk("mymask2 %d is set\n", k);
			//if(cpumask_test_cpu(k,&mymask2))
			//printk("mymask2 %d is set\n", k);

		}

		/*starting remote activities*/
		on_each_cpu_mask(&mymask1,activity_idle,NULL,false);
	        on_each_cpu_mask(&mymask2,activity_stress,NULL,false);

		/*This way for all locks corresponding to all remote cores we are trying
		  to grab the lock. spin_lock spins and tries to acquire the lock*/
		for (z = 0; z < 4; z++)
		{
			if (z == local_core) continue; // we don want to spin on lock corresponds to local core
			spin_lock(&my_lock[z]);
			printk("BEFORE MEASUREMENT:lock[%d] is:%d\n",z,spin_is_locked(&my_lock[z]));
		    
		}

 
  
  
		local_irq_save(flags);
		/*beginning of time mesurment*/
		g_start = ktime_get_ns();

		//Benchmarking: accessing the memory
		for (i = 0; i < repeat; i++) //is just for repeating
		{
			if (actInfo->operation == ACTIVITY_BANDWIDTH)
			{
				sum_read += bandwidth_read(actInfo);// pass as pointer to keep changes
			}
			
			else if (actInfo->operation == ACTIVITY_LATENCY)
			{
				sum_read += latency_read(actInfo); 
			}
		}
		    

		g_end = ktime_get_ns();

		local_irq_restore(flags);

		/*ending remote activities*/
		mywait = 0;

		for (z = 0; z < 4; z++)
		{
			if (z == local_core) continue; // we don want to spin on lock corresponds to local core
			spin_lock(&my_lock[z]);
		}

		msleep(100);

		dur = g_end - g_start;
//	printk("elapsed time is: %ld cycles\n", (end-start));
		printk("elapsed = (%d usec)\n", dur);

		//calculation
		if (actInfo->operation == ACTIVITY_BANDWIDTH) //BW
		{
			printk("g_nread(bytes read) = %lld\n", (uint64_t)(actInfo->g_nread));
			bandwidth = (uint64_t)actInfo->g_nread / (dur / 1000);
			bandwidth_frac = (uint64_t)actInfo->g_nread % (dur / 1000);

			printk("B/W = %ld.%ld MB/s", bandwidth, bandwidth_frac);
			
		}

		if (actInfo->operation == ACTIVITY_LATENCY) //Latency
		{
		  avglat = dur/((actInfo->buffer_size*repeat)/CACHE_LINE);
		  printk("SIZE is %ld\n",((actInfo->buffer_size*repeat)/CACHE_LINE));
			printk("average latency is: %ld\n",avglat);
		}
	
	

	       
		} //j loop


	put_cpu();
	
	/*freeing the buffer*/
	if (actInfo->operation == ACTIVITY_BANDWIDTH) //BW
	  {
	    gen_pool_free(actInfo->alloc_pool, (unsigned long)(actInfo->buffer_va), actInfo->buffer_size);
	  }

	if (actInfo->operation == ACTIVITY_LATENCY) //Latency
	  {
	    gen_pool_free(actInfo->alloc_pool, (unsigned long)(actInfo->lat_buff_va), actInfo->buffer_size);
	  }
	
}

static void __print_activity(struct activityInfo * actInfo)
{
	char * act_op2string [] = {"INVALID", "BANDWIDTH", "LATENCY"};
	printk(PREFIX "=== Activity Information: ===\n");
	printk(PREFIX "operation: %s\n", act_op2string[actInfo->operation]);
	printk(PREFIX "buffer_size: %ld bytes\n", actInfo->buffer_size);
	printk(PREFIX "=============================\n");
}


static int mm_exp_load(void) {

	int res;
	int* ret;
	struct activityInfo actInfo;

	printk(PREFIX "===== Loading Memory Benchmarking Module =====\n");

	/* Start with the detection of the memory pools in the system. */
	res = detect_mempools();

	if (res < 0) {
		pr_err(PREFIX "ERROR: Unable to correctly detect memory pools.\n");
		return -EINVAL;
	}
    
	res = initialize_pools();
	if (res < 0) {
		pr_err(PREFIX "ERROR: Unable to correctly initialize memory pools.\n");
		return -EINVAL;
	}

	actInfo.operation = ACTIVITY_BANDWIDTH;
	actInfo.g_nread = 0;
	actInfo.alloc_pool = mem_pool[2];
        actInfo.buffer_size = param_buffer_size; ///should I get this from user? Yes!

	__print_activity(&actInfo);
	
	measurement(&actInfo); /*benchmarking*/

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
MODULE_DESCRIPTION ("Memory profiler to characterize different memory technologies in the system");
MODULE_LICENSE("GPL");
