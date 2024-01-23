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

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 13, 0)
#  include <linux/sched/types.h>
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 8, 0)
#  include <linux/sched/rt.h>
#endif
#include <linux/sched.h>

#include "memory_benchmarking.h"

/* START - Kernel Module Parameter Definition */
int verbose = 0;
module_param(verbose, int, 0660);

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
volatile int g_exp_running = 1;   /* global var to tell activities on other core to start/stop*/

/*defining spinlocks this way for dynamic initialization*/
static spinlock_t cpu_lock[4]; // one lock per core

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
		pool->pool_kva = (unsigned long) memremap(pool->phys_start, pool->size, MEMREMAP_WB);

                if (pool->pool_kva == 0) {
                        pr_err(PREFIX "Unable to remap memory region @ 0x%08llx. Exiting.\n",
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
                        goto error_unmap;
                }
		
                res = gen_pool_add(pool->alloc_pool, (unsigned long)pool->pool_kva,
				   pool->size, NUMA_NODE_THIS);
                if (res != 0) {
			pr_err(PREFIX "Unable to initialize genalloc memory pool.\n");
                        goto error_unmap;
                }

		/* If everything goes well, mark this pool as ready. */
		pool->ready = 1;
        }

        return 0;

error_unmap:
	/* TODO actually unmap partially initialized pools before exiting */
	return -1;	
}

uint64_t latency_read(struct activity_info* myinfo)
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

int64_t bandwidth_read(struct activity_info* myinfo)
{
	int i;
	int64_t readsum = 0;
    
	for ( i = 0; i < myinfo->buffer_size/sizeof(BUF_TYPE); i+=(CACHE_LINE/sizeof(BUF_TYPE)) ) {

		readsum += myinfo->buffer_va[i];
	 
	}

	myinfo->g_nread += myinfo->buffer_size;// here g_nread is addr, we received as addr 

	return readsum;
}

int alloc_map_cache_buffer (struct activity_info * actInfo, int cpus) 
{ 
	int i;
	ssize_t total_size = actInfo->buffer_size * cpus;
     
	/* allocating buffer, buffer_va is the beginning addr */
	actInfo->buffer_va = (u64 *) gen_pool_alloc(actInfo->pool->alloc_pool, total_size);

	if (!(actInfo->buffer_va)) {
		return -1;
	}

	/* Fill the buffer/array */	
	for (i = 0; i < total_size/sizeof(BUF_TYPE); i++)
	{
		actInfo->buffer_va[i] = i;
	}

	return 0;
}

#if 0
int latency_buffer_allocation(struct activity_info* myinfo)
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
#endif 

/* These are the low-level functions that correspond to the various
 * access types supported for benchmarking */

static inline void __access_bw_read (BUF_TYPE * r, BUF_TYPE * w)
{
	BUF_TYPE tmp;
	
	(void)w;
	
	__asm__ volatile(
		"ldr %0, [%1]"  // Load from the address in r
		: "=r" (tmp)    // Output operand: store the result in tmp
		: "r" (r)       // Input operand: address to load from is in r
		: "memory"
		);
}

static inline void __access_bw_write (BUF_TYPE * r, BUF_TYPE * w)
{
	BUF_TYPE tmp;
	
	(void)r;
	
	__asm__ volatile(
		"str %1, [%0]"       // Store at the address in w
		:                    // No output operands
		: "r" (w), "r" (tmp) // Input operand: address to store at, and value to store
		: "memory"
		);
}

static inline void __access_bw_rw (BUF_TYPE * r, BUF_TYPE * w)
{
	BUF_TYPE tmp;
		
	__asm__ volatile(
		"ldr %0, [%1]\n\t"     // Load from the address in r
		"str %0, [%2]"       // Store into address in w
		: "=r" (tmp)         // Output operand: store the result in tmp
		: "r" (r), "r" (w)   // Input operand: address to load from is in r
		: "memory"
		);
}

#define ACCESS_BUFFER(var, start, end, incr, access_type)	\
	do {							\
		for (var = start; var < end; var += incr)	\
			__access_##access_type(var, var);	\
	} while (0)

static void activity_stress(void * params)
{
	struct activity_info * actInfo = (struct activity_info * )params;
	unsigned long flags;
	BUF_TYPE * ptr;

	local_irq_save(flags);
	get_cpu();
	spin_unlock(&cpu_lock[smp_processor_id()]);

	/* TODO -- actually figure out which access type to use!! */
	while(g_exp_running)
	{
		ACCESS_BUFFER(ptr, actInfo->buffer_va,
			      actInfo->buffer_va + actInfo->buffer_size/sizeof(BUF_TYPE),
			      CACHE_LINE/sizeof(BUF_TYPE),
			      bw_rw);
	}
	
	spin_unlock(&cpu_lock[smp_processor_id()]);

        put_cpu();
	local_irq_restore(flags);
}

static void activity_idle(void* params)
{
	unsigned long flags;
	
	local_irq_save(flags);
	
	get_cpu();
	spin_unlock(&cpu_lock[smp_processor_id()]);

	/* CPU-bound busy loop */
	while (g_exp_running);
  
	spin_unlock(&cpu_lock[smp_processor_id()]);

	put_cpu();
	local_irq_restore(flags);
}

int alloc_init_buffers (struct experiment_info * expInfo)
{

	unsigned int cpus;

	/* Retrieve the configuration for the activity to time on the
	 * observed core */
	struct activity_info * actInfo = &expInfo->obs_info;
	struct activity_info * interf_actInfo = &expInfo->interf_info;

	cpus = num_online_cpus();
	
	if (actInfo->buffer_va || interf_actInfo->buffer_va) {
		pr_err(PREFIX "Experiment ABORTED -- non-zero buffer pointers before init.\n");
		return -1;
	}

	if (actInfo->map_type == MAP_NCACHE || interf_actInfo->map_type == MAP_NCACHE) {
		pr_err(PREFIX "Experiment ABORTED -- MAP_NCACHE not supported yet.\n");
		return -1;		
	}

	/* Allocate cacheable buffer for core under analysis */
	if (actInfo->map_type == MAP_CACHE) 
	{
		if (alloc_map_cache_buffer(actInfo, 1) < 0) {
			pr_err(PREFIX "Experiment ABORTED -- "
			       "unable to allocate cacheable buffer for observed core.\n");
			return -1;			
		}
	}

	/* Allocate cacheable buffer for intefering cores analysis */
	if (interf_actInfo->map_type == MAP_CACHE) 
	{
		if (alloc_map_cache_buffer(interf_actInfo, cpus - 1) < 0) {
			pr_err(PREFIX "Experiment ABORTED -- "
			       "unable to allocate cacheable buffer for interfering cores.\n");
			return -1;			
		}
	}	
	
	if (actInfo->access_type == ACCESS_LATENCY || actInfo->access_type == ACCESS_LATENCY_NT)
	{
		pr_err(PREFIX "Experiment ABORTED -- ACCESS_LATENCY not supported yet.\n");
		return -1;		
	}
		
	return 0;		
}

void dealloc_buffers(struct experiment_info * expInfo)
{
	unsigned int cpus;

	/* Deallocate any buffer related to this experiment */
	/* Retrieve the configuration for the activity to time on the
	 * observed core */
	struct activity_info * actInfo = &expInfo->obs_info;
	struct activity_info * interf_actInfo = &expInfo->interf_info;

	cpus = num_online_cpus();
		
	if (actInfo->buffer_va) {
		gen_pool_free(actInfo->pool->alloc_pool,
			      (unsigned long)actInfo->buffer_va, actInfo->buffer_size);
		actInfo->buffer_va = NULL;
	}
	
	if (interf_actInfo->buffer_va) {
		gen_pool_free(interf_actInfo->pool->alloc_pool,
			      (unsigned long)interf_actInfo->buffer_va,
			      (cpus -1) * interf_actInfo->buffer_size);
		interf_actInfo->buffer_va = NULL;
	}
}

int validate_experiment (struct experiment_info * expInfo)
{
	unsigned int cpus;

	/* Retrieve the configuration for the activity to time on the
	 * observed core */
	struct activity_info * actInfo = &expInfo->obs_info;
	struct activity_info * interf_actInfo = &expInfo->interf_info;

	cpus = num_online_cpus();

	/* Clean-up and initialize aux fields */
	expInfo->bytes_count = 0;

	/* Find the pointer to the genpool allocation pools */
	if (actInfo->pool_id < 0 || actInfo->pool_id >= g_pools_count) {
		pr_err(PREFIX "Experiment ABORTED -- invalid pool ID: %d\n",
		       actInfo->pool_id);
		return -1;
	}

	if (!g_pools[actInfo->pool_id].ready) {
		pr_err(PREFIX "Experiment ABORTED -- selected non-ready pool ID: %d\n",
		       actInfo->pool_id);
		return -1;		
	}

	actInfo->pool = &g_pools[actInfo->pool_id];

	if (interf_actInfo->pool_id < 0 || interf_actInfo->pool_id >= g_pools_count) {
		pr_err(PREFIX "Experiment ABORTED -- invalid pool ID: %d\n",
		       actInfo->pool_id);
		return -1;
	}

	if (!g_pools[interf_actInfo->pool_id].ready) {
		pr_err(PREFIX "Experiment ABORTED -- selected non-ready pool ID: %d\n",
		       actInfo->pool_id);
		return -1;		
	}

	interf_actInfo->pool = &g_pools[interf_actInfo->pool_id];

	/* Check buffer sizes against poll sizes */
	if (actInfo->pool_id == interf_actInfo->pool_id) {
		/* Check that there is enough space in the pool if
		 * both observed CPU and interfering CPUs will use the
		 * same pool. */
		if (actInfo->buffer_size + (cpus-1) * interf_actInfo->buffer_size >
		    g_pools[actInfo->pool_id].size) {
			pr_err(PREFIX "Experiment ABORTED -- pool ID %d is too small\n",
			       actInfo->pool_id);
			return -1;
		}		
	} else {
		/* Check that there is enough space in the pool if
		 * both observed CPU and interfering CPUs will use
		 * different pools. */
		if (actInfo->buffer_size > g_pools[actInfo->pool_id].size) {
			pr_err(PREFIX "Experiment ABORTED -- pool ID %d is too small\n",
			       actInfo->pool_id);
			return -1;
		}
		if ((cpus-1) * interf_actInfo->buffer_size >
		    g_pools[interf_actInfo->pool_id].size) {
			pr_err(PREFIX "Experiment ABORTED -- pool ID %d is too small\n",
			       interf_actInfo->pool_id);
			return -1;
		}		
	}

	return 0;
}

static void __prepare_activity_masks(struct cpumask * idle_cores_mask,
				     struct cpumask * active_cores_mask,
				     int idle_cores_count, int active_cores_count,
				     int local_core)
{
	int cpus = idle_cores_count + active_cores_count;
	int idle_cores = 0, active_cores = 0;
	int c;
	
	/* Reset masks */
	cpumask_clear(idle_cores_mask);
	cpumask_clear(active_cores_mask);
	
	/* Loop over the CPUs and decide what core to assign to each
	 * activity mask */
	for (c = 0; c < cpus; c++)
	{
		/* The local observation core should not be assigned
		 * to any other activity. */
		if (c == local_core)
				continue;

		/* Are there more cores to keep idle? */
		if (idle_cores < idle_cores_count) 
		{
			cpumask_set_cpu(c, idle_cores_mask);
			idle_cores++;
		}
		/* If not, mark the other cores to be active. */
		else if (active_cores < active_cores_count)
		{
			cpumask_set_cpu(c, active_cores_mask);
			active_cores++;
		}	
	}
	
	/* DEBUG: let's print out the current settings */
	pr_info(PREFIX "\nDEBUG: setting activity masks. Local core: %d, "
		"idle cores: %d, active cores: %d\n",
		local_core, idle_cores_count, active_cores_count);

	pr_info(PREFIX "\tIDLE CORE IDs: ");
	for (c = 0; c < cpus; c++)
	{
		if(cpumask_test_cpu(c, idle_cores_mask))
			printk("%d, ", c);
	}
	pr_info(PREFIX "\n");

	pr_info(PREFIX "\tACTIVE CORE IDs: ");
	for (c = 0; c < cpus; c++)
	{
		if(cpumask_test_cpu(c, active_cores_mask))
			printk("%d, ", c);
	}
	pr_info(PREFIX "\n");	
}

void run_experiment (struct experiment_info * expInfo)
{
	unsigned long flags; // for interrupt state
	unsigned int dur, cpus;
	long int bandwidth, bandwidth_frac;
	long int i, j, c;
	long int avglat; 
	int local_core;
	struct cpumask idle_cores, active_cores;
	uint64_t sum_read = 0;
	int repeat = DEFAULT_ITER;

	/* Retrieve the configuration for the activity to time on the
	 * observed core */
	struct activity_info * actInfo = &expInfo->obs_info;
	struct activity_info * interf_actInfo = &expInfo->interf_info;

	cpus = num_online_cpus();

	if (validate_experiment(expInfo) < 0) {
		/* Experiment validation failed. Abort experiment. */
		return;
	}

	if (alloc_init_buffers(expInfo) < 0) {
		/* Buffer allocation failed. Abort experiment. */
		dealloc_buffers(expInfo);
		return;		
	}
	
	/* Initialize all the locks - TODO parametrize number of locks. */
	for (i = 0; i < cpus; i++)
	{
		spin_lock_init(&cpu_lock[i]);
		spin_lock(&cpu_lock[i]);	
	}

	local_core = get_cpu();
	
	/* Main experiment loop -- i holds the number of cores that
	 * needs to be activated to generate interference, while (cpus - i)
	 * will be the number of cores to keep idle. */
	for (i = 0; i < cpus; i++)
	{
		/* Reset statistics */
		actInfo->g_nread = 0;

		/* Prepare the masks of cores that need to remain idle vs. activated at this iteration. */
		__prepare_activity_masks(&idle_cores, &active_cores, cpus - i, i, local_core);
		
		/* Globally mark the beginning of an experiment  */
		g_exp_running = 1;
		
		/*starting remote activities*/
		on_each_cpu_mask(&idle_cores, activity_idle, NULL, false);
	        on_each_cpu_mask(&active_cores, activity_stress, interf_actInfo, false);

		/* This way for all locks corresponding to all remote
		  cores we are trying to grab the lock. spin_lock
		  spins and tries to acquire the lock*/
		for (c = 0; c < cpus; c++)
		{
			if (c == local_core) continue; // we don want to spin on lock corresponds to local core

			/* When this lock is acquired, we know that core c has entered its main stress/idle loop. */
			spin_lock(&cpu_lock[c]);
		}

		local_irq_save(flags);

		/*beginning of time mesurment*/
		g_start = ktime_get_ns();

		// Benchmarking: perform REPEAT number of accesses to
		// memory buffer from observed core.
		/* TODO -- actually figure out which access type to use!! */
		for (j = 0; j < repeat; j++)
		{
			BUF_TYPE * ptr;
			ACCESS_BUFFER(ptr, actInfo->buffer_va,
				      actInfo->buffer_va + actInfo->buffer_size/sizeof(BUF_TYPE),
				      CACHE_LINE/sizeof(BUF_TYPE),
				      bw_rw);			
		}

		g_end = ktime_get_ns();

		local_irq_restore(flags);

		/* Ending remote activities */
		g_exp_running = 0;

		for (c = 0; c < cpus; c++)
		{
			if (c == local_core) continue; // we don want to spin on lock corresponds to local core
			
			spin_lock(&cpu_lock[c]);
		}

		/* Do we need a bit of delay here to allow the cores to exit? */
		msleep(100);

		dur = g_end - g_start;

		printk("RESULT: elapsed = (%d usec)\n", dur);

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
	
	} /* end of main loop */


	put_cpu();

	/* Make sure to deallocate the buffers on the way out. */
	dealloc_buffers(expInfo);	
}

static void __print_activity(struct activity_info * actInfo)
{
	char * act_op2string [] = {"INVALID", "BANDWIDTH", "LATENCY"};
	printk(PREFIX "=== Activity Information: ===\n");
	printk(PREFIX "operation: %s\n", act_op2string[actInfo->operation]);
	printk(PREFIX "buffer_size: %ld bytes\n", actInfo->buffer_size);
	printk(PREFIX "=============================\n");
}


static int __init mm_exp_load(void) {

	int res;
	struct experiment_info expInfo;

	printk(PREFIX "===== Loading Memory Benchmarking Module =====\n");

	/* Setup the debugfs interface to communicate with the module */
	res = debugfs_interface_init();
	if (res < 0) {	
		pr_err(PREFIX "ERROR: Unable to correctly initialize interface files.\n");
		return -EINVAL;	
	}

	/* Start with the detection of the memory pools in the system. */
	res = detect_mempools();

	if (res < 0) {
		pr_err(PREFIX "ERROR: Unable to correctly detect memory pools.\n");
		return -EINVAL;
	}

	/* Go ahead and perform any initialization for the detected memory pools */
	res = initialize_pools();
	if (res < 0) {
		pr_err(PREFIX "ERROR: Unable to correctly initialize memory pools.\n");
		return -EINVAL;
	}

	/* This is just to try a sample experiment. Later, only the
	 * debugfs interface will be used to launch experiments and
	 * collect results. */
	expInfo.obs_info.map_type = MAP_CACHE;
	expInfo.obs_info.access_type = ACCESS_BW_RW;
        expInfo.obs_info.buffer_size = param_buffer_size;
	expInfo.obs_info.pool_id = 2;

	expInfo.interf_info.map_type = MAP_CACHE;
	expInfo.interf_info.access_type = ACCESS_BW_RW;
        expInfo.interf_info.buffer_size = 1*1024*1024; /* 1 MB */
	expInfo.interf_info.pool_id = 2;

	__print_activity(&expInfo.obs_info);
	
	run_experiment(&expInfo);

	pr_info(PREFIX "===== success =====.\n\n");

	return 0;
}	
	

static void __exit mm_exp_unload(void)
{
	int i;

	printk(PREFIX "===== Removing Memory Benchmarking Module =====\n");

	/* destroy genalloc memory pool */
	for (i = 0; i < g_pools_count; i++)
	{
		struct mem_pool *pool = &g_pools[i];
		if (pool->alloc_pool){
			pr_info(PREFIX "Destroying gen_pool %d\n", i);
	                gen_pool_destroy(pool->alloc_pool);
		}

		if (pool->pool_kva) {
			pr_info(PREFIX "Unmapping pool %d\n", i);
			memunmap((void *)pool->pool_kva);
		}
	}

	/* Free any memory taken by pool descriptors */
	if (g_pools_count) {
		kfree(g_pools);
		g_pools = NULL;
	}
	
	pr_info(PREFIX "===== success =====.\n\n");
}

module_init(mm_exp_load);
module_exit(mm_exp_unload);

MODULE_AUTHOR ("Golsana Ghaemi, Renato Mancuso");
MODULE_DESCRIPTION ("Memory profiler to characterize different memory technologies in the system");
MODULE_LICENSE("GPL");
