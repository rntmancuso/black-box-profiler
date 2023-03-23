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
//#include <linux/perf_event.h>
//#include <linux/perf_event.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
//#include <linux/seq_file.h>
#include <asm/atomic.h>
//#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/printk.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/smp.h> /* IPI calls */
//#include <linux/migrate.h>
//#include <linux/sched.h>
//#include <linux/list.h>
#include <linux/syscalls.h>
#include <asm-generic/getorder.h>
//#include <asm/tlbflush.h>
//#include <asm/page.h>
//#include <linux/hash.h>
#include <linux/ioport.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/mm.h>
//#include <asm-generic/pgalloc.h>
#include <asm/io.h>
//#include <linux/proc_fs.h>
//#include <linux/sched/mm.h>
#include <linux/of.h>

//#include <asm/mman.h>
#include <linux/smp.h>   /* for on_each_cpu */
#include <linux/kallsyms.h>
#include <linux/genalloc.h>
//#include <linux/timekeeping.h>
#include <linux/delay.h> /*for msleep() using as test*/
#include <linux/cpumask.h>
#include <linux/random.h>

/* #ifdef __arm__ */
/* #include <asm/cacheflush.h> /\*for processor L1 cache flushing*\/ */
/* #include <asm/outercache.h> */
/* #include <asm/hardware/cache-l2x0.h> */
/* #endif */


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
OCM, 0xfffc0000, 0x40000
BRAM, 0xa0000000, 0x100000         
DRAM, 0x10000000, 0x10000000 
FPGA-DRAM (mig), 0x4 0x00000000, 0x10000000
**********************************************/

int mem_no = 0; //for now, but I think is better to pass it rather than having as general

#define NUMA_NODE_THIS    -1

//#define THRESHOLD 62000000

#define CACHE_LINE  64

#define MY_TYPE int               /*type of data in allocated buffer which we read/write for BW benchmarking*/

volatile unsigned int g_start;	  /* starting time */
volatile unsigned int g_end;      /* ending time */

volatile int mywait = 1;          /*global var to tell activities on other core to start/stop*/

#define DEFAULT_ITER 100          /*number of iterations for the benchmark on the current core*/ 


//extern void __clean_inval_dcache_area(void * kaddr, size_t size);

/* Handle for remapped memory */
unsigned long  __pool_kva_lo[4];
//static void * __pool_kva_lo = NULL

/*Initializing spinlocks statically*/
//DEFINE_SPINLOCK(my_lock);
/* static spinlock_t my_lock[3] = { */
/* 	__SPIN_LOCK_UNLOCKED(my_lock_0), */
/* 	__SPIN_LOCK_UNLOCKED(my_lock_1), */
/* 	__SPIN_LOCK_UNLOCKED(my_lock_2), */
/* }; */

/*defining spinlocks this way for dynamic initialization*/
static spinlock_t my_lock[4]; // one lock per core

struct gen_pool ** mem_pool;

struct MemRange
{
  unsigned long start;  /*start addr of memory pool*/
  unsigned long size;  /*size of memory pool*/
};


struct activityInfo
{
        volatile uint64_t g_nread; /* number of bytes read for BW benchmarking */
	int* buffer_va; /*kvirt addr of beginning of the buffer for BW benchmarking*/
        long int* lat_buff_va;/*same as buffer_va but for latency benchmark*/
        unsigned long int buffer_size; /*size of buffer we are allocating*/
        int operation; /*latency or BW benchmarking?*/
  
};

//for keeping reg property of memory device node in dtb 
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
	printk("mem_ni is : %d\n",mem_no);
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
	  //__pool_kva_lo[i] = (unsigned long)ioremap_nocache(mem[i].start, mem[i].size);

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
	myinfo->buffer_va = (int *) gen_pool_alloc(mem_pool[2], myinfo->buffer_size);
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
	myinfo->lat_buff_va = (long int *) gen_pool_alloc(mem_pool[1], myinfo->buffer_size);
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
	int64_t sum;

	local_irq_save(flags);
	get_cpu();
	printk("we are on cpu: %d\n",smp_processor_id());

	spin_unlock(&my_lock[smp_processor_id()]);

	printk("[STRESS] first lock in STRESS :%d",!!spin_is_locked(&my_lock[smp_processor_id()]));


	/*allocating buffer*/
	//size of buffer for remote stress activities
	my_info.buffer_size = 1*1024*1024; //should we get this from outside?
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
		for ( i = 0; i < my_info.buffer_size/sizeof(MY_TYPE); i+=(CACHE_LINE/sizeof(MY_TYPE)) ) {
			sum += my_info.buffer_va[i];                                                                               	}
	}
	
	spin_unlock(&my_lock[smp_processor_id()]);

	printk("[STRESS] second lock in STRESS :%d",!!spin_is_locked(&my_lock[smp_processor_id()]));


	/*freeing the buffer*/
	gen_pool_free(mem_pool[2], (unsigned long)(my_info.buffer_va),my_info.buffer_size);
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

/*static int*/void measurment(void)
{
  
	//cycles_t start,end;
	unsigned long flags; // for interrupt state
	unsigned int dur, c;
	long int bandwidth, i;
	long int avglat; 
	int retval, j, k, z, local_core, counter1, counter2;
	struct cpumask mymask1, mymask2;
	uint64_t sum_read = 0;
	struct activityInfo myinfo;
	//int operation = 2; //for now latency
	int repeat = DEFAULT_ITER;

	
	myinfo.operation = 2; //latency
	myinfo.g_nread = 0;
        myinfo.buffer_size = 1*1024*1024; ///should I get this from user?
	
	printk("myinfo.operation is %d\n",myinfo.operation);

	/*allocation and initialization at the same time*/
	if (myinfo.operation == 1) //BANDWIDTH
	{
		retval = BW_buffer_allocation(&myinfo);//for remote cors I assume
		if (retval != 0) {
			printk("buffer_allocation() for BW failed.\n");
		}
	}

	if (myinfo.operation == 2) //LATENCY
	{
		retval = latency_buffer_allocation(&myinfo);//for remote cors I assume
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
		myinfo.g_nread = 0;


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
			printk("BEFORE MEASURMENT:lock[%d] is:%d\n",z,spin_is_locked(&my_lock[z]));
		    
		}

 
  
  
		local_irq_save(flags);
		/*beginning of time mesurment*/
		g_start = ktime_get_ns();

		//Benchmarking: accessing the memory
		for (i = 0; i < repeat; i++) //is just for repeating
		{
			if (myinfo.operation == 1)
			{
				sum_read += bandwidth_read(&myinfo);// pass as pointer to keep changes
			}
			
			else if (myinfo.operation == 2)
			{
				sum_read += latency_read(&myinfo); 
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
		if (myinfo.operation == 1) //BW
		{
			printk("g_nread(bytes read) = %lld\n", (uint64_t)(myinfo.g_nread));
			bandwidth = (uint64_t)myinfo.g_nread / dur;
			printk("B/W = %ld MB/s", bandwidth);
			
		}

		if (myinfo.operation == 2) //Latency
		{
		  avglat = dur/((myinfo.buffer_size*repeat)/CACHE_LINE);
		  printk("SIZE is %ld\n",((myinfo.buffer_size*repeat)/CACHE_LINE));
			printk("average latency is: %ld\n",avglat);
		}
	
	

	       
		} //j loop


	put_cpu();
	
	/*freeing the buffer*/
	if (myinfo.operation == 1) //BW
	  {
	    gen_pool_free(mem_pool[2], (unsigned long)(myinfo.buffer_va), myinfo.buffer_size);
	  }

	if (myinfo.operation == 2) //Latency
	  {
	    gen_pool_free(mem_pool[1], (unsigned long)(myinfo.lat_buff_va), myinfo.buffer_size);
	  }
	
}




static int mm_exp_load(void){

	int init;
	int* ret;
	
	printk(KERN_INFO "Online CPUs: %d, Present CPUs: %d\n", num_online_cpus(),num_present_cpus());
	
	pool_range(); /*reading start and size from dtb for making memory pools*/
    
        ret = kmalloc(mem_no*sizeof(int),GFP_KERNEL);

	/*initialization of memory pools*/
	init = initializer(ret);
        if (init == 0)
                printk("init is %d\n",init);
        printk("after mem_pool initialization\n");


	measurment(); /*benchmarking*/

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
