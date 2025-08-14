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
#include <linux/cdev.h>

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

/* END   - Kernel Module Parameter Definition */

/**************for physical memory based on dtb 
memory type, MEM_START, MEM_SIZE
OCM, 0xfffc0000, 0x40000
BRAM, 0xa0000000, 0x100000         
DRAM, 0x10000000, 0x10000000 
FPGA-DRAM (mig), 0x5 0x00000000, 0x10000000
PV-HI 0x8 0x5dc00000,0x1f400000
PV-LO 40000000,  0x20000000
**********************************************/

/* START - Global variables */

/* Number of pools detected in the system */
unsigned int g_pools_count = 0;

/* Array of pool descriptors of size g_pool_count */
struct mem_pool *g_pools = NULL;
EXPORT_SYMBOL(g_pools);

/* END - Global variables */

volatile int g_exp_running = 1;   /* global var to tell activities on other core to start/stop*/
atomic_t g_stressor_id = ATOMIC_INIT(0); /* Used by the stressor cores to know their order of arrival */

/*defining spinlocks this way for dynamic initialization*/
static spinlock_t cpu_lock[4]; // one lock per core

/*-----------perf counters--aarch64-------------------*/
/*----PMCR_EL0:Performance Monitoring Control Register in ARMv8----*/
/** -- Initialization & boilerplate ---------------------------------------- */
#define ARMV8_PMCR_MASK         0x3f     /*Ensure only the relevant control bits are manipulated*/
#define ARMV8_PMCR_E            (1 << 0) /*  01 Enable all counters */
#define ARMV8_PMCR_P            (1 << 1) /*  10 Reset all counters */
#define ARMV8_PMCR_C            (1 << 2) /*  100 Cycle counter reset */
#define ARMV8_PMCR_D            (1 << 3) /*  CCNT counts every 64th cpu cycle */
#define ARMV8_PMCR_X            (1 << 4) /*  Export to ETM */
#define ARMV8_PMCR_DP           (1 << 5) /*  Disable CCNT if non-invasive debug*/
#define ARMV8_PMCR_N_SHIFT      11       /*  Number of counters supported */
#define ARMV8_PMCR_N_MASK       0x1f     /*mask or isolate the "Number of events" field in the PMCR_EL0 register*/

/*setting PMUSERENR_EL0 register's enable user-level performance monitoring feature for exception level 0 (EL0)**/
#define ARMV8_PMUSERENR_EN_EL0  (1 << 0) /*  EL0 access enable */
#define ARMV8_PMUSERENR_CR      (1 << 2) /*  Cycle counter read enable */
#define ARMV8_PMUSERENR_ER      (1 << 3) /*  Event counter read enable */
///**PMCNTENSET_EL0 is a control register for the ARMv8 performance monitoring unit (PMU) in EL0**/
#define ARMV8_PMCNTENSET_EL0_ENABLE ((1<<31)| 0xF) /* *< Enable Perf count reg and bit0 bc -->continue */

//#define ARMV8_PMCNTENSET_EL1_ENABLE (1 << 31)

#define L2_CACHE_REFILL_EVENT    (0x17)    // Event code for L2 cache refill in ARMv8

#define PERF_DEF_OPTS (1 | 16)
#define PERF_OPT_RESET_CYCLES (2 | 4)
#define PERF_OPT_DIV64 (8)

static inline u32 armv8pmu_pmcr_read(void)
{
	u64 val=0;
	asm volatile("mrs %0, pmcr_el0" : "=r" (val));
	return (u32)val;
}

static inline void armv8pmu_pmcr_write(u32 val)
{
	val &= ARMV8_PMCR_MASK;
	isb();
	asm volatile("msr pmcr_el0, %0" : : "r" ((u64)val));
}
static void
setup_cpu_counters(struct activity_info * actInfo)
{
	/*  Initialize & Reset PMNC: C and P bits. */
	armv8pmu_pmcr_write(ARMV8_PMCR_P | ARMV8_PMCR_C);
	/*   Performance Monitors Count Enable Set register bit 30:0 disable, 31 enable
	     .also enable pmevcntr0. ...,pmevcntr3 */
	asm volatile("msr pmcntenset_el0, %0" : : "r" (ARMV8_PMCNTENSET_EL0_ENABLE));
	asm volatile("msr pmevtyper0_el0, %0" : : "r" (actInfo->perf_counter[0]));
	asm volatile("msr pmevtyper1_el0, %0" : : "r" (actInfo->perf_counter[1]));
	asm volatile("msr pmevtyper2_el0, %0" : : "r" (actInfo->perf_counter[2]));
	asm volatile("msr pmevtyper3_el0, %0" : : "r" (actInfo->perf_counter[3]));

	armv8pmu_pmcr_write(armv8pmu_pmcr_read() | ARMV8_PMCR_E);
}

static void
sample_cpu_counters(uint32_t * c1, uint32_t * c2, uint32_t * c3, uint32_t * c4)
{
	asm volatile("mrs %0, pmevcntr0_el0" : "=r" (*c1));
	asm volatile("mrs %0, pmevcntr1_el0" : "=r" (*c2));
	asm volatile("mrs %0, pmevcntr2_el0" : "=r" (*c3));
	asm volatile("mrs %0, pmevcntr3_el0" : "=r" (*c4));
}

static void
save_cpu_counters(uint32_t * c1, uint32_t * c2, uint32_t * c3, uint32_t * c4,
		  struct perf_results * results)
{
	uint32_t _c1 = 0, _c2 = 0, _c3 = 0, _c4 = 0;
	sample_cpu_counters(&_c1, &_c2, &_c3, &_c4);
	results->cnt[0] = _c1 - *c1;
	results->cnt[1] = _c2 - *c2;
	results->cnt[2] = _c3 - *c3;
	results->cnt[3] = _c4 - *c4;
}

static void
disable_cpu_counters(void* data)
{
	uint32_t r;
        DBG_PRINT("disabling user-mode PMU access on CPU #%d",
		  smp_processor_id());

	//#if __aarch64__
	asm volatile("mrs %0, pmuserenr_el0" : "=r"(r));
	DBG_PRINT("pmuserenr_el0 = %d\n", r);

	/*  Performance Monitors Count Enable Set register bit 31:0 disable, 1 enable */
	asm volatile("msr pmcntenset_el0, %0" : : "r" (0<<31));
	/*  Note above statement does not really clearing register...refer to doc */
	/*  Program PMU and disable all counters */
	armv8pmu_pmcr_write(armv8pmu_pmcr_read() |~ARMV8_PMCR_E);
	/*  disable user-mode access to counters. */
	asm volatile("msr pmuserenr_el0, %0" : : "r"((u64)0));

	//	#else
	//#error Unsupported Architecture
	//#endif
}
//#endif

/* int init_cpu_counters(void) */
/* { */
/* 	DBG_PRINT("Now enabling performance counters on all cores.\n"); */
/* 	on_each_cpu(enable_cpu_counters, NULL, 1); */
/* 	DBG_PRINT("Done.\n"); */
/* 	return 0; */
/* } */

int reset_cpu_counters(void)
{
	DBG_PRINT("Now enabling performance counters on all cores.\n");
	on_each_cpu(disable_cpu_counters, NULL, 1);
	DBG_PRINT("Done.\n");
	return 0;
}

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
	for (i = 0; i < g_pools_count; i++){
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
		//pool->pool_kva = (unsigned long) ioremap_wc(pool->phys_start, pool->size);

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

int latency_buffer_init(struct activity_info* actInfo)
{
	int i;
	uint64_t temp;
	uint64_t random;
	uint64_t next;
	uint64_t * perm;
	uint64_t perm_len = actInfo->buffer_size / CACHE_LINE;
	printk("PERM_LEN IS : %lld\n", perm_len);
		   
	/* Allocate an array to keep as many indexes as the number of
	 * cacheline in the buffer to be initizaliezed*/
	perm = vmalloc(sizeof(uint64_t) * perm_len);
	if(!perm)
	{
		printk("Unable to allocate permutation buffer needed "
		       "to initialize the main buffer for latency experiment.\n");
		return -1;
	}
	
	/* Fill the elements of the permutation buffer */
	for (i = 0; i < perm_len; ++i)
	{
	       perm[i] = i;
		  //(i + 1) % perm_len;
	}

	/* Enact permutation on the support buffer first. This loop is
	  essentially performing a (large) number of random swaps in
	  the permutaion buffer. */
	for (i = 0; i < perm_len; ++i)
	{
		temp = perm[i];
		get_random_bytes(&random, sizeof(random));
		next = random % perm_len;
		perm[i] = perm[next];
		perm[next] = temp;
	}

	/* The permutation buffer is good to go. Now apply the
	 * permutations in the actual buyffer. */
	//actInfo->buffer_va[0] = perm[perm[perm_len -1]];
        for (i = 0; i < perm_len - 1; ++i)
	{
	  //actInfo->buffer_va[(i+1)*(CACHE_LINE/sizeof(BUF_TYPE))] = perm[perm[i]];
	  uint64_t index = perm[i];
	  uint64_t next = perm[i+1];
	  actInfo->buffer_va[(index)*(CACHE_LINE/sizeof(BUF_TYPE))] = next;
	}

	actInfo->buffer_va[(perm[i])*(CACHE_LINE/sizeof(BUF_TYPE))] = perm[0];

#if 0
	/* Just for debugging, print out the initialized latency buffer */
        for (i = 0; i < perm_len; ++i)
	{
		printk("[%4lld]", actInfo->buffer_va[i*(CACHE_LINE/sizeof(BUF_TYPE))]);
		if (i % 20 == 0)
			printk("\n");
	}
	printk("\n");
#endif	
	
	vfree(perm);
	
	return 0;
}

/* These are the low-level functions that correspond to the various
 * access types supported for benchmarking */

static inline void __access_bw_read (BUF_TYPE * r, BUF_TYPE * w, BUF_TYPE * end)
{
	BUF_TYPE tmp;
	
	(void)w;
	
	__asm__ volatile(
		"%=:               \n\t" 
		"ldr %0, [%1], %3  \n\t"  // Load from the address in r
		"cmp %2, %1        \n\t"  // Compare current and end pointers
		"b.hi %=b          \n\t"  // Loop if end not reached
		: "=&r" (tmp), "+r" (r)    // Output operand: store the result in tmp
		: "r"(end), "I" (BUF_INCR)  // Input operand: address to load from is in r
		: "memory"
		);
}

static inline void __access_bw_write (BUF_TYPE * r, BUF_TYPE * w, BUF_TYPE * end)
{
	BUF_TYPE tmp = (BUF_TYPE)w;
	
	__asm__ volatile(
		"%=:               \n\t" 
		"str %1, [%0], %3  \n\t"  // Store at the address in w
		"cmp %2, %0        \n\t"  // Compare current and end pointers
		"b.hi %=b          \n\t"  // Loop if end not reached
		: "+&r" (w)                // Output operand: store the result in tmp
		: "r" (tmp), "r"(end), "I" (BUF_INCR)  // Input operand: address to load from is in r
		: "memory"
		);

}

static inline void __access_bw_rw (BUF_TYPE * r, BUF_TYPE * w, BUF_TYPE * end)
{
	//printk(KERN_INFO "__access_bw_rw func at %s:%d\n", __FILE__, __LINE__);
	
	BUF_TYPE tmp;
		
	__asm__ volatile(
		"%=:               \n\t" 
		"ldr %0, [%1]      \n\t"  // Load from the address in r
		"str %0, [%1], %3  \n\t"  // Store at the address in r		
		"cmp %2, %1        \n\t"  // Compare current and end pointers
		"b.hi %=b          \n\t"  // Loop if end not reached
		: "=&r" (tmp), "+r" (r)    // Output operand: store the result in tmp
		: "r"(end), "I" (BUF_INCR)  // Input operand: address to load from is in r
		: "memory"
		);
}

static inline void __access_bw_read_nt(BUF_TYPE * r, BUF_TYPE * w, BUF_TYPE * end)
{
	BUF_TYPE tmp;// for trashing data we read

	(void)w;

	//#define __NC_IMPL_DCADD
#define __NC_IMPL_DCAFTER
#if defined __NC_IMPL_DCAFTER
	__asm__ volatile(
		"%=:               \n\t" 
		"ldr %0, [%1], %3  \n\t"  // Load from the address in r
		"dc civac, %1      \n\t"  // Invalidate the next cacheline
		"cmp %2, %1        \n\t"  // Compare current and end pointers
		"b.hi %=b          \n\t"  // Loop if end not reached
		: "=&r" (tmp), "+r" (r)    // Output operand: store the result in tmp
		: "r"(end), "I" (BUF_INCR)  // Input operand: address to load from is in r
		: "memory"
		);
#endif
#if defined __NC_IMPL_DCADD
	__asm__ volatile(
		"%=:               \n\t" 
		"ldr %0, [%1]      \n\t"  // Load from the address in r
		"dc civac, %1      \n\t"  // Invalidate the next cacheline
		"add %1, %1, %3    \n\t"  // Move to the next cacheline for next access
		"cmp %2, %1        \n\t"  // Compare current and end pointers
		"b.hi %=b          \n\t"  // Loop if end not reached
		: "=&r" (tmp), "+r" (r)    // Output operand: store the result in tmp
		: "r"(end), "I" (BUF_INCR)  // Input operand: address to load from is in r
		: "memory"
		);
#endif

}

/* Read normal memory with non-temporal load instructions. Does not
   work on Cortex A53. To achieve non-temporal reads, we use
   clean+invalidate instead.*/
static inline void __access_bw_read_nt_ldnp(BUF_TYPE * r, BUF_TYPE * w, BUF_TYPE * end)
{
	BUF_TYPE tmp1,tmp2;// for trashing data we read
	
	(void)w;

	__asm__ volatile(
		"%=:                  \n\t" 
		"ldnp %0, %1,[%2]     \n\t"  // Load from the address in r
		"add  %2, %2, %4      \n\t"
		"cmp %3, %2           \n\t"  // Compare current and end pointers
		"b.hi %=b             \n\t"  // Loop if end not reached
		: "=&r" (tmp1), "=&r" (tmp2), "+r" (r)    // Output operand: store the result in tmp
		: "r"(end), "I" (BUF_INCR)  // Input operand: address to load from is in r
		: "memory"
		);

}
/***********************************TEST NONCACHEABLE WRITE OPERATION***************************/
static inline void __access_bw_write_nstream (BUF_TYPE * r, BUF_TYPE * w, BUF_TYPE * end)
{
  //printk(KERN_INFO "__access_bw_write_nt func  %s:%d\n", __FILE__, __LINE__);

	BUF_TYPE tmp = (BUF_TYPE)w;

	//printk("WRITENT\n");
	
	    __asm__ volatile(
		"%=:               \n\t" 
		"dc zva, %0        \n\t"  // write zero in the memory, this is cosidered are our write
		"add %0, %0, %3    \n\t"
		"cmp %2, %0        \n\t"  // Compare current and end pointers
		"b.hi %=b          \n\t"  // Loop if end not reached
		: "+&r" (w)                // Output operand: store the result in tmp
		: "r" (tmp), "r"(end), "I" (BUF_INCR)  // Input operand: address to load from is in r
		: "memory"
		);
}

static inline void __access_bw_write_nt (BUF_TYPE * r, BUF_TYPE * w, BUF_TYPE * end)
{
         BUF_TYPE tmp = (BUF_TYPE)w;
	 
	 __asm__ volatile(
		"%=:               \n\t" 
		"str %1,[%0], %3        \n\t"  // store at the address in w
	        "dc civac, %0      \n\t"  // Invalidate the next cacheline
		"cmp %2, %0        \n\t"  // Compare current and end pointers
		"b.hi %=b          \n\t"  // Loop if end not reached
		: "+&r" (w)                // Output operand: store the result in tmp
		: "r" (tmp), "r"(end), "I" (BUF_INCR)  // Input operand: address to load from is in r
		: "memory"
		);


}
/*************************************************************************************************/

static inline void __access_lat_read(BUF_TYPE * r, BUF_TYPE * w, BUF_TYPE * end)
{
	BUF_TYPE * cur = &r[(*r) * CACHE_LINE/sizeof(BUF_TYPE)];

	/*printk("BEGINING OF LAT_READ: cur: %p, *r: %lld, *cur: %lld, (*r) * CACHE_LINE/sizeof(BUF_TYPE): %lld\n ",
	  cur, *r, *cur, (*r) * CACHE_LINE/sizeof(BUF_TYPE));*/
	//int lat_counter = 0;
	/* Loop until the pointer we are looking at is the same we
	 * started from. */
	while (cur != r)
	{
		cur = &r[(*cur) * CACHE_LINE/sizeof(BUF_TYPE)];
		//lat_counter++;
        		   
	}

	
	//printk("LAT_COUNTER : %d\n", lat_counter);
	/*printk("[LAT_COUNTER] is : %d and *cur is: %lld, cache/sizeof(buff type): %ld, multiplication : %lld \n",
	       lat_counter, (*cur), CACHE_LINE/sizeof(BUF_TYPE),
	       (*cur) * CACHE_LINE/sizeof(BUF_TYPE));*/
	//}

}


static inline void __access_lat_read_nt(BUF_TYPE * r, BUF_TYPE * w, BUF_TYPE * end)
{
	BUF_TYPE * cur = &r[(*r) * CACHE_LINE/sizeof(BUF_TYPE)];

	/* Loop until the pointer we are looking at is the same we
	 * started from. */
	while (cur != r)
	{
		cur = &r[(*cur) * CACHE_LINE/sizeof(BUF_TYPE)];
	        __asm__ volatile("dc civac, %0      \n\t"
			    :
			    :"r"(cur)
			    :"memory"
			    );
	}

}

static inline void __access_cache_clean_inv(BUF_TYPE * r, BUF_TYPE * w, BUF_TYPE * end)
{
	//BUF_TYPE tmp = (BUF_TYPE)w; //why in some places we have but we dont use?
	BUF_TYPE *start = r;
	//BUF_TYPE end = &end;
	BUF_TYPE line_size;


	__asm__ volatile(
		//"%=:               \n\t"
		"mrs %0, ctr_el0          \n\t"
		"ubfm %0, %0, #16, #19    \n\t"
		//"mov %0, #4               \n\t"
		"lsl %0, %0, #4           \n\t"
		: "=r" (line_size)
	);
	printk("the cache line size is %lld:\n", line_size);
       // Align the start address to the cache line boundary
	start = (BUF_TYPE*)((u64)start & (~(line_size - 1)));

       while (start < end){
	        __asm__ volatile(
			"dc civac, %0      \n\t"
			:
			:"r" (start)
			: "memory"
			);

		start = ((void*)start) + line_size;
       }

       __asm__ volatile("dsb sy         \n\t");   
     
}

/* Implementation of USTRESS access patterns. Assuming that the DRAM
   row bits are located at bit 15, and that column bits are LSB
   bits. */

#if 0
/* DRAM Geometry Specified Here */
#define USTRESS_COL_SHIFT  (0)
#define USTRESS_COL_BITS   (10)
#define USTRESS_BANK_SHIFT (COL_BITS)
#define USTRESS_BANK_BITS  (4)
#define USTRESS_ROW_SHIFT  (COL_BITS+BANK_BITS)
#define USTRESS_ROW_BITS   (15)
#define USTRESS_NEXT_ROW   (1 << ROW_SHIFT)
#define USTRESS_NEXT_COL   (BUF_INCR)
#define USTRESS_TOT_COLS   (1 << COL_BITS)  

static inline void __access_ustress_read (BUF_TYPE * r, BUF_TYPE * w, BUF_TYPE * end)
{
	BUF_TYPE tmp;
	
	(void)w;
	
	__asm__ volatile(
		"%=:               \n\t" 
		"ldr %0, [%1], %4  \n\t"  // Load from the address in r
		"cmp %2, %1        \n\t"  // Compare current and end pointers
		"b.hi %=b          \n\t"  // Loop if end not reached
		: "=&r" (tmp), "+r" (r)    // Output operand: store the result in tmp
		: "r"(end),               // End of buffer pointer
		  "I" (USTRESS_NEXT_COL), // Increment to target next column
		  "I" (USTRESS_NEXT_ROW), // Increment to target next row
		  "I" (USTRESS_TOT_COLS)  // Total number of columns to access
		: "memory"
		);
}

static inline void __access_ustress_write (BUF_TYPE * r, BUF_TYPE * w, BUF_TYPE * end)
{
	BUF_TYPE tmp = (BUF_TYPE)w;
	
	__asm__ volatile(
		"%=:               \n\t" 
		"str %1, [%0], %3  \n\t"  // Store at the address in w
		"cmp %2, %0        \n\t"  // Compare current and end pointers
		"b.hi %=b          \n\t"  // Loop if end not reached
		: "+&r" (w)                // Output operand: store the result in tmp
		: "r" (tmp), "r"(end), "I" (BUF_INCR)  // Input operand: address to load from is in r
		: "memory"
		);

}

#endif

#define ACCESS_BUFFER(start, end, access_type)				\
	do {								\
		register BUF_TYPE * __var = start;			\
		register BUF_TYPE *__end = end;                         \
	     	__access_##access_type(__var, __var, __end); \
	} while (0)

#define ACCESS_BUFFER_UNTIL(stop_cond, start, end, access_type)	\
	while(stop_cond) {					\
		ACCESS_BUFFER(start, end, access_type);		\
	}

#define ACCESS_BUFFER_REPEAT(repeat, start, end, access_type)	\
	do {							\
	        register int __cnt = 0;				\
		for(; __cnt < repeat; ++__cnt) {		\
			ACCESS_BUFFER(start, end, access_type);	\
		}						\
	} while (0)

#define ACCESS_BUFFER_NC(start, end, access_type)		\
	do {							\
	        register int __cnt = 0;				\
		for(; __cnt < 1; ++__cnt) {			\
			ACCESS_BUFFER(start, end, access_type);	\
		}						\
	} while (0)

static void activity_stress(void * params)
{
	struct activity_params * actParams = (struct activity_params *)params;
	struct activity_info * actInfo = actParams->act_info;
	struct experiment_result * expRes = actParams->exp_res;
	BUF_TYPE * buf_start;
	unsigned long flags;
	unsigned long local_id;
	uint32_t c1,c2,c3,c4;
	struct perf_results * cnts;
	
	/* Get local ID */
	local_id = atomic_inc_return(&g_stressor_id) -1;
	cnts = &expRes->interf_cnt[local_id];
	buf_start = actInfo->buffer_va + ((local_id) * actInfo->buffer_size/sizeof(BUF_TYPE));

	local_irq_save(flags);

	get_cpu();

	// Signal begin of activity
	spin_unlock(&cpu_lock[smp_processor_id()]);

	setup_cpu_counters(actInfo);
	sample_cpu_counters(&c1, &c2, &c3, &c4);

	switch (actInfo->access_type) {
	case ACCESS_BW_READ:
		ACCESS_BUFFER_UNTIL(g_exp_running, buf_start,
				    buf_start + actInfo->buffer_size/sizeof(BUF_TYPE),
				    bw_read);
		break;
	case ACCESS_BW_WRITE:
		ACCESS_BUFFER_UNTIL(g_exp_running, buf_start,
				    buf_start + actInfo->buffer_size/sizeof(BUF_TYPE),
				    bw_write);
		break;		
	case ACCESS_BW_RW:
		ACCESS_BUFFER_UNTIL(g_exp_running, buf_start,
				    buf_start + actInfo->buffer_size/sizeof(BUF_TYPE),
				    bw_rw);
		break;
	case ACCESS_BW_READ_NT:
		ACCESS_BUFFER_UNTIL(g_exp_running, buf_start,
				    buf_start + actInfo->buffer_size/sizeof(BUF_TYPE),
				    bw_read_nt);
		break;	
	case ACCESS_BW_WRITE_NT:
	        ACCESS_BUFFER_UNTIL(g_exp_running, buf_start,
				    buf_start + actInfo->buffer_size/sizeof(BUF_TYPE),
				    bw_write_nt);
		break;
	case ACCESS_BW_WRITE_NSTREAM:
	        ACCESS_BUFFER_UNTIL(g_exp_running, buf_start,
				    buf_start + actInfo->buffer_size/sizeof(BUF_TYPE),
				    bw_write_nstream);
		break;

	case ACCESS_BW_RW_NT:
	case ACCESS_LATENCY:
	        ACCESS_BUFFER_REPEAT(g_exp_running, buf_start,
				     buf_start + actInfo->buffer_size/sizeof(BUF_TYPE),
					     lat_read);
		break;
	case ACCESS_LATENCY_NT:
	        ACCESS_BUFFER_REPEAT(g_exp_running, buf_start,
					     buf_start + actInfo->buffer_size/sizeof(BUF_TYPE),
					     lat_read_nt);
		break;
	  
	default:
		break;		
	};
	save_cpu_counters(&c1, &c2, &c3, &c4, cnts);

	// Signal end of activity
	spin_unlock(&cpu_lock[smp_processor_id()]);

        put_cpu();
	
	local_irq_restore(flags);
	//rcu_read_unlock_sched();
	printk("STRESS - END core id : %d\n",smp_processor_id());
}

static void activity_idle(void* params)
{
	unsigned long flags, local_id;
	struct activity_params * actParams = (struct activity_params *)params;
	struct activity_info * actInfo = actParams->act_info;
	struct experiment_result * expRes = actParams->exp_res;
	uint32_t c1,c2,c3,c4;
	struct perf_results * cnts;

	local_id = atomic_inc_return(&g_stressor_id) -1;
	cnts = &expRes->interf_cnt[local_id];

	local_irq_save(flags);
	//rcu_read_lock_sched();
		
	get_cpu();

	// Setup and acquire initial value of perf counters
	setup_cpu_counters(actInfo);
	sample_cpu_counters(&c1, &c2, &c3, &c4);

	// Signal that we have begun activity
	spin_unlock(&cpu_lock[smp_processor_id()]);
	
	/* CPU-bound busy loop */
	while (g_exp_running);

	// Signal that we are done with actitivty
	spin_unlock(&cpu_lock[smp_processor_id()]);

	// Acquire final value of perf counters and store result of difference
	save_cpu_counters(&c1, &c2, &c3, &c4, cnts);
	
	put_cpu();

	local_irq_restore(flags);
	//rcu_read_unlock_sched();
	printk("IDLE - END core id : %d\n",smp_processor_id());
}

int alloc_init_buffers (struct experiment_info * expInfo)
{
	unsigned int cpus, i;

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
		if (latency_buffer_init(actInfo) < 0) {
			pr_err(PREFIX "Experiment ABORTED -- "
			       "unable to initialize buffer for latency access pattern.\n");
			return -1;
		}
	}
		
	/* Finally allocate memory to record the results of the experiment */
	expInfo->results = (struct experiment_result *)kmalloc(cpus * sizeof(struct experiment_result),
							       GFP_KERNEL);
	// Allocate perf counter results for all the cores
	for (i = 0; i < cpus; ++i) {
		/* Allocate buffers to hold the result of perf samples from interfering cores */
		expInfo->results[i].interf_cnt = (struct perf_results *)kmalloc((cpus-1) * sizeof(struct perf_results), GFP_KERNEL);		
	}
	
	return 0;		
}

void dealloc_results(struct experiment_info * expInfo)
{
	unsigned int cpus =  num_online_cpus();

	if (expInfo->results) {
		while (cpus--) {
			kfree(expInfo->results[cpus].interf_cnt);
		}
		kfree(expInfo->results);
		expInfo->results = NULL;
	}
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
	printk("in dealloc_buffers 1\n");
	
	if (actInfo->buffer_va) {
		gen_pool_free(actInfo->pool->alloc_pool,
			      (unsigned long)actInfo->buffer_va, actInfo->buffer_size);
		actInfo->buffer_va = NULL;
	}
	printk("in dalloc_buffers 2\n");
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
	if(expInfo->results) {
		pr_err(PREFIX "Experiment ABORTED -- non-null resultset at beginning of experiment.\n");
		return -1;		
	}

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
	int cpus = idle_cores_count + active_cores_count + 1;
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
	pr_info(PREFIX "DEBUG: setting activity masks. Local core: %d, "
		"idle cores: %d, active cores: %d\n",
		local_core, idle_cores_count, active_cores_count);

	pr_info(PREFIX "\tIDLE CORE IDs: ");
	for (c = 0; c < cpus; c++)
	{
		if(cpumask_test_cpu(c, idle_cores_mask))
			printk(KERN_CONT "%d, ", c);
	}
	pr_info(PREFIX "\n");

	pr_info(PREFIX "\tACTIVE CORE IDs: ");
	for (c = 0; c < cpus; c++)
	{
		if(cpumask_test_cpu(c, active_cores_mask))
			printk(KERN_CONT "%d, ", c);
	}
	pr_info(PREFIX "\n");	
}

void run_experiment (struct experiment_info * expInfo)
{
	unsigned long flags; // for interrupt state
	unsigned int cpus;
	long int i, c;
	int local_core;
	struct cpumask idle_cores, active_cores;
	int repeat = DEFAULT_ITER;
	uint32_t c1,c2,c3,c4;
	
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
	//init_cpu_counters();
	/* Main experiment loop -- i holds the number of cores that
	 * needs to be activated to generate interference, while (cpus - i)
	 * will be the number of cores to keep idle. */
	for (i = 0; i < cpus; i++)
	{
		/* Init statistics */
		struct experiment_result * result = &expInfo->results[i];
		struct activity_params interf_actParams = {
			.act_info = interf_actInfo,
			.exp_res = result
		};
		result->interf_cpus = i;

		/* Prepare the masks of cores that need to remain idle vs. activated at this iteration. */
		__prepare_activity_masks(&idle_cores, &active_cores, cpus - i - 1, i, local_core);
		//init_cpu_counters();//right place before changing	
		/* Globally mark the beginning of an experiment  */
		g_exp_running = 1;
		atomic_set(&g_stressor_id, 0);
		//local_irq_save(flags);
		/*starting remote activities*/
		on_each_cpu_mask(&idle_cores, activity_idle, &interf_actParams, false);
	        on_each_cpu_mask(&active_cores, activity_stress, &interf_actParams, false);
		printk("BEFORE the c loop for setting spinlock\n");
		/* This way for all locks corresponding to all remote
		  cores we are trying to grab the lock. spin_lock
		  spins and tries to acquire the lock*/
		for (c = 0; c < cpus; c++)
		{
		  printk("c : %ld and local_core : %d\n",c,local_core);
			if (c == local_core) continue; // we don want to spin on lock corresponds to local core

			/* When this lock is acquired, we know that core c has entered its main stress/idle loop. */
			spin_lock(&cpu_lock[c]);
			printk("C : %ld\n",c);
		}

		
		
		printk("MAIN - START\n");
		/*just in case -- if we do cacheable and nc experiments back to back
		 to make sure there is not any targeted addresses left in cache from cacheable experiment*/

		switch(actInfo->access_type) {
		case ACCESS_BW_READ_NT:
		case ACCESS_BW_WRITE_NT:
		case ACCESS_BW_WRITE_NSTREAM:
		case ACCESS_BW_RW_NT:
		case ACCESS_LATENCY_NT:
		        ACCESS_BUFFER_NC(actInfo->buffer_va,
				   actInfo->buffer_va + actInfo->buffer_size/sizeof(BUF_TYPE),
					 cache_clean_inv);
		        break;
		default:
			break;
		}
		
		//here was main place of irq save?
		local_irq_save(flags);
		//rcu_read_lock_sched();
		setup_cpu_counters(actInfo);
		sample_cpu_counters(&c1, &c2, &c3, &c4);		
		
		/*beginning of time mesurment*/
		result->exp_start = ktime_get_ns();

		// Benchmarking: perform REPEAT number of accesses to
		// memory buffer from observed core.
		/* TODO -- actually figure out which access type to use!! */

		switch (actInfo->access_type) {
		case ACCESS_BW_READ:
			ACCESS_BUFFER_REPEAT(repeat, actInfo->buffer_va,
					     actInfo->buffer_va + actInfo->buffer_size/sizeof(BUF_TYPE),
					     bw_read);
			break;
		case ACCESS_BW_WRITE:
			ACCESS_BUFFER_REPEAT(repeat, actInfo->buffer_va,
					     actInfo->buffer_va + actInfo->buffer_size/sizeof(BUF_TYPE),
					     bw_write);
			break;
		case ACCESS_BW_RW:
			ACCESS_BUFFER_REPEAT(repeat, actInfo->buffer_va,
					     actInfo->buffer_va + actInfo->buffer_size/sizeof(BUF_TYPE),
					     bw_rw);
			break;
		case ACCESS_BW_READ_NT:
			ACCESS_BUFFER_REPEAT(repeat, actInfo->buffer_va,
					     actInfo->buffer_va + actInfo->buffer_size/sizeof(BUF_TYPE),
					     bw_read_nt);
			break;
		case ACCESS_BW_WRITE_NT:
		  	ACCESS_BUFFER_REPEAT(repeat, actInfo->buffer_va,
					     actInfo->buffer_va + actInfo->buffer_size/sizeof(BUF_TYPE),
					     bw_write_nt);
			break;
		case ACCESS_BW_WRITE_NSTREAM:
		  	ACCESS_BUFFER_REPEAT(repeat, actInfo->buffer_va,
					     actInfo->buffer_va + actInfo->buffer_size/sizeof(BUF_TYPE),
					     bw_write_nstream);
			break;
		case ACCESS_BW_RW_NT:
			break;
		case ACCESS_LATENCY:
			ACCESS_BUFFER_REPEAT(repeat, actInfo->buffer_va,
					     actInfo->buffer_va + actInfo->buffer_size/sizeof(BUF_TYPE),
					     lat_read);
			break;			
		case ACCESS_LATENCY_NT:
		        ACCESS_BUFFER_REPEAT(repeat, actInfo->buffer_va,
					     actInfo->buffer_va + actInfo->buffer_size/sizeof(BUF_TYPE),
					     lat_read_nt);
			break;
		default:
			break;
		};

		result->exp_end = ktime_get_ns();

		// Acquire final value of perf counters and store result of difference
		save_cpu_counters(&c1, &c2, &c3, &c4, &result->obs_cnt);
		
		local_irq_restore(flags);
		//rcu_read_unlock_sched();
	        printk("MAIN - END\n");
		/* Ending remote activities */
		g_exp_running = 0;

		for (c = 0; c < cpus; c++)
		{
			if (c == local_core)
				continue; // we don want to spin on lock corresponds to local core
			
			spin_lock(&cpu_lock[c]);
		}
	        printk("MAIN - ALL DONE\n");
		/* Do we need a bit of delay here to allow the cores to exit? */
		msleep(100);

		/* Compute how much traffic was generated by this experiment */
		if (actInfo->access_type == ACCESS_BW_READ ||
		    actInfo->access_type == ACCESS_BW_WRITE ||
		    actInfo->access_type == ACCESS_BW_RW ||
		    actInfo->access_type == ACCESS_BW_READ_NT ||
		    actInfo->access_type == ACCESS_BW_WRITE_NT ||
		    actInfo->access_type == ACCESS_BW_RW_NT ||
		    actInfo->access_type == ACCESS_LATENCY ||
		    actInfo->access_type == ACCESS_LATENCY_NT) {
			result->bytes_r = actInfo->buffer_size * repeat;
		}

		if (actInfo->access_type == ACCESS_BW_WRITE ||
		    actInfo->access_type == ACCESS_BW_RW ||
		    actInfo->access_type == ACCESS_BW_WRITE_NT ||
		    actInfo->access_type == ACCESS_BW_WRITE_NSTREAM ||
		    actInfo->access_type == ACCESS_BW_RW_NT) {
			result->bytes_w = actInfo->buffer_size * repeat;
		} else {
			result->bytes_w = 0;
		}

		pr_info(PREFIX "Experiment Completed with %ld interfering cores.\n", i);
	} /* end of main loop */

	put_cpu();

	/* Make sure to deallocate the buffers on the way out. */
	dealloc_buffers(expInfo);	
}

static void deallocate_pools(void) {
	int i;
	
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
}

static int __init mm_exp_load(void) {

	int res;

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
		err_debugfs_interface_exit();
		return -EINVAL;
	}

	/* Go ahead and perform any initialization for the detected memory pools */
	res = initialize_pools();
	if (res < 0) {
		err_debugfs_interface_exit();
		pr_err(PREFIX "ERROR: Unable to correctly initialize memory pools.\n");
		return -EINVAL;
	}

	res = initialize_user_pools();
	if (res < 0) {
		err_debugfs_interface_exit();
		deallocate_pools();
		pr_err(PREFIX "ERROR: Unable to correctly initialize user memory pools.\n");
		return -EINVAL;
	}
	
	//init_cpu_counters();
	
	pr_info(PREFIX "===== success =====.\n\n");

	return 0;
}	
	

static void __exit mm_exp_unload(void)
{
	printk(PREFIX "===== Removing Memory Benchmarking Module =====\n");

	/* Destroy debufs interface */
	debugfs_interface_exit();

	/* Exit user-side pools */
	exit_user_pools();
	
	/* Deallocate kernel-side pools */
	deallocate_pools();
	
	reset_cpu_counters();

	//cache_monitor_exit();
	pr_info(PREFIX "===== success =====.\n\n");
}

module_init(mm_exp_load);
module_exit(mm_exp_unload);

MODULE_AUTHOR ("Golsana Ghaemi, Renato Mancuso");
MODULE_DESCRIPTION ("Memory profiler to characterize different memory technologies in the system");
MODULE_LICENSE("GPL");
