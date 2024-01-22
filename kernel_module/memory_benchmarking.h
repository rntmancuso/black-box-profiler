#ifndef __MEM_BENCHMARKING_H__
#define __MEM_BENCHMARKING_H__

#define PREFIX                "[MemFiler] "
#define ACTIVITY_BANDWIDTH    (1)
#define ACTIVITY_LATENCY      (2)
#define DEFAULT_ITER          (100) /* Nr. of iterations for the benchmark */ 
#define DEFAULT_BUFFER_SIZE   (1*1024*1024) /* Deafult buffers size */ 
#define NUMA_NODE_THIS        -1
#define CACHE_LINE            64
#define BUF_TYPE              u64  /* type of data in allocated buffer
				    * which we read/write for BW
				    * benchmarking*/
/* 
   Helper macro to prefix any print statement produced by the host
   process.
*/

#ifndef _SILENT_
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
	u64 phys_start;  /* start physical addr of memory pool */
	u64 size;  /* size of memory pool */	
	unsigned char ready;
};

enum map_type {
	MAP_CACHE = 0, /* Cacheable mapping using mremap */
	MAP_NCACHE,    /* Non-cacheable mapping using ioremap */
};

enum access_type {
	ACCESS_BW_READ = 0, /* Normal read-only access to bufffer */
	ACCESS_BW_WRITE, /* Normal write-only access to bufffer */
	ACCESS_BW_RW, /* Normal read+write access to bufffer */
	ACCESS_BW_READ_NT, /* Read-only access to bufffer, non-temporal loads */
	ACCESS_BW_WRITE_NT, /* Write-only access to bufffer, non-tempral stores */
	ACCESS_BW_RW_NT, /* Read+write access to bufffer, non-temporal load/stores */
	ACCESS_LATENCY, /* Access in read-only with data dependencies */
	ACCESS_LATENCY_NT, /* Access in read-only with data dependencies, non-temporal loads */
};

struct activity_info
{
        volatile uint64_t g_nread; /* number of bytes read for BW benchmarking */

	union {
		enum map_type map_type; /* Type of mapping to be used: cacheable vs. non-cacheable */
		char __raw_map_type;
	};

	union {
		enum access_type access_type; /* Type of access to be used */
		char __raw_access_type;
	};
		
	ssize_t buffer_size; /*size of buffer we are allocating*/
	BUF_TYPE * buffer_va; /*kvirt addr of beginning of the buffer for BW benchmarking*/

	int pool_id; /* Index of the pool to target for this experiment */
	struct mem_pool * pool;
};

struct experiment_info {
	uint64_t bytes_count;
	struct activity_info obs_info;
	struct activity_info interf_info;
};

/* END - Kernel Module Structure Definition */

/**************for physical memory based on dtb 
memory type, MEM_START, MEM_SIZE
OCM, 0xfffc0000, 0x40000
BRAM, 0xa0000000, 0x100000         
DRAM, 0x10000000, 0x10000000 
FPGA-DRAM (mig), 0x4 0x00000000, 0x10000000
**********************************************/

/* START - Global variables exported to other compilation units */

/* Number of pools detected in the system */
extern unsigned int g_pools_count;

/* Array of pool descriptors of size g_pool_count */
extern struct mem_pool *g_pools;

/* END - Global variables exported to other compilation units */


/* START - Function prototypes */

/* Initialize the debugfs interface to communicate with the module */
int __init debugfs_interface_init(void);

/* Teardown the debugfs interface */
void __exit debugfs_interface_exit(void);

/* END - Function prototypes */

#endif
