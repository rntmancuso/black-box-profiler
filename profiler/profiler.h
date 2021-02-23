 /*********************************************************************
 *                                                                    *
 *   This program can be used to acquire timing information for any   *
 *   function of a target program passed as a parameter.              *
 *                                                                    *
 *   Usage: functime <function name> <target binary> <target params>  *
 *                                                                    *
 *   Authors: Golsana Ghaemi (BU)                                     *
 *            Renato Mancuso (BU)                                     *
 *                                                                    *
 **********************************************************************/

/* Addresses of jumps will have a 1 in LSB to indicate that the CPU
   will jump to ARM code (as opposed to Thumb code). This mask is used
   to get rid of the extra 1 when reading memory content via ptrace
   syscalls. */
#define ARM_ISA_MASK (~(1UL))

extern int __run_flags;
extern int __print_layout;
extern enum page_operation __page_op;

/* Helper macro to prefix any print statement produced by the host
 * process. */
#ifdef _VERBOSE_
extern int __verbose_output;
#define DBG_PRINT(format, ...)						\
	do {								\
		if (__verbose_output)					\
			fprintf(stderr, "[DBG] " format, ##__VA_ARGS__); \
	} while (0)
#else
#define DBG_PRINT(format, ...)				\
	{}
#endif

#define DBG_INFO(format, ...)				\
	fprintf(stderr, "[DBG] " format, ##__VA_ARGS__)

#define DBG_INFO_NOPREF(format, ...)				\
	fprintf(stderr, format, ##__VA_ARGS__)

#define DBG_FATAL(format, ...)				\
	fprintf(stderr, "[DBG] FATAL: " format, ##__VA_ARGS__)

#define DBG_ABORT(format, ...)				\
	do {						\
		DBG_FATAL(format, ##__VA_ARGS__);	\
		exit(EXIT_FAILURE);			\
	} while(0)

#define DBG_PRINT_NOPREF(format, ...)		\
	fprintf(stderr, format, ##__VA_ARGS__)

#define DBG_PERROR(prefix)			\
	do {					\
		if (prefix == NULL)		\
			perror(" ");		\
		else				\
			perror(prefix);		\
	} while(0)


#define HELP_STRING					\
	"==== BU Black-box Cache Profiler ====\n"	\
	"Written by: Golsana Ghaemi\n"			\
	"            Renato Mancuso\n"			\
	"\n"						\
	"USAGE: %s [-h] -m <mode> -n <samples>\n"	\
	"       -c <cacheable> -s <symbol>\n"		\
	"\n"


/* The assembly opcode to use when inserting a breakpoint */
#define BRKPOINT_INSTR (0xffffffffUL)

#define KERN_PROCFILE "/proc/memprofile"

/*for vma scanning*/
#define mapped_file_fmt "%32s"
#define max_num_vma 1024
#define max_vma_mappedfile 33
#define PARENT_CPU 2 //for set_realtime
#define CHILD_CPU 2 //for set_realtime
#define STAGES 2

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

struct trace_params
{
	/* Symbol to install a breakpoint on */
	char * symbol;
       	pid_t pid;
	long brkpnt_data [STAGES];
	void * brkpnt_addr [STAGES];
	unsigned long t_start;
	unsigned long t_end;
	unsigned long vm_peak;
	unsigned int run_flags;

	/* To monitor memory activity */
	unsigned long m_start;
	unsigned long m_end;

	/* To find the text region for vma indexes */
	char * exe_name;
	char ** exe_params;
};

/*struct for keeping each line of process' mapping*/
struct vma_struct {
	unsigned long start;
	size_t len;
	unsigned long end;
	int target:1,
		shared:1,
		executable:1,
		readable:1,
		writable:1,
		fmapped:1,
		mprotected:1,
		reserved:1,
		stack:1,
		heap:1;
	int chunk_id;
	unsigned long offset;
	unsigned long inode;
	char perms[5];
	char dev[6];
	char mappedfile[max_vma_mappedfile];
	/* this is a bitmask of pages to lock  */
	//struct bitmask tolock;
};


struct profiled_vma_page {
	int page_index;
	unsigned long min_cycles;
	unsigned long max_cycles;
	double avg_cycles;
};

/*structure for keeping output of profiling mode-not relatedd to kernel*/
struct profiled_vma {
	unsigned int vma_index;
	unsigned int page_count;
	struct profiled_vma_page * pages;
};

struct profile {
	unsigned int profile_len;
	unsigned int num_samples;
	unsigned int heap_pad;
	struct profiled_vma * vmas;
};

/* Enum to keep track of the current stage in the execution of the
 * tracee */
enum tracee_stage {
	TRACEE_ENTRY = 0,
	TRACEE_EXIT,
	TRACEE_INIT,
};

enum page_operation {
	/* Make all pages non-cacheable but keep the ones in the list
	 * as cacheable */
	PAGE_CACHEABLE = 0,
	/* Keep all pages as cacheable, but make the ones in the list
	 * non-cacheable */
	PAGE_NONCACHEABLE,
	/* Migrate pages specified in the list to the private cache
	 * pool */
	PAGE_MIGRATE,
	/* Do not migrate pages, but instead allocate directly from
	 * private cache pool during faultin_vma operation */
	PAGE_PVTALLOC,
};

/* For measuring time directly through per-core cycle counters */
#ifdef __arm__
#define get_timing(cycles)					\
	do {							\
		asm volatile("mrc p15, 0, %0, c9, c13, 0"	\
			     : "=r" (cycles));			\
	} while (0)
#elif defined(__aarch64__)
#define get_timing(cycles)				\
	do {						\
		asm volatile("mrs %0, cntvct_el0"	\
			     : "=r"(cycles));		\
	} while (0)
#else
#ifndef __GET_TIMING_WARNED
#warning No get_timing routine implemented on this architecture!
#define get_timing(cycles) {}
#define __GET_TIMING_WARNED
#endif
#endif

#define __NR_perf_event_open 241
long long read_pmu(void);
