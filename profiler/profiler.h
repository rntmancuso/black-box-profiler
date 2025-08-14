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
extern int __non_realtime;
extern unsigned long __scan_flags;
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


#define HELP_STRING							\
	"==== BU Black-box Cache Profiler ====\n"			\
	"Written by: Golsana Ghaemi\n"					\
	"            Renato Mancuso\n"					\
	"            (Copyrights: Boston University)"			\
	"\n\n"								\
	"USAGE: %s [OPTIONS] -s <symbol> <exec.> [<exec. params>]\n\n"	\
	"OPTIONS:\n"							\
	"-h       \t Print this help message.\n"			\
	"-m MODE  \t Profiling mode: c = make page cacheable, everything else non-cacheable. (default)\n" \
	"         \t                 nc = make page non-cacheable, everything else cacheable.\n" \
	"-l       \t Print out application's layout when scanning VMAs.\n" \
	"-f FLAGS \t VMA scan flags: t = text, h = heap, s = stack, b = BSS, r = rodata\n" \
	"         \t                 a = first anon, A = all anon, m = libm, c = libc\n" \
	"         \t                 (default = hs)\n"			\
	"-r       \t Perform page ranking. Output sent to stdout.\n"	\
	"-o PATH  \t Save profile to file specified by PATH.\n"		\
	"-i PATH  \t Load profile from file specified by PATH.\n"	\
	"-p       \t Pretend mode, i.e. no kernel-side operations.\n"	\
	"-q       \t Quiet mode, i.e. output of tracee is suppressed.\n" \
	"-v       \t Verbose mode, i.e. show A LOT of debug messages.\n" \
	"-n NUM   \t Number of profiling samples to acquire and aggregate (default = 1).\n" \
	"-g NUM   \t Perform page migration. Migrate the NUM top-ranking pages.\n" \
	"-s SYM   \t Name of target function to profile in the target executable.\n" \
	"-t       \t Translate profile acquired or specified via -i parameter in human readable form.\n" \
	"-N       \t Non-realtime mode: do not set real-time priorities for profiler nor tracee.\n" \
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

/* Flags to control VMA selection */
#define SCAN_TEXT      0x0001
#define SCAN_HEAP      0x0002
#define SCAN_ANON      0x0004
#define SCAN_ALL_ANON  0x0008
#define SCAN_STACK     0x0010
#define SCAN_BSS       0x0020
#define SCAN_RODATA    0x0040
#define SCAN_GETLIBM   0x0080
#define SCAN_GETLIBC   0x0100

/* Include data structures shared between user and kernel module(s) */
#include "profiler_uapi.h"

/* Trace parameters definition */
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
	unsigned long vma_id;
	unsigned long offset;
	unsigned long inode;
	char perms[5];
	char dev[6];
	char mappedfile[max_vma_mappedfile];
	/* this is a bitmask of pages to lock  */
	//struct bitmask tolock;
};



/* Enum to keep track of the current stage in the execution of the
 * tracee */
enum tracee_stage {
	TRACEE_ENTRY = 0,
	TRACEE_EXIT,
	TRACEE_INIT,
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
