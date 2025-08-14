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

#ifndef __PROFILER_UAPI_H__
#define __PROFILER_UAPI_H__

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
	unsigned int vma_id;
	/* Number of pages in a specific VMA */
	unsigned int total_pages;
	/* Number of pages to perform operations on */
	unsigned int page_count;
	/* Command/operation to apply to the pages in this VMA */
	unsigned int operation;
	/* Array of page offsets on which an operation is to be performed */
	unsigned int * page_index;
};

struct profiled_vma_page {
	int page_index;
	unsigned long min_cycles;
	unsigned long max_cycles;
	double avg_cycles;
};

/*structure for keeping output of profiling mode-not relatedd to kernel*/
struct profiled_vma {
	unsigned int vma_id;
	unsigned int page_count;
	struct profiled_vma_page * pages;
};

struct profile {
	unsigned int profile_len;
	unsigned int num_samples;
	unsigned int heap_pad;
	struct profiled_vma * vmas;
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

#endif
