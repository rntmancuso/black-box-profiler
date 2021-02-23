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

#ifndef __PROFILER_UTILS_H__
#define __PROFILER_UTILS_H__

/* Run flags for traceee */
#define RUN_QUIET          (1 << 0)
#define RUN_SET_MALLOC     (1 << 1)

#define clear_disk_cache()				\
	system("echo 1 > /proc/sys/vm/drop_caches")

/* Collect profiling information after a single round of profiling,
 * i.e. after timing the effect of manipulating the cacheability of a
 * single page. */
void collect_profiling(struct profile * profile, struct trace_params * tparam,
		       struct vma_descr * vma,
		       unsigned int vma_idx, unsigned int page_idx);

/* This function recursively deallocates a profile structure */
void free_profile(struct profile * profile);
void free_params(struct profile_params * params);

/* Save an acquired profile to file specified via @filename. */
void save_profile(char * filename, const struct vma_descr * vma_targets,
		  const unsigned int vma_count, struct profile * profile);

/* Load an acquired profile from a file specified via @filename. */
void load_profile(char * filename, struct vma_descr ** vma_targets,
		  unsigned int * vma_count, struct profile * profile);

/* This function is used to build a struct profile_params where the
 * entire of target VMAs is passed but only 1 page at a time is
 * selected for kernel-side manipulation. */
void build_profiling_params(struct profile_params * out_profile,
			    struct vma_descr * vma_targets, unsigned int vma_count,
			    unsigned int vma_idx, unsigned int page_idx);

/* This function is used to build a partial struct profile_params
 * construct where only the most impactful @nr_pages are
 * included. This will then be passed to the lernel. */
void build_incremental_params(const struct profile * in_profile,
			      struct profile_params * out_profile,
			      struct vma_descr * vma_targets, unsigned int vma_count,
			      unsigned int nr_pages);

/* This function sets the VMA and page index for the current profiling
 * operation. When profiling, we know that the profile_params
 * structure will only contain a single VMA with a single page
 * index. */
void set_profiling_page(struct profile_params * params,
			struct vma_descr * vma, int page_index);

/* This function sets the desired operation to perform in the
 * kernel-side handling of the profile parameters */
void params_set_operation(struct profile_params * params, int operation);

/* Prints a nicely formatted view of the current profile */
void print_profile(struct profile * profile);

/* Prints a nicely formatted view of the parameters that will be
 * passed to the kernel */
void print_params(struct profile_params * params);

/* Allocate a new set of profile parameters */
struct profile_params * alloc_params(void);

/* Sort all the VMAs in the profile by cycles statistics */
void sort_profile_by_stats(struct profile * profile);

/* Sort all the VMAs in the profile by page index */
void sort_profile_by_idx(struct profile * profile);

/* Set real-time SCHED_FIFO scheduler with given priority */
void set_realtime(int prio, int cpu);

/* This function will attempt to resolve the address of a symbol
 * passed as a string via the second parameter in the ELF binary
 * provided in the first parameter. It will return the value of the
 * symbol as a pointer upon success. It will return (void *)-1 upon
 * failure. */
void * resolve_symbol(char * elf_path, char * symbol_to_search);

/* Run the debuggee until we hit the break-point */
int run_to_symbol(struct trace_params * tparams);

/* Run the debuggee until we hit the return instruction from the
 * observed function */
int run_to_return(struct trace_params * tparams);

/* Run the debuggee until we reach the end of execution */
int run_to_exit(struct trace_params * tparams);

/* Run the debuggee until the end. */
int run_to_completion(struct trace_params * tparams);

/* This function sets up signal handling in the parent so that we can
 * use synchronous handling for anything generated by the
 * tracee/child.
 */
void setup_signals(void);

/* Print a progress bar. Adapted from:
 * https://gist.github.com/amullins83/24b5ef48657c08c4005a8fab837b7499 */
void print_progress(const char * prefix, size_t count, size_t max);


#endif
