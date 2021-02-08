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

/* Collect profiling information after a single round of profiling,
 * i.e. after timing the effect of manipulating the cacheability of a
 * single page. */
void collect_profiling(struct profiler_output ** output, unsigned int * profile_len,
		       struct trace_params * tparam,
		       unsigned int vma_idx, unsigned int page_idx);

/* This function sets the VMA and page index for the current profiling
 * operation. When profiling, we know that the profile_params
 * structure will only contain a single VMA with a single page
 * index. */
void set_profiling_page(struct profile_params * params,
			struct vma_descr * vma, int page_index);

/* Allocate a new set of profile parameters */
struct profile_params * alloc_params(void);

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

/* Run the debuggee until we hit the break-point */
int run_to_completion(struct trace_params * tparams);


/* This function sets up signal handling in the parent so that we can
 * use synchronous handling for anything generated by the
 * tracee/child.
 */
void setup_signals(void);

#endif