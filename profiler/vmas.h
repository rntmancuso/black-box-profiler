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

#ifndef __PROFILER_VMAS_H__
#define __PROFILER_VMAS_H__

#ifdef __aarch64__
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#endif

/* Returns the total number of pages in the selected VMA targets */
int get_total_pages(struct vma_descr * vma_targets, unsigned int vma_count);

struct vma_descr * params_get_vma(struct profile_params * params,
				  struct profiled_vma * vma);

/* Add a new page/vma pair in the set of parameters that willl be
 * passed to the kernel. */
void params_add_page(struct profile_params * params, struct profiled_vma * vma,
		     struct profiled_vma_page * page);

/* Add an entire VMA to the parameter passed to the kernel */
void params_add_unprofiled_vma(struct profile_params * params,
			       unsigned int vma_index);

/* Add a VMA in the layout of the application under analysis, starting
 * from a vma descriptor extraced by the vma finder */
struct vma_descr * add_vma_descr(struct vma_descr *vma, struct vma_descr ** vmas,
				 unsigned int * vma_count);

/* Add a VMA in the layout of the application under analysis */
void add_vma(struct vma_struct *vma, struct vma_descr ** vmas,
	     unsigned int * vma_count);

/* This function allocates and fills up an array of VMAs */
int select_vmas(struct trace_params * tparams,
		struct vma_descr ** vmas, unsigned int * vma_count);

/* Find out the maximum VM size of the application. */
int detect_vmpeak(struct trace_params * tparams);

#endif
