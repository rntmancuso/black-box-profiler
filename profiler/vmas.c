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

///
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdlib.h>
#include <sys/mman.h>   /* Memory locking functions */
#include <fcntl.h>
#include <stdbool.h>
#include <sched.h>

/* this part for reading elf */
#include <sys/types.h>
#include <sys/stat.h>
#include <libelf.h>
#include <gelf.h>
#include <sched.h>
#include <errno.h>

#include "profiler.h"
#include "utils.h"
#include "vmas.h"

/* Returns the total number of pages in the selected VMA targets */
int get_total_pages(struct vma_descr * vma_targets, unsigned int vma_count)
{
	int retval = 0;
	unsigned int i;
	for (i = 0; i < vma_count; ++i) {
		retval += vma_targets[i].total_pages;
	}

	return retval;
}


struct vma_descr * params_get_vma(struct profile_params * params,
					 struct profiled_vma * vma)
{
	unsigned int i;
	struct vma_descr * out_vma = NULL;

	for (i = 0; i < params->vma_count; ++i) {
		if (params->vmas[i].vma_index == vma->vma_index) {
			out_vma = &params->vmas[i];
			break;
		}
	}

	/* The VMA needs to be allocated? */
	if (!out_vma) {
		struct vma_descr tmp_vma;
		tmp_vma.vma_index = vma->vma_index;
		tmp_vma.page_count = vma->page_count;
		out_vma = add_vma_descr(&tmp_vma, &params->vmas, &params->vma_count);
	}

	return out_vma;
}

/* Retrieve the reference to the VMA descriptor inside the list of
 * parameters given a VMA descriptor from the application's memory
 * layput. The VMA will be added if missing. */
struct vma_descr * params_get_vma_descr(struct profile_params * params,
					struct vma_descr * vma)
{
	unsigned int i;
	struct vma_descr * out_vma = NULL;

	for (i = 0; i < params->vma_count; ++i) {
		if (params->vmas[i].vma_index == vma->vma_index) {
			out_vma = &params->vmas[i];
			break;
		}
	}

	/* The VMA needs to be allocated? */
	if (!out_vma) {
		out_vma = add_vma_descr(vma, &params->vmas, &params->vma_count);
	}

	return out_vma;
}

/* Add a new page/vma pair in the set of parameters that willl be
 * passed to the kernel. */
void params_add_page(struct profile_params * params, struct profiled_vma * vma,
		     struct profiled_vma_page * page)
{
	/* First off, let's figure out if a VMA with the same index
	 * already exists */
	struct vma_descr * out_vma = params_get_vma(params, vma);

	/* Here we know for sure that out_vma points to a valid VMA to
	 * which we will add the new page. */
	if (!out_vma->page_index) {
		out_vma->page_index = (unsigned int *)malloc(sizeof(unsigned int));
		out_vma->page_count = 1;
	} else {
		++out_vma->page_count;
		out_vma->page_index = (unsigned int *)realloc(out_vma->page_index,
				    out_vma->page_count * sizeof(unsigned int));
	}

	out_vma->page_index[out_vma->page_count-1] = page->page_index;
}

/* Add an entire VMA to the parameter passed to the kernel */
void params_add_unprofiled_vma(struct profile_params * params, unsigned int vma_index)
{
	/* Here we know for sure that out_vma points to a valid VMA to
	 * which we will add the new page. */

	/* NOTE: we use "(unsigned int)(-1)" to signal the kernel that
	 * we do not have any information about the size of this
	 * VMA. */
	struct vma_descr to_add = {
		.vma_index = vma_index,
		.total_pages = (unsigned int)(-1),
		.page_count = 0,
		.operation = __page_op,
		.page_index = NULL,
	};

	struct vma_descr * out_vma = params_get_vma_descr(params, &to_add);

	/* This should never happen */
	if (out_vma->page_index)
		DBG_ABORT("Adding non-profiled VMA %d but non-empty list of "
			  "pages exists in parameters.\n", vma_index);
}

struct vma_descr * add_vma_descr(struct vma_descr *vma, struct vma_descr ** vmas,
	     unsigned int * vma_count)
{
	unsigned int pos;
	if (*vmas == NULL) {
		*vma_count = 1;
		*vmas = (struct vma_descr *)malloc(sizeof(struct vma_descr));
	} else {
		(*vma_count)++;
		*vmas = (struct vma_descr *)realloc(*vmas,
				       sizeof(struct vma_descr) * (*vma_count));
	}

	/* Find out where to insert the new VMA */
	for (pos = 0; pos < (*vma_count) - 1; ++pos) {
		struct vma_descr * cur_vma = &(*vmas)[pos];
		if (cur_vma->vma_index > vma->vma_index)
			break;
	}

	if (pos < (*vma_count) - 1) {
		unsigned int to_move = ((*vma_count) - 1) - pos;
		memmove(&(*vmas)[pos+1], &(*vmas)[pos],
			to_move * sizeof(struct vma_descr));
	}

	struct vma_descr * new_vma = &(*vmas)[pos];
	new_vma->vma_index = vma->vma_index;
	new_vma->total_pages = vma->total_pages;

	/* Reset all the other fields */
	new_vma->page_count = 0;
	new_vma->operation = 0;
	new_vma->page_index = NULL;

	return new_vma;
}

void add_vma(struct vma_struct *vma, struct vma_descr ** vmas,
	     unsigned int * vma_count)
{
	if (*vmas == NULL) {
		*vma_count = 1;
		*vmas = (struct vma_descr *)malloc(sizeof(struct vma_descr));
	} else {
		(*vma_count)++;
		*vmas = (struct vma_descr *)realloc(*vmas,
				       sizeof(struct vma_descr) * (*vma_count));
	}

	struct vma_descr * new_vma = &(*vmas)[*vma_count-1];
	new_vma->vma_index = vma->chunk_id;
	new_vma->total_pages = (vma->end - vma->start) >> PAGE_SHIFT;

	/* Reset all the other fields */
	new_vma->page_count = 0;
	new_vma->operation = 0;
	new_vma->page_index = NULL;
}

static int vma_index_finder(struct vma_struct *vma, struct vma_descr ** vmas,
			    unsigned int * vma_count, unsigned int index)
{
	/* We assume that vma numbers are in increasing order */
	static int get_anon = 1;
	static int get_text = 1;
	static int get_bss = 1;
	static int get_rodata = 1;

	int get_heap = (__scan_flags & SCAN_HEAP);
	int get_stack = (__scan_flags & SCAN_STACK);

	/* Preprocess scan flags */
	if (get_anon && !(__scan_flags & SCAN_ANON))
	    get_anon = 0;

	if (get_text && !(__scan_flags & SCAN_TEXT))
	    get_text = 0;

	if (get_bss && !(__scan_flags & SCAN_BSS))
	    get_bss = 0;

	if (get_rodata && !(__scan_flags & SCAN_RODATA))
	    get_rodata = 0;

	if ((!(strcmp(vma->mappedfile,"anonymous")) && get_anon))
	{
		if (!(__scan_flags & SCAN_ALL_ANON))
			get_anon = 0; /* Get all the Anon areas */

		add_vma(vma, vmas, vma_count);
		return 1;
	}

	else if (get_heap && (strcmp(vma->mappedfile,"[heap]")) == 0)
	{
		add_vma(vma, vmas, vma_count);
		return 1;
	}

	else if  ((__scan_flags & SCAN_GETLIBM) &&
		  !vma->executable && strstr(vma->mappedfile, "libm"))
	{
		add_vma(vma, vmas, vma_count);
		return 1;
	}

	else if  ((__scan_flags & SCAN_GETLIBC) &&
		  !vma->executable && strstr(vma->mappedfile, "libc"))
	{
		add_vma(vma, vmas, vma_count);
		return 1;
	}


	else if  (vma->executable && get_text)
	{
		get_text = 0;
		add_vma(vma, vmas, vma_count);
		return 1;
	}

	else if  (vma->writable && get_bss && index < 3)
	{
		get_bss = 0;
		add_vma(vma, vmas, vma_count);
		return 1;
	}

	else if  (!vma->writable && !vma->executable && get_rodata && index < 3)
	{
		get_rodata = 0;
		add_vma(vma, vmas, vma_count);
		return 1;
	}


	else if (get_stack && (strcmp(vma->mappedfile,"[stack]")) == 0)
	{
		add_vma(vma, vmas, vma_count);
		return 1;
	}

	return 0;
}

static struct vma_struct * scan_proc_maps_line(int chunk_id, char const *buf)
{
	unsigned long start, end, offset, inode;
	char *p, perms[5], dev[6], mappedfile[max_vma_mappedfile];
	int rc;
	struct vma_struct * vma;

	/* FIXME This is horribly broken */
	mappedfile[0] = '\0';
	rc = sscanf(buf, "%lx-%lx %s %lx %s %lu " mapped_file_fmt ,
		    &start, &end, perms, &offset, dev, &inode, mappedfile);

	mappedfile[max_vma_mappedfile-1] = '\0';
	if (rc < 6) {
		DBG_ABORT("Invalid line in maps file.\n");
	}

	vma = (struct vma_struct *)malloc(sizeof(struct vma_struct));
	if (!vma) {
		DBG_ABORT("Memory allocation error.\n");
	}

	vma->chunk_id = chunk_id;
	vma->start = start;
	vma->end = end;
	vma->len = end-start;
	vma->offset = offset;
	vma->inode = inode;

        /* FIXME broken broken broken !! */
	strncpy(vma->perms, perms, 5);
	strncpy(vma->dev, dev, 6);
	if (strlen(mappedfile) > 0) {
		p = strrchr(buf, '/');
		if (p == NULL) {
			/* this looks like a single file name, so just
			 * truncate it, if necessary */
			strncpy(vma->mappedfile, mappedfile, max_vma_mappedfile-1);
			vma->mappedfile[max_vma_mappedfile-1]='\0';
		} else {
			/* this looks like a pathname, so select the
			 * last component */
			strncpy(vma->mappedfile, p+1, max_vma_mappedfile-1);
			vma->mappedfile[max_vma_mappedfile-1]='\0';
		}
	}
	else
		snprintf(vma->mappedfile, max_vma_mappedfile, "%s", "anonymous");

	vma->mappedfile[max_vma_mappedfile-1] = '\0';
	vma->readable = (perms[0] == 'r');
	vma->writable = (perms[1] == 'w');
	vma->executable = (perms[2] == 'x');
	vma->shared = (perms[3] == 's');
	vma->fmapped = (inode != 0);
	vma->mprotected = 0;
	vma->reserved = 0;
	vma->stack = (strcmp(mappedfile, "[stack]") == 0);
        if (strcmp(mappedfile, "[heap]") == 0)
		vma->heap = 1;

	return vma;
}


static void read_proc_maps_file(pid_t pid, struct vma_descr ** vmas,
			 unsigned int * vma_count)
{
	struct vma_struct * vma;
	unsigned int nvma = 0;
	char buf[256];
	char path[100];
	sprintf(path,"/proc/%d/maps", pid);

	FILE *f = fopen(path, "r");
	if (f == NULL) {
		DBG_ABORT("Unable to open file %s", path);
	}

	/* This is the beginning of a new scan. Make sure we reset any
	 * previos VMA count */
	*vma_count = 0;

	for(;;) {
		int added;

		if (fgets(buf, 256, f) == NULL)
		{
			if(feof(f))
				break;

		        DBG_ABORT("Error reading %s maps file.\n", path);
		}

		/* Make sure buffer is zero-terminated. */
		buf[255] = '\0';
		buf[strlen(buf)-1] = '\0';

		vma = scan_proc_maps_line(nvma, buf);

		/* for finding vma indices and size of each vma */
		added = vma_index_finder(vma, vmas, vma_count, nvma);

		if(__verbose_output || __print_layout) {
			DBG_INFO("[%3d] %c  %s\n", nvma, (added?'*':' '),buf);
		}

		free(vma);

		++nvma;
	}

	fclose(f);
}

/* This function allocates and fills up an array of VMAs */
int select_vmas(struct trace_params * tparams,
		struct vma_descr ** vmas, unsigned int * vma_count)
{
	int res;

	/* First off, run the target process until the breakpoint */
	res = run_to_symbol(tparams);

	if (res) {
		DBG_FATAL("Unable to run child until [%s]. Exiting.\n", tparams->symbol);
		return -1;
	}

	/* Scan the /proc/PID/maps file to recognize the application's
	 * memory layout and perform VMA selection. */
	read_proc_maps_file(tparams->pid, vmas, vma_count);

	/* NOTE: the tracee is still stopped at the breakpoint when we
	 * get here. We might want to kill it or just leverage this
	 * property to speed-up the first profiling iteration. */

	if (*vma_count == 0) {
		DBG_FATAL("No VMAs were selected for debugging.\n");
		return -1;
	}

	return 0;
}

/* Find out the maximum VM size of the application. */
int detect_vmpeak(struct trace_params * tparams)
{
	int retval;
	char buf[256];
	char path[100];
	tparams->vm_peak = 0;

	retval = run_to_return(tparams);

	if (retval)
		return retval;

	/* We have just completed the function under
	 * observation. Let's retrieve the max VM size */
	sprintf(path,"/proc/%d/status", tparams->pid);

	FILE *f = fopen(path, "r");
	if (f == NULL) {
		DBG_ABORT("Unable to open file %s", path);
	}

	for(;;) {
		if (fgets(buf, 256, f) == NULL)
		{
			if(feof(f))
				break;

		        DBG_ABORT("Error reading %s status file.\n", path);
		}

		/* Make sure buffer is zero-terminated. */
		buf[255] = '\0';
		buf[strlen(buf)-1] = '\0';

		if (strncmp("VmData:", buf, 7) == 0) {
			tparams->vm_peak = strtol(buf+7, NULL, 10);
			DBG_PRINT("VmData: %ld\n", tparams->vm_peak);
			break;
		}
	}

	fclose(f);

	if (!tparams->vm_peak)
		DBG_ABORT("Unable to determine peak VM size. Exiting.\n");

	retval = run_to_exit(tparams);

	tparams->run_flags |= RUN_SET_MALLOC;

	return retval;
}

/* Convert the passed string of scan flags into SCAN_* flags.  
   Acceptable string flags:
   t -> SCAN_TEXT
   h -> SCAN_HEAP
   a -> SCAN_ANON (first anon VMA)
   A -> SCAN_ALL_ANON
   s -> SCAN_STACK
   b -> SCAN_BSS
   r -> SCAN_RODATA
   m -> SCAN_GETLIBM
   c -> SCAN_GETLIBC
 */
unsigned long set_scan_flags(char * param_str)
{
	int len = strlen(param_str);
	unsigned long retval = 0;
	int i;

	for (i = 0; i < len; ++i) {
		char flag = param_str[i];
		switch (flag) {
		case 't':
			retval |= SCAN_TEXT;
			break;
		case 'h':
			retval |= SCAN_HEAP;
			break;
		case 'a':
			retval |= SCAN_ANON;
			break;
		case 'A':
			retval |= SCAN_ANON | SCAN_ALL_ANON;
			break;
		case 's':
			retval |= SCAN_STACK;
			break;
		case 'b':
			retval |= SCAN_BSS;
			break;
		case 'r':
			retval |= SCAN_RODATA;
			break;
		case 'm':
			retval |= SCAN_GETLIBM;
			break;
		case 'c':
			retval |= SCAN_GETLIBC;
			break;
		}
	}

	return retval;
}
