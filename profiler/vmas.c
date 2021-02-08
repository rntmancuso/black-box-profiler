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

void add_vma_descr(struct vma_descr *vma, struct vma_descr ** vmas,
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
	new_vma->vma_index = vma->vma_index;
	new_vma->total_pages = vma->total_pages;

	/* Reset all the other fields */
	new_vma->page_count = 0;
	new_vma->operation = 0;
	new_vma->page_index = NULL;
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

static void vma_index_finder(struct vma_struct *vma, struct vma_descr ** vmas,
			     unsigned int * vma_count)
{
	/* We assume that vma numbers are in increasing order */
	static int get_anon = 1;
	static int get_text = 1;

	int get_stack = 0;

	if ((!(strcmp(vma->mappedfile,"anonymous")) && get_anon))
	{
		get_anon = 0;
		add_vma(vma, vmas, vma_count);
	}

	else if ((strcmp(vma->mappedfile,"[heap]")) == 0)
	{
		add_vma(vma, vmas, vma_count);
	}

	else if  (vma->executable && get_text)
	{
		get_text = 0;
		printf("Text and its index is : %d\n", vma->chunk_id);
		add_vma(vma, vmas, vma_count);
	}

	else if (get_stack && (strcmp(vma->mappedfile,"[stack]")) == 0)
	{
		add_vma(vma, vmas, vma_count);
	}
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
		DBG_PRINT("Invalid line in maps file.\n");
		exit(EXIT_FAILURE);
	}

	vma = (struct vma_struct *)malloc(sizeof(struct vma_struct));
	if (!vma) {
		DBG_PRINT("Memory allocation error.\n");
		exit(EXIT_FAILURE);
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
		DBG_PRINT("Unable to open file %s", path);
		exit(EXIT_FAILURE);
	}

	/* This is the beginning of a new scan. Make sure we reset any
	 * previos VMA count */
	*vma_count = 0;

	for(;;) {
		if (fgets(buf, 256, f) == NULL)
		{
			if(feof(f))
				break;

		        DBG_PRINT("Error reading %s maps file.\n", path);
		        exit(EXIT_FAILURE);
		}

		/* Make sure buffer is zero-terminated. */
		buf[255] = '\0';
		buf[strlen(buf)-1] = '\0';
		vma = scan_proc_maps_line(nvma, buf);

		/* for finding vma indices and size of each vma */
		vma_index_finder(vma, vmas, vma_count);

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
		DBG_PRINT("Unable to run child until [%s]. Exiting.\n", tparams->symbol);
		return -1;
	}

	/* Scan the /proc/PID/maps file to recognize the application's
	 * memory layout and perform VMA selection. */
	read_proc_maps_file(tparams->pid, vmas, vma_count);

	/* NOTE: the tracee is still stopped at the breakpoint when we
	 * get here. We might want to kill it or just leverage this
	 * property to speed-up the first profiling iteration. */

	if (*vma_count == 0) {
		DBG_PRINT("No VMAs were selected for debugging.\n");
		return -1;
	}

	return 0;
}