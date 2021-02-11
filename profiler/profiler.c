/********************************************************************** 
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

/* Global variables */
int __verbose_output = 0;

/* TODO: implement this. */
void send_profile_to_kernel(struct profile_params * params)
{
	(void)params;
	DBG_PRINT("Sending profile...\n");
}

/* Perform a first pass over the application's memory layout and
 * select the VMAs that we will care about. */
struct vma_descr * do_layout_detect(struct trace_params * tparams,
				    unsigned int * count)
{
	struct vma_descr * vma_targets = NULL;
	int res;

	/* Now run the task until the breakpoint and select the VMAs
	 * that will be used for profiling */
	res = select_vmas(tparams, &vma_targets, count);

	if (res) {
		DBG_ABORT("VMA selection failed. Exiting.\n");
	}

	return vma_targets;
}

/* Perform page-by-page timing analysis of the target
 * application. Per-page timing results are accumulated in the @output
 * array. */
void do_profiling(struct trace_params * tparams, struct profile * profile,
		  struct vma_descr * vma_targets, unsigned int vma_count)
{
	struct profile_params * params = alloc_params();
	int res;
	unsigned i, j;
	int skip_first = 1;

	/* Setup the parameters that we will pass to the kernel */
	params->pid = tparams->pid;
	/* This will be always 1 for profiling since we test a single
	 * vma/page at a time. */
	params->vma_count = 1;
	add_vma_descr(&vma_targets[0], &params->vmas, &params->vma_count);

	/* Make sure we start with a clean profile */
	memset(profile, 0, sizeof(struct profile));

	/* Okay, we have the VMAs to work with. Let's loop over each
	 * VMA and each page to profile the behavior of the task when
	 * the cacheability of each page is modified. */
	for (i = 0; i < vma_count; ++i) {
		struct vma_descr * cur_vma = &vma_targets[i];

		for (j = 0; j < cur_vma->total_pages; ++j) {
			/* Select the j-th page of this vma for profiling */
			set_profiling_page(params, cur_vma, j);

			/* Remember that the debugee is currently at
			 * the breakpoint the first time we do this */
			if (!skip_first)
				res = run_to_symbol(tparams);
			else
				skip_first = 0;

			/* Perform interact with the kernel */
			send_profile_to_kernel(params);

			/* Let the task complete. We will collect
			 * timing information in the process. */
			res = run_to_completion(tparams);

			/* All done for this page, save the collected
			 * timing info. */
			collect_profiling(profile, tparams, cur_vma, i, j);
		}

		/* Sort the profile of the current VMA */
		qsort(profile->vmas[i].pages, profile->vmas[i].page_count,
		      sizeof(struct profiled_vma_page), profiled_vma_page_cmp);
	}


}

int main(int argc, char* argv[])
{
	int opt, i, tracee_cmd_idx, sample_size;
	struct trace_params tparams;
	struct vma_descr * vma_targets;
	unsigned int vma_count;
	struct profile profile;
	struct profile_params incr_profile;
	unsigned int operation;
	int nr_pages = 3;

	/* Parse command line parameters. Just as an example, this
	 * program accepts a parameter -e <value> and if specified it
	 * will print the value passed. It also accepts a parameter -s
	 * <symbol name> for the function to time.  Other than that,
	 * the executable to run and its parameters is expected at the
	 * end of the command line after all the optional
	 * arguments. */

	while((opt = getopt(argc, argv, ":s:c:n:m:hv")) != -1) {
		switch (opt) {
		case 'h':
			DBG_PRINT(HELP_STRING, argv[0]);
			return EXIT_SUCCESS;
			break;
			/*case 'm': //this doesnt work rn
			mode = optarg; //either profiling or running
			if(strcmp("profile",optarg) == 0)
			{
			  kernel_params.touched_vmas... = 1;
			  printf("mode is :%s and size is:%d\n",mode,kernel_params.size);}
			else if (strcmp("run",optarg) == 0)
			  kernel_params.size = 10;
			else
				printf("wrong mode input\n");
				break;*/
		case 'v':
			__verbose_output = 1;
			break;
		case 'n': //number of samples
			sample_size = strtol(optarg, NULL, 0);
			break;
		case 'c': //cacheabe : c = 1, noncacheable : c = 0
			operation = strtol(optarg, NULL, 0);
			printf("operation is : %d\n",operation);
			break;
		case 's': //symbol which we are gonna put breakpoint on
			tparams.symbol = optarg;
			DBG_PRINT("Timing function %s\n", tparams.symbol);
			break;
			//case 'o':
		case '?':
			DBG_ABORT("Invalid parameter. Exiting.\n");
		}
	}

	/* Check that the symbol to observe has been specified */
	if (!tparams.symbol) {
		DBG_ABORT("No symbol/function to observe has been"
			  " specified with the -s parameter. Exiting.\n");
	}

	/* Check that there is a non-empty command to launch the
	 * tracee after the optional parameters */
	if (optind >= argc) {
	  	DBG_ABORT("Expected command to run after parameters. Exiting.\n");
	}

	/* Keep track that the command line for the tracee starts at
	 * position optind in the list of arguments. */
	tracee_cmd_idx = optind;
	tparams.exe_name = argv[tracee_cmd_idx];
	tparams.exe_params = &argv[tracee_cmd_idx];

	/* Print out the reminder of the command, i.e. what to
	 * execute and its paramters */
	DBG_PRINT("Command to execute: [");
	for (i = tracee_cmd_idx; i < argc; ++i)
		DBG_PRINT_NOPREF("%s ", argv[i]);
	DBG_PRINT_NOPREF("\b]\n");


	/* We are ready to start the tracee. But let's try to resolve
	 * the symbol to observe right away. If we can't resolve the
	 * target symbol, there is no point in running the tracee. */
	tparams.brkpnt_addr[TRACEE_ENTRY] = resolve_symbol(tparams.exe_name,
							   tparams.symbol);

	/* If the breakpoint was correctly installed, the address
	 * saved as the tracee's entry point will be a valid
	 * one. There is nothing to do if this fails. */
	if (tparams.brkpnt_addr[TRACEE_ENTRY] == (void *)-1) {
		return EXIT_FAILURE;
	}

	/* We are ready to launch the process to be profiled to learn
	 * about its layout and identify the VMAs we will work
	 * with. But before we do the first launch, setup the signal
	 * handling for the parent. */
	setup_signals();

	/* We are ready for some profiling. Pin the parent to a CPU
	 * and set it to execute with real-time priority. */
	set_realtime(1, PARENT_CPU);

	/* Let's start by acquiring the application's profile */
	vma_targets = do_layout_detect(&tparams, &vma_count);

	/* First mode, perform layout scan and per-page profiling */
	do_profiling(&tparams, &profile, vma_targets, vma_count);

	/* Output a pretty print of the profile. */
	print_profile(&profile);

	build_incremental_params(&profile, &incr_profile,
				 vma_targets, vma_count, nr_pages);

	print_params(&incr_profile);

	return EXIT_SUCCESS;
}
