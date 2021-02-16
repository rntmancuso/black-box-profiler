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
int __no_kernel = 0;
int __run_flags = 0;
int __do_ranking = 0;
int __print_layout = 0;
enum page_operation __page_op = PAGE_CACHEABLE;
char * __save_to = NULL;
char * __load_from = NULL;

/* Send parameters to the kernel module  */
void send_profile_to_kernel(struct profile_params * params,
			    struct trace_params * tparams)
{
	static int kfd = -1;

	if(!params)
		return;

	/* Set the PID to communicate to the kernel */
	params->pid = tparams->pid;

	/* If verbose output requested, print out what is
	 * about to be sent to the kernel */
	if (__verbose_output)
		print_params(params);

	if (__no_kernel) {
		return;
	}

	if (kfd < 0) {
		kfd = open(KERN_PROCFILE, O_RDWR);
		if (kfd < 0)
			DBG_ABORT("Unable to open kernel procfile %s\n", KERN_PROCFILE);
	}

	write(kfd, (void *)params, sizeof(struct profile_params));

	DBG_PRINT("Kernel interaction completed.\n");
}

/* Perform a first pass over the application's memory layout and
 * select the VMAs that we will care about. */
struct vma_descr * do_layout_detect(struct trace_params * tparams,
				    unsigned int * count)
{
	struct vma_descr * vma_targets = NULL;
	int res;

	res = run_to_symbol(tparams);
	res = detect_vmpeak(tparams);

	/* Now run the task until the breakpoint and select the VMAs
	 * that will be used for profiling */
	res = select_vmas(tparams, &vma_targets, count);
	res = run_to_completion(tparams);

	if (res) {
		DBG_ABORT("VMA selection failed. Exiting.\n");
	}

	return vma_targets;
}

/* Perform page-by-page timing analysis of the target
 * application. Per-page timing results are accumulated in the @output
 * array. */
static void __do_profiling(struct trace_params * tparams, struct profile * profile,
			   struct vma_descr * vma_targets, unsigned int vma_count,
			   int total_pages)
{
	struct profile_params params;
	int res;
	unsigned int i, j;
	int pg_count = 0;

	/* Setup the parameters that we will pass to the kernel */
	memset(&params, 0, sizeof(struct profile_params));

	/* Okay, we have the VMAs to work with. Let's loop over each
	 * VMA and each page to profile the behavior of the task when
	 * the cacheability of each page is modified. */
	for (i = 0; i < vma_count; ++i) {
		struct vma_descr * cur_vma = &vma_targets[i];

		for (j = 0; j < cur_vma->total_pages; ++j) {
			/* Select the j-th page of this vma for profiling */
			build_profiling_params(&params, vma_targets,
					       vma_count, i, j);

			/* Remember that the debugee is currently at
			 * the breakpoint the first time we do this */
			res = run_to_symbol(tparams);

			/* Perform interact with the kernel */
			send_profile_to_kernel(&params, tparams);

			/* Let the task complete. We will collect
			 * timing information in the process. */
			res = run_to_completion(tparams);

			/* All done for this page, save the collected
			 * timing info. */
			collect_profiling(profile, tparams, cur_vma, i, j);

			/* Release current parameter */
			free_params(&params);

			/* Print progress */
			print_progress("PROFILING", ++pg_count, total_pages);
		}
	}
}

/* Perform page-by-page timing analysis of the target
 * application. Per-page timing results are accumulated in the @output
 * array. */
void do_profiling(struct trace_params * tparams, struct profile * profile,
		  struct vma_descr * vma_targets, unsigned int vma_count,
		  int sample_count)
{
	int res;
	int s;
	int total_pages = get_total_pages(vma_targets, vma_count);

	for (s = 0; s < sample_count; ++s) {
		DBG_INFO("PROFILING: Collecting sample %d of %d\n", s+1, sample_count);

		/* Record that a new sample has been added to the profile */
		profile->num_samples++;

		__do_profiling(tparams, profile, vma_targets, vma_count, total_pages);
	}
}

void do_ranking(struct trace_params * tparams, struct profile * profile,
		  struct vma_descr * vma_targets, unsigned int vma_count)
{
	int total_pages = get_total_pages(vma_targets, vma_count);
	struct profile_params incr_profile;
	int i, res;
	unsigned long * incr_timing = (void *)malloc(total_pages *
						     sizeof(unsigned long));

	/* Make sure that the profile is sorted by page statistics! */
	sort_profile_by_stats(profile);

	for (i = 0; i < total_pages; ++i) {
		/* Generate new incremental profile */
		build_incremental_params(profile, &incr_profile,
					 vma_targets, vma_count, i);

		res = run_to_symbol(tparams);

		/* Perform interact with the kernel */
		send_profile_to_kernel(&incr_profile, tparams);

		res = run_to_completion(tparams);

		free_params(&incr_profile);

		/* Print progress */
		print_progress("RANKING", i+1, total_pages);

		incr_timing[i] = tparams->t_end - tparams->t_start;
	}

	/* Printout timing results */
	DBG_INFO("\nRANKED TIMING:\n");
	for (i = 0; i < total_pages; ++i) {
		DBG_INFO("%d, %ld\n", i+1, incr_timing[i]);
	}

	free(incr_timing);
}

int main(int argc, char* argv[])
{
	int opt, i, tracee_cmd_idx, __addl_sample_count = 1;
	struct trace_params tparams;
	struct vma_descr * vma_targets;
	unsigned int vma_count;
	struct profile profile;
	unsigned int operation;

	/* Parse command line parameters. Just as an example, this
	 * program accepts a parameter -e <value> and if specified it
	 * will print the value passed. It also accepts a parameter -s
	 * <symbol name> for the function to time.  Other than that,
	 * the executable to run and its parameters is expected at the
	 * end of the command line after all the optional
	 * arguments. */

	while((opt = getopt(argc, argv, ":s:c:n:m:hvpqo:i:rl")) != -1) {
		switch (opt) {
		case 'h':
			DBG_PRINT(HELP_STRING, argv[0]);
			return EXIT_SUCCESS;
			break;
		case 'm': /* Determine the operation mode. */
			if(strcmp("c", optarg) == 0)
				__page_op = PAGE_CACHEABLE;
			else if (strcmp("nc", optarg) == 0)
				__page_op = PAGE_NONCACHEABLE;
			else if (strcmp("mi", optarg) == 0)
				__page_op = PAGE_MIGRATE;
			else
				DBG_ABORT("Unknown mode %s. Exiting.\n", optarg);
			break;
		case 'l':
			/* Perform ranking after profiling */
			__print_layout = 1;
			break;
		case 'r':
			/* Perform ranking after profiling */
			__do_ranking = 1;
			break;
		case 'o':
			/* Output profile to the file specified
			 * through this paramter */
			__save_to = optarg;
			break;
		case 'i':
			/* Output profile to the file specified
			 * through this paramter */
			__load_from = optarg;
			break;
		case 'p':
			/* In "pretend" mode, do everything except
			 * interacting with the kernel. */
			__no_kernel = 1;
			break;
		case 'q':
			/* In "quiet" mode, the stdout and stderr
			 * output of the traced application are
			 * suppressed. */
			__run_flags |= RUN_QUIET;
			break;
		case 'v':
			__verbose_output = 1;
			break;
		case 'n': //number of samples
			__addl_sample_count = strtol(optarg, NULL, 0);
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
	DBG_INFO("Command to execute: [");
	for (i = tracee_cmd_idx; i < argc; ++i)
		DBG_INFO_NOPREF("%s ", argv[i]);
	DBG_INFO_NOPREF("\b]\n");


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

	/* Pass run flags, if any. */
	tparams.run_flags = __run_flags;

	/* We are ready to launch the process to be profiled to learn
	 * about its layout and identify the VMAs we will work
	 * with. But before we do the first launch, setup the signal
	 * handling for the parent. */
	setup_signals();

	/* We are ready for some profiling. Pin the parent to a CPU
	 * and set it to execute with real-time priority. */
	set_realtime(3, PARENT_CPU);

	if (__load_from) {
		/* Attempt to read memory layout and profile from file. */
		load_profile(__load_from, &vma_targets, &vma_count, &profile);

		/* If we load a profile from file, we will be skipping
		 * layout detection. Hence, make sure we initialize
		 * flags as needed. */
		tparams.vm_peak = profile.heap_pad;
		tparams.run_flags |= RUN_SET_MALLOC;
	} else {
		/* Make sure we start with a clean profile */
		memset(&profile, 0, sizeof(struct profile));

		/* Let's start by acquiring the application's profile */
		vma_targets = do_layout_detect(&tparams, &vma_count);

		/* Make sure we record any adjustment to the run
		 * parameters determined during layout detection .*/
		profile.heap_pad = tparams.vm_peak;
	}


	/* How many samples on top of what we read from file we need
	 * to acquire? */
	if (__addl_sample_count > 0) {
		/* First mode, perform layout scan and per-page profiling */
		do_profiling(&tparams, &profile, vma_targets, vma_count,
			     __addl_sample_count);
	}

	/* Do we need to save the profile to file? */
	if (__save_to) {
		save_profile(__save_to, vma_targets, vma_count, &profile);
	}

	/* Output a pretty print of the profile. */
	print_profile(&profile);

	/* Now perform full page ranking */
	if (__do_ranking) {
		if (!__load_from && !__addl_sample_count)
			DBG_ABORT("No profiling samples to perform ranking. Exiting.\n");

		do_ranking(&tparams, &profile, vma_targets, vma_count);
	}

	return EXIT_SUCCESS;
}
