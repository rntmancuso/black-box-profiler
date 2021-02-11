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

#include <asm/ptrace.h>

#include "profiler.h"
#include "vmas.h"
#include "utils.h"

/* Collect profiling information after a single round of profiling,
 * i.e. after timing the effect of manipulating the cacheability of a
 * single page. */
void collect_profiling(struct profile * profile, struct trace_params * tparam,
		       struct vma_descr * vma,
		       unsigned int vma_idx, unsigned int page_idx)
{
	int new_vma = 0;
	if (profile->vmas == NULL) {
		profile->vmas = (struct profiled_vma *)malloc(
			sizeof(struct profiled_vma));
		profile->profile_len = 1;
		new_vma = 1;
	} else {
		if (vma_idx >= profile->profile_len) {
			profile->profile_len += 1;
			profile->vmas = (struct profiled_vma *)realloc(profile->vmas,
			       (profile->profile_len) * sizeof(struct profiled_vma));
			new_vma = 1;
		}
	}

	if (new_vma) {
		struct profiled_vma * new_entry;
		new_entry = &profile->vmas[profile->profile_len-1];
		new_entry->vma_index = vma->vma_index;
		new_entry->page_count = 0;
		new_entry->pages = NULL;
	}

	/* Add the stats for the new page */
	struct profiled_vma * cur_entry = &profile->vmas[vma_idx];
	if (cur_entry->pages == NULL) {
		cur_entry->page_count = 1;
		cur_entry->pages = (struct profiled_vma_page *)malloc(
			sizeof(struct profiled_vma_page));
	} else {
		cur_entry->page_count++;
		cur_entry->pages = (struct profiled_vma_page *)realloc(cur_entry->pages,
			cur_entry->page_count * sizeof(struct profiled_vma_page));
	}

	struct profiled_vma_page * page = &cur_entry->pages[cur_entry->page_count-1];
	page->page_index = page_idx;
	page->cycles = tparam->t_end - tparam->t_start;
}

/* Deallocates a profile structure */
void free_profile(struct profile * profile)
{
	unsigned int i;
	if (!profile)
		return;

	for (i = 0; i < profile->profile_len; ++i) {
		struct profiled_vma * cur_entry = &profile->vmas[i];
		if (cur_entry->pages) {
			free(cur_entry->pages);
			cur_entry->pages = NULL;
		}
	}

	if (profile->vmas) {
		free(profile->vmas);
		profile->vmas = NULL;
	}
}

/* This function is used to build a partial struct profile_params
 * construct where only the most impactful @nr_pages are
 * included. This will then be passed to the lernel. */
void build_incremental_params(const struct profile * in_profile,
			      struct profile_params * out_profile,
			      struct vma_descr * vma_targets, unsigned int vma_count,
			      unsigned int nr_pages)
{
	/* This function assumes that pages in each VMA in the
	 * @in_profile have already been sorted within the VMA. We
	 * then select the page that led to the best timing among all
	 * the VMA pages and create a brand new profile in this
	 * way. */

	unsigned int * __page_ind;
	unsigned int i, j, in_len = in_profile->profile_len;

	/* Reset out_profile. */
	memset(out_profile, 0, sizeof(struct profile));

	if (!in_profile)
		return;

	/* We will need to keep an index to the list of pages of each
	 * VMA in the @in_profile */
	__page_ind = (unsigned int *)malloc(in_len * sizeof(unsigned int));

	if(!__page_ind)
		DBG_ABORT("Unable to allocate memory.\n");

	memset(__page_ind, 0, in_len * sizeof(int));

	/* Now for the fun part: scan all the pages in all the VMAs,
	 * keeping track of the global min and select/add one page at
	 * a time. */
	for (i = 0; i < nr_pages; ++i) {
		unsigned long min_cycles = ~(0UL);
		int min_vma;
		for (j = 0; j < in_len; ++j) {
			struct profiled_vma * in_vma = &in_profile->vmas[j];
			if (__page_ind[j] < in_vma->page_count) {
				struct profiled_vma_page * in_page = &in_vma->pages[__page_ind[j]];
				if (in_page->cycles < min_cycles) {
					min_vma = j;
					min_cycles = in_page->cycles;
				}
			}
		}

		/* We found the next page leading to the highest
		 * speedup. Now add this information in the output
		 * construct. */
		struct profiled_vma * vma = &in_profile->vmas[min_vma];
		struct profiled_vma_page * page = &vma->pages[__page_ind[min_vma]];

		/* Update the output construct with the new page */
		params_add_page(out_profile, vma, page);

		/* Finally move the page pointer in the considered
		 * VMA */
		++(__page_ind[min_vma]);
	}

	free(__page_ind);


	/* Now just do a round where we fill up any missing info from
	 * the VMAs detected at layout construction time. */
	for (i = 0; i < out_profile->vma_count; ++i) {
		for (j = 0; j < vma_count; ++j) {
			if (vma_targets[j].vma_index == out_profile->vmas[i].vma_index) {
				out_profile->vmas[i].total_pages = vma_targets[j].total_pages;
				out_profile->vmas[i].operation = vma_targets[j].operation;
				break;
			}
		}
	}

}

/* This function sets the VMA and page index for the current profiling
 * operation. When profiling, we know that the profile_params
 * structure will only contain a single VMA with a single page
 * index. */
void set_profiling_page(struct profile_params * params,
			struct vma_descr * vma, int page_index)
{
	if (params->vmas[0].page_index == NULL) {
		params->vmas[0].page_index =
			(unsigned int *)malloc(sizeof(unsigned int));
		params->vmas[0].page_count = 1;
	}

	params->vmas[0].vma_index = vma->vma_index;
	params->vmas[0].total_pages = vma->total_pages;
	params->vmas[0].page_index[0] = page_index;
}

/* Prints a nicely formatted view of the current profile */
void print_profile(struct profile * profile)
{
	unsigned int i, j;
	unsigned int len = profile->profile_len;
	        DBG_INFO("\n----------------- PROFILE -----------------\n");
	for (i = 0; i < len; ++i) {
		struct profiled_vma cur_vma = profile->vmas[i];
		DBG_INFO("========== (%d/%d) VMA index: %d ==========\n",
			 i, len, cur_vma.vma_index);

		for (j = 0; j < cur_vma.page_count; ++j) {
			struct profiled_vma_page cur_page = cur_vma.pages[j];
			DBG_INFO("PAGE: 0x%04x\t\tCYCLES: %ld\n",
				          cur_page.page_index, cur_page.cycles);
		}
	}
	DBG_INFO("\n-------------------------------------------\n");

}

/* Prints a nicely formatted view of the parameters that will be
 * passed to the kernel */
void print_params(struct profile_params * params)
{
	unsigned int i, j;
	unsigned int len = params->vma_count;
	DBG_INFO("\n----------------- KPARAMS -----------------\n");
	DBG_INFO("PID  : \t%d\n", params->pid);
	DBG_INFO("#VMAS: \t%d\n", len);
	for (i = 0; i < len; ++i) {
		struct vma_descr cur_vma = params->vmas[i];
		DBG_INFO("========== (%d/%d) VMA index: %d ==========\n",
			 i, len, cur_vma.vma_index);
		DBG_INFO("Index     :\t%d\n", cur_vma.vma_index);
		DBG_INFO("Tot. Pages:\t%d\n", cur_vma.total_pages);
		DBG_INFO("Op.  Pages:\t%d\n", cur_vma.page_count);
		DBG_INFO("Operation :\t%d\n", cur_vma.operation);
		DBG_INFO("Page list :\n");

		for (j = 0; j < cur_vma.page_count; ++j) {
			DBG_INFO("\t%03d) +0x%04x\n", j, cur_vma.page_index[j]);
		}
	}
	DBG_INFO("\n-------------------------------------------\n");

}

struct profile_params * alloc_params(void)
{
	struct profile_params * retval;
	retval = (struct profile_params *)malloc(sizeof(struct profile_params));

	if (!retval)
		DBG_ABORT("Unable to allocate memory. Exiting.\n");

	/* Initialize the other fields */
	retval->pid = -1;
	retval->vma_count = 0;
	retval->vmas = NULL;

	return retval;
}

/* Set real-time SCHED_FIFO scheduler with given priority */
void set_realtime(int prio, int cpu)
{
	struct sched_param sp;

	/* Initialize parameters */
	memset(&sp, 0, sizeof(struct sched_param));
	sp.sched_priority = prio;

	/* Attempt to set the scheduler for current process */
	if (sched_setscheduler(0, SCHED_FIFO, &sp) < 0) {
		DBG_ABORT("Unable to set SCHED_FIFO scheduler");
	}

	/* Set CPU affinity if isolate flag specified */

	cpu_set_t set;
	CPU_ZERO(&set);

	/* default to CPU x for parent */
	CPU_SET(cpu, &set);

	if (sched_setaffinity(getpid(), sizeof(set), &set) == -1) {
		DBG_ABORT("Unable to set CPU affinity.");
	}


}

/* Compare function for qsort */
int profiled_vma_page_cmp (const void * a, const void * b) {
	return (
	    ((struct profiled_vma_page*)a)->cycles -
	    ((struct profiled_vma_page*)b)->cycles
	    );
}

/* Get the value of the link register value. LR keeps the return
 * address of a function. Upon failure it returns -1. */
static long get_LR (pid_t pid)
{
	/* User registers for ARM (check sys/usr.h header) */
#ifdef __arm__
	struct user_regs regs;
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
		DBG_PRINT("Unable to retrieve tracee registers.");
		return -1;
	}
	/* LR is register 14 */
	long lr = regs.uregs[14];
#elif __aarch64__
	struct user_regs_struct gregs;
	struct iovec iovec;
	iovec.iov_base = &gregs;
	iovec.iov_len = sizeof (gregs);

	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iovec) < 0) {
		DBG_PRINT("Unable to retrieve tracee registers.");
		return -1;
	}
	/* LR is register 30 */
	long lr = gregs.regs[30];
#else
	#warning No get_LR routine implemented on this architecture!
	long lr = 0;
#endif
	(void)pid;
	return lr;
}

/* Setting the program counter to the specified value. Returns -1 on
 * failure, 0 on success. */
static long set_PC (pid_t pid, void * addr)
{
#ifdef __arm__
	struct user_regs regs;
	memset(&regs, 0, sizeof(regs));
	/* Get registers of the child */
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
		DBG_PRINT("Unable to retrieve tracee PC register.");
		return -1;
	}
	regs.uregs[15] = (unsigned long)addr;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
		DBG_PRINT("Unable to set tracee PC register.");
		return -1;
	}
	DBG_PRINT("Done setting the program counter\n\n");
#elif __aarch64__
	struct user_regs_struct gregs;
	struct iovec iovec;
	iovec.iov_base = &gregs;
	iovec.iov_len = sizeof (gregs);

	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iovec) < 0) {
		DBG_PRINT("Unable to retrieve tracee registers.");
		return -1;
	}
	gregs.pc = (unsigned long)addr;
	if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iovec) < 0) {
		DBG_PRINT("Unable to set tracee PC register.");
		return -1;
	}
	DBG_PRINT("Done setting the program counter\n\n");

#else
#warning No set_PC routine implemented on this architecture!
	(void)pid;
	(void)addr;
#endif
	return 0;
}

/* Set breakpoint at desired address. Returns -1 upon failure. */
static long set_breakpoint(pid_t pid, void * addr)
{
	long data;

	/* Fist off, read the original data at the breakpoint address */
	data = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);

	if (data == -1) {
		DBG_ABORT("Unable to read data at desired breakpoint address.\n");
	}

	if (ptrace(PTRACE_POKETEXT, pid, (void *)addr, BRKPOINT_INSTR) < 0) {
		DBG_ABORT("Unable to set breakpoint.\n");
	}

	DBG_PRINT("Setting a breakpoint at %p (data: 0x%08lx)\n", addr, data);

	/* data is the original instruction at addr (before being
	 * replaced by breakpoint instruction). */
	return data;
}

/* This function will attempt to resolve the address of a symbol
 * passed as a string via the second parameter in the ELF binary
 * provided in the first parameter. It will return the value of the
 * symbol as a pointer upon success. It will return (void *)-1 upon
 * failure. */
void * resolve_symbol(char * elf_path, char * symbol_to_search) {
	void * retval = (void*)-1;

	/* To interface with the libElf library */
	Elf         *elf;
	Elf_Scn     *scn = NULL;
	GElf_Shdr   shdr;
	Elf_Data    *elf_data;
	int         fd, ii, count;

	/* First off, some simple sanity check on the parameters */
	if (!elf_path || !symbol_to_search) {
		DBG_PRINT("Invalid ELF path or symbol to be resolved.");
		return retval;
	}

	/* Set ELF version to the current one (default) */
	elf_version(EV_CURRENT);

	/* Attempt to open the target ELF file */
	fd = open(elf_path, O_RDONLY);

	if (fd < 0) {
		DBG_FATAL("Unable to open ELF file at %s", elf_path);
		DBG_PERROR(NULL);
		return retval;
	}

	/* All good with open syscall, let's proceed with ELF
	 * parsing. */
	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		DBG_FATAL("Unable to parse ELF file at %s\n", elf_path);
		goto err_close;
	}

	/* Scan the list of section headers to find the symbols
	 * table */
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		gelf_getshdr(scn, &shdr);
		if (shdr.sh_type == SHT_SYMTAB) {
			/* found a symbol table. We are done. */
			break;
		}
	}
	if (!scn) {
		DBG_FATAL("Unable to find the symbols table.\n");
		goto err_close;
	}

	/* Get the content of the symbols table */
	elf_data = elf_getdata(scn, NULL);
	count = shdr.sh_size / shdr.sh_entsize;

	/* Scan each symbol in the table to find a match */
	for (ii = 0; ii < count; ++ii)
	{
		/* For whatever reason, when we perform a strcmp, we
		 * lose the address of the symbol. Something funky is
		 * going on here, so getting the symbol twice is a
		 * temporary workaround. */
		GElf_Sym sym, sym2;
		gelf_getsym(elf_data, ii, &sym);
		char * symbol_name =  elf_strptr(elf, shdr.sh_link, sym.st_name);
		if (strcmp(symbol_name, symbol_to_search) == 0)
		{
			gelf_getsym(elf_data, ii, &sym2);
			retval = (void *)((unsigned long)sym2.st_value & ARM_ISA_MASK);
			DBG_PRINT("Found symbol [%s]. Address = %p\n", symbol_to_search, retval);
			return retval;
		}
	}

	DBG_FATAL("Unable to find symbol [%s]\n", symbol_to_search);

err_close:
	close(fd);
	return retval;
}

/* Executes tracee program. Returns 0 upon error. Won't return if
 * successful in the child, but will return the PID of the spawned
 * child process in the parent. */
static pid_t run_debuggee(char * program_name, char * arguments [])
{
	/* First, attempt a fork to spawn a child process */
	pid_t child_pid = fork();

	/* PID = 0 means we are in the child process after a
	 * successful fork */
	if(child_pid == 0)
	{
	        set_realtime(2, CHILD_CPU);

		//setenv("MALLOC_TOP_PAD_", "1400000", 1);

		/*Allow tracing of this process*/
		if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
		{
			DBG_ABORT("Unable to initate tracing on program %s\n",
				  program_name);
		}

		int cpu;
		if ((cpu = sched_getcpu()) < 0)
		{
			DBG_ABORT("Unable to detect the current CPU\n");
		}

		DBG_PRINT("Executing tracee on CPU %d\n", cpu);

		/* Replace this process's image with the given program image
		   will load a new binary image into memory and start
		   executing from that image's entry point */
		if (execv(program_name, arguments) < 0) {
			DBG_ABORT("Unable to execute program %s\n", program_name);
		}

		DBG_ABORT("How did I get here?\n");
	}

	/* This will be executed by the parent after a successful fork */
	else if (child_pid > 0)
	{
		return child_pid;
	}

	/* Something wnet wrong with the fork systcall */
	else
	{
		DBG_ABORT("Fork syscall failed\n");
	}
}

static int get_child_wstat (void)
{
	int wstat;
	pid_t pid;

	pid = waitpid (-1, &wstat, WNOHANG);
	if (pid == 0) {
		/* No change in the state of the child(ren) */
		return -1;
	} else if (pid == -1 && errno != ECHILD) {
		/* Something went wrong */
		DBG_FATAL("Unexpected waitpid() result.\n");
		DBG_PERROR(NULL);
		return -1;
	} else if (WIFSTOPPED(wstat) || WIFEXITED(wstat)) {
		return wstat;
	}

	return -1;
}

static void continue_until_breakpoint(struct trace_params * tparams)
{
	/* ENTRY means entry of the function we are gonna set
	   bp at VMAs can't be scanned here since at this
	   point there's no heap */
	tparams->brkpnt_data[TRACEE_ENTRY] =
		set_breakpoint(tparams->pid, tparams->brkpnt_addr[TRACEE_ENTRY]);

	if(ptrace(PTRACE_CONT, tparams->pid, NULL, NULL) < 0){
		DBG_ABORT("Unable to resume tracee. Exiting.\n");
	}

}

static void continue_until_return(struct trace_params * tparams)
{
	/* This function should be called when no PC restore has been
	 * done. E.g., right after continue_until_breakpoint() has
	 * returned. So some of that work is done here. */

	/* Restore the original value at the breakpoint so that the
	 * process can continue */
	if(ptrace(PTRACE_POKETEXT, tparams->pid,
		  tparams->brkpnt_addr[TRACEE_ENTRY],
		  tparams->brkpnt_data[TRACEE_ENTRY]) < 0)
	{
		DBG_ABORT("Unable to resume from breakpoint. Exiting.\n");
	}

	/* Rewind the PC of the tracee to before the
	 * breakpoint */
	if(set_PC(tparams->pid, tparams->brkpnt_addr[TRACEE_ENTRY]) < 0) {
		DBG_ABORT("Unable to rewind PC.\n");
	}

	/* Now read return address to set a breakpoint at the
	 * return from the observed function. TODO handle
	 * possible error. */
	tparams->brkpnt_addr[TRACEE_EXIT] = (void *)(get_LR(tparams->pid) & ARM_ISA_MASK);
	tparams->brkpnt_data[TRACEE_EXIT] = set_breakpoint(tparams->pid,
					       tparams->brkpnt_addr[TRACEE_EXIT]);

	DBG_PRINT("Traced function set to return to %p\n",
		  tparams->brkpnt_addr[TRACEE_EXIT]);

	/* Ready to resume tracee, but not before acquiring the timing */
	get_timing(tparams->t_start);

	if(ptrace(PTRACE_CONT, tparams->pid, NULL, NULL) < 0) {
		DBG_ABORT("Unable to resume from breakpoint. Exiting.\n");
	}

}

static void continue_until_end(struct trace_params * tparams)
{
	/* First thing first, get end of timing observation */
	get_timing(tparams->t_end);

	DBG_PRINT("TIMING: function [%s] took %ld CPU cycles\n",
		  tparams->symbol, tparams->t_end - tparams->t_start);

	/* FIXME: embed this logic in the get_timing routine */
	if(tparams->t_start > tparams->t_end)
		printf("OVERFLOW: %lu\n",(0xFFFFFFFFUL-tparams->t_start)+tparams->t_end);

	/* Restore the original value at the breakpoint so
	 * that the process can continue */
	if(ptrace(PTRACE_POKETEXT, tparams->pid,
		  tparams->brkpnt_addr[TRACEE_EXIT],
		  tparams->brkpnt_data[TRACEE_EXIT]) < 0)
	{
		DBG_ABORT("Unable to resume from breakpoint. Exiting.\n");
	}

	/* Rewind the PC of the tracee to before the
	 * breakpoint */
	if(set_PC(tparams->pid, tparams->brkpnt_addr[TRACEE_EXIT]) < 0) {
		DBG_ABORT("Unable to rewind PC.\n");
	}

	if(ptrace(PTRACE_CONT, tparams->pid, NULL, NULL) < 0) {
		DBG_ABORT("Unable to resume from breakpoint. Exiting.");
	}
}

/* Run the debuggee until we hit the break-point */
int run_to_symbol(struct trace_params * tparams)
{
	sigset_t waitmask;
	siginfo_t info;
	int signo;
	int wstat;

	tparams->pid = run_debuggee(tparams->exe_name, tparams->exe_params);
	/* The first signal we expect is when the process begins
	 * execution */

	/* Wait for signals from the child */
	sigaddset(&waitmask, SIGCHLD);

	signo = sigwaitinfo(&waitmask, &info);
	wstat = get_child_wstat();

	DBG_PRINT("PID %d stopped by signal %d\n", tparams->pid, WSTOPSIG(wstat));

	if(!WIFSTOPPED(wstat)) {
		DBG_ABORT("Unexpected child status %d. Exiting.\n", wstat);
	}

	continue_until_breakpoint(tparams);

	/* The second signal we expect is when the process hits the
	 * entry breakpoint */
	signo = sigwaitinfo(&waitmask, &info);
	wstat = get_child_wstat();

	DBG_PRINT("PID %d stopped by signal %d\n", tparams->pid, WSTOPSIG(wstat));

	if(!WIFSTOPPED(wstat)) {
		DBG_ABORT("Unexpected child status %d. Exiting.\n", wstat);
	}

	/* If we have reached this point, the child has reached the
	 * breakpoint. NOTE: the PC needs to be restored before the
	 * child can continue. */
	return 0;
}

/* Run the debuggee until we hit the break-point */
int run_to_completion(struct trace_params * tparams)
{
	sigset_t waitmask;
	siginfo_t info;
	int signo;
	int wstat;

	/* We continue from the breakpoint until the return of the
	 * target function. */
	continue_until_return(tparams);

	/* Wait for signals from the child */
	sigaddset(&waitmask, SIGCHLD);

	signo = sigwaitinfo(&waitmask, &info);
	wstat = get_child_wstat();

	DBG_PRINT("PID %d stopped by signal %d\n", tparams->pid, WSTOPSIG(wstat));

	if(!WIFSTOPPED(wstat)) {
		DBG_ABORT("Unexpected child status %d. Exiting.\n", wstat);
	}

	continue_until_end(tparams);

	/* The second signal we expect is when the process exits */
	signo = sigwaitinfo(&waitmask, &info);
	wstat = get_child_wstat();

	if(!WIFEXITED(wstat)) {
		DBG_ABORT("Unexpected child status %d. Exiting.\n", wstat);
	}

	DBG_PRINT("PID %d exited.\n", tparams->pid);

	/* If we have reached this point, the child has reached the
	 * breakpoint. NOTE: the PC needs to be restored before the
	 * child can continue. */
	return 0;
}



/* This function sets up signal handling in the parent so that we can
 * use synchronous handling for anything generated by the
 * tracee/child.
 */
void setup_signals(void)
{
	sigset_t waitmask;
	sigaddset(&waitmask, SIGCHLD);

	/* Block SIGCHLD signal so that it is never asynchronously
	 * executed */
	sigprocmask(SIG_BLOCK, &waitmask, NULL);
}
