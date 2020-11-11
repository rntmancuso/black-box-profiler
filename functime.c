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

/* Addresses of jumps will have a 1 in LSB to indicate that the CPU
   will jump to ARM code (as opposed to Thumb code). This mask is used
   to get rid of the extra 1 when reading memory content via ptrace
   syscalls. */
#define ARM_ISA_MASK (~(1UL))

/* Helper macro to prefix any print statement produced by the host
 * process. */
#define DBG_PRINT(format, ...)				\
	fprintf(stderr, "[DBG] " format, ##__VA_ARGS__)

#define DBG_PRINT_NOPREF(format, ...)		\
	fprintf(stderr, format, ##__VA_ARGS__)

#define DBG_PERROR(prefix)			\
	do {					\
		if (prefix == NULL)		\
			perror(" ");		\
		else				\
			perror(prefix);		\
	} while(0)


#define HELP_STRING					\
	"==== BU Black-box Cache Profiler ====\n"	\
	"Written by: Golsana Ghaemi\n"			\
	"            Renato Mancuso\n"			\
	"\n"						\
	"USAGE: %s [-h] -m <mode> -n <samples>\n"	\
	"       -c <cacheable> -s <symbol>\n"		\
	"\n"


/* The assembly opcode to use when inserting a breakpoint */
//#define BRKPOINT_INSTR (0xe7f001f0UL)
#define BRKPOINT_INSTR (0xffffffffUL)


/*for vma scanning*/
#define mapped_file_fmt "%32s"
#define max_num_vma 1024
#define PAGE_SIZE 4096
#define max_vma_mappedfile 33
#define PARENT_CPU 2 //for ser_realtime
#define CHILD_CPU 2 //for ser_realtime
#define STAGES 2

/* Structure of parameters that will be passed to the kernel */ 
struct params
{
	int size;
	long * buff;
	bool shouldSkip;
	pid_t pid;
};

struct trace_params
{
	char * symbol;
	pid_t pid;
	long brkpnt_data [STAGES];
	void * brkpnt_addr [STAGES];
	unsigned long t_start;
	unsigned long t_end;
};

/*struct for keeping each line of process' mapping*/
struct l2p__vma_struct {
	unsigned long start;
	size_t len;
	//struct rb_node node;
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
	unsigned long offset;
	unsigned long inode;
	char perms[5];
	char dev[6];
	char mappedfile[max_vma_mappedfile];
	/* this is a bitmask of pages to lock  */
	//struct bitmask tolock;
};

/*structure for keeping output of profiling mode*/
struct page_stats{
	int cycles;
	int page_number;
};

/* Enum to keep track of the current stage in the execution of the
 * tracee */
enum tracee_stage {
	TRACEE_ENTRY = 0,
	TRACEE_EXIT,
	TRACEE_INIT,
};

/* for measuring time */
#define get_timing(cycles)					\
	do {							\
		asm volatile("mrc p15, 0, %0, c9, c13, 0"	\
			     : "=r" (cycles));			\
	} while (0)

/* ===== GLOBAL VARIABLES ===== */
volatile int done = 0;
struct trace_params tparams;
struct params kernel_params;
static int  heap_size = 0;
static int vma_idx = -1;
static struct l2p__vma_struct vmas[max_num_vma];
int samples; /*for holding summation of  cpu cycles for one page (in "sample_size" samples)*/
struct page_stats *page; // can I pass it to compare func of qsort in order not to have it global?
/* ============================ */


/* Set real-time SCHED_FIFO scheduler with given priority */
void set_realtime(int prio, int cpu)
{
	struct sched_param sp;

	/* Initialize parameters */
	memset(&sp, 0, sizeof(struct sched_param));
	sp.sched_priority = prio;

	/* Attempt to set the scheduler for current process */
	if (sched_setscheduler(0, SCHED_FIFO, &sp) < 0) {
		perror("Unable to set SCHED_FIFO scheduler");
		exit(EXIT_FAILURE);
	}

	/* Set CPU affinity if isolate flag specified */
 
	cpu_set_t set;
	CPU_ZERO(&set);

	/* default to CPU x for parent */
	CPU_SET(PARENT_CPU, &set);

	if (sched_setaffinity(getpid(), sizeof(set), &set) == -1) {
		perror("Unable to set CPU affinity.");
		exit(EXIT_FAILURE);
	}

  
}



/*compare function for qsort*/
int cmpfunc (const void * a, const void * b) {
	return ( ((struct page_stats*)a)->cycles - ((struct page_stats*)b)->cycles);
}



/*scanning heap region*/
struct l2p__vma_struct *vma_alloc(void)
{
	if (++vma_idx == max_num_vma)
		return NULL;
	return vmas + vma_idx;
}

static struct l2p__vma_struct *
scan_proc_maps_line(int chunk_id, char const *buf, char const *defname)
{
	unsigned long start, end, offset, inode;
	char *p, perms[5], dev[6], mappedfile[max_vma_mappedfile];
	int rc;
	struct l2p__vma_struct *vma;
	/* FIXME This is horribly broken */
	mappedfile[0] = '\0';
	rc = sscanf(buf, "%lx-%lx %s %lx %s %lu " mapped_file_fmt ,
		    &start, &end, perms, &offset, dev, &inode, mappedfile);
	mappedfile[max_vma_mappedfile-1] = '\0';
	if (rc < 6)
		DBG_PRINT("Invalid line in maps file");//should be quit macro
	vma = vma_alloc();
	if (!vma)
		DBG_PRINT("Memory allocation error"); //should be quit macro
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
			/* this looks like a single file name, so just truncate it, if necessary */
			strncpy(vma->mappedfile, mappedfile, max_vma_mappedfile-1);
			vma->mappedfile[max_vma_mappedfile-1]='\0';
		} else {
			/* this looks like a pathname, so select the last component */
			strncpy(vma->mappedfile, p+1, max_vma_mappedfile-1);
			vma->mappedfile[max_vma_mappedfile-1]='\0';
		}
	}
	else
		snprintf(vma->mappedfile, max_vma_mappedfile, "[%s]", defname);
        
	vma->mappedfile[max_vma_mappedfile-1] = '\0';
	vma->readable = (perms[0] == 'r');
	vma->writable = (perms[1] == 'w');
	vma->executable = (perms[2] == 'x');
	vma->shared = (perms[3] == 's');
	vma->fmapped = (inode != 0);
	vma->mprotected = 0;
	vma->reserved = 0;
	vma->stack = (strcmp(mappedfile, "[stack]") == 0);
       
	if (strcmp(mappedfile, "[heap]") == 0) { //if we get here means we are scanning the [heap] line of all lines of maps file
		vma->heap = 1;
		/*we are here, mean this vma (this line of maps file) is heap. so vma->start means
		  start of heap and vma->end means end of heap. since vma->len is size_t and page_size is decima, I used end-start which are decimal*/            //printf("inside heap\n");
		heap_size = (vma->end - vma->start)/PAGE_SIZE;
		//heap_size = 10;
		
	}

	return vma; //just one line/entry of maps file (/proc/PID/maps)
}

/*can't we have just one func for this read and scan? also just get heap entry? is better to keep generic?*/
void read_proc_maps_file(pid_t pid) 
{
	struct l2p__vma_struct *vma; // for getting one line of maps file (after calling scan_proc_maps_line
	unsigned int nvma = 0;
	char buf[256];
	const char *defname = "unknown";
	char path[100] ;
	sprintf(path,"/proc/%d/maps",pid);
	FILE *f = fopen(path, "r");
	if (f == NULL)
		DBG_PRINT("Cannot open file %s", path);


	for(;;) {
		if (fgets(buf, 256, f) == NULL)
		{	if(feof(f))
				break;
		        DBG_PRINT("Error reading maps file\n");
		        //exit();?//return 1; 
		}
	

		buf[255] = '\0';
		buf[strlen(buf)-1] = '\0'; //why both?
		//DBG_PRINT("maps #%-3u: \"%s\"\n", nvma, buf); //the whole line is in buf as a string
		vma = scan_proc_maps_line(nvma, buf, defname);
		++nvma;

		defname = vma->mappedfile;
	}
       

	fclose(f);

}
/*end of scanning heap */


/* Set breakpoint at desired address. Returns -1 upon failure. */
long set_breakpoint(pid_t pid, void * addr)
{
	long data, check;

	/* Fist off, read the original data at the breakpoint address */
	data = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);

	if (data == -1) {
		DBG_PRINT("Unable to read data at desired breakpoint address.\n");
		return -1;
	}
	
	if (ptrace(PTRACE_POKETEXT, pid, (void *)addr, BRKPOINT_INSTR) < 0) {
		DBG_PRINT("Unable to set breakpoint.\n");
		return -1;
	}
	DBG_PRINT("Setting a breakpoint at %p (data: 0x%08lx)\n", addr, data);
	
	/* data is the original instruction at addr (before being
	 * replaced by breakpoint instruction). */
	return data;
}

/* Get the value of the link register value. LR keeps the return
 * address of a function. Upon failure it returns -1. */
long get_LR (pid_t pid)
{
	/* User registers for ARM (check sys/usr.h header) */
	struct user_regs regs;
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
		DBG_PRINT("Unable to retrieve tracee registers.");
		return -1;
	}
	/* LR is register 14 */
	long lr = regs.uregs[14];
	return lr;
}

/* Setting the program counter to the specified value. Returns -1 on
 * failure, 0 on success. */
long set_PC (pid_t pid, void * addr)
{
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
	return 0;
}

/* Executes tracee program. Returns 0 upon error. Won't return if
 * successful in the child, but will return the PID of the spawned
 * child process in the parent. */
pid_t run_debuggee(char * program_name, char * arguments [])
{
       
	/* First, attempt a fork to spawn a child process */
	pid_t child_pid = fork();
        printf("after fork\n");
	/* PID = 0 means we are in the child process after a
	 * successful fork */
	if(child_pid == 0)
	{
	        set_realtime(2, CHILD_CPU);

		setenv("MALLOC_TOP_PAD_", "1400000", 1);
		
		/*Allow tracing of this process*/
		if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
		{
			DBG_PRINT("Unable to initate tracing on program %s", program_name);
			DBG_PERROR(NULL);
			exit(EXIT_FAILURE);			
		}

		int cpu;
		if ((cpu = sched_getcpu()) < 0)
		{
			DBG_PRINT("Unable to detect the current CPU");
			DBG_PERROR(NULL);
			exit(EXIT_FAILURE);			
		}
		DBG_PRINT("Executing tracee on CPU %d\n", cpu);
		
		/* Replace this process's image with the given program image
		   will load a new binary image into memory and start
		   executing from that image's entry point */
		if (execv(program_name, arguments) < 0) {
			DBG_PRINT("Unable to execute program %s", program_name);
			DBG_PERROR(NULL);
			exit(EXIT_FAILURE);
		}

		DBG_PRINT("How did I get here?\n");
		exit(EXIT_FAILURE);
	}

	/* This will be executed by the parent after a successful fork */
	else if (child_pid > 0)
	{
	        
		return child_pid;
	}

	/* Something wnet wrong with the fork systcall */
	else
	{
		DBG_PRINT("Fork syscall failed");
	  	DBG_PERROR(NULL);
		return 0;
	}
       
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
		DBG_PRINT("Unable to open ELF file at %s", elf_path);
		DBG_PERROR(NULL);
		return retval;
	}

	/* All good with open syscall, let's proceed with ELF
	 * parsing. */
	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		DBG_PRINT("Unable to parse ELF file at %s\n", elf_path);
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
		DBG_PRINT("Unable to find the symbols table.\n");
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

	DBG_PRINT("Unable to find symbol [%s]\n", symbol_to_search);

err_close:
	close(fd);
	return retval;
}

/* This function is invoked whenever the tracee is stopped by a
 * signal. The wstat parameter carries information about the signal
 * that was delivered to the tracee. This function is invoked only
 * when WIFSTOPPED(wstat) == true */
void handle_trace_event(pid_t pid, int wstat)
{
	static enum tracee_stage stage = TRACEE_INIT;
	int procfd;
	DBG_PRINT("PID %d stopped by signal %d\n", pid, WSTOPSIG(wstat));

	switch (stage) {
		/* The tracee has just started and performed the execv
		 * call. */
	case TRACEE_INIT:
		DBG_PRINT("Process spawned. Setting breakpoint at %s (%p)\n",
			  tparams.symbol, tparams.brkpnt_addr[TRACEE_ENTRY]);
		
		tparams.brkpnt_data[TRACEE_ENTRY] =  set_breakpoint(pid, tparams.brkpnt_addr[TRACEE_ENTRY]);// ENTRY means entry of the function we are gonna set bp at
		//heap can't be scanned here since at this point there's no heap
		//if(!heap_size)
		//read_proc_maps_file(pid);//here size of heap should be set
		//DBG_PRINT("heap_size is:%d\n",heap_size);
		if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0){
			DBG_PRINT("Unable to resume tracee. Exiting.");
			exit(EXIT_FAILURE);
		}

		stage = TRACEE_ENTRY;
		break;

		/* The tracee has hit the breakpoint at the beginning
		 * of the timed function. */		
	case TRACEE_ENTRY:		
		DBG_PRINT("Process reached breakpoint at %s\n", tparams.symbol);
	
	        if (!heap_size) /*has heap already been scanned?*/
			read_proc_maps_file(pid); /*if no (heap_size = 0) scan it*/
		DBG_PRINT("heap_size after hitting the first bp is:%d\n",heap_size);
                /*interacting with kernel*/
		/*writing in proc file for calling desired function from kernel module*/
                kernel_params.pid = tparams.pid;
		procfd = open("/proc/memprofile", O_RDWR);
		if(procfd < 0) {
			DBG_PRINT("Unable to open procfile. Are you root?");
		}
		write(procfd, &kernel_params, 1* sizeof(struct params));
		//DBG_PRINT("done with interacting with kernel\n");
		
		/* Restore the original value at the breakpoint so
		 * that the process can continue */
		if(ptrace(PTRACE_POKETEXT, pid, tparams.brkpnt_addr[stage], tparams.brkpnt_data[stage]) < 0) {
			DBG_PRINT("Unable to resume from breakpoint. Exiting.");
			exit(EXIT_FAILURE);			
		}	       
		/* Rewind the PC of the tracee to before the
		 * breakpoint */
		if(set_PC(pid, tparams.brkpnt_addr[stage]) < 0) {
			exit(EXIT_FAILURE);
		}

		/* Now read return address to set a breakpoint at the
		 * return from the observed function. TODO handle
		 * possible error. */
		tparams.brkpnt_addr[stage+1] = (void *)(get_LR(pid) & ARM_ISA_MASK);
		tparams.brkpnt_data[stage+1] = set_breakpoint(pid, tparams.brkpnt_addr[stage+1]);

		DBG_PRINT("Traced function set to return to %p\n", tparams.brkpnt_addr[stage+1]);

		/* Ready to resume tracee, but not before acquiring the timing */
		get_timing(tparams.t_start);
		
		if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
			DBG_PRINT("Unable to resume from breakpoint. Exiting.");
			exit(EXIT_FAILURE);
		}
		
		stage = TRACEE_EXIT;
		break;
	case TRACEE_EXIT: /*uppon hitting the second breakpoint*/
		/* First thing first, get end of timing observation */
		get_timing(tparams.t_end);
		DBG_PRINT("TIMING: function [%s] took %ld CPU cycles\n",
			  tparams.symbol, tparams.t_end - tparams.t_start);
		if(tparams.t_start > tparams.t_end)
			printf("OVERFLOW: %lu\n",(0xFFFFFFFFUL-tparams.t_start)+tparams.t_end); 
		samples += (tparams.t_end - tparams.t_start);
		//printf("%lu,%ld\n",kernel_params.buff[kernel_params.size - 1], tparams.t_end - tparams.t_start);
		//char c = getchar();
		/* Restore the original value at the breakpoint so
		 * that the process can continue */
		if(ptrace(PTRACE_POKETEXT, pid, tparams.brkpnt_addr[stage], tparams.brkpnt_data[stage]) < 0) {
			DBG_PRINT("Unable to resume from breakpoint. Exiting.");
			exit(EXIT_FAILURE);			
		}
			       
		/* Rewind the PC of the tracee to before the
		 * breakpoint */
		if(set_PC(pid, tparams.brkpnt_addr[stage]) < 0) {
			exit(EXIT_FAILURE);
		}

		if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
			DBG_PRINT("Unable to resume from breakpoint. Exiting.");
			exit(EXIT_FAILURE);
		}
		stage = TRACEE_INIT;
		break;
	}
	
}

void child_exit_handler (int signo, siginfo_t * info, void * extra)
{
	int wstat;
	pid_t pid;

	(void)info;
	(void)extra;

	DBG_PRINT("Handler called with SIGNAL %d\n", signo);
	
	for (;;) {
		pid = waitpid (-1, &wstat, WNOHANG);
		if (pid == 0) {
			/* No change in the state of the child(ren) */
			return;		
		} else if (pid == -1 && errno != ECHILD) {
			/* Something went wrong */
			DBG_PRINT("errno is %d\n", errno);
			DBG_PERROR("Waitpid() exited with error %d");
			exit(EXIT_FAILURE);
			return;
		} else if (WIFSTOPPED(wstat)) { //for times, child is stopped
			handle_trace_event(pid, wstat);			
		} else if (WIFEXITED(wstat)){
			DBG_PRINT("PID %d terminated with status %d\n",
				  pid, WEXITSTATUS(wstat));
			done = 1;
			return;
		}
		
	}
}

/* This function installs an asynchronous handler for any signal
 * generated by the tracee/child. The global flag "done" is used to
 * terminate the sigsuspend loop.  */
void handle_tracee_signals(void)
{
	sigset_t waitmask;
	struct sigaction chld_sa, trap_sa;

	DBG_PRINT("Installing child signal handlers.\n");
	
	/* Use RT POSIX extension */
	chld_sa.sa_flags = SA_SIGINFO;
	chld_sa.sa_sigaction = child_exit_handler;
	sigemptyset(&chld_sa.sa_mask);
	sigaddset(&chld_sa.sa_mask, SIGCHLD);

	/* Install SIGCHLD signal handler */
	sigaction(SIGCHLD, &chld_sa, NULL);
       
	/* Wait for any signal */
	sigemptyset(&waitmask);
	while(!done){
		sigsuspend(&waitmask);
	}
 
	done = 0;
	//DBG_PRINT("DONE with child signal handlers.\n");

}

int main(int argc, char* argv[])
{
	int opt, i, tracee_cmd_idx, sample_size, count = 0;
	long e_value = -1;
	//char *page_numbers;
	char* mode;
	//int output[];
	//struct page_stats *page; // I cant malloc here, i dont have heap size
	FILE* fptr = fopen("output.csv","w");
	if (fptr == NULL)
	  return -1;
        FILE* fprof = fopen("profiling.csv","w");
	if(fprof == NULL)
	return -1;
	//kernel_params.buff = malloc(kernel.size*sizeof(long));
	while((opt = getopt(argc, argv, ":s:e:c:n:m:h")) != -1) {
		switch (opt) {
		case 'h':
			DBG_PRINT(HELP_STRING, argv[0]);
			return EXIT_SUCCESS;
			break;
		case 'm': //this doesnt work rn
			mode = optarg; //either profiling or running
			if(strcmp("profile",optarg) == 0)
			{kernel_params.size = 1;
				printf("mode is :%s and size is:%d\n",mode,kernel_params.size);}
			else if (strcmp("run",optarg) == 0)
				kernel_params.size = 10;
			else
				printf("wrong mode input\n");
			break;
		case 'n': //number of samples
			sample_size = strtol(optarg, NULL, 0);
			break;
		case 'c': //cacheabe : c = 1, noncacheable : c = 0
			kernel_params.shouldSkip = strtol(optarg, NULL, 0);
			printf("shouldSkip is : %d\n",kernel_params.shouldSkip);
			break;
		case 's': //symbol which we are gonna put breakpoint on
			tparams.symbol = optarg;
			DBG_PRINT("Timing function %s\n", tparams.symbol);
			break;
			//case 'o':
		        
		case 'e':
			e_value = strtol(optarg, NULL, 0);
			//DBG_PRINT("Parameter -e value: 0x%08lx\n", e_value);
			break;
		case '?':
			//DBG_PRINT("Invalid parameter. Exiting.\n");
			return EXIT_FAILURE;
		}
	}

	
	/* Parse command line parameters. Just as an example, this
	 * program accepts a parameter -e <value> and if specified it
	 * will print the value passed. It also accepts a parameter -s
	 * <symbol name> for the function to time.  Other than that,
	 * the executable to run and its parameters is expected at the
	 * end of the command line after all the optional
	 * arguments. */


	/*filling page numbers which should be sent to kernel*/
	//kernel_params.buff = malloc(kernel_params.size*sizeof(long));//if is profiling mode, size is one
	//printf("strlen(page_numbers) is: %d\n",strlen(page_numbers));
	/*for (int i = 0; i < strlen(page_numbers); i++)
	  {
	  if(!(page_numbers[i] == ','))
	  {
	  //printf("%c\n",page_numbers[i]);
	  //for (int j = i-j; j < kernel_params.size; j++)

	  kernel_params.buff[i-i/2] = strtol(&page_numbers[i], NULL, 0);
	  }
	  }
	  for (int i = 0; i < kernel_params.size; i++)
	  {
	  printf("%lu\n",kernel_params.buff[i]);
	  }*/

	//if () checking sample size

	/* Check that the symbol to observe has been specified */
	if (!tparams.symbol) {
		DBG_PRINT("No symbol/function to observe has been"
			  " specified with the -s parameter. Exiting.\n");
		return EXIT_FAILURE;		
	}

	       
	/* Check that there is a non-empty command to launch the
	 * tracee after the optional parameters */
	if (optind >= argc) {
	  	DBG_PRINT("Expected command to run after parameters. Exiting.\n");
		return EXIT_FAILURE;
	}

	/* Keep track that the command line for the tracee starts at
	 * position optind in the list of arguments. */
	tracee_cmd_idx = optind;

	/* Print out the reminder of the command, i.e. what to
	 * execute and its paramters */
	DBG_PRINT("Command to execute: [");
	for (i = tracee_cmd_idx; i < argc; ++i)
		DBG_PRINT_NOPREF("%s ", argv[i]);
	DBG_PRINT_NOPREF("\b]\n");


	/* We are ready to start the tracee. But let's try to resolve
	 * the symbol to observe right away. If we can't resolve the
	 * target symbol, there is no point in running the tracee. */
	tparams.brkpnt_addr[TRACEE_ENTRY] = resolve_symbol(argv[tracee_cmd_idx], tparams.symbol);
        
	if (tparams.brkpnt_addr[TRACEE_ENTRY] == (void *)-1) {
		return EXIT_FAILURE;
	}
	//if (strcmp(mode,"profile") == 0){
	//	printf("mode is: %s\n",mode);
	/*switch (strcmp(mode,"profiling")){
	  case 0: //profiling mode*/

	// FIRST PART IS FPR PROFILING (JUST ONE PAGE AT A TIME)
	/*for testing profiling mode i have this here, hardcoded. after fixing i should change the place
and also get the mode (profiling or running) from user I think*/

	/******************************* FIRST MODE ****************************************/

	kernel_params.size = 1; //profiling mode
	kernel_params.buff = malloc(kernel_params.size*sizeof(long));//if is profiling mode, size is one   

        set_realtime(1, PARENT_CPU); // for parent


	do
	{
		samples = 0;
		*(kernel_params.buff) = count; //because is profiling, one page at a time kernel_params.buff[0]
		//printf("count (which is page number to be sent to kernel) before the for loop is: %d\n",count);
		//kernel_params.buff = malloc(kernel_params.size*sizeof(long));//if is profiling mode, size is one
		//		      kernel_params.buff[0] = count; //page number that is gonna be sent to kernel
		for (int j = 0; j < sample_size; j++)
		{
			
			// The symbol was resolved correctly. Let's run the process
			// and do the tracing 
			tparams.pid = run_debuggee(argv[tracee_cmd_idx], &argv[tracee_cmd_idx]);
			if (tparams.pid == 0) {
				return EXIT_FAILURE;
			}
	
			// The tracee has been started and it is being traced. Now
			//install handler for signals coming from the child. 
			handle_tracee_signals();
				     
		}
			     
		if (count == 0) //first round of execution, I think for page = 0
			page = malloc(heap_size*sizeof(struct page_stats));
		page[count].cycles = samples/sample_size; 
		page[count].page_number = count; //(Don't laugh at me Renato if you are seeing this comment): . and not -> altho page is pointer to struct. bc page[i] is content, is not pointer
		printf("page[%d].cycles = %d   page[%d].page_number = %d\n",count,page[count].cycles,count,page[count].page_number);
		count++;
	
		//  printf("heap_size is:%d   count is :%d\n",heap_size,count);
	}
	while(count < heap_size);

       



	/******************************* SECOND MODE **************************************/

	//SECOND PART IS RUNNING ONCE BUT WITH MULTOPLE PAGES

	//printf("page[8].cycles = %d and page[8].page_number = %d\n", page[8].cycles,page[8].page_number);

	qsort(page,heap_size,sizeof(struct page_stats),cmpfunc); //page is sorted array after this, increasingly based on cycles
	// for cacheable mode we want max cycles (end of array, max cycles) and vice versa for noncacheable mode
	for (int i = 0; i < heap_size; i++){
		printf("cycle: %d and page number: %d\n", page[i].cycles, page[i].page_number);
	        fprintf(fprof,"%d,%d\n",page[i].page_number, page[i].cycles);
	}

	fclose(fprof);
	
        int output[heap_size];
	free(kernel_params.buff); //probably should change its place
	kernel_params.shouldSkip = 0; //bc we want to have all pages noncacheable except those in profiling info
	for (int i = 1; i <= heap_size; i++)
	  {
	    samples = 0;
	    sample_size = 1; //for now
	    
	    kernel_params.size = i;
	    kernel_params.buff = malloc(kernel_params.size*sizeof(long));
	    
	    //this parts for now just makes sense for nonc mode.when all other problems are fixed I will complete the design of this part
	        for(int j = 0; j <  i; j++)
	      {
		kernel_params.buff[j] = page[j].page_number;//read this from output of profiling mode
		//this way works if c = 0 (non-c)
		//for cacheable (c=1) kernel_params.buff[i] = page[heap_size-1-i].page_number
		//printf("kernel_params.buff[%d] = %lu\n", i, kernel_params.buff[i]);
	      }

		for (int i = 0; i < i; i++)
		  {
		    DBG_PRINT("kernel_parames.buff[%d] : %lu\n", i, kernel_params.buff[i]);
		  }
	     //The symbol was resolved correctly. Let's run the process                                                                                   
	     //run benchmark with multiple pages and getting one timing
	     tparams.pid = run_debuggee(argv[tracee_cmd_idx], &argv[tracee_cmd_idx]);

	     if (tparams.pid == 0) {
		return EXIT_FAILURE;
	      }
	   
	     //The tracee has been started and it is being traced. Now                                                                                    
	     //install handler for signals coming from the child. 
	     handle_tracee_signals();

	     //outputting
	     //DBG_PRINT("number of pages are cacheable: %d, cycles: %d\n", i, samples/sample_size);
	     output[i] = samples/sample_size;
	     fprintf(fptr,"%d,%d\n",i,output[i]);
	     free(kernel_params.buff);
	   
	    
	     }
	fclose(fptr);
	/*for (int i = 1; i <= heap_size; i++)
	  {
	    DBG_PRINT("%d , %d\n",i, output[i]);
	    }*/
	return EXIT_SUCCESS;
	  }	

