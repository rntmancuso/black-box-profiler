#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>

/* Functions to interact with CPU cycle counter */
#define magic_timing_begin(cycles)\
	do{								\
		asm volatile("mrs %0, CNTVCT_EL0": "=r"(*(cycles)) );	\
	}while(0)

#define magic_timing_end(cycles)					\
	do{								\
		unsigned long tempCycleLo;				\
		asm volatile("mrs %0, CNTVCT_EL0":"=r"(tempCycleLo) );  \
		*(cycles) = tempCycleLo - *(cycles);			\
	}while(0)


#define NOP_SINGLE asm volatile("nop");
#define NOPS_2 \
	NOP_SINGLE \
	NOP_SINGLE
#define NOPS_4 \
	NOPS_2 \
        NOPS_2
#define NOPS_8 \
	NOPS_4 \
        NOPS_4
#define NOPS_16 \
	NOPS_8 \
        NOPS_8
#define NOPS_32 \
	NOPS_16 \
        NOPS_16
#define NOPS_64 \
	NOPS_32 \
        NOPS_32
#define NOPS_128 \
	NOPS_64 \
        NOPS_64
#define NOPS_256 \
	NOPS_128 \
        NOPS_128
#define NOPS_512 \
	NOPS_256 \
        NOPS_256
#define NOPS_1K \
	NOPS_512 \
        NOPS_512
#define NOPS_2K \
	NOPS_1K \
        NOPS_1K
#define NOPS_4K \
	NOPS_2K \
        NOPS_2K
#define NOPS_8K \
	NOPS_4K \
        NOPS_4K
#define NOPS_16K \
	NOPS_8K \
        NOPS_8K
#define NOPS_32K \
	NOPS_16K \
        NOPS_16K
#define NOPS_64K \
	NOPS_32K \
        NOPS_32K


void long_function(void) {
	asm volatile("dsb sy");
	NOPS_64K;
	asm volatile("dsb sy");
}

/* Set real-time SCHED_FIFO scheduler with given priority */
void set_realtime(int prio)
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

	cpu_set_t set;
	CPU_ZERO(&set);
	
	/* default to CPU 1 by default */
	CPU_SET(1, &set);
	
	if (sched_setaffinity(getpid(), sizeof(set), &set) == -1) {
		perror("Unable to set CPU affinity.");
		exit(EXIT_FAILURE);			
	}
	
}

int main() {
	unsigned long ts;

	int max_prio = sched_get_priority_max(SCHED_FIFO);
	set_realtime(max_prio);
	
	while(1) {
		magic_timing_begin(&ts);
		long_function();
		magic_timing_end(&ts);
		printf("Exec. took %d\n", ts);
		//sleep(1);
	}

	return EXIT_SUCCESS;
}
