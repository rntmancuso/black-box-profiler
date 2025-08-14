/******************************************************************************/
/*                                                                            */
/* BU Black-Box Profiler (BBProf) -- Staicase Access Synthetic Benchmark      */
/*                                                                            */
/* Author: Golsana Ghaemi, Renato Mancuso (BU)                                */
/*                                                                            */
/* Description: This benchmark allocates a large pool of heap memory and then */
/*              accesses pages towards the end of the buffer less and less    */
/*              often, resuling in the relative importance of heap pages to   */
/*              have a characteristic "staircase" shape when correctly        */
/*              detected and plotted.                                         */
/*                                                                            */
/* NOTE: make sure to compile with -O0 to prevent the compiler from           */
/*       optimizing away the main memory access loop.                         */
/*                                                                            */
/******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>     /* Support all standards    */
#include <sys/mman.h>   /* Memory locking functions */
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

/* Allocate 100 heap pages */
#define BUF_SIZE 100*4*1024

/* How many loops will be performed */
#define ITERATIONS 1000

/* After how many additional iterations we descrease the starting
 * point in the buffer */
#define THRESHOLD 200

/* By how much we advance the buffer pointer every time we hit a new
 * threshold (20KB) */
#define INCREMENT 20*4*1024

unsigned long do_access (char * buf)
{
	unsigned long crc = 0;
	int i, s, thr = THRESHOLD, start = 0;

	/* Main access loop */
	for (i = 0; i < ITERATIONS; ++i) {
		if (i == thr) {
			thr += THRESHOLD;
			start += INCREMENT;
			printf("%d -> %d\n", i, start);
		}

		for (s = start; s < BUF_SIZE; ++s) {
			crc += buf[s];
		}
	}

	return crc;
}

int main (int argc, char** argv)
{
	/* Allocate and initialize main buffer */
	char * buf = malloc(BUF_SIZE);
	memset(buf, 1, BUF_SIZE);

	/* Perform accesses. Launch profiler as: -s do_access */
	unsigned long crc = do_access(buf);

	/* Deallocate buffer */
	free(buf);

	/* Print out CRC just in case */
	printf("Staircase benchmark completed. CRC = %ld\n", crc);

	return 0;
}
