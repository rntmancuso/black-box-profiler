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

#define BUF_SIZE 50*1024 //50KB, each page is 4KB, so first 12 pages of the heap are used
#define BUF2_SIZE 500*1024

#define get_timing(cycles) 				\
	do {                                            \
		asm volatile("mrs %0, cntvct_el0"       \
			     : "=r"(cycles));		\
	} while (0)

void loop (char *buf, char *buf2)
{
     	for(int i=0; i<1000; ++i)
	{
		for(int c=0; c< BUF_SIZE; c+=64)
		{
			buf[c] = buf[c] + 1;
		}
       	}


	for (int j=0; j < 100; j++)
	{
		for (int d = 0; d < BUF2_SIZE; d+=64)
		{
			buf2[d] = buf2[d] + 1;
		}

	}

}
int main (int argc, char** argv)
{     
	unsigned long time_start;
	unsigned long time_end;
	char buff[100];
	char *buf  =  malloc(BUF_SIZE);
	char *buf2 = malloc(BUF2_SIZE);

	
	//starting time measurment
	time_start = 0;
	get_timing(time_start);
	//function we put breakpoint at
	loop (buf,buf2);
	//ending the time measurment
	time_end = 0;
	get_timing(time_end);
  
	//printing time measurment
	if (time_end > time_start)
		printf("\nCycles : %lu\n",time_end - time_start);
        
	return 0;

}
