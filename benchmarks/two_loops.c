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

#define BUF_SIZE 50*1024 //50KB, each page is 4KB, so first 12 pages of heap are used
#define BUF2_SIZE 500*1024

#define get_timing(cycles) 				\
	do {                                            \
		asm volatile("mrs %0, cntvct_el0"       \
			: "=r"(cycles));                \
	} while (0)
	


void loop (char *buf, char *buf2)
{
	unsigned long ts, te;
	get_timing(ts);

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

	get_timing(te);
	printf("Loop took: %lu\n", te-ts);

}
int main (int argc, char** argv)
{

  
         
//for measuring time using ARM counter (PMU) 
//  struct timespec start, finish;     
	unsigned long time_start;
	unsigned long time_end;
        int procfd;
	char buff[100];
	char *ptr;
        char c;
	char *buf  =  malloc(BUF_SIZE);
	char *buf2 = malloc(BUF2_SIZE);

	
	//starting time measurment
	time_start = 0;
	get_timing(time_start);
	
	printf("before loop() buf = %p, buf2 = %p\n", buf, buf2);
	//getchar();
	loop (buf,buf2);

	//do real stuff (writing into heap)
  	printf("after loop\n");

        //printf("goodbye!\n");
	//ending time mesurment
	//clock_gettime(CLOCK_REALTIME, &finish);
		time_end = 0;
		get_timing(time_end);
  

	//	if (time_end > time_start)
		printf("\nCycles : %lu\n",time_end - time_start);
	//	printf("%ld:%lu\n",/*strtol(argv[1],&ptr,0)*/page_number,time_end - time_start); 
	//	else
	//	printf("%ld:%lu\n",page_number,(0xFFFFFFFFUL-time_start)+time_end); 
         
	//free (buf);
	//c = getchar();
	
	return 0;

}
