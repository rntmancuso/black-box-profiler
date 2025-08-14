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

#define BUF_SIZE 50*1024 // each page is 4KB, so first 12 pages of heap are used
#define BUF2_SIZE 500*1024 //500KB, almost 212 pages
#define BUF3_SIZE 300*1024 //300 KB, almsot 75 pages


#define get_timing(cycleLo) {                                           \
		asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r" (cycleLo) ); \
	}


void loop(char* buf, char* buf2, char* buf3)
{
  	for(int i=0; i<500; ++i)
	{
		for(int c=0; c< BUF_SIZE; c+=32)
		{
			if (c%5 == 0)
			{
				buf[c] = c;
			}
			buf[c] = i;
		}
	}

	 for (int j=0; j < 200; j++)
	{
		for (int d = 0; d < BUF2_SIZE; d+=32)
		{
			buf2[d] = j;
		}
	    
		}

	 for(int i=0; i<500; ++i)
	  {
	    for(int c=0; c< BUF3_SIZE; c+=32)
	      {
		if (c%5 == 0)
		  {
		    buf3[c] = c;
		  }
		buf3[c] = i;
	      }
	      }
}

int main (int argc, char** argv)
{

       
	unsigned long time_start;
	unsigned long time_end;
        int procfd;
	char buff[100];
	char *ptr;
        char c;
	char *buf  =  malloc(BUF_SIZE);  
	char *buf2 = malloc(BUF2_SIZE);
	char *buf3 = malloc(BUF3_SIZE);


	/*
	//starting time measurment
	time_start = 0;
	get_timing(time_start);*/
	printf("before loop\n");

	// real stuff
	loop(buf,buf2,buf3);

	printf("after loop\n");

	/*time_end = 0;
	get_timing(time_end);
	
	if (time_end > time_start)
	printf("\nCycles when page %ld is cacheable are: %lu\n",page_number,time_end - time_start);*/
	// printf("%ld:%lu\n",/*strtol(argv[1],&ptr,0)*/page_number,time_end - time_start);
//else
//		printf("%ld:%lu\n",page_number,(0xFFFFFFFFUL-time_start)+time_end); 
         
	//free (buf);
	//c = getchar();
	return 0;

}

