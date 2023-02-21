/*memory profiler: reads different memory infrastructures from the dtb of the kernel,
  generates memory pools from those mem infrastructures, benchmarks these different memories
  for modeling them by collecting peak bw,...., and presents it (memory profiler's output) as
  ...*/
#include <linux/timex.h> //using get_cycles 

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/irq_work.h>
#include <linux/hardirq.h>
#include <linux/perf_event.h>
#include <linux/perf_event.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <asm/atomic.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/printk.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/smp.h> /* IPI calls */
#include <linux/migrate.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <asm-generic/getorder.h>
#include <asm/tlbflush.h>
#include <asm/page.h>
#include <linux/hash.h>
#include <linux/ioport.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <asm-generic/pgalloc.h>
#include <asm/io.h>
#include <linux/proc_fs.h>
#include <linux/sched/mm.h>
#include <linux/of.h>

#include <asm/mman.h>
#include <linux/smp.h>   /* for on_each_cpu */
#include <linux/kallsyms.h>
#include <linux/genalloc.h>
#include <linux/timekeeping.h>
#include <linux/delay.h> /*for msleeo() using as test*/
#include <linux/cpumask.h>

/* #include <linux/timex.h> //using get_cycles */
/* #include <asm/barrier.h> //getting counter */
/* #include <asm/hwcap.h> */
/* #include <asm/sysreg.h> */


#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 13, 0)
#  include <linux/sched/types.h>
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 8, 0)
#  include <linux/sched/rt.h>
#endif
#include <linux/sched.h>

/* At insert time, decide if we are gonna use both pools or disable
 * them selectively */
/* int use_lopool = 1; */
/* module_param(use_lopool, int, 0660); */

/* int use_hipool = 1; */
/* module_param(use_hipool, int, 0660); */

/*****************************************************************
 *
 ****************************************************************/
/* Helper macro to prefix any print statement produced by the host *
 * process. */

//extern int (*profile_decomposer) (int);


#ifndef _SILENT_
int verbose = 0;
module_param(verbose, int, 0660);

#define DBG_PRINT(format, ...)                                          \
        do {                                                            \
		if (verbose)						\
                        pr_info("[KPROF] " format, ##__VA_ARGS__);	\
        } while (0)
#else
#define DBG_PRINT(format, ...)			\
        {}
#endif

#define DBG_INFO(format, ...)					\
        do {							\
		pr_info("[KPROF] " format, ##__VA_ARGS__);	\
        } while (0)



/**************for physical memory based on dtb 
memory type, MEM_START, MEM_SIZE
BRAM         
FPGA-DRAM           0xfffc0000UL 
OCM
DRAM
***************/


//unsigned long MEM_START[4]; //array for keeping the start address of each memory pool
//unsigned long MEM_SIZE[4];  //size of each memory pool
//TODO? enum for each memory (index for each mem to be used inabove arrays

int mem_no = 0; //for now, but I think is better to pass it rather than having as general

#define NUMA_NODE_THIS    -1

#define CACHE_LINE  64
//#define BUFFER_SIZE 16*1024*1024            /*size of buffer we read from/write to for benchmarking*/
#define MY_TYPE int                        /*type of data in allocated buffer which we read/write*/
volatile unsigned int g_start;		   /* starting time */
volatile unsigned int g_end;               /* ending time */
volatile int mywait = 1;                               //global var to tell activities on other core to start/stop

/* Handle for remapped memory */
unsigned long  __pool_kva_lo[4];
//static void * __pool_kva_lo = NULL

/*Initializing spinlocks statically*/
//DEFINE_SPINLOCK(my_lock);
/* static spinlock_t my_lock[3] = { */
/* 	__SPIN_LOCK_UNLOCKED(my_lock_0), */
/* 	__SPIN_LOCK_UNLOCKED(my_lock_1), */
/* 	__SPIN_LOCK_UNLOCKED(my_lock_2), */
/* }; */
/*defining spinlocks this way for dynamic initialization*/
static spinlock_t my_lock[4]; // one lock per core

struct gen_pool ** mem_pool;
//struct gen_pool * mem_pool[4];


struct MemRange
{
	unsigned long start;
	unsigned long size;
};

struct activityInfo
{
	volatile uint64_t g_nread; /* number of bytes read */  
	int* buffer_va; /*kvirt addr of beginning of the buffer*/
	unsigned long int buffer_size;
  
};

//for keeping reg property of memory device node in dtb
//struct MemRange mem[4]; 
struct MemRange *mem;

/* struct profiled_vma_page{ */
/*   int page_index; */
/*   unsigned long min_cycles; */
/*   unsigned long max_cycles; */
/*   double avg_cycles; */
/* }; */

/* struct profiled_vma{ */
/*   unsigned int vma_index; */
/*   unsigned int page_count; */
/*   struct profiled_vma_page *pages; */
/* }; */

//TODO
/*This should ne in header file and included by this module and kernel src*/
/* struct profile{ */
/*   unsigned int profile_len; */
/*   unsigned int num_samples;*/
/*   unsigned int heap_pad */
/*   struct profiled_vma* vmas; */
/* }; */

extern struct profile* (*profile_decomposer) (char* profile);

/*int*/struct profile*  my_profile_decomposer(char* profile)
{
        struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct file *file;
	dev_t dev = 0;
	vm_flags_t flags;
	unsigned long ino = 0;
	char* src_pos = profile;
	int i;
	unsigned long long pgoff = 0;
	unsigned int vma_count, profile_len;
	const char *name = NULL;
	//unsigned int vma_count = *(unsigned int*)(src_pos);
	//unsigned int* vma_count_ptr = kmalloc(sizeof(unsigned int));
	struct profile *myprofile = kmalloc(sizeof(struct profile), GFP_KERNEL);
	//TODO error checking for kmalloc
	printk("we are inside the __profile_decomposer()\n");

  
	//Make sure we start with a clean struct profile
	memset(myprofile, 0, sizeof(struct profile));

	/*deserializing the profile information to profile struct*/
	//memcpy(vma_count_ptr, src_pos ,sizeof(unsigned int)); 
	//reading number of VMAs in this layout
	memcpy((void *)&vma_count, src_pos,sizeof(unsigned int)); //(void* or &vma_count?
	printk("test after the first memcpy\n");
	src_pos += sizeof(unsigned int);
	printk("number of VMAs in the layout of this process is:%d\n",vma_count);

	//going forward as much as application layout
	src_pos += vma_count*sizeof(struct vma_descr);

	//reading the actual profile (header), reading all first three elements in one shot
	memcpy((void*)&myprofile->profile_len, src_pos, 3*sizeof(unsigned int));
	src_pos += 3*sizeof(unsigned int); // position now is at profiled_vma* 
	profile_len = myprofile->profile_len; //I think # VMAs have been profiled
	printk("profile_len is: %d\n",myprofile->profile_len);

	myprofile->vmas = kmalloc(profile_len*sizeof(struct profiled_vma),GFP_KERNEL);
	//TODO error checking for kmalloc

	for (i = 0; i < profile_len; ++i) { //profile_len is number of profiled VMA
		struct profiled_vma *vma = &myprofile->vmas[i];// putting address of field vmas[i] of myprofile which we kmalloced above
		/*address of first element of myprofile->vmas (which is a vma that is included
		  in the profile meaning that it has at least one imp page, is in vma in each round.
		  in this memcpy we read from right src_pos in each i and put in right place
		  we read both vma_index and page_count in one shot*/
		memcpy((void *)&vma->vma_id, src_pos, 2*sizeof(unsigned int));
		src_pos += 2*sizeof(unsigned int);
		if (i == 0) //heap is 20
		  vma->vma_id = 20;
		if (i == 1) //stack is zero
		  vma->vma_id = 0;
		printk("VMA %d (idx: %d) has %d pages.\n", i, vma->vma_id, vma->page_count);

		if (vma->page_count) {
		       
			ssize_t pg_size = vma->page_count*sizeof(struct profiled_vma_page);
			vma->pages = (struct profiled_vma_page *)kmalloc(pg_size,GFP_KERNEL);
			memcpy(vma->pages, src_pos, pg_size /*sizeof(struct profiled_vma_page)*/);
			src_pos += pg_size /*sizeof(struct profiled_vma_page)*/;
		}
		else {
			vma->pages = NULL;
		}
    
	}

	//printing layout of the application
	mm = current->mm;
	vma = mm->mmap;
	file = vma->vm_file;
	flags = vma->vm_flags;
	printk("\nThis mm_struct has %d vmas.\n", mm->map_count);
	//for (vma = mm->mmap ; vma ; vma = vma->vm_next){
	if (file) {
                struct inode *inode = file_inode(vma->vm_file);
		dev = inode->i_sb->s_dev;
                ino = inode->i_ino;
                pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
        }

	if (vma->vm_ops && vma->vm_ops->name) {
		name = vma->vm_ops->name(vma);
		printk("name is %s\n",name);
		//goto done;
	}
	//name = arch_vma_name(vma);
	/* if (!name) { */
        /*         if (!mm) { */
        /*                 name = "[vdso]"; */
        /*                 //goto done; */
        /*         } */

        /*         if (vma->vm_start <= mm->brk && */
        /*             vma->vm_end >= mm->start_brk) { */
        /*                 name = "[heap]"; */
        /*                 //goto done; */
        /*         } */
//	}


	//}

//done:
	
	
  

	return myprofile;

  
}


unsigned int get_usecs(void)
{
	//ktime_t time;
	struct timeval time; //inclduing sec and ns or us?
	time = ktime_to_timeval(ktime_get_real());
	return (time.tv_sec * 1000000 + time.tv_usec);
  
}

///*static int*/ void pool_range(void)// why static int? //designing error handling path
void pool_range(void){
  
	struct device_node **mem_type;
	struct device_node *node_count;
	u64 regs[2];//regs[0] = start and regs[1] = size 
	int rc,i,j;
	
	printk("inside pool_range()\n");

        /*scanning nodes in the first round for realizing the number of nodes with compatible = genpool*/
	node_count = NULL;
	do
	{
		node_count = of_find_compatible_node(node_count, "memory","genpool");
		if (node_count)
			mem_no++;
	}
	while(node_count != NULL);

	mem_type = kmalloc(mem_no*sizeof(struct device_node*), GFP_KERNEL);
  	mem = kmalloc(mem_no*sizeof(struct MemRange),GFP_KERNEL);

	/*second round is for actually reading nodes of dtb with compatible = genpool and reading
	  the start addr and the size of each type of memory node to make memory pool with*/
	
	//for reading the start and size of the first desired  memory node
	mem_type[0] = of_find_compatible_node(NULL,"memory","genpool");

	if (!mem_type){
		printk("mem_type is NULL!\n");
	}
	
	for (i = 0; i < 2; i++)
	{
		rc = of_property_read_u64_index(mem_type[0],"reg",
						i, &regs[i]);
		if (rc){
			printk("didn't catch the regs<mem_start> correctly\n");
		}
	}
        printk("mem[0].start : %llx, mem[0].size = %llx \n",regs[0], regs[1]);
        mem[0].start = regs[0];
        mem[0].size = regs[1];

	//for reading the start and size of rest of desired memory nodes
	for (i = 1; i <= mem_no; i++){
		mem_type[i] = of_find_compatible_node(mem_type[i-1],"memory","genpool");

		if (!mem_type[i]){
			printk("END of memory nodes\n");
			break;
		}

		
		for (j = 0; j < 2; j++)
		{
		
			rc = of_property_read_u64_index(mem_type[i],"reg",
							j, &regs[j]);
			if (rc){
				printk("didn't catch the regs<mem_start> correctly\n");
			}
		} 

		printk("mem[%d].start: %llx and mem[%d].size: %llx\n",i,regs[0],i,regs[1]);
		
		mem[i].start = regs[0];
		mem[i].size = regs[1];
	}
  

}

static int initializer(int* ret)
{
	int i;
	printk("mem_ni is : %d\n",mem_no);
	for (i = 0; i < mem_no; i++)
        {
                ret[i] = -1;
        }
	//two-dimension array kmallocing
	mem_pool = kmalloc(mem_no*sizeof(struct gen_pool*),GFP_KERNEL);
        for (i = 0; i < mem_no; i++)
        {
                mem_pool[i] = kmalloc(sizeof(struct gen_pool),GFP_KERNEL);
        }

	printk("Remapping reserved memory area\n");

	for (i = 0; i < mem_no; i++)
        {
         	__pool_kva_lo[i] = (unsigned long)memremap(mem[i].start, mem[i].size, MEMREMAP_WB);

                if (__pool_kva_lo[i] == 0) {
                        pr_err("Unable to request memory region @ 0x%08lx. Exiting.\n",mem[i].start);
                        goto unmap;
                }

		ret[i] = 0;
        }
	/*creating memory pools for different memory technologies*/
	for (i = 0; i < mem_no; i++)
        {
                mem_pool[i] = gen_pool_create(PAGE_SHIFT, NUMA_NODE_THIS);
                ret[i] |= gen_pool_add(mem_pool[i], (unsigned long)__pool_kva_lo[i],
                                       mem[i].size, NUMA_NODE_THIS);

                if (ret[i] != 0) {
			pr_err("Unable to initialize genalloc memory pool.\n");
                        goto unmap;
                }
        }

        kfree(mem);

        return 0;

unmap:
	printk("for now: here is unmap!\n");
	return -1;
	
}



int64_t bench_read(struct activityInfo* myinfo)
{
	int i;
	int64_t sum = 0;
	//int count = 0;
	for ( i = 0; i < myinfo->buffer_size/sizeof(MY_TYPE); i+=(CACHE_LINE/sizeof(MY_TYPE)) ) {
		sum += myinfo->buffer_va[i];
		//count++;
	}
	myinfo->g_nread += myinfo->buffer_size;// here g_nread is addr, we received as addr 
	//printk("number of iteration in the memory buffer is: %d\n", count);
	return sum;
}

int buffer_allocation(struct activityInfo* myinfo) 
{ 
	int i;

	/*allocating buffer, buffer_va is the beginning addr*/
        myinfo->buffer_va = (int *) gen_pool_alloc(mem_pool[2], myinfo->buffer_size);
        printk("VA of beginning of the buffer: 0x%08lx\n",(unsigned long)(myinfo->buffer_va));

        if (!(myinfo->buffer_va)) {
                printk("unable to allocate buffer.\n");
		return 1;
        }

        for ( i = 0; i < myinfo->buffer_size/sizeof(MY_TYPE); i++)
        {
                myinfo->buffer_va[i] = i;
        }

	return 0;
} 


static void activity_stress(void* myinfo)
{
	struct activityInfo my_info;
	unsigned long flags;
	int i, retval;
	int64_t sum;

	local_irq_save(flags);
	get_cpu();
	printk("we are on cpu: %d\n",smp_processor_id());

	spin_unlock(&my_lock[smp_processor_id()]);

	printk("first lock in STRESS :%d",!!spin_is_locked(&my_lock[smp_processor_id()]));


	/*allocating buffer*/
	my_info.buffer_size = 1*1024*1024; //should we get this from outside?
	printk("STRESS: before buffer_allocation()\n");

	retval = buffer_allocation(&my_info);
	if (retval != 0) {
		printk("buffer_allocation() failed.\n");
		//return;
	}
	/*main activity*/
	while(mywait)
	{		
		for ( i = 0; i < my_info.buffer_size/sizeof(MY_TYPE); i+=(CACHE_LINE/sizeof(MY_TYPE)) ) {
			sum += my_info.buffer_va[i];                                                                               	}
	}
	
	spin_unlock(&my_lock[smp_processor_id()]);

	printk("second lock in STRESS :%d",!!spin_is_locked(&my_lock[smp_processor_id()]));


	/*freeing the buffer*/
	gen_pool_free(mem_pool[2], (unsigned long)(my_info.buffer_va),my_info.buffer_size);
        put_cpu();
	local_irq_restore(flags);

}

static void activity_idle(void* myinfo)
{
	/* int count = 1000; */
	/* printk("mywait is %d\n",mywait); */
	/* while (1) */
	/* { */
	/* 	if (mywait != 0) */
	/* 	{ */
	/* 		count--; */
	/* 		if (count < 0) */
	/* 			break; */
	/* 	} */
	/* } */
	/* printk("mywait is %d\n",mywait); */
	unsigned long flags;
	
	local_irq_save(flags);
	get_cpu();
        printk("IDLE: mywait before while is %d\n",mywait);

	spin_unlock(&my_lock[smp_processor_id()]);

	printk("first lock in IDLE :%d",!!spin_is_locked(&my_lock[smp_processor_id()]));

	/*main activity-busy loop*/
	while (mywait)
	{
		//break;
	}
	//printk("mywait after while is %d\n",mywait);
	spin_unlock(&my_lock[smp_processor_id()]);

	printk("second lock in IDLE :%d",!!spin_is_locked(&my_lock[smp_processor_id()]));

	put_cpu();
	local_irq_restore(flags);

}

/*static int*/void  bandwidth_measurment(void)
{
	//cycles_t start,end;
	unsigned long flags; // for interrupt state
	unsigned int dur, c;
	long int bandwidth, i;
	int retval, j, k, z, local_core, counter1, counter2;
	struct cpumask mymask1, mymask2;
	int64_t sum_read = 0;
	struct activityInfo myinfo;

	myinfo.g_nread = 0;
        myinfo.buffer_size = 16*1024*1024; ///should I get this from user?

	/*allocating buffer for benchmarking*/
	retval = buffer_allocation(&myinfo);
	if (retval != 0) {
		printk("buffer_allocation() failed.\n");
	}

	//Initializing locks
	for (i = 0; i < 4; i++)
	{
		spin_lock_init(&my_lock[i]);
		spin_lock(&my_lock[i]);
		//if locked, return value is 1
		printk("lock is :%d",spin_is_locked(&my_lock[i]));
	
	}


	local_core = get_cpu();
	printk("local_core is: %d\n",local_core);

	/*main activity loop*/
	for (j = 0; j < 4; j++)
	{
		/*reset masks at the begining of each iteration*/
		cpumask_clear(&mymask1);
		cpumask_clear(&mymask2);
		myinfo.g_nread = 0;


		//j = 3;
		printk(" j = %d\n",j);
		mywait = 1;
		counter1 = 0;
		counter2 = 0;
		printk("local core is(inside for): %d\n",local_core);
		/*c is # of cores which run the activity*/
		for ( c = 0; c < 4; c++) 
		{
	
			if (c == local_core)
				continue;

			if (counter1 < j) //when we want just one core runs f1
			{
				//f1_mask.set(c);
				cpumask_set_cpu(c,&mymask1);
				counter1++;
			}
			else if (counter2 < (4-j))
			{
				cpumask_set_cpu(c,&mymask2);
				counter2++;
			}
		
		
		}

		/*for testing mymask*/
		for (k = 0; k < 4; k++)
		{
			if(cpumask_test_cpu(k,&mymask1))
				printk("mymask1 %d is set\n", k);
			//if(cpumask_test_cpu(k,&mymask2))
			//printk("mymask2 %d is set\n", k);

		}

		for (k = 0; k < 4; k++)
		{
			if(cpumask_test_cpu(k,&mymask2))
				printk("mymask2 %d is set\n", k);
			//if(cpumask_test_cpu(k,&mymask2))
			//printk("mymask2 %d is set\n", k);

		}

		/*starting remote activities*/
		on_each_cpu_mask(&mymask1,activity_idle,NULL,false);
	        on_each_cpu_mask(&mymask2,activity_stress,NULL,false);

		/*This way for all locks corresponding to all remote cores we are trying
		  to grab the lock. spin_lock spins and tries to acquire the lock*/
		for (z = 0; z < 4; z++)
		{
			if (z == local_core) continue; // we don want to spin on lock corresponds to local core
			spin_lock(&my_lock[z]);
			printk("BEFORE MEASURMENT:lock[%d] is:%d\n",z,spin_is_locked(&my_lock[z]));
		    
		}
		local_irq_save(flags);
		/*beginning of time mesurment*/
		g_start = get_usecs();

		//Benchmarking: accessing the memory
		for (i = 0; i < 100; i++)
		{
			sum_read += bench_read(&myinfo);// pass as pointer to keep changes
		}
		    

		g_end = get_usecs();
		local_irq_restore(flags);
		/*ending remote activities*/
		mywait = 0;

		for (z = 0; z < 4; z++)
		{
			if (z == local_core) continue; // we don want to spin on lock corresponds to local core
			spin_lock(&my_lock[z]);
		}

		msleep(100);

		dur = g_end - g_start;
//	printk("elapsed time is: %ld cycles\n", (end-start));
		printk("elapsed = (%d usec)\n", dur);

		//bandwidth calculation
		printk("g_nread(bytes read) = %lld\n", (uint64_t)(myinfo.g_nread));
		bandwidth = myinfo.g_nread / dur;
		printk("B/W = %ld MB/s", bandwidth);

	       
	} //j loop


	put_cpu();



	//
	/* printk("g_nread is :%lld\n",myinfo.g_nread); */
	/* smp_call_function_single(0, test_other_cpu,NULL,false); */
	/* g_start = get_usecs(); */
	
	/* retval = smp_call_function_single(1, test_local_cpu,&myinfo,true); */
	/* if (retval != 0) */
	/*   { */
	/*     printk("error!!!\n");//what are right questions to ask to design error handling paths? */
	/*   } */

	/* g_end = get_usecs(); */
	

	/* /\*benchmarking operation*\/ */
	/* this_cpu = get_cpu(); */
	/* printk("cpu ID is = %d\n",this_cpu); */
	/* //start = get_cycles(); */
	/* g_start = get_usecs(); */
	
	/* //accessing the memory */
	/* for (i = 0; i < 1000; i++) */
	/* { */
	/* sum_read += bench_read(buffer_va, &g_nread);// pass as pointer to keep changes */
	/* } */

	/* //msleep(10); /\*for test*\/ */

	/* //end = get_cycles(); */
	/* g_end = get_usecs(); */
	

	/* put_cpu(); */

	
	/*freeing the buffer*/
	gen_pool_free(mem_pool[2], (unsigned long)(myinfo.buffer_va), myinfo.buffer_size);
}
	


static int mm_exp_load(void){

	int init;
	int* ret;
	
	printk(KERN_INFO "Online CPUs: %d, Present CPUs: %d\n", num_online_cpus(),num_present_cpus());
	
	pool_range(); //reading start and size from dtb for making memory pools
	//printk("outside the pool_range() and mem_no is:%d\n",mem_no);
	//int ret[mem_no];
    
        ret = kmalloc(mem_no*sizeof(int),GFP_KERNEL);

	/*initialization of memory pools*/
	init = initializer(ret);
        if (init == 0)
                printk("init is %d\n",init);
        printk("after mem_pool initialization\n");

	bandwidth_measurment(); /*benchmarking the bandwidth*/

	//Install handlers (callback function)
	profile_decomposer = my_profile_decomposer;

	pr_info("KPROFILER module installed successfully.\n");

	return 0;

}	
	

static void mm_exp_unload(void)
{
	int i;

	/* destroy genalloc memory pool */
	for (i = 0; i < mem_no; i++)
	{
	
		if (mem_pool[i]){
	                gen_pool_destroy(mem_pool[i]);
			printk("destroying happened successfully\n");}
	}
        

	/* Unmap & release memory regions */
	for (i = 0; i < mem_no; i++)
	{
		memunmap((void *)__pool_kva_lo[i]);
	}

	//free the handler
	profile_decomposer = NULL;

	pr_info("KPROFILER module uninstalled successfully.\n");
}

module_init(mm_exp_load);
module_exit(mm_exp_unload);

MODULE_AUTHOR ("Golsana Ghaemi, Renato Mancuso");
MODULE_DESCRIPTION ("memory profiler to characterize different memories in the system");
MODULE_LICENSE("GPL");
