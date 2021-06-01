# BU Black-box Profiler

This repository contains the user and kernel code, and the kernel
patches to instantiate the BU black-box cache profiler.

## Deploy Instructions

### Setting-up ZCU102 Board

Familiarize with the partitions of the SD-card. There are two partitions, namely a **boot** partition and the **root** partition.
Follow the steps below to compile and deploy the custom Linux kernel and DTB.

1. Download the files in the archive under *bootfiles/* and decompress them into the boot partition.

2. The bootfiles do not include the kernel (`Image`) and device tree (`system.dtb`). These will be generated as we compile the custom kernel.

3. Checkout the modified kernel from the *linux-xlnx-prof* repo: https://github.com/rntmancuso/linux-xlnx-prof

4. Copy the kernel configuration file *config/linux-xlnx-prof.config* into the kernel source directory and rename it *.config*

5. Make sure you have the aarch64 gcc compiler installed. On Ubuntu (or Debian-based distros), you can install that via `sudo apt-get install gcc-aarch64-linux-gnu`

6. Make also sure you have the device tree compiler installed. On Ubuntu, do `sudo apt-get install device-tree-compiler`

7. Compile the kernel! If you have 4 cores, move to the kernel sources directory and run: `make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- Image -j 4`

8. If the compilation is successful, you will find the file *arch/arm64/boot/Image* to copy into the boot partition.

9. Let's compile the DTB next. Once again from the top of the kernel sources directory run: `make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- dtbs`

10. If the step above is successful, the file *arch/arm64/boot/dts/xilinx/zynqmp-zcu102-pvtsh.dtb* will be generated.

11. Copy the .dtb file mentioned above in the boot partition **but rename it as** *system.dtb*

That's it! The board should be able to boot now. Notice that the *boot.scr* is set up so to start the kernel using the `/dev/mmcblk0p2` partition of the sd-card as the root filesystem.

### Setting-up the Black-box profiler

1. Clone the profiler from *black-box-profiler* repo: https://github.com/rntmancuso/black-box-profiler.git

2. Before compiling the profiler on the ZCU, you need to either cross-compile the elf library or decompress the pre-compiled library. For the former, run the install_libelf.sh from the profiler folder on Ubuntu. For the later, decompress the *zcu_elflib.tar.gz* on the ZCU and add it to the Makefile for the profiler compilation. It is added as *libs* as the following in the Makefile: `CFLAGS=-I. -W -Wall -I./libs/include/ -D_VERBOSE_`, and `LDFLAGS=-lelf -L./libs/lib/ -lz`

3. Next step is cross-compiling the BBProf's kernel module (aarch64_kmod) from the kernel_module folder of the  *black-box-profiler* repo. To do that, replace the path of custom kernel source code in  `BLDDIR = ` with your own path of the kernel source code which you have checked out in the setting-up ZCU102.

4. At this point the BBProf is ready to use. Profiler is supposed to be run with 2 mandatory command-line parameters. One of them is the name of the executable binary file of the program that we want to profile and the second one is the name of the symbol which we are interested in putting the breakpoint at. The first parameter should be set as the last command-line argument and symbol is determined by -s flag. (ex: ./profiler -s f1(name of the function) hello (name of the exe).

5. As an example, we consider synthetic benchmrk *two_loops* and run it  with different command-line parameters of the profiler which are listed as the following:<br/>
<br>-h : Prints the help string.<br/>
           -m MODE : Profiling mode: c = make page cacheable, everything else non-cacheable.(default)
	           nc = make page non-cacheable, everything else cacheable.<br/>
           -l : Print out application's layout when scanning VMAs.<br/>
           -f FLAGS : VMA scan flags: t = text, h = heap, s = stack, b = BSS, r = rodata.<br/>
	                              a = first anon, A = all anon, m = libm, c = libc<br/>
				      (default = hs)<br/>
           -r : Perform page ranking. Output sent to stdout.<br/>
	   -s SYM : Name of target function to profile in the target executable.<br/>
           -o PATH : Save profile to file specified by PATH.<br/>
	   -i PATH : Load profile from file specified by PATH.<br/>
           -p : Pretend mode, i.e. no kernel-side operations.<br/>
           -q : Quiet mode, i.e. output of tracee is suppressed.<br/>
           -v : Verbose mode, i.e. show A LOT of debug messages.<br/>
           -n NUM : Number of profiling samples to acquire and aggregate (default = 1).<br/>
           -g NUM : Perform page migration. Migrate the NUM top-ranking pages.<br/>
           -t : Translate profile acquired or specified via -i parameter in human readable form..<br/>
           -N : Non-realtime mode: do not set real-time priorities for profiler nor tracee.<br/>


In the example below, loop is the name of function (symbol) we put the breakpoint at, two_loops is the name of executable binary of the process, -l prints the virtual memory layout of the process, the profile is saved in two_loops_layout.prof. Two * show that among VMAs, heap and stack are scanned.
```
./profiler -o two_loops_layout.prof -l -s loop two_loops
	[DBG] Command to execute: [two_loops]
	[DBG] [  0]    00400000-00401000 r-xp 00000000 b3:02 3585                               /home/root/two_loops
        [DBG] [  1]    00410000-00411000 rw-p 00000000 b3:02 3585                               /home/root/two_loops
        [DBG] [  2] *  1f0ed000-1f1b0000 rw-p 00000000 00:00 0                                  [heap]
        [DBG] [  3]    7fa3061000-7fa318c000 r-xp 00000000 b3:02 784937                         /lib/libc-2.23.so
        [DBG] [  4]    7fa318c000-7fa319b000 ---p 0012b000 b3:02 784937                         /lib/libc-2.23.so
        [DBG] [  5]    7fa319b000-7fa319f000 r--p 0012a000 b3:02 784937                         /lib/libc-2.23.so
        [DBG] [  6]    7fa319f000-7fa31a1000 rw-p 0012e000 b3:02 784937                         /lib/libc-2.23.so
	[DBG] [  7]    7fa31a1000-7fa31a5000 rw-p 00000000 00:00 0 
        [DBG] [  8]    7fa31a5000-7fa31c1000 r-xp 00000000 b3:02 785052                         /lib/ld-2.23.so
        [DBG] [  9]    7fa31ca000-7fa31cb000 rw-p 00000000 00:00 0 
        [DBG] [ 10]    7fa31cd000-7fa31ce000 rw-p 00000000 00:00 0 

	[DBG] [ 11]    7fa31ce000-7fa31cf000 r--p 00000000 00:00 0                              [vvar]
	[DBG] [ 12]    7fa31cf000-7fa31d0000 r-xp 00000000 00:00 0                              [vdso]
	[DBG] [ 13]    7fa31d0000-7fa31d1000 r--p 0001b000 b3:02 785052                         /lib/ld-2.23.so
	[DBG] [ 14]    7fa31d1000-7fa31d3000 rw-p 0001c000 b3:02 785052                         /lib/ld-2.23.so
	[DBG] [ 15] *  7fe57a7000-7fe57c8000 rw-p 00000000 00:00 0                              [stack]
	[DBG] PROFILING: Collecting sample 1 of 1
	PROFILING: [####################################################################################################] (228/228)
	[DBG] Profile written to two_loops_layout.prof. Total size: 7376 bytes
	[DBG] Profile written to two_loops_layout.prof. Total size: 7376 bytes~
```
      
In the second example, -t parametr translates the profile information to the human-readable format.
```
./profiler -t -o two_loops_verbose.prof -s loop two_loops
       [DBG] Command to execute: [two_loops]
       [DBG] PROFILING: Collecting sample 1 of 1
       PROFILING: [####################################################################################################] (228/228)
       [DBG] Profile written to two_loops_verbose.prof. Total size: 7376 bytes
       [DBG] Profile written to two_loops_verbose.prof. Total size: 7376 bytes
       [DBG] 
       ----------------- PROFILE (1 samples) -----------------
       [DBG] heap_pad = 728
       [DBG] ========== (0/2) VMA index: 2 ==========
       [DBG] PAGE: 0x000b	CYCLES: max: 59497177	min: 59497177	avg: 59497177.000000
       [DBG] PAGE: 0x0002	CYCLES: max: 59565874	min: 59565874	avg: 59565874.000000
       [DBG] PAGE: 0x0096	CYCLES: max: 59709451	min: 59709451	avg: 59709451.000000
       [DBG] PAGE: 0x0010	CYCLES: max: 59736791	min: 59736791	avg: 59736791.000000
       [DBG] PAGE: 0x0027	CYCLES: max: 59785253	min: 59785253	avg: 59785253.000000
       [DBG] PAGE: 0x00ba	CYCLES: max: 59850656	min: 59850656	avg: 59850656.000000
       [DBG] PAGE: 0x0005	CYCLES: max: 59863999	min: 59863999	avg: 59863999.000000
       [DBG] PAGE: 0x000a	CYCLES: max: 59872283	min: 59872283	avg: 59872283.000000
       [DBG] PAGE: 0x008a	CYCLES: max: 59933988	min: 59933988	avg: 59933988.000000
       [DBG] PAGE: 0x000e	CYCLES: max: 59954842	min: 59954842	avg: 59954842.000000
       [DBG] PAGE: 0x0009	CYCLES: max: 59962777	min: 59962777	avg: 59962777.000000
       [DBG] PAGE: 0x008c	CYCLES: max: 59981105	min: 59981105	avg: 59981105.000000
       [DBG] PAGE: 0x0088	CYCLES: max: 59986433	min: 59986433	avg: 59986433.000000
       [DBG] PAGE: 0x0018	CYCLES: max: 59991245	min: 59991245	avg: 59991245.000000
       [DBG] PAGE: 0x0060	CYCLES: max: 60015186	min: 60015186	avg: 60015186.000000
       ...
```

In the third example, with -r parameter the profile information is ranked and shown in the standard output:
```
./profiler -r -o two_loops_rank.prof -s loop two_loops
      [DBG] Command to execute: [two_loops]
      [DBG] PROFILING: Collecting sample 1 of 1
      PROFILING: [####################################################################################################] (228/228)
      [DBG] Profile written to two_loops_rank.prof. Total size: 7376 bytes
      [DBG] Profile written to two_loops_rank.prof. Total size: 7376 bytes
      RANKING: [####################################################################################################] (228/228)
      [DBG]
      RANKED TIMING:
      [DBG] 1, C: 61467409	M: 158
      [DBG] 2, C: 61094036	M: 160
      [DBG] 3, C: 20009349	M: 125
      [DBG] 4, C: 19941346	M: 130
      [DBG] 5, C: 19248420	M: 255
      [DBG] 6, C: 19270093	M: 323
      [DBG] 7, C: 19192718	M: 370
      [DBG] 8, C: 18546387	M: 359
      [DBG] 9, C: 18431164	M: 487
      [DBG] 10, C: 18374773	M: 555
      [DBG] 11, C: 18309513	M: 636
      [DBG] 12, C: 18242713	M: 616
      [DBG] 13, C: 18268441	M: 602
      [DBG] 14, C: 18220233	M: 657
      [DBG] 15, C: 18187028	M: 759
      [DBG] 16, C: 18098127	M: 792
      [DBG] 17, C: 18016254	M: 811
      [DBG] 18, C: 17941902	M: 994
      ...
```

Forth example depicts the effect of using -v flag which is profiling in the verbose mode. Below you can see all debug messages for only one round of profiling for just one specific page.
```

./profiler -v -o two_loops_rank.prof -s loop two_loops
     [DBG] Timing function loop
     [DBG] Command to execute: [two_loops]
     [DBG] Found symbol [loop]. Address = 0x400570
     [DBG] Executing tracee on CPU 2 (flags = 0x0)
     [DBG] Waitpid() returned PID = 18683
     [DBG] PID 18683 stopped by signal 5 (Trace/breakpoint trap)
     [DBG] Setting a breakpoint at 0x400570 (data: 0xf90007e0d10083ff)
     [DBG] Waitpid() returned PID = 18683
     [DBG] PID 18683 stopped by signal 4 (Illegal instruction)
     [DBG] Done setting the program counter

     [DBG] Setting a breakpoint at 0x4006a8 (data: 0xd53be040f9004bbf)
     [DBG] Traced function set to return to 0x4006a8
     [DBG] Waitpid() returned PID = 18683
     [DBG] PID 18683 stopped by signal 4 (Illegal instruction)
     [DBG] VmData: 728
     [DBG] TIMING: function [loop] took 2845876 CPU cycles
     [DBG] Done setting the program counter

     [DBG] Waitpid() returned PID = 18683
     [DBG] PID 18683 stopped by signal 0 ((null))
     [DBG] PID 18683 exited.
     [DBG] NOTE: setting MALLOC_TOP_PAD_ to 745472.
     [DBG] Executing tracee on CPU 2 (flags = 0x2)
     [DBG] Waitpid() returned PID = 18684
     [DBG] PID 18684 stopped by signal 5 (Trace/breakpoint trap)
     [DBG] Setting a breakpoint at 0x400570 (data: 0xf90007e0d10083ff)
     [DBG] Waitpid() returned PID = 18684

     ...

     [DBG] Setting a breakpoint at 0x4006a8 (data: 0xd53be040f9004bbf)
     [DBG] Traced function set to return to 0x4006a8
     [DBG] Waitpid() returned PID = 18684
     [DBG] PID 18684 stopped by signal 4 (Illegal instruction)
     [DBG] TIMING: function [loop] took 2914169 CPU cycles
     [DBG] Done setting the program counter

     [DBG] Waitpid() returned PID = 18684
     [DBG] PID 18684 stopped by signal 0 ((null))
     [DBG] PID 18684 exited.
     [DBG] PROFILING: Collecting sample 1 of 3
     [DBG] NOTE: setting MALLOC_TOP_PAD_ to 745472.
     [DBG] Executing tracee on CPU 2 (flags = 0x2)
     [DBG] Waitpid() returned PID = 18685
     [DBG] PID 18685 stopped by signal 5 (Trace/breakpoint trap)
     [DBG] Setting a breakpoint at 0x400570 (data: 0xf90007e0d10083ff)
     [DBG] Waitpid() returned PID = 18685
     [DBG] PID 18685 stopped by signal 4 (Illegal instruction)
     [DBG] 

     ----------------- KPARAMS -----------------
     [DBG] PID  : 	18685
     [DBG] #VMAS: 	2
     [DBG] ========== (0/2) VMA index: 2 ==========
     [DBG] Index     :	2
     [DBG] Tot. Pages:	195
     [DBG] Op.  Pages:	1
     [DBG] Operation :	0
     [DBG] Page list :
     [DBG] 	000) +0x0000
     [DBG] ========== (1/2) VMA index: 15 ==========
     [DBG] Index     :	15
     [DBG] Tot. Pages:	33
     [DBG] Op.  Pages:	0
     [DBG] Operation :	0
     [DBG] Page list :
     [DBG] 
    -------------------------------------------
    [DBG] Kernel interaction completed.
    [DBG] Done setting the program counter
```

Now you are able to not only get the profile of any application but also the ranking information. The other useful operational mode is profile-driven page migration.

### Test Page Migration

Before even deploying the Jailhouse hypervisor, let's use our synthetic task to test that page migration works correctly.

1. First off, cross-compile the *migr_test* kernel module against the custom kernel. To do that:
   l. Move to the *kernel_module* directory and edit the *Makefile*
   l. Change the line `BLDDIR= /home/renato/BU/Collab/BOSCH/petalinux-v2018.3/components/linux-xlnx-prof` so that it points to the directory where you have checked out the custom kernel sources
   l. Next, just execute `make`
   l. If everything goes smooth, the *migr_mod.ko* file will be generated. Copy this file somewhere on the ZCU102 board.

2. Now move the migration benchmark *benchmarks/migrate.c* to the ZCU102. We will compile it there.
   l. On the ZCU102, execute `gcc -o migrate migrate.c -W -Wall` to compile the migrate benchmark

3. Test that the migrate benchmark works as expected. Execute: `./migrate | head` ; the expected output should be something like:
````
root@xilinx-zcu102-2017_3:~/bb_profiler/benchmarks# ./migrate | head
Exec. took 821866
Exec. took 10641
Exec. took 7483
Exec. took 7437
Exec. took 7586
Exec. took 7466
Exec. took 7432
Exec. took 7663
Exec. took 7455
Exec. took 7472
````

4. Now start the application, suppress its output and send it to background: `./migrate 1>/dev/null &` ; expected output (PID might vary):
````
root@xilinx-zcu102-2017_3:~/bb_profiler/benchmarks# ./migrate 1>/dev/null &
[1] 601
````

5. Move to the kernel module directory and execute `insmod ./migr_mod.ko`

6. The module will locate the *migrate* process and attempt to migrate the first two pages of the heap to the private page pool. The expected output on the serial console should be something like:
````
root@xilinx-zcu102-2017_3:~/bb_profiler/kernel_module# insmod migr_mod.ko 
[ 3701.358177] migr_mod: loading out-of-tree module taints kernel.
[ 3701.364807] migr_mod: Remapping PRIVATE_LO reserved memory area
[ 3701.370752] migr_mod: Remapping PRIVATE_LO reserved memory area
[ 3701.376699] migr_mod: Page struct address of pool kernel VA (LO): 0xffffffff01300000
[ 3701.384441] migr_mod: Physical address of pool (LO): 0x60000000
[ 3701.390357] migr_mod: Page struct address of pool kernel VA (HI): 0xffffffff1d282000
[ 3701.398094] migr_mod: Physical address of pool (HI): 0x85dc00000
[ 3701.404098] migr_mod: Page struct address of known kernel PA: 0xffffffff1c880000
[ 3701.411494] migr_mod: Physical address of known address: 0x830000000
[ 3701.417894] migr_mod: Target task located!
[ 3701.422009] migr_mod: Process page (0xffffffff1d0d2258): VA = 0x022c4000, PA = 0x85609d000 (res = 1)
[ 3701.431145] migr_mod: No mapping!
[ 3701.434472] migr_mod: Process page (0xffffffff1d0d5c88): VA = 0x022c5000, PA = 0x8561a7000 (res = 1)
[ 3701.443599] migr_mod: No mapping!
[ 3701.446912] migr_mod: --- Migration for VMA 2 started ---
[ 3701.452346] MIGR: Adding VA 0x022c4000
[ 3701.456093] MIGR: Adding VA 0x022c5000
[ 3701.459838] MIGR: Done adding VAs. Performing migration.
[ 3701.465142] MIGR: Migration started!
[ 3701.468710] migr_mod: POOL: Allocating VA: 0xffffff885dc00000
[ 3701.474452] page:ffffffff1d282000 refcount:1 mapcount:0 mapping:0000000000000000 index:0x0
[ 3701.482721] raw: 4000000000001000 ffffffff1d282008 ffffffff1d282008 0000000000000000
[ 3701.490463] raw: 0000000000000000 0000000000000000 00000001ffffffff
[ 3701.496723] page dumped because: pool alloc debug
[ 3701.501438] migr_mod: POOL: Allocating VA: 0xffffff885dc01000
[ 3701.507177] page:ffffffff1d282038 refcount:1 mapcount:0 mapping:0000000000000000 index:0x0
[ 3701.515447] raw: 4000000000001000 ffffffff1d282040 ffffffff1d282040 0000000000000000
[ 3701.523186] raw: 0000000000000000 0000000000000000 00000001ffffffff
[ 3701.529452] page dumped because: pool alloc debug
[ 3701.534169] MIGR: Migration completed (0)!
[ 3701.538267] migr_mod: Migrating selected pages, ret = 0
[ 3701.543487] migr_mod: ------------------------------------
[ 3701.543489] migr_mod: Page migration returned: 0
[ 3701.553584] migr_mod: Process page (0xffffffff1d282000): VA = 0x022c4000, PA = 0x85dc00000 (res = 1)
[ 3701.562713] migr_mod: No mapping!
[ 3701.566024] migr_mod: Process page (0xffffffff1d282038): VA = 0x022c5000, PA = 0x85dc01000 (res = 1)
[ 3701.575149] migr_mod: No mapping!
[ 3701.578459] migr_mod: Migration of task pages migration completed.
````

Notice in the output that the return of the migration operation is 0, i.e. *success*.
Also note that the initial physical addresses (PA) of the heap pages --- `0x85609d000` and `0x8561a7000` --- correspond to pages in our private pool after the migration, in this case `0x85dc00000` and `0x85dc01000` respectively.

7. Bring the application to foreground with the `fg` command and kill it with Ctrl+C. The private pool pages will be released and the serial terminal should output something like the following:
````
[ 3922.427408] migr_mod: Dynamic de-allocation for phys page 0x85dc01000
[ 3922.433864] page:ffffffff1d282038 refcount:1 mapcount:0 mapping:ffffff8856525001 index:0x22c5
[ 3922.442392] anon flags: 0x400000000008100e(referenced|uptodate|dirty|reserved|swapbacked)
[ 3922.450576] raw: 400000000008100e ffffffff1d282008 ffffffff1d0f6178 ffffff8856525001
[ 3922.458316] raw: 00000000000022c5 0000000000000000 00000001ffffffff
[ 3922.464578] page dumped because: pool dealloc debug
[ 3922.469449] migr_mod: Dynamic de-allocation for phys page 0x85dc00000
[ 3922.475892] page:ffffffff1d282000 refcount:1 mapcount:0 mapping:ffffff8856525001 index:0x22c4
[ 3922.484420] anon flags: 0x400000000008100e(referenced|uptodate|dirty|reserved|swapbacked)
[ 3922.492597] raw: 400000000008100e ffffffff1d0ced00 ffffffff1d0f6178 ffffff8856525001
[ 3922.500340] raw: 00000000000022c4 0000000000000000 00000001ffffffff
[ 3922.506602] page dumped because: pool dealloc debug
````

Note in the output above that the two physical pages that were allocated from the private pool are correctly released.

8. It is now safe to remove the migration test kernel module with `rmmod migr_mod`

### Jailhouse Compilation and Deployment

*Coming Soon*
