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

8. If the compilation is successful, you will find the file *arch/arm64/boot/Image* to copy into the boot partition (/run/media/mmcblk0p1).

9. Let's compile the DTB next. Once again from the top of the kernel sources directory run: `make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- dtbs`

10. If the step above is successful, the file *arch/arm64/boot/dts/xilinx/zynqmp-zcu102-pvtsh.dtb* will be generated.

11. Copy the .dtb file mentioned above in the boot partition **but rename it as** *system.dtb*

That's it! The board should be able to boot now. Notice that the *boot.scr* is set up so to start the kernel using the `/dev/mmcblk0p2` partition of the sd-card as the root filesystem.

### Setting-up the Black-box profiler

1. Clone the profiler from *black-box-profiler* repo: https://github.com/rntmancuso/black-box-profiler.git

2. Before compiling the profiler on the ZCU, you need to either cross-compile the elf library or decompress the pre-compiled library. For the former, run the install_libelf.sh from the profiler folder [ADDRESS] on Ubuntu. For the latter, decompress the *zcu_elflib.tar.gz* [ADDRESS] on the ZCU using `tar -xvf zcu_elflib.tar.gz` and add it to the Makefile for the profiler compilation. It is added as *libs* as the following in the Makefile: `CFLAGS=-I. -W -Wall -I./libs/include/ -D_VERBOSE_`, and `LDFLAGS=-lelf -L./libs/lib/ -lz`

3. Next step is cross-compiling the BBProf's kernel module (aarch64_kmod.c) from the *kernel_module* folder of the  *black-box-profiler* repo. To do that, in its Makefile, replace the path of custom kernel source code `BLDDIR = ` with your own path of the kernel source code which you have checked out in the setting-up ZCU102. Insert the resulting aarch_kmod.ko kernel module by `insmod aarch_kmod.ko`.

4. At this point the BBProf is ready to be used. Profiler is supposed to be run with 2 mandatory command-line parameters. One of them is the name of the executable binary file of the program that we want to profile and the second one is the name of the symbol which we are interested in putting the breakpoint at. The first parameter should be set as the last command-line argument and symbol is determined by -s flag (ex: `./profiler -s f1(name of the function) hello (name of the exe)`).<br/>
Apart from mandatory parameters, there is a number of command-line options that can be passed to modify the behavior of the prfoiler. The full list is provided below:
```
           -h : Prints the help string.<br/>
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
```

5. Now, let's look at the synthetic benchmrk *two_loops* located in the benchmark folder [put the link] and consider some practical examples by running it with different command-line parameters of the profiler.


In the first example, *loop* is the name of the function (symbol) we put the breakpoint at, *two_loops* is the name of executable binary, `-l` prints the virtual memory layout of the process, with `-o` option we save the result of the profile into a binaty file called *two_loops_layout.prof*. Because we do not use `-n`, by default it acquires only one sample.Two `*` show that among all VMAs, heap and stack are being profiled.
```
$ ./profiler -o two_loops_layout.prof -l -s loop two_loops
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
        PROFILING: [#                                                                                                   ] (1/228)
        PROFILING: [#                                                                                                   ] (2/228)
	PROFILING: [##                                                                                                  ] (3/228)
        PROFILING: [##                                                                                                  ] (4/228)
        PROFILING: [###                                                                                                 ] (5/228)
        PROFILING: [###                                                                                                 ] (6/228)

        ...

        PROFILING: [####################################################################################################] (228/228)
	[DBG] Profile written to two_loops_layout.prof. Total size: 7376 bytes
	[DBG] Profile written to two_loops_layout.prof. Total size: 7376 bytes
```
      
In the second example, we assume that the profile information is already acquired (two_loops_layout.prof). Using `-i` we give this profile information as the input, and set `-n0` for avoiding acquiring more profiling samples. Flag `-t` translates the resulting profile information into the human-readable format.
```
$ ./profiler -i two_loops_layout.prof -t -n0  -s loop two_loops
       [DBG] Command to execute: [two_loops]
       [DBG] Profile read from two_loops_layout.prof.
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

In the third example, we give already acquired profile information (two_loops_layout.prof), then by setting  `-n2` it collects two more samples and the result would be accumulated profiling information with total of three samples, saved in binary file of *two_loops_rank.prof*. By setting ` -r` parameter the profile information is ranked and shown in the standard output, here we just shows the ranking information:
```
$ ./profiler -i two_loops_layout.prof  -n2 -o two_loops_rank.prof -r -s loop two_loops
      [DBG] Command to execute: [two_loops]
      [DBG] Profile read from two_loops_layout.prof.
      [DBG] PROFILING: Collecting sample 1 of 2
      PROFILING: [#                                                                                                   ] (1/228)
      PROFILING: [#                                                                                                   ] (2/228)
      PROFILING: [##                                                                                                  ] (3/228)
      PROFILING: [##                                                                                                  ] (4/228)
      PROFILING: [###                                                                                                 ] (5/228)
      PROFILING: [###                                                                                                 ] (6/228)

        ...

      PROFILING: [####################################################################################################] (228/228)
      [DBG] Profile written to two_loops_rank.prof. Total size: 7376 bytes
      [DBG] PROFILING: Collecting sample 2 of 2
      PROFILING: [#                                                                                                   ] (1/228)
      PROFILING: [#                                                                                                   ] (2/228)
      PROFILING: [##                                                                                                  ] (3/228)
      PROFILING: [##                                                                                                  ] (4/228)
      PROFILING: [###                                                                                                 ] (5/228)
      PROFILING: [###                                                                                                 ] (6/228)

        ...

       PROFILING: [####################################################################################################] (228/228)
      [DBG] Profile written to two_loops_rank.prof. Total size: 7376 bytes
      [DBG] Profile written to two_loops_rank.prof. Total size: 7376 bytes
      RANKING: [############################################                                                        ] (100/228)
      RANKING: [#############################################                                                       ] (101/228)
      RANKING: [#############################################                                                       ] (102/228)
      RANKING: [##############################################                                                      ] (103/228)
      RANKING: [##############################################                                                      ] (104/228)

       ... 


      RANKING: [####################################################################################################] (228/228)
      [DBG]
      RANKED TIMING:
      [DBG] 1, C: 60079155	M: 279
      [DBG] 2, C: 61988614	M: 194
      [DBG] 3, C: 60233975	M: 187
      [DBG] 4, C: 60570137	M: 232
      [DBG] 5, C: 17939447	M: 290
      [DBG] 6, C: 57522717	M: 428
      [DBG] 7, C: 16605660	M: 486
      [DBG] 8, C: 16530555	M: 534
      [DBG] 9, C: 57172055	M: 665
      [DBG] 10, C: 55844196	M: 639
      [DBG] 11, C: 55853908	M: 738
      [DBG] 12, C: 15749703	M: 752
      [DBG] 13, C: 55270798	M: 827
      [DBG] 14, C: 15615214	M: 830
      [DBG] 15, C: 55135498	M: 943
      [DBG] 16, C: 15487865	M: 1028
      [DBG] 17, C: 14745339	M: 987
      ...
```

Forth example depicts the effect of using -v flag which is profiling in the verbose mode. Below you can see all debug messages for only one round of profiling for just one specific page.
```

$ ./profiler -v -o two_loops_rank.prof -s loop two_loops
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

6- For the page migration  mode, first we should make sure that the modfied kernel and system.dtb are in place, and Jailhouse hypervisor has been deployed. In the last example, we want to migrate the first 10 pages of the profile using -g. 

In any cases above if you use -p, you can test the profiler without (interacting with) the kernel module. In this case although the profile is not meaningful and does not give correct information, it can verify whether the profiler works.

### Jailhouse Compilation and Deployment

*Coming Soon*
