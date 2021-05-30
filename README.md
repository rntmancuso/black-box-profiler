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

2. Before compiling the profiler, you need to compile/cross-compile the elf library. For doing so, run the install_libelf.sh from profiler folder. Then compress its results and move them to ZCU board.

3. Next step is cross-compiling the BBProf's kernel module (kprofiler) from the kernel_module folder of *black-box-profiler* repo. To do that, replace the path of custom kernel source code in  `BLDDIR = ` with your own path of the kernel source code which you have checked in part setting-up ZCU102.

4. At this point the BBProf is ready to use. Profiler is supposed to be run with 2 mandatory command-line parameters which is the name of the executable binary file of the program that we want to profile and the name of the symbol at which we are interested in putting the breakpoint. The first parameter should be set as the last command-line argument and symbol is determined by -s flag. (ex: ./profiler -s f1(name of the function) hello (name of the exe).

5. As an example, we consider synthetic benchmrk *two_synthetic*, example of running this benchmark with different arbitrary command-line parameters of the profiler is as the following:<br/>
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
```
	./profiler -o two_loops_layout.prof -l -s loop two_loops
	[DBG] Command to execute: [two_loops]
	[DBG] [  0]    00400000-00401000 r-xp 00000000 b3:02 3585                               /home/root/two_loops
        [DBG] [  1]    00410000-00411000 rw-p 00000000 b3:02 3585                               /home/root/two_loops
        [DBG] [  2] *  1f0ed000-1f1b0000 rw-p 00000000 00:00 0                                  [heap]
	
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
<br\>
 -i PATH : Load profile from file specified by PATH.<br/>
           -p : Pretend mode, i.e. no kernel-side operations.<br/>
           -q : Quiet mode, i.e. output of tracee is suppressed.<br/>
           -v : Verbose mode, i.e. show A LOT of debug messages.<br/>
           -n NUM : Number of profiling samples to acquire and aggregate (default = 1).<br/>
           -g NUM : Perform page migration. Migrate the NUM top-ranking pages.<br/>
           -t : Translate profile acquired or specified via -i parameter in human readable form..<br/>
           -N : Non-realtime mode: do not set real-time priorities for profiler nor tracee.<br/>
      


6. Run the profiler alongside with arbitrary parameters as the follow:
      `./profiler -s function_name <arbitrary_parameters> exe_file arguments_of_exe`

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
