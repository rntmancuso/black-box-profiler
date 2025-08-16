


# BU MemScope: Open-Source Kernel-Level Framework for Heterogeneous Memory Characterization

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#)
[![Build Status](https://img.shields.io/badge/build-pending-yellow.svg)](#)

## Overview

MemScope is a tool to analyze and characterize the temporal behavior of memory subsystems, including heterogeneous memories. It helps designers evaluate performance, identify corner cases, and guide memory-aware application optimization.

This repository contains all the kernel modules necessary for instantiating BU MemScope.

---

## Repository Contents

-   `kernel_module/memory_benchmarking.c`: MemScope source code
-   `kernel_module/memory_benchmarking.h`: MemScope header file
-   `kernel_module/memory_benchmarking_interf.c`: MemScope user-interface source code
-   `Makefile`: Build scripts

---

## Device Tree Blob (DTB)

Modified part of DTB file we used on ZCU102 platform for incorporating heterogeneous memory types:

```dts
ocm@fffc0000 {
    device_type = "memory";
    compatible = "genpool";
    reg = <0x0 0xfffc0000 0x0 0x40000>;
};

bram@a0000000 {
    device_type = "memory";
    compatible = "genpool";
    reg = <0x0 0xa0000000 0x0 0x100000>;
};

dram@10000000 {
    device_type = "memory";
    compatible = "genpool";
    reg = <0x0 0x10000000 0x0 0x10000000>;
};

mig@500000000 {
    device_type = "memory";
    compatible = "genpool";
    reg = <0x5 0x00000000 0x0 0x10000000>;
};
```
---

## Compilation and Module Insertion

Build MemScope using the provided `Makefile`:
1.Make sure you have the aarch64 gcc compiler installed. On Ubuntu (or Debian-based distros), you can install that via `sudo apt-get install gcc-aarch64-linux-gnu`
2.Next step is cross-compiling the MemScop's kernel modules from the *kernel_module* folder of the repo. To do that, in its Makefile, replace the path of custom kernel source code `BLDDIR = ` with your own path of the kernel source code. 

```bash
make 

```
It should be noted that we first cross-compiled, as described, using the provided Makefile with the path to the custom kernel we checked out from the *linux-xlnx-prof* repository: [https://github.com/rntmancuso/linux-xlnx-prof](https://github.com/rntmancuso/linux-xlnx-prof). Using a custom DTB consistent with our memory apertures, we then cross-compiled it based on the *BBProf* repository README [https://github.com/rntmancuso/black-box-profiler](https://github.com/rntmancuso/black-box-profiler)
 and booted it on our ZCU102 platform. Finally, we inserted the `membench.ko` kernel module into our board using:

```bash
insmod membench.ko

```
---


## User Interface

MemScope provides a console-based interface through the debug filesystem with the following entries.

* **`experiment`**
    * Configures the test scenario. The configuration string specifies parameters for the core under observation and for any interfering cores.
    * **Parameters:**
        * **Buffer Type**: Whether the memory buffer is cacheable (`c`) or non-cacheable (`nc`). Currently, MemScope supports the non-cacheable mapping.
        * **Operation Type/Access Pattern**: The type of memory access to perform.

            | Access Pattern | Description                                                               |
            |:--------------:|:--------------------------------------------------------------------------|
            | `r`            | Sequential reads to benchmark memory read bandwidth.                      |
            | `w`            | Sequential writes to benchmark memory write bandwidth.                    |
            | `l`            | Data-dependent random reads (pointer chasing) to benchmark latency.       |
            | `s`            | Non-cacheable version of the `r` benchmark.                               |
            | `x`            | Non-cacheable version of the `w` benchmark.                               |
            | `m`            | Non-cacheable version of the `l` benchmark.                               |
            | `y`            | Non-cacheable write-streaming to the memory (no write-allocate).          |

        * **Buffer Size**: The size of the memory buffer in bytes.

        * **Memory Pool**: The target memory pool ID for the experiment. MemScope uses the following mapping: `0` – OCM, `1` – BRAM, `2` – PS-side DRAM, `3` – PL-side DRAM.

    * **Example:**
        Configure an experiment by writing a formatted string to `/sys/kernel/debug/membench/experiment`:
        ```bash
        echo "c r 32000 2 c w 40000 3" > /sys/kernel/debug/membench/experiment
        ```
        This command sets up two distinct operations:

        1.  **Core Under Observation (`c r 32000 2`)**:
            -   `c`: Use a **c**acheable memory buffer.
            -   `r`: Perform a **bandwidth read** access pattern.
            -   `32000`: Allocate a buffer of **32,000** bytes.
            -   `2`: Target memory pool **2**.
        2.  **Interfering/Remote Cores (`c w 40000 3`)**:
            -   `c`: Use a **c**acheable memory buffer.
            -   `w`: Perform a **bandwidth write** access pattern.
            -   `40000`: Allocate a buffer of **40,000** bytes.
            -   `3`: Target memory pool **3**.

* **`cmd`**
    * Selects the type of command to apply to the configured experiment. Currently cmd just includes start.
     * **Example:**
      
        ```bash
        echo -n "start" > /sys/kernel/debug/membench/cmd 
        ```

* **`pools`**
    * Displays the existing memory pools and their current status.
    * **Example:**
        Based on your DTB, you can view the configured pools with this command:
        ```bash
        cat /sys/kernel/debug/membench/pools
        ```
        The output will look similar to this:
        ```text
        === Configured Pools ===
        	Pool ID: 0
        	Phys Start: 0xfffc0000
        	Size: 0x00040000
        	Pool KVA: 0xffffff80fffc0000
        	Ready: Y

        	Pool ID: 1
        	Phys Start: 0xa0000000
        	Size: 0x00100000
        	Pool KVA: 0xffffff80a0000000
        	Ready: Y

        	Pool ID: 2
        	Phys Start: 0x10000000
        	Size: 0x10000000
        	Pool KVA: 0xffffff8010000000
        	Ready: Y

        	Pool ID: 3
        	Phys Start: 0x500000000
        	Size: 0x10000000
        	Pool KVA: 0xffffff8500000000
        	Ready: Y

        	Pool ID: 4
        	Phys Start: 0x85dc00000
        	Size: 0x1f400000
        	Pool KVA: 0xffffff885dc00000
        	Ready: Y

        	Pool ID: 5
        	Phys Start: 0x40000000
        	Size: 0x20000000
        	Pool KVA: 0xffffff8040000000
        	Ready: Y

        ==========================
        ```   
 

* **`perfcount`**
    * Selects the desired performance counters for sampling. This is **architecture-specific**, so the event IDs must be based on your platform's technical reference manual. This entry accepts a string of numeric event IDs.
    * **Example (ZCU102 Platform):**
        On a ZCU102, you would use `16` for the `L2D_CACHE_ACCESS` event or `17` for the `L2D_CACHE_REFILL` event.

        **1. Setting the Counters**

        Use `echo` to write a space-separated string of event IDs. The firs shows the event ID that should be sampled for all counters of the **core under observation** and the second number the event that should be counted by rest of the              cores (**interfering cores**). In ZCU102 four performance counters can active simultaneously for each core. 
        ```bash
        echo "4 4 4 4 3 3 3 3" > /sys/kernel/debug/membench/perfcount
        ```

        **2. Viewing the Current Configuration**

        Use `cat` to see the currently selected counters.
        ```bash
        cat /sys/kernel/debug/membench/perfcount
        ```
        The output will show the four counters for the observed core and four counters of all the interfering cores.
        ```text
        Selected Performance Counters:
        	 Core under observation:      4,      4,      4,      4
        	 Interfering cores:       3,      3,      3,      3
        ```



* **`results`**
    * Displays the collected results from the experiment, including:
        * Number of active cores
        * Start and end time of sampling (ns)
        * Total duration (ns)
        * Number of bytes read or written
        * Samples of selected performance counters


<br><br>
**Extended Memory pools to the User-Space : Upool**
  * This UI extension allows arbitrary user applications to access memory pools by mapping their allocation policies to these pools via *mmap*, enabling direct allocation and deallocation. We used this feature alongside test-benches from RT-bench [https://gitlab.com/rt-bench/rt-bench](https://gitlab.com/rt-bench/rt-bench) .

Example of using RT-bench workload with the upool feature:
 ```bash
./mser -t 1 -l4 -H /dev/upool2 -m 1M  -b .
 ```
`./mser` — Benchmark from the Vision suite of RT-bench.  **`-H`**: Determines the location of the heap. For `upooli`, this is `/dev/upooli`.  **Upools**: The number of upools matches the number of pools mentioned above. For example, `upool2` is PS-side DRAM.


---
## Example: Running a Test Experiment with MemScope

1.  After **cross-compiling** the project, load the `membench.ko` kernel module onto the target platform (in this case, a ZCU 102 board). First, configure the experiment by writing to the `debugfs` interface:

    ```bash
    echo "c r 131072 2 c r 131072 3" > /sys/kernel/debug/membench/experiment
    ```

    Next, verify that the experiment was set correctly by reading from the same file:

    ```bash
    cat /sys/kernel/debug/membench/experiment
    ```

    The output will look similar to this:

    ```text
    === Current Experiment ===
    OBSERVED:
    	 Map Type: MAP_CACHE
    	 Access Type: ACCESS_BW_READ
    	 Buffer Size: 0x00020000
    	 Pool ID: 2
    INTERFERENCE:
    	 Map Type: MAP_CACHE
    	 Access Type: ACCESS_BW_READ
    	 Buffer Size: 0x00020000
    	 Pool ID: 3
    
    USAGE: Provide new experiment definition with format:
    <OBS map type: c/n> <OBS access type: r/w/b/s/x/c/l/m> <OBS buffer size> <OBS pool ID> <INT map type: c/n> <INT access type: r/w/b/s/x/c/l/m> <INT buffer size> <INT pool ID>
    ==========================
    ```

2.  Configure the performance counters for the experiment. In this example, we monitor `L1D_CACHE_ACCESS` (event `4`) for the core under observation and `MEM_ACCESS` (event `13`) for the interfering cores.

    ```bash
    echo "13 13 13 13 4 4 4 4" > /sys/kernel/debug/membench/perfcount
    ```

3.  Start the experiment with the `start` command:

    ```bash
    echo -n "start" > /sys/kernel/debug/membench/cmd
    ```

4.  Finally, display the results:

    ```bash
    cat /sys/kernel/debug/membench/results
    ```

    The output will look similar to this:

    ```text
    == Displaying results information ==
    === Current Experiment ===
    OBSERVED:
    	 Map Type: MAP_CACHE
    	 Access Type: ACCESS_BW_READ
    	 Buffer Size: 0x00020000
    	 Pool ID: 2
    INTERFERENCE:
    	 Map Type: MAP_CACHE
    	 Access Type: ACCESS_BW_READ
    	 Buffer Size: 0x00020000
    	 Pool ID: 3

    USAGE: Provide new experiment definition with format:
    <OBS map type: c/n> <OBS access type: r/w/b/s/x/c/l/m> <OBS buffer size> <OBS pool ID> <INT map type: c/n> <INT access type: r/w/b/s/x/c/l/m> <INT buffer size> <INT pool ID>
    ==========================
    RESULTS:
    Active Cores: 0; Start (ns): 41767162693683; End (ns): 41767169428336; Diff (ns): 6734653; Bytes R: 65536000; Bytes W: 0; Perf.Obs: 4=1025054, 3=123513, 13=1025054, 13=1025053; Perf.Interf[0]: 4=21839120, 4=21839121, 4=21839121, 4=21839121; Perf.Interf[1]: 4=21815392, 4=21815393, 4=21815393, 4=21815393; Perf.Interf[2]: 4=21807470, 4=21807471, 4=21807471, 4=21807471; 
    Active Cores: 1; Start (ns): 41767348312289; End (ns): 41767358352082; Diff (ns): 10039793; Bytes R: 65536000; Bytes W: 0; Perf.Obs: 4=1025054, 3=67623, 13=1025054, 13=1025053; Perf.Interf[0]: 4=23826242, 4=23826243, 4=23826243, 4=23826243; Perf.Interf[1]: 4=5508580, 4=5508580, 4=5508580, 4=5508580; Perf.Interf[2]: 4=23793902, 4=23793903, 4=23793903, 4=23793903; 
    Active Cores: 2; Start (ns): 41767536358338; End (ns): 41767551139345; Diff (ns): 14781007; Bytes R: 65536000; Bytes W: 0; Perf.Obs: 4=1025054, 3=58053, 13=1025054, 13=1025053; Perf.Interf[0]: 4=26680711, 4=26680712, 4=26680712, 4=26680712; Perf.Interf[1]: 4=4042773, 4=4042773, 4=4042773, 4=4042773; Perf.Interf[2]: 4=3999719, 4=3999719, 4=3999719, 4=3999719; 
    Active Cores: 3; Start (ns): 41767716313189; End (ns): 41767736867793; Diff (ns): 20554604; Bytes R: 65536000; Bytes W: 0; Perf.Obs: 4=1025054, 3=56559, 13=1025054, 13=1025053; Perf.Interf[0]: 4=3089479, 4=3089479, 4=3089479, 4=3089479; Perf.Interf[1]: 4=3081287, 4=3081287, 4=3081287, 4=3081287; Perf.Interf[2]: 4=3017732, 4=3017732, 4=3017732, 4=3017732; 
    ```

5.  Optionally, if you are using `upool` with `RT-Bench`, run a command similar to the following:

    ```bash
    ./bandwidth -H /dev/upool2 -m 4M -t60 -l2 -c2 -b "-i500 -aread -m2000"
    ```
