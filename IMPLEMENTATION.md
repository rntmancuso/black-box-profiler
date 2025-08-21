# Implementation Details

This document provides a detailed overview of the key components of the **MemScope** benchmarking infrastructure, which is implemented as a Linux 5.4 kernel module for ARMv8 architectures. The implementation does not require any kernel source code modifications.

---

## Memory Pool Manager

The **MemScope** memory pool manager is designed to automatically detect and configure available memory modules. It uses **Device Tree Blobs (DTBs)**, which are provided to the kernel at boot time, to describe hardware components.

The manager scans the DTB for any memory node with a `compatible` property set to `"mempool"`. For each such node, it retrieves the start address and size from the `reg` property using the `of_property_read_u64_index` kernel function.

```dts
bram@a0000000 {
    device_type = "memory";
    compatible = "mempool";
    reg = <0x0 0xa0000000 0x0 0x100000>;
};

dram@10000000 {
    device_type = "memory";
    compatible = "mempool";
    reg = <0x0 0x10000000 0x0 0x10000000>;
};
```

To initialize a pool, the manager maps the physical memory aperture into kernel virtual memory using `memremap`. It then uses the **genpool** Linux kernel API (`gen_pool_create`, `gen_pool_add`) to create and populate an ad-hoc allocation pool with all the pages in the virtual address range. Each pool is assigned a unique ID. Upon module removal, the manager cleans up by destroying the pools with `gen_pool_destroy`.

---

## Workload Library

The workload library provides the core benchmarking functions and buffer management.

### Configurable Buffer Initialization

Memory buffers are allocated from a selected pool using the `gen_pool_alloc` API.
* For **bandwidth tests**, buffers are filled sequentially with simple integer values.
* For **latency measurements**, buffers are initialized to create a randomized dereference chain. This forces data dependencies and minimizes outstanding memory transactions. The buffer is first filled sequentially, then a randomized permutation array is created to shuffle the indices, ensuring a random but complete traversal of the buffer.

### Test Bench Algorithm and Structure

**MemAcope** implements low-level functions for various access types using ARM assembly instructions:
* **Bandwidth (Cacheable):** `__access_bw_read` and `__access_bw_write` use `ldr` and `str` instructions with post-increment addressing for efficiency.
* **Bandwidth (Non-Cacheable):**
    * **Reads:** Two methods are used:
        1.  `__NC_IMPL_DCAFTER`: Loads the address, then immediately invalidates the next address with `dc civac` to force a cache miss on the next access.
        2.  `__NC_IMPL_DCADD`: Loads the address, then cleans and invalidates the *same* address with `dc civac` to handle the first-access cache hit issue. The address is manually incremented with `add`.
    * **Writes:**
        1.  A store-based operation similar to `__NC_IMPL_DCAFTER` using `str`.
        2.  A non-cacheable write stream using the `dc zva` instruction, which writes a cacheline of zeros, bypassing the cache allocation.
* **Latency:** Functions are read-only and traverse the randomized dereference chain. For non-cacheable latency, `dc civac` is used after each access.

### Performance Counter Implementation

Performance counters are accessed via the **Performance Monitoring Unit (PMU)** on ARM Cortex-A53.
1.  The **Performance Monitor Control Register (PMCR)** is enabled by setting the `C` (Clear) and `P` (Performance enable) bits.
2.  Specific counters are enabled by setting the corresponding bits in the `pmcntenset_el0` register.
3.  The event ID to be sampled is written to the `pmevtyperX_el0` register.
4.  Sampling occurs by reading the value of the `pmevcntrX_el0` register.
To ensure accuracy, interrupts and preemption are disabled during measurements using `local_irq_save` and re-enabled with `local_irq_restore`.

---

## Core Coordination

This section describes how **MemScope** coordinates activities across multiple CPU cores for concurrent experiments.

* **Remote Core Scheduling:** **MemScope** uses the Linux kernel API `on_each_cpu_mask()` to schedule specific functions on designated CPUs. A `cpumask` is used to define which cores should run a workload (`activity stress`) and which should remain idle (`activity idle`). The observation core is always excluded from these masks.
* **Measurement Coordination:** An unconventional spinlock mechanism is used to synchronize the cores. Each core has its own lock, which is initialized before the main activity loop using `spin_lock_init()`. When the core under observation is waiting for remote cores to start or stop their execution, it spins on their locks, continuously checking whether their locks are on or off. The core under observation starts spinning and waits for all locks to be acquired `using spin_lock()`. When all the locks are acquired, it indicates that all remote cores have started their respective remote activities. At this point, the main activity can begin and the measurement either time or performance counter samples start. Once the main activity concludes, and the core coordinator instructs remote cores to stop, the core under observation spins on the locks again to ensure all locks are released, signifying the remote executions are complete. This allows the core under observation to proceed to the next scenario. Thus, the main activity is sandwiched between two phases of `spin_lock` spinning, ensuring that measurements are taken at the correct times.
Each core has a dedicated `spinlock`. The observation core waits for all remote cores to acquire their locks, which signals that their activities have started. Only then does the main measurement begin. After the main activity, the observation core waits for all locks to be released, ensuring all remote activities have completed before proceeding.
* **Measurement:** Time is measured using the `ktime_get_ns()` function. Performance counters are sampled by reading the `pmevcntri_el0` register. To prevent CPU migration, each activity is pinned to its assigned core using `put_core`. A global variable, `g_exp_running`, controls the start and stop of remote execution.
* **Cleanup:** After each experiment, caches are cleaned and invalidated using `dc civac` to prevent any addresses from a previous cacheable experiment from affecting the next one. Finally, all allocated buffers are freed with `gen_pool_free`.

---

## User Interface Implementation

The user interface (UI) is implemented as part of the main **MemScope** kernel module, providing communication channels between user and kernel space.

* **debugfs Interface:** A `membench` directory is created in the `debugfs` virtual file system. This directory contains five main entries, each implemented as a file:
    * **`experiment`**: Writable to configure a new experiment and readable to view the last one.
    * **`pools`**: Read-only, lists the detected memory pools.
    * **`results`**: Read-only, displays the results of the most recent experiment.
    * **`perfcount`**: Writable to set performance counter event IDs and readable to view the current setup.
    * **`cmd`**: Writable for commands and readable for the current command status.
    All data transfer from user to kernel space is handled by `copy_from_user` and `sscanf`.

* **devfs Interface:** To expose memory pools to user space applications, **MemScope** uses the `/dev` file system. Device nodes named `/dev/upool<ID>` are created for each memory pool. These nodes are file descriptors with three main file operations:
    * **`open`**: Handled by the driver to identify the accessed pool.
    * **`release`**: Prepares the `upool` instance for closure and deallocates memory.
    * **`mmap`**: The primary operation. When a user application calls `mmap()` on a `upool` file, the requested pages are allocated from the corresponding **MemScope** pool using `gen_pool_alloc`. The kernel virtual address is then converted to a physical page frame number (PFN) and mapped into user space using `remap_pfn_range`, allowing the user to directly access the physical memory.
