obj-m += memory_profiler.o aarch64_kmod.o memory_benchmarking.o
mem_profiler-objs = memory_profiler.o
latency_kmod-objs = memory_benchmarking.o
aarch64_kmod-objs = aarch64_kprofiler.o cache_ops.o

export CROSS_COMPILE:=aarch64-linux-gnu-
export ARCH:=arm64

KVERSION = $(shell uname -r)
BLDDIR= /home/golsana/linux-xlnx-prof

all:
	make -C $(BLDDIR) M=$(PWD) modules

clean:
	make -C $(BLDDIR) M=$(PWD) clean
