obj-m += membench.o

latency_kmod-objs = memory_benchmarking.o
membench-objs = memory_benchmarking.o memory_benchmarking_interf.o


export CROSS_COMPILE:=aarch64-linux-gnu-
export ARCH:=arm64

KVERSION = $(shell uname -r)
BLDDIR= /home/golsana/Golsish/linux-xlnx-prof

all:
	make -C $(BLDDIR) M=$(PWD) modules

clean:
	make -C $(BLDDIR) M=$(PWD) clean
