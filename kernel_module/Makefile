obj-m += memory_profiler.o
mem_profiler-objs = memory_profiler.o 

export CROSS_COMPILE:=aarch64-linux-gnu-
export ARCH:=arm64
KVERSION = $(shell uname -r)
BLDDIR= /home/golsana/linux-xlnx-prof

all:
	make -C $(BLDDIR) M=$(PWD) modules

clean:
	make -C $(BLDDIR) M=$(PWD) clean
