obj-m += aarch64_kmod.o
aarch64_kmod-objs = aarch64_kprofiler.o cache_ops.o migr_pgtables.o

export CROSS_COMPILE:=aarch64-linux-gnu-
export ARCH:=arm64
KVERSION = $(shell uname -r)
BLDDIR= /home/renato/BU/Collab/BOSCH/petalinux-v2018.3/components/linux-xlnx-prof/build

all:
	make -C $(BLDDIR) M=$(PWD) modules

clean:
	make -C $(BLDDIR) M=$(PWD) clean
