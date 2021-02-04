obj-m = migr_mod.o

export CROSS_COMPILE:=aarch64-linux-gnu-
export ARCH:=arm64
KVERSION = $(shell uname -r)
BLDDIR= /home/renato/BU/Collab/BOSCH/petalinux-v2018.3/components/linux-xlnx-prof

all:
	make -C $(BLDDIR) M=$(PWD) modules

clean:
	make -C $(BLDDIR) M=$(PWD) clean
