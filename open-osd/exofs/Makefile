# Makefile
#
#

OSD_INC ?= `pwd`/../include/
KSRC = /lib/modules/$(shell uname -r)/build
DEST = /lib/modules/$(shell uname -r)/kernel/fs/exofs

obj-m += exofs.o
exofs-objs := src/dir.o src/file.o src/inode.o src/osd.o src/namei.o \
              src/super.o src/symlink.o

all:
	make -C $(KSRC) M=`pwd` OSD_INC=$(OSD_INC) modules

clean:
	make -C $(KSRC) M=`pwd` OSD_INC=$(OSD_INC) clean

install:
	mkdir -p $(DEST)
	cp exofs.ko $(DEST) && depmod -a

