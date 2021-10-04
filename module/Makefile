KPATH := /lib/modules/$(shell uname -r)/build
MDIR := $(shell pwd)

obj-m += monitor.o
monitor-y := tasks.o memory.o hooks.o
EXTRA_CFLAGS=-I$(PWD)/inc

all:
	make -C $(KPATH) M=$(shell pwd) modules

clean:
	make -C $(KPATH) M=$(shell pwd) clean

load:
	sudo insmod $(SRC).ko

unload:
	sudo rmmod $(SRC).ko

info:
	modinfo $(SRC).ko

logs:
	sudo dmesg
