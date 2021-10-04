KDIR := /lib/modules/$(shell uname -r)/build
SRC := monitor
obj-m := $(SRC).o

default:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules -o $(SRC)

clean:
	rm -f *.o .*.cmd .*.flags *.mod.c *.order .*.*.cmd *~ *.*~ TODO.*
	rm -fR .tmp*
	rm -rf .tmp_versions
	rm *.ko *.symvers *.mod

load:
	sudo insmod $(SRC).ko

unload:
	sudo rmmod $(SRC).ko

info:
	modinfo $(SRC).ko

logs:
	sudo dmesg
