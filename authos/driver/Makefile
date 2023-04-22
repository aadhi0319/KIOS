obj-m += lkm_authos.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
test:
	sudo dmesg -C
	sudo insmod lkm_authos.ko
	cat bob.txt
	sudo rmmod lkm_authos
	sudo dmesg
