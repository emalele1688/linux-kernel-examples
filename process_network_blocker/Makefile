obj-m := process_network_blocker.o

COMPILE_DIR=$(PWD)
KDIR = /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(COMPILE_DIR) modules

clean:
	rm -f -v *.o *.ko
