procinfo_module-objs := kjson/kjson_main.o kjson/kjson_parser.o procinfo.o
obj-m := procinfo_module.o

KDIR = /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	rm -v *.o *.ko

