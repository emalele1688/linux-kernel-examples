kobject_example_obj-objs := kobject_example.o
kobject_example_kobj-objs := kobj_attribute_example.o
kobject_example_kset-objs := sysfs_kset_example.o

obj-m := kobject_example_obj.o kobject_example_kobj.o kobject_example_kset.o

#KDIR = /home/emanuele/linux-dev/linux-5.10.20
COMPILE_DIR=$(PWD)
KDIR = /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(COMPILE_DIR) modules

clean:
	rm -f -v *.o *.ko
