// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 - 2024 Emanuele Santini <emanuele.santini.88@gmail.com>
 */
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>

/*
 * This module shows how to create a simple subdirectory in sysfs called
 * /sys/kernel/kobject-example. In that directory, 2 files are created:
 * "my_int" and "my_second_int". If an integer is written to these files, it can be
 * later read out of it.
 */

struct my_example_data {
	struct kobject example_kobj;
	int my_int;
	char my_buffer[256];
};

/*
 * "my_file_show" file perform the file read.
 */
static ssize_t my_file_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct my_example_data* my_data;
	my_data = container_of(kobj, struct my_example_data, example_kobj);

	// buf is mapped in user space. sysfs_emit will take care the dimension of the user space buffer for the output
	return sysfs_emit(buf, "%d\n", my_data->my_int);
}

/*
 * "my_file_store" file perform the file write.
 */
static ssize_t my_file_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct my_example_data* my_data;
	my_data = container_of(kobj, struct my_example_data, example_kobj);

	// Copy our int buffer to the char kernel buffer mapped in user space
	if(kstrtoint(buf, 10, &my_data->my_int) < 0)
		return 0;

	return count;
}

static ssize_t my_buffer_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct my_example_data* my_data;
	my_data = container_of(kobj, struct my_example_data, example_kobj);

	// Copy out buffer to user - buf points a kernel page, that will be mapped in user space
	return sysfs_emit(buf, "%s\n", my_data->my_buffer);
}

static ssize_t my_buffer_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct my_example_data* my_data;
	my_data = container_of(kobj, struct my_example_data, example_kobj);
	// Copy the user space string stored in buf to our buffer - buf points a kernel page mapped in user space
	strncpy(my_data->my_buffer, buf, 256);

	return count;
}

static void my_file_release(struct kobject *kobj)
{
	// Invoked when kobject_put is called to destroy this kobject
	printk("Anything to do!\n");
}

/* Defines my_int attribute in /sys/kernel/kobjec-example-2/ */
static struct kobj_attribute my_file_attribute = __ATTR(my_int, 0664, my_file_show, my_file_store);

/* Defines my_buffer attribute in /sys/kernel/kobjec-example-2/  */
static struct kobj_attribute my_buffer_attribute = __ATTR(my_buffer, 0664, my_buffer_show, my_buffer_store);

// The attributes array to bind to the kobject
static struct attribute *my_file_attrs[] = {
	&my_file_attribute.attr,
	&my_buffer_attribute.attr,
	NULL,
};

/* This is the same of:
 *  struct attribute_group the my_file_groups = {
 *		.attrs = my_file_attrs,
 * };
 * That contains the attribute_group
 */
ATTRIBUTE_GROUPS(my_file);

/*
 * Our own ktype for our kobjects.  Here we specify kobj_sysfs_ops
 * as sysfs ops, that is a default operations struct,
 * release function, and the set of attributes we want created
 * whenever a kobject of this type is registered with the kernel.
 */
static const struct kobj_type my_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = my_file_release,
	.default_groups = my_file_groups,
};

struct my_example_data *data = NULL;

static int __init example_init(void)
{
	int retval;

	if((data = kzalloc(sizeof(struct my_example_data), GFP_KERNEL)) == NULL)
		return -ENOMEM;

	/*
	 * Create a simple kobject with the name of "kobject_example",
	 * located under /sys/kernel/
	 * The kobject path will be: /sys/kernel/kobject_example
	 */
	retval = kobject_init_and_add(&data->example_kobj, &my_ktype, kernel_kobj, "%s", "kobject_example");
	if(retval)
		return -ENOMEM;

	return 0;
}

static void __exit example_exit(void)
{
	kobject_put(&data->example_kobj);
	kfree(data);
}

module_init(example_init);
module_exit(example_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emanuele Santini <emanuele.santini.88@gmail.com>");
