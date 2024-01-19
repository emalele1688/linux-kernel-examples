// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 - 2024 Emanuele Santini <emanuele.santini.88@gmail.com>
 */
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/init.h>

/*
 * This module shows how to create a simple subdirectory in sysfs called
 * /sys/kernel/kobject-example. In that directory, 2 files are created:
 * "my_int" and "my_second_int". If an integer is written to these files, it can be
 * later read out of it.
 */

struct kobject example_kobj;
static int my_int = 0;
static int my_second_int = 0;

/*
 * "my_file_show" file perform the file read.
 */
static ssize_t my_file_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	int ret = 0;

	// attr->name is the name of the attribute where the read operation is performed

	if(strncmp(attr->name, "my_int", 6))
		ret = sysfs_emit(buf, "%d\n", my_int);
	else // if(strcmp(attr->name, "my_second_int"))
		ret = sysfs_emit(buf, "%d\n", my_second_int);

	return ret;
}

/*
 * "my_file_store" file perform the file write.
 */
static ssize_t my_file_store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t count)
{
	int ret;

	// attr->name is the name of the attribute where the read operation is performed

	if(strncmp(attr->name, "my_int", 6))
		ret = kstrtoint(buf, 10, &my_int);
	else
		ret = kstrtoint(buf, 10, &my_second_int);

	// Converts the string type to an integer

	if(ret < 0)
		return ret;

	return count;
}

static void my_file_release(struct kobject *kobj)
{
	// Invoked when kobject_put is called to destroy this kobject
	printk("Anything to do!\n");
}

// Defines the sysfs operation methods (read and write).
struct sysfs_ops my_sysfs_ops = {
	.show = my_file_show,
	.store = my_file_store,
};

/* Defines my_int attribute */
static struct attribute my_file_attribute = {
	.name = "my_int", // The regular file name
	.mode = 0664,
};

/* Defines my_second_int attribute */
static struct attribute my_second_file_attribute = {
	.name = "my_second_int", // The regular file name
	.mode = 0664,
};

// The attributes array to bind to the kobject
static struct attribute *my_file_attrs[] = {
	&my_file_attribute,
	&my_second_file_attribute,
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
 * Our own ktype for our kobjects.  Here we specify our sysfs ops, the
 * release function, and the set of attributes we want created
 * whenever a kobject of this type is registered with the kernel.
 */
static const struct kobj_type my_ktype = {
	.sysfs_ops = &my_sysfs_ops,
	.release = my_file_release,
	.default_groups = my_file_groups,
};

static int __init example_init(void)
{
	int retval;

	/*
	 * Create a simple kobject with the name of "kobject_example",
	 * located under /sys/kernel/
	 * The kobject path will be: /sys/kernel/kobject_example
	 */
	retval = kobject_init_and_add(&example_kobj, &my_ktype, kernel_kobj, "%s", "kobject_example");
	if (retval)
		return -ENOMEM;

	return 0;
}

static void __exit example_exit(void)
{
	kobject_put(&example_kobj);
}

module_init(example_init);
module_exit(example_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emanuele Santini <emanuele.santini.88@gmail.com>");
