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
	struct my_example_data* my_data;
	my_data = container_of(kobj, struct my_example_data, example_kobj);
	printk("Freeing %s\n", kobj->name);
	kfree(my_data);
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

static struct kset *example_kset = NULL;
struct my_example_data *m_data_1 = NULL;
struct my_example_data *m_data_2 = NULL;
struct my_example_data *m_data_3 = NULL;

static struct my_example_data *create_kobject(const char *name)
{
	struct my_example_data *m_data;
	int retval;

	if((m_data = kzalloc(sizeof(struct my_example_data), GFP_KERNEL)) == NULL)
		return ERR_PTR(-ENOMEM);

	/*
	 * As we have a kset for this kobject, we need to set it before calling the kobject.
	 */
	m_data->example_kobj.kset = example_kset;

	retval = kobject_init_and_add(&m_data->example_kobj, &my_ktype, NULL, "%s", name);
	if(retval)
	{
		kfree(m_data);
		return ERR_PTR(-ENOMEM);
	}

	/*
	 * We are always responsible for sending the uevent that the kobject
	 * was added to the system.
	 */
	kobject_uevent(&m_data->example_kobj, KOBJ_ADD);

	return m_data;
}

static int __init example_init(void)
{
	int retval;

	/*
	 * Create a kset with the name of "kset_example",
	 * located under /sys/kernel/
	 */
	example_kset = kset_create_and_add("kset_example", NULL, kernel_kobj);
	if(!example_kset)
		return -ENOMEM;

	/*
	 * Create three objects and register them with our kset
	 */
	if((m_data_1 = create_kobject("setA")) == NULL)
		goto SETA_ERROR;

	if((m_data_2 = create_kobject("setB")) == NULL)
		goto SETB_ERROR;

	if((m_data_3 = create_kobject("setC")) == NULL)
		goto SETC_ERROR;

	return 0;

SETC_ERROR:
	kobject_put(&m_data_2->example_kobj);
	kfree(m_data_2);
SETB_ERROR:
	kobject_put(&m_data_1->example_kobj);
	kfree(m_data_1);
SETA_ERROR:
	kset_unregister(example_kset);
	return -EINVAL;
}

static void __exit example_exit(void)
{
	kobject_put(&m_data_1->example_kobj);
	kobject_put(&m_data_2->example_kobj);
	kobject_put(&m_data_3->example_kobj);
	kset_unregister(example_kset);
}

module_init(example_init);
module_exit(example_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emanuele Santini <emanuele.santini.88@gmail.com>");
