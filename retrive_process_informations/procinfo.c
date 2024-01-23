// SPDX-License-Identifier: GPL-2.0
// Authors: Emanuele Santini <emanuele.santini.88@gmail.com>

/*
 * Example usage:
 * # insmod procinfo.ko
 * # cd /sys/kernel/procinfo/
 * # echo { \"process_pid\": 1, \"request\": [\"process_path\", \"file_open\", \"process_socket\"] } > jsoninfo
 * # cat jsoninfo
 * {"ExecutablePath": "/usr/lib/systemd/systemd", "request": ["process_path", "file_open", "process_socket"], "ProcessFilesOpen": ["/dev/null", "/dev/null", "/dev/null", "/dev/kmsg", "anon_inode:[eventpoll]", "anon_inode:[signalfd]", "anon_inode:inotify", "/sys/fs/cgroup", "anon_inode:[timerfd]", "anon_inode:[eventpoll]", "/proc/1/mountinfo", "anon_inode:inotify", "/usr/lib/x86_64-linux-gnu/libgcr-base-3.so.1.0.0", "anon_inode:inotify", "/proc/swaps", "socket:[20768]", "socket:[20769]", "socket:[20770]", "socket:[20771]", "socket:[20772]", "socket:[20774]", "socket:[20775]", "/usr/lib/x86_64-linux-gnu/libglib-2.0.so.0.7200.4", "/usr/lib/x86_64-linux-gnu/libX11.so.6.4.0", "/usr/lib/x86_64-linux-gnu/libgmodule-2.0.so.0.7200.4", "/usr/lib/x86_64-linux-gnu/libsystemd.so.0.32.0", "anon_inode:inotify", "/dev/autofs", "pipe:[20781]", "anon_inode:[timerfd]", "/run/dmeventd-server", "/run/dmeventd-client"], "process_pid": 1, "ProcessSockOpen": [{"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 15}, {"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 0}, {"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 0}, {"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 0}, {"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 0}, {"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 0}, {"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 0}]}
 */


#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/workqueue.h>

#include "kjson/kjson.h"
#include "kjson/kjstring.h"

#define PROCINFO_OBJECT	"procinfo"
#define PROCINFO_ATTR_NAME jsoninfo

// Job of the workqueue proinfo_job
static void start_procinfo_job(struct work_struct *work);
static ssize_t procinfo_show(struct kobject *kobj, struct kobj_attribute *attr, char *buffer);
static ssize_t procinfo_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buffer, size_t count);

static void procinfo_release(struct kobject *kobj) { }

struct procinfo_data {
	struct kobject kobj;
	struct kjson_container *json;
	struct kjstring_t *json_answer;
	
	/*
	 * Declare a workqueue to make the job: Creating the JSON when the user request the process info,
	 * or better, it will read the procinfo file on sysfs.
	 */
	struct workqueue_struct *procinfo_job;
	struct work_struct job;
};

// Define a procinfo attribute name.
static struct kobj_attribute procinfo_attribute = __ATTR(PROCINFO_ATTR_NAME, 0664, procinfo_show, procinfo_store);

// Create an array of attribute with all attribute defined for the kobect
static struct attribute *procinfo_attrs[] = {
	&procinfo_attribute.attr,
	NULL
};
// And define the procinfo_groups from the procinfo_attrs
ATTRIBUTE_GROUPS(procinfo);

// Create the kobject proinfo with all attributes
static const struct kobj_type procinfo_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = procinfo_release,
	.default_groups = procinfo_groups,
};

ssize_t procinfo_show(struct kobject *kobj, struct kobj_attribute *attr, char *buffer)
{
	struct procinfo_data *pinfo;
	
	pinfo = container_of(kobj, struct procinfo_data, kobj);
	
	// If there is no a JSON string loaded, return NULL
	if(pinfo->json_answer == NULL)
		return 0;
	
	// If there was a parsing error into the procinfo_store call, print the error
	if(pinfo->json == NULL)
	{
		sysfs_emit(buffer, "%s", kjstring_str(pinfo->json_answer));
		return kjstring_size(pinfo->json_answer);
	}
	
	// Copy the JSON string to the kobject output buffer
	sysfs_emit(buffer, "%s", kjstring_str(pinfo->json_answer));
	return kjstring_size(pinfo->json_answer);
}

ssize_t procinfo_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buffer, size_t count)
{
	struct procinfo_data *pinfo;
	
	if(count == 0)
		return 0;

	pinfo = container_of(kobj, struct procinfo_data, kobj);
	
	// If a JSON was previously loaded we have to destroy it
	if(pinfo->json)
	{
		kjson_delete_container(pinfo->json);
		pinfo->json = NULL;
	}
	
	/* json_answer is created into the start_procinfo_job, or is used here to print errors.
	 * If we already have an old answer we have to destroy it
	 */
	if(pinfo->json_answer)
	{
		kjstring_free(pinfo->json_answer);
		pinfo->json_answer = NULL;
	}
	
	// Parse the JSON string passed and create the json container
	if((pinfo->json = kjson_parse(buffer)) == NULL)
	{
		// In case of error, we will write the error string into the sysfs buffer
		pinfo->json_answer = kjstring_alloc(128);
		if(pinfo->json_answer == NULL)
			return 0;
			
		kjstring_append(pinfo->json_answer, "Error parsing json. ");
		kjstring_append(pinfo->json_answer, kjson_parser_error_msg);
		kjstring_push(pinfo->json_answer, '\n');
		
		return count;
	}
	
	// Ok, json is parsed. We can schedule our work and create the new json_answer.
	queue_work(pinfo->procinfo_job, &pinfo->job);

	return count;
}

void set_process_path(struct kjson_container *my_json, struct task_struct *task)
{
    // Here we will do some operation to get the executable file to know it's path

    struct file *exe_file = NULL;
    struct mm_struct *mm;
    char exe_path_str[256], *res;

    if(unlikely(!task || !task->mm))
        return;
        
    memset(exe_path_str, 0x0, 256);

    task_lock(task);

    // The executable file object is stored inside the mm_struct of the process
    mm = task->mm;
    rcu_read_lock();
    exe_file = rcu_dereference(mm->exe_file);
    if(exe_file && !get_file_rcu(exe_file))
        exe_file = NULL;
    rcu_read_unlock();

    task_unlock(task);
    
    if(IS_ERR(res = d_path(&exe_file->f_path, exe_path_str, 256)))
        return;

    // Now, I can write the executable path to the my_json
    kjson_push_string(my_json, "ExecutablePath", res);
}

void set_file_open(struct kjson_container *my_json, struct task_struct *task)
{
    // Here we will do some operation to get the file opened by the process
    
	struct files_struct *fss;
	struct file *filp;
	char *paths[32], *buffer[32];
	int i = 0;
	
	memset(paths, 0x0, 32);
	
	task_lock(task);
	if(!(fss = task->files))
		goto EXIT;
		
	while(fss->fd_array[i] != NULL && i < 32)
	{
		filp = fss->fd_array[i];
		if(!(buffer[i] = (char*)get_zeroed_page(GFP_ATOMIC)))
			goto EXIT;
		paths[i] = d_path(&filp->f_path, buffer[i], 4096);
		i++;
	}
	
	// Now, I can write the process files open
	kjson_push_object(my_json, "ProcessFilesOpen", KOBJECT_TYPE_STRING_ARRAY, paths, i);
		
EXIT:	
	task_unlock(task);
	while(i > 0)
		free_page((unsigned long)buffer[--i]);
}

void set_socket_data(struct kjson_container *my_json, struct task_struct *task)
{
    // Here we will do some operation to get the socket opened by the process
    
	struct files_struct *fss;
	struct file *filp;
	struct inode *inodp;
	struct socket *sk;
	struct sock *sockp;
	char addr[INET_ADDRSTRLEN];
	int i = 0, j = 0;
	
	/* Pointer to an array of annidated JSON
	 * We are storing each socket into a single JSON container
	 */
	struct kjson_container* json_socks[32];
	
	task_lock(task);
	if(!(fss = task->files))
		goto EXIT;
		
	while(fss->fd_array[i] != NULL && i < 32)
	{
		filp = fss->fd_array[i];
		if(((inodp = file_inode(filp)) != NULL) && S_ISSOCK(inodp->i_mode))
		{
			if((sk = (struct socket*)filp->private_data) != NULL)
			{
				sockp = sk->sk;
				if((json_socks[j] = kjson_new_container()) != NULL)
				{
					kjson_push_integer(json_socks[j], "Protocol", (int64_t)sockp->sk_protocol);
					
					snprintf(addr, 16, "%pI4", &sockp->sk_daddr);
					kjson_push_string(json_socks[j], "DestinationIP", addr);
					
					snprintf(addr, 16, "%pI4", &sockp->sk_rcv_saddr);
					kjson_push_string(json_socks[j], "SourceIP", addr);
					
					kjson_push_integer(json_socks[j], "DestinationPort", sockp->sk_dport);
					kjson_push_integer(json_socks[j], "SourceIP", sockp->sk_num);
					
					j++;
				}
			}
		}
		i++;
	}
	
	// Now, I can write the process files open
	kjson_push_object(my_json, "ProcessSockOpen", KOBJECT_TYPE_OBJECT_ARRAY, json_socks, j);
	
EXIT:	
	task_unlock(task);
}

// Job of the workqueue proinfo_job
void start_procinfo_job(struct work_struct *work)
{
	struct procinfo_data *pinfo;
	struct kjson_object_t *obj;
	struct kjstring_t *error_message;
	
	pinfo = container_of(work, struct procinfo_data, job);
	
	// If no json is allocated or json_answer already contains an answer: do anything
	// json and json_answer is deallocated when you insert a new request (store callback)
	if(pinfo->json == NULL || pinfo->json_answer != NULL)
    		return;
		
	// Alloc memory to send errors
	error_message = kjstring_alloc(128);
	if(error_message == NULL)
    		return;

    // Read the process_pid
    if((obj = kjson_lookup_object(pinfo->json, "process_pid")) == NULL)
    {
    	kjstring_append(error_message, "No 'process_pid' key found\n");
    	// The json answer will contain the parse error
    	pinfo->json_answer = error_message;
    	return;
    }

    pid_t ppid = kjson_as_integer(obj);
    
    // Read the user requests
    if((obj = kjson_lookup_object(pinfo->json, "request")) == NULL)
    {
    	kjstring_append(error_message, "No 'request' key found\n");
		// The json answer will contain the parse error
    	pinfo->json_answer = error_message;    	
    	return;
    }
    
    size_t array_len = kjson_array_length(obj); 
    char **options = kjson_as_string_array(obj);
    
    // ------ Execute our program ------

	// Get the task_struct from the pid
    struct task_struct *task = get_pid_task(find_get_pid(ppid), PIDTYPE_TGID);
    // We want to avoid TASK_DEAD 
    if(!task || task_state_index(task) == TASK_DEAD)
    {
    	// Copy the error in the json_answer string
    	kjstring_append(error_message, (int64_t)ppid);
    	kjstring_append(error_message, ": pid doesn't match any task\n");
		// The json answer will contain the parse error
    	pinfo->json_answer = error_message;    	
		return;
    }
    
    int i = 0;
    while(i < array_len)
    {
    	if(strcmp(options[i], "process_path") == 0)
    		set_process_path(pinfo->json, task);
    	else if(strcmp(options[i], "file_open") == 0)
    		set_file_open(pinfo->json, task);
    	else if(strcmp(options[i], "process_socket") == 0)
    		set_socket_data(pinfo->json, task);
    		
    	i++;
    }
    
    // Get the json dump and print it
    if(IS_ERR(pinfo->json_answer = kjson_dump(pinfo->json)))
    {
    	kjstring_append(error_message, "kjson dump error\n"); // THIS COULD'T BE HAPPEN
    	// The json answer will contain the parse error
    	pinfo->json_answer = error_message;
	}
	else // No error, we don't need error_message (it is empty)
		kjstring_free(error_message);
}

static struct procinfo_data *init(void)
{
	struct procinfo_data *pinfo;
	int retval;
	
	if(IS_ERR(pinfo = kzalloc(sizeof(struct procinfo_data), GFP_KERNEL)))
		return ERR_PTR(-ENOMEM);
	
	// initialize a sysfs kobject to open an interface with the user
    if((retval = kobject_init_and_add(&pinfo->kobj, &procinfo_ktype, kernel_kobj, "%s", PROCINFO_OBJECT)))
		goto ERROR;
		
	INIT_WORK(&pinfo->job, start_procinfo_job);
	if((pinfo->procinfo_job = create_workqueue("procinfo_job")) == NULL)
		goto ERROR;
	
	goto EXIT;
	
ERROR:
	kfree(pinfo);
	pinfo = ERR_PTR(-ENOMEM);
	
EXIT:
	return pinfo;
}

struct procinfo_data *pinfo = NULL;

int __init test_init(void)
{
	if(IS_ERR((pinfo = init())))
		return PTR_ERR(pinfo);
		
	return 0;
}

void __exit test_exit(void)
{
	kobject_put(&pinfo->kobj);
	kfree(pinfo);
}

module_init(test_init);
module_exit(test_exit);

MODULE_LICENSE("GPL");

