// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 - 2024 Emanuele Santini <emanuele.santini.88@gmail.com>
 */

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>


#define PATH_MAX 128

struct process_stats {
    pid_t tgid;
    unsigned int old_uid;
    unsigned int new_uid;    
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024);
} process_stats_buffer SEC(".maps");

static void send_event(const struct task_struct *task, kuid_t old_uid, kuid_t new_uid)
{
    struct process_stats *value;
    
    // Get a buffer from the ring buffer
    value = bpf_ringbuf_reserve(&process_stats_buffer, sizeof(struct process_stats), 0);
    if(!value)
	{
		bpf_printk("Error - ringbuffer is full\n");
		return;
	}
    
    // Get's the PID of the process
    value->tgid = BPF_CORE_READ(task, tgid);
    
    value->old_uid = old_uid.val;
    value->new_uid = new_uid.val;

    // Commit the buffer to user
    bpf_ringbuf_submit(value, 0);
}

SEC("kprobe/commit_creds")
int commit_creds(struct pt_regs *regs)
{
    const struct task_struct *task;
    const struct cred *old_cred, *new_cred;
    kuid_t old_uid, new_uid;
    
    // Gets the first parameter of the commit_creds kernel call -> struct cred *new
    if(!(new_cred = (struct cred*)PT_REGS_PARM1(regs)))
        return 0;
    
    task = (struct task_struct*)bpf_get_current_task();
    if(!task)
        return 0;
    
    // Gets the current cred of the executed process
    if(bpf_core_read(&old_cred, sizeof(void *), &task->cred)) 
        return 0;

    // On this tutorial we are only interested about UID creds.
    old_uid = BPF_CORE_READ(old_cred, uid);
    new_uid = BPF_CORE_READ(new_cred, uid);
    
    /* 
     * Compare the current cred with the old cred. 
     * We have a privilege escalation if: 
     * new credentials uid is 0 AND old_uid is greather than 0 
     */
    if(new_uid.val == 0 && old_uid.val > 0)
        send_event(task, old_uid, new_uid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";


