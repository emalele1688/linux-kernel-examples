// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 - 2024 Emanuele Santini <emanuele.santini.88@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define PATH_MAX 128

struct process_stats {
    pid_t tgid;
    unsigned int old_uid;
    unsigned int new_uid;
};

// Callback executed at every ring buffer message reveived from bpf_ringbuf_submit
static int handle_msg(void *ctx, void *data, size_t sz)
{
    const struct process_stats *proc = (const struct process_stats*)data;
    char proc_path[PATH_MAX], exe_path[PATH_MAX], cmd_line[PATH_MAX];
    int cmdline_ds, i;
    
    memset(proc_path, 0x0, PATH_MAX);
    memset(exe_path, 0x0, PATH_MAX);
    memset(cmd_line, 0x0, PATH_MAX);    
    
    // Gets the process executable path
    snprintf(proc_path, PATH_MAX, "/proc/%d/exe", proc->tgid);
    readlink(proc_path, exe_path, PATH_MAX);

    // Gets the process command line    
    snprintf(proc_path, PATH_MAX, "/proc/%d/cmdline", proc->tgid);    
    if((cmdline_ds = open(proc_path, O_RDONLY)))
    {
        read(cmdline_ds, cmd_line, PATH_MAX);
        for(i = 0; i < PATH_MAX - 1; i++)
            if(cmd_line[i] == '\0' && cmd_line[i + 1] != '\0')
                cmd_line[i] = ' ';
        
        close(cmdline_ds);
    }
    
    printf("Escalation from: PID %d: Executable path: %s Command line: %s Old UID: %u New UID: %u\n", proc->tgid, exe_path, cmd_line, proc->old_uid, proc->new_uid);
    
    return 0;
}

int main(int argc, char *argv[])
{
    struct bpf_object *obj = NULL;
	struct bpf_program *prog;
    struct bpf_link *link;
    struct ring_buffer *rb;
    int mapfd;

    // Open the eBPF object program
    obj = bpf_object__open_file("privilege_escalation_monitor_kern.o", NULL);
	if(libbpf_get_error(obj)) 
	{
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		obj = NULL;
		return 0;
	}
	
	// load BPF program
	if(bpf_object__load(obj)) 
	{
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		return 1;
	}	

    // Get the program entry point symbol
	prog = bpf_object__find_program_by_name(obj, "commit_creds");
	if(!prog) 
	{
		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		return 1;
	}

    // Get the ring buffer data structure symbol
	mapfd = bpf_object__find_map_fd_by_name(obj, "process_stats_buffer");
	if(mapfd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed\n");
		return 1;
	}
	
	// Creates a new instance of a user ring buffer. Uses as event callback
	rb = ring_buffer__new(mapfd, handle_msg, NULL, NULL);

    // Start the eBPF program "commit_creds"
    if((link = bpf_program__attach(prog)) == NULL)
    {
        fprintf(stderr, "ERROR: attaching BPF object file failed\n");
		return 1;
	}
	
	printf("Escalation privilege monitor starts; Press CTRL-C to exit\n");

    for(;;) {
        ring_buffer__poll(rb, 1000); // 1000 is the ms timeout
    }

	return 0;
}



