CLANG ?= clang
LIBS := -lbpf -lelf
ARCH = x86


all: privilege_escalation_monitor_kern.o privilege_escalation_monitor

clean:
	rm -f *.o
	rm -f cred_monitor.skel.h

vmlinux.h: 
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

#
# BPF is kernel code. We need to pass -D__KERNEL__ to refer to fields present
# in the kernel version of pt_regs struct. uAPI version of pt_regs (from ptrace)
# has different field naming.
# See: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fd56e0058412fb542db0e9556f425747cf3f8366
#
privilege_escalation_monitor_kern.o: privilege_escalation_monitor_kern.c vmlinux.h
	$(CLANG) -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -D__KERNEL__ -c $< -o $@
		

privilege_escalation_monitor: privilege_escalation_monitor_user.c
	$(CC) -g -Wall $(LIBS) $< -o $@

