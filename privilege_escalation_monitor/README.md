# Privilege Escalation Monitor

This is an eBPF program based to monitor the root access on your system. You'll find more information on my article: 
[Enhance Linux Security: Monitoring Privilege Escalation on Processes with eBPF](https://medium.com/@emanuele.santini.88/enhance-linux-security-monitoring-privilege-escalation-on-processes-with-ebpf-624531434a87)

## Build: 

Install bpftool from your distro repo or download and build from here: https://github.com/libbpf/bpftool

Type: `make` 

## Run:

Type `./privilege_escalation_monitor`
