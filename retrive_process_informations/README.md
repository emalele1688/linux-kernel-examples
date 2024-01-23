This module is capable of receiving a JSON file from the user through the sysfs object created, which contains details about a specific process identified by its process ID (PID). 
Upon receiving the file, the module processes the request and responds with comprehensive information about the specified process.
This information includes the list of files currently opened by the process, the open sockets associated with the process, and the path to the executable file of the process.

This module uses kjson library.

Json input format:
{ 
 "process_pid": 1, 
 "request": ["process_path", "file_open", "process_socket"]
} 

Example:
```
 # insmod procinfo.ko
 # cd /sys/kernel/procinfo/
 # echo { \"process_pid\": 1, \"request\": [\"process_path\", \"file_open\", \"process_socket\"] } > jsoninfo
 # cat jsoninfo
 {"ExecutablePath": "/usr/lib/systemd/systemd", "request": ["process_path", "file_open", "process_socket"], "ProcessFilesOpen": ["/dev/null", "/dev/null", "/dev/null", "/dev/kmsg", "anon_inode:[eventpoll]", "anon_inode:[signalfd]", "anon_inode:inotify", "/sys/fs/cgroup", "anon_inode:[timerfd]", "anon_inode:[eventpoll]", "/proc/1/mountinfo", "anon_inode:inotify", "/usr/lib/x86_64-linux-gnu/libgcr-base-3.so.1.0.0", "anon_inode:inotify", "/proc/swaps", "socket:[20768]", "socket:[20769]", "socket:[20770]", "socket:[20771]", "socket:[20772]", "socket:[20774]", "socket:[20775]", "/usr/lib/x86_64-linux-gnu/libglib-2.0.so.0.7200.4", "/usr/lib/x86_64-linux-gnu/libX11.so.6.4.0", "/usr/lib/x86_64-linux-gnu/libgmodule-2.0.so.0.7200.4", "/usr/lib/x86_64-linux-gnu/libsystemd.so.0.32.0", "anon_inode:inotify", "/dev/autofs", "pipe:[20781]", "anon_inode:[timerfd]", "/run/dmeventd-server", "/run/dmeventd-client"], "process_pid": 1, "ProcessSockOpen": [{"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 15}, {"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 0}, {"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 0}, {"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 0}, {"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 0}, {"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 0}, {"DestinationPort": 0, "DestinationIP": "0.0.0.0", "SourceIP": "0.0.0.0", "Protocol": 0}]}
```
