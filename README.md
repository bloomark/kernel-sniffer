##Kernel-Sniffer
For [CS5413](http://www.cs.cornell.edu/courses/CS5413/2014fa/labs/lab3.htm) at Cornell

###Usage
- Loading the module
`insmod ./sniffer_mod.ko`
- Unload the module
`rmmod sniffer_mod`
- Create a device file for the character device interface
`sudo mknod sniffer.dev c 251 0`
- Control the sniffer
`./sniffer_control [mode] [src_ip] [src_port] [dst_ip] [dst_port] [action]``
- Read captured packets
`./sniffer_read [-i input file] [-o output file]`

####Action options
Filter
Capture
DPI