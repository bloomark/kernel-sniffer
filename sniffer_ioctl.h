#ifndef __SNIFFER_IOCTL_
#define __SNIFFER_IOCTL__

struct sniffer_flow_entry {
    // TODO
    int mode;
    //char src_ip[16];
    uint32_t src_ip;
    int src_port;
    //char dest_ip[16];
    uint32_t dest_ip;
    int dest_port;
    //char action[15];
    int action;
    //struct sniffer_flow_entry *next;
};

#define SNIFFER_IOC_MAGIC       'p'

#define SNIFFER_FLOW_ENABLE     _IOW(SNIFFER_IOC_MAGIC, 0x1, struct sniffer_flow_entry)
#define SNIFFER_FLOW_DISABLE    _IOW(SNIFFER_IOC_MAGIC, 0x2, struct sniffer_flow_entry)

#define SNIFFER_IOC_MAXNR   0x3

#define ACTION_NONE             1
#define ACTION_CAPTURE          2
#define ACTION_DPI              3
#define ACTION_NULL             0

#define SNIFFER_ACTION_NULL     0x0
#define SNIFFER_ACTION_CAPTURE  0x1
#define SNIFFER_ACTION_DPI      0x2

#endif /* __SNIFFER_IOCTL__ */
