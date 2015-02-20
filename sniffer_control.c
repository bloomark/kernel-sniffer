#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include "sniffer_ioctl.h"
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>

static char * program_name;
static char * dev_file = "sniffer.dev";
int flag = 0;

void usage() 
{
    fprintf(stderr, "Usage: %s [parameters]\n"
                "parameters: \n"
                "    --mode [enable|disable]\n"
                "    --src_ip [url|any] : default is any \n"
                "    --src_port [XXX|any] : default is any \n"
                "    --dst_ip [url|any] : default is any \n" 
                "    --dst_port [XXX|any] : default is any \n"
                "    --action [capture|dpi] : default is null\n", program_name);
    exit(EXIT_FAILURE);
}

int sniffer_send_command(struct sniffer_flow_entry *flow)
{
    int fd;

    fd = open(dev_file, O_WRONLY);
    if(fd < 0){
        printf("Error opening file\n");
        exit(1);
    }
    
    if(flag == 0)
        flow->mode = -1;

    if(ioctl(fd, flow->mode, flow) == -1){
        printf("IOCTL Error\n");
        exit(1);
    }

    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    int c;
    int i;
    program_name = argv[0];

    struct sniffer_flow_entry test;
    struct hostent *rethost;
    struct in_addr **addr_list;

    test.mode = 0;
    test.src_port = -1;
    test.dest_port = -1;
    test.src_ip = 0;
    test.dest_ip = 0;
    test.action = ACTION_NONE;

    while(1) {
        static struct option long_options[] = 
        {
            {"mode", required_argument, 0, 0},
            {"src_ip", required_argument, 0, 0},
            {"src_port", required_argument, 0, 0},
            {"dst_ip", required_argument, 0, 0},
            {"dst_port", required_argument, 0, 0},
            {"action", required_argument, 0, 0},
            {"dev", required_argument, 0, 0},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        c = getopt_long (argc, argv, "", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
        case 0:
            printf("option %d %s", option_index, long_options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg); 
            printf("\n");

            switch(option_index) {
            case 0:     // mode
                if(strcmp(optarg, "enable") == 0){
                    flag = 1;
                    test.mode = SNIFFER_FLOW_ENABLE;
                }
                else if(strcmp(optarg, "disable") == 0){
                    flag = 1;
                    test.mode = SNIFFER_FLOW_DISABLE;
                }
                break;
            case 1:     // src_ip
                if(strcmp(optarg, "any") == 0){
                    test.src_ip = 0;
                }
                else{
                    if((rethost = gethostbyname(optarg)) == NULL){
                        printf("Invalid source ip\n");
                        return 1;
                    }
                    addr_list = (struct in_addr **)rethost->h_addr_list;
                    for(i=0; addr_list[i]!=NULL; i++){  
                        printf("Integer source = %u\n", ntohl(addr_list[i]->s_addr));
                        test.src_ip=ntohl(addr_list[i]->s_addr);
                        break;
                    }
                }
                break;
            case 2:     // src_port
                if(strcmp(optarg, "any") == 0)
                    test.src_port = -1;
                else
                    test.src_port = atoi(optarg);
                break;
            case 3:     // dst_ip
                if(strcmp(optarg, "any") == 0){
                    test.dest_ip = 0;
                }
                else{
                    if((rethost = gethostbyname(optarg)) == NULL){
                        printf("Invalid source ip\n");
                        return 1;
                    }
                    addr_list = (struct in_addr **)rethost->h_addr_list;
                    for(i=0; addr_list[i]!=NULL; i++){
                        test.dest_ip=ntohl(addr_list[i]->s_addr);
                        break;
                    }
                }
                break;
            case 4:     // dst_port
                if(strcmp(optarg, "any") == 0)
                    test.dest_port = -1;
                else
                    test.dest_port = atoi(optarg);
                break;
            case 5:     // action
                if(strcmp(optarg,"none") == 0){
                    test.action = ACTION_NONE;
                }
                else if(strcmp(optarg, "capture") == 0){
                    test.action = ACTION_CAPTURE;
}
                else if(strcmp(optarg, "dpi") == 0){
                    test.action = ACTION_DPI;
}
                else{
                    usage();
                    exit(1);
}
                break;
            case 6:     // dev
                dev_file = optarg;
                break;
            }
            break;
        default:
            usage();
            exit(0);
        }
    }
    sniffer_send_command(&test);

    return 0;
}
