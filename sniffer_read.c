#define _BSD_SOURCE
#define __FAVOR_BSD
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <netinet/ip.h>   /* Internet Protocol  */
#include <netinet/tcp.h>   /* Internet Protocol  */
#include <arpa/inet.h>
#include "sniffer_ioctl.h"

static char * program_name;
static char * dev_file = "sniffer.dev";

static char * out_file;
char *buff;
int ofd=1;

void usage() 
{
    fprintf(stderr, "Usage: %s [-i input_file] [-o output_file]\n", program_name);
    exit(EXIT_FAILURE);
}

int print_packet(char * pkt, int len)
{
    /* print format is :
     * src_ip:src_port -> dst_ip:dst_port
     * pkt[0] pkt[1] ...    pkt[64] \n
     * ...
     * where pkt[i] is a hex byte */
    
    int i;
    struct ip *iph = NULL;          
    struct tcphdr *tcph = NULL;
    
    iph = (struct ip *)(pkt);
    tcph = (struct tcphdr*)(pkt+20);
    
    dprintf(ofd, "\n%s:%d -> %s:%d", inet_ntoa(iph->ip_src), ntohs(tcph->th_sport), inet_ntoa(iph->ip_dst), ntohs(tcph->th_dport));

    for(i=0 ; i<len; i++){
        if(i%64 == 0)
            dprintf(ofd, "\n");
        dprintf(ofd, "%.2x ", (unsigned char)pkt[i]);      
    }
    dprintf(ofd, "\n");

    return 0;
}

int main(int argc, char **argv)
{
    int c;
    char *input_file, *output_file = NULL;
    int ret_val,ifd;
    
    program_name = argv[0];

    //input_file= dev_file;

    while((c = getopt(argc, argv, "i:o:")) != -1) {
        switch (c) {
        case 'i':
            dev_file = optarg;                    
            break;
        case 'o':
            out_file = optarg;
            ofd = open(out_file, O_WRONLY);
            if(ofd < 0){
                printf("Can't open output file %s\n", out_file);
                exit(1);
            }
            break;
        default:
            usage();
        }
    }

    //ifd = open(input_file, O_RDONLY);
    ifd = open(dev_file, O_RDONLY);
    if(ifd < 0){
       printf("Can't open device file: %s\n", dev_file);
       exit(-1);
    }

    while(1){
        buff = (char*)malloc(2048);
        ret_val = read(ifd,buff,2048);
        if(ret_val == -666){
            free(buff);
            printf("One reader already exists\n");
            break;
        }            
        if(ret_val < 0){
            free(buff);
            printf("Error reading!!\n");
            break;
        } 
        else if(ret_val == 0 ){
            free(buff);
            printf("No more data to read\n");
            break;
        } 
        else{
            print_packet(buff,ret_val);
            free(buff);
        }
    }

    close(ifd);
    close(ofd);

    return 0;
}
