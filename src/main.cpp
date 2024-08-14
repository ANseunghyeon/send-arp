#include <cstdio>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> ...\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

void send_arp(pcap_t* handle, Mac my_mac, Mac s_mac, Ip s_ip, Ip t_ip)
{
	EthArpPacket packet;
	
	packet.eth_.dmac_ = s_mac;
	packet.eth_.smac_ = my_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = my_mac;
	packet.arp_.sip_ = htonl(s_ip);
	packet.arp_.tmac_ = (s_mac == Mac("ff:ff:ff:ff:ff:ff")) ? Mac("00:00:00:00:00:00") : s_mac;
	packet.arp_.tip_ = htonl(t_ip);
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return;
	}
}

char* get_my_mac(const char* ifname) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        close(sockfd);
        return NULL;
    }

    close(sockfd);

    char* mac_str = (char*)malloc(18);
    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    snprintf(mac_str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return mac_str;
}


char* get_my_ip(const char* ifname) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("Failed to get IP address");
        close(sockfd);
        return NULL;
    }

    close(sockfd);

    struct sockaddr_in* ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
    char* ip_str = (char*)malloc(16);
    unsigned char* ip = (unsigned char*)&ip_addr->sin_addr.s_addr;
    snprintf(ip_str, 16, "%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0]);

    return ip_str;
}

Mac get_s_mac(pcap_t* handle, Mac my_mac, Ip my_ip, Ip s_ip)
{
	send_arp(handle, my_mac, Mac("ff:ff:ff:ff:ff:ff"), my_ip, s_ip);
	
	Mac s_mac;
	
	struct pcap_pkthdr* header;
    const u_char* packet_data;
    
	while (int res = pcap_next_ex(handle, &header, &packet_data) >= 0) {
        if (res == 0) continue; 
        EthArpPacket* recv_packet = (EthArpPacket*)packet_data;

        if (recv_packet->eth_.type() == 0x0806 && recv_packet->arp_.op() == 2){
			s_mac = recv_packet->arp_.smac();
			break;
		}
    }

    return s_mac;
}
int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	char* my_mac_str = get_my_mac(dev);
    char* my_ip_str = get_my_ip(dev);
    if (my_mac_str == NULL || my_ip_str == NULL) {
        fprintf(stderr, "Failed to get my MAC or IP\n");
        return -1;
    }
	
	Mac my_mac = Mac(my_mac_str);
    Ip my_ip = Ip(ntohl(*(unsigned int*)my_ip_str));
    free(my_mac_str);
    free(my_ip_str);  

	for (int i = 2; i < argc; i += 2)
	{
		Ip s_ip = Ip(argv[i]);
		Ip t_ip = Ip(argv[i+1]);
		Mac s_mac = get_s_mac(handle, my_mac, my_ip, s_ip);
		
		if (!s_mac.isNull()) {
            send_arp(handle, my_mac, s_mac, t_ip, s_ip); 
        } else {
            fprintf(stderr, "Failed to get sender MAC\n");
        }
	}

	pcap_close(handle);
}
