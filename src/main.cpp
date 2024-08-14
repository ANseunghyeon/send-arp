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
	ArpHdr arp_;
	EthHdr eth_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

void send_arp(pcap_t* handle, char* my_mac, char* s_mac, char* s_ip, char* t_ip)
{
	EthArpPacket packet;
	
	packet.eth_.dmac_ = Mac("sender MAC");
	packet.eth_.smac_ = Mac("My MAC");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("My MAC");
	packet.arp_.sip_ = htonl(Ip("TARGET IP"));
	packet.arp_.tmac_ = !strncmp(s_mac, "ff:ff:ff:ff:ff:ff", 18) ? Mac("00:00:00:00:00:00") : packet.arp_.tmac_ = Mac("sender MAC");; 
	packet.arp_.tip_ = htonl(Ip("sender IP"));
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return;
		}
	
	return;
}

char* get_my_mac(char* ifname) {
    struct ifreq ifr;
    int sockfd;
    char* my_mac = (char*)malloc(18);
	memset(my_mac, 0, sizeof(my_mac));
	
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return "error";
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        close(sockfd);
        return "error";
    }

    close(sockfd);

    unsigned char *mac = (unsigned char*) ifr.ifr_hwaddr.sa_data;
    snprintf(my_mac, sizeof(my_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return my_mac;
}
char* get_my_ip(char* ifname) {
    struct ifreq ifr;
    int sockfd;
    char* ip_str = (char*)malloc(16); 
	memset(ip_str, 0, sizeof(ip_str));
	
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return "error";
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("Failed to get IP address");
        close(sockfd);
        return "error";
    }

    close(sockfd);

    struct sockaddr_in* ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
    unsigned char* ip = (unsigned char*)&ip_addr->sin_addr.s_addr;
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

    return ip_str;
}

char* get_s_mac(pcap_t* handle, char* my_mac, char* my_ip, char* s_ip);
{
	send_arp(handle, my_mac, "ff:ff:ff:ff:ff:ff", my_ip, s_ip);
	
	struct pcap_pkthdr* header;
    const u_char* packet_data;
    
	char* s_mac = (char*)malloc(18);
    memset(s_mac, 0, sizeof(s_mac));
	
	while (int res = pcap_next_ex(handle, &header, &packet_data) >= 0) {
        if (res == 0) continue; 
        EthArpPacket* recv_packet = (EthArpPacket*)packet_data;

        if (ntohs(recv_packet->eth_.type_) == EthHdr::Arp &&
            ntohs(recv_packet->arp_.op_) == ArpHdr::Reply &&
            recv_packet->arp_.sip_ == htonl(Ip(s_ip))) {
				
            snprintf(s_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                     recv_packet->arp_.smac_[0], recv_packet->arp_.smac_[1],
                     recv_packet->arp_.smac_[2], recv_packet->arp_.smac_[3],
                     recv_packet->arp_.smac_[4], recv_packet->arp_.smac_[5]);
        }
    }

    return s_mac;
}
int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 !=0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char tempbuf[1500];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	char* my_mac = get_my_mac(dev);
    char* my_ip = get_my_ip(dev);
    if (my_mac == NULL || my_ip == NULL) {
        fprintf(stderr, "my_error\n");
        return -1;
    }
	
	for( int i =2; i<argc/2; i+=2)
	{
		
		char* s_ip = argv[i];
		char* t_ip = argv[i+1];
		char* s_mac = get_s_mac(handle, my_mac, my_ip, s_ip);
		
		//해시테이블
		
		if (s_mac != NULL) {
            send_arp(handle, my_mac, s_mac, s_ip, t_ip); // 상대 arp어택.
            free(s_mac);
        } else {
            fprintf(stderr, "s_mac 에러\n");
        }
	}
	free(my_mac);
    free(my_ip);
	pcap_close(handle);
}
