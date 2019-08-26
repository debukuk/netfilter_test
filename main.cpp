#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

struct ip_header {
    uint8_t version_and_length;
    uint8_t type;
    uint16_t length;
    uint16_t identification;
    uint16_t flag_and_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
};

struct tcp_header {
    uint8_t src_port[2];
    uint8_t dst_port[2];
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;
    uint8_t flag;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_p;
};

struct packet{
	struct ip_header ip;
	struct tcp_header tcp;
};

char *domain = {'\0',};
bool filter_chk = 0;

/* returns packet id */

void usage(){
	printf("netfilter_test <host>\n");
	printf("ex : netfilter_test debu.kr\n");
}

bool filter(unsigned char *buf, int size) {
	int i;
	struct packet p;
	struct ip_header ip;
	struct tcp_header tcp;
	unsigned char payload[0x100];

	if (buf == NULL)
		return 0;

	memcpy(&p, buf, 40);
	printf("size: %d\n", size);
	if ( (p.ip.version_and_length & 0xf0) >> 4 == 0x4 ){ // check ipv4
		if (p.ip.protocol == 6 && size != 0) {
			int ip_header_length = (p.ip.version_and_length & 0xf) * 4;
			int tcp_header_length = ((p.tcp.data_offset & 0xf0) >> 4) * 4;
			int tcp_data_length = size - ip_header_length - tcp_header_length;

			if ((buf[40] == 'G' && buf[41] == 'E' && buf[42] == 'T') || // check method is get
			   (buf[40] == 'P' && buf[41] == 'O' && buf[42] == 'S' && buf[43] == 'T')) { // check method is post
				if (tcp_data_length < 0x100)
					memcpy(payload, &buf[40], tcp_data_length);
				else 
					memcpy(payload, &buf[40], 0x100);

				if (strstr((char *)payload, (char *)domain)){
					//printf("payload : %s\n", payload);
					//printf("domain : %s\n", domain);
					return 1;
				}else
					return 0;
			}else
				return 0;
		}else
			return 0;
	}else
		return 0;
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		/*
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
		*/
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		/*
		printf("hw_src_addr=");
		
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
		*/
	}

	/*
	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);
	*/

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);
	

	fputc('\n', stdout);

	if (filter(data, ret)) 
		filter_chk = 1;
	else
		filter_chk = 0;

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);

	printf("entering callback\n");
	if (filter_chk == 1) {
		printf("%s filtered!\n", domain);
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}else {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
}

void holy(){
	system("iptables -F");
	system("iptables -A OUTPUT -j NFQUEUE");
	system("iptables -A INPUT -j NFQUEUE");
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	holy(); // set for network setting

	if (argc < 2) {
		usage();
		return -1;
	}else
		domain = argv[1];
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
