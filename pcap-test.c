#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#define _CRT_SECURE_NO_WARNINGS

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param ens33  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&ens33, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(ens33.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", ens33.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        printf("%u bytes captured\n", header->caplen);
        printf("src mac : %02X %02X %02X %02X %02X %02X\n",packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
        printf("dst mac : %02X %02X %02X %02X %02X %02X\n",packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
        if ((packet[12]==0x08)&&(packet[13]==0x00)){
            printf("IPv4\n");
            printf("src ip : %02X %02X %02X %02X\n",packet[26],packet[27],packet[28],packet[29]);
            printf("dst ip : %02X %02X %02X %02X\n",packet[30],packet[31],packet[32],packet[33]);
            if (packet[23]==0x06){
                printf("TCP\n");
                printf("src port : %02X %02X\n", packet[33], packet[34]);
                printf("dst port : %02X %02X\n", packet[35], packet[36]);
                //if TCP data > 8,
            }
            else {
                printf("Not TCP\n");
            }
        }
        else if((packet[12]==0x08)&&(packet[13]==0x06)){
            printf("ARP\n");
        }
        else{
            printf("else\n");
        }
        printf("========================================================================");



	}

    pcap_close(pcap);
}
