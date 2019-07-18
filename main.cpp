#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

struct L2_header{
    uint8_t dst_MAC[6];
    uint8_t src_MAC[6];
    int ether_type;
};
struct L3_header{
    uint8_t dst_IP[4];
    uint8_t src_IP[4];
    uint8_t protocol;
};
struct L4_header{
    uint8_t dst_port[2];
    uint8_t src_port[2];
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_MAC(uint8_t *addr){
    printf(": %02X:%02X:%02X:%02X:%02X:%02X\n",
           addr[0],addr[1],addr[2],addr[3],
            addr[4],addr[5]);
}
void print_IP(uint8_t *addr){
    printf(": %u.%u.%u.%u\n",
          addr[0],addr[1],addr[2],addr[3]);
}
void print_PORT(uint8_t *addr){
    printf(": %u\n",addr[0]<<8|addr[1]);
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    //time, length info
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    struct L2_header h2;
    for(int i=0;i<6;i++)
        h2.dst_MAC[i]=packet[i];
    for(int i=6;i<12;i++)
        h2.src_MAC[i-6]=packet[i];
    h2.ether_type=(packet[12]<<8)|packet[13];
    if(h2.ether_type!=2048)
        continue; //if not IPv4

    uint8_t ip_len=0;
    int ip=(packet[16]<<8)|packet[17];
    struct L3_header h3;
    for(int j=0;j<4;j++)
        h3.src_IP[j]=packet[j+26];
    for(int j=4;j<8;j++)
        h3.dst_IP[j-4]=packet[j+26];
    h3.protocol=packet[23];
    if(h3.protocol!=6)
        continue;  //if not TCP
    uint8_t a = packet[14]>>4;
    uint8_t b= packet[14]&0xF;
    ip_len=a*b;
    printf("\nip header len: %d\n",ip_len);
    printf("full ip: %d\n",ip);

    struct L4_header h4;
    h4.src_port[0]=packet[ip_len+14];
    h4.src_port[1]=packet[ip_len+15];
    h4.dst_port[0]=packet[ip_len+16];
    h4.dst_port[1]=packet[ip_len+17];

    int tcp_len = (packet[14+ip_len+12]>>4)*4; //tcp header length
    printf("tcp len: %d\n",tcp_len);

    printf("\n----------------------------\n");
    //Ehter Header
    printf("Dst MAC");
    print_MAC(h2.dst_MAC);
    printf("Src MAC");
    print_MAC(h2.src_MAC);
    printf("Ehter type: %04X\n",h2.ether_type);

    //IP header
    printf("\nDst IP");
    print_IP(h3.dst_IP);
    printf("Src IP");
    print_IP(h3.src_IP);
    printf("protocol: %X\n\n",h3.protocol);

    //TCP header
    printf("Dst port");
    print_PORT(h4.dst_port);
    printf("Src port");
    print_PORT(h4.src_port);

    //data
    if(ip-ip_len-tcp_len>0){
        printf("data:");
        for(int i=14+ip_len+tcp_len;i<14+ip_len+tcp_len+10;i++)
            printf("%02X ",packet[i]);
    }
    printf("\n----------------------------");
  }

  pcap_close(handle);
  return 0;
}
