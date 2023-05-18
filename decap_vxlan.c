#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#define VXLAN_PORT 4789
#define VXLAN_HDR_SIZE 8

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    pcap_t *handle;
    pcap_dumper_t *outfile;
    
    handle = pcap_open_offline("-", errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open pcap file: %s\n", errbuf);
        return(2);
    }
    
    outfile = pcap_dump_open(handle, "-");
    if (outfile == NULL) {
        fprintf(stderr, "Couldn't open output file: %s\n", pcap_geterr(handle));
        return(2);
    }

    while ((packet = pcap_next(handle, &header))) {
        struct ether_header *eth_header;
        struct ip *ip_header;
        struct udphdr *udp_header;
        
        eth_header = (struct ether_header *) packet;
        if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
            continue;
        }

        ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
        if (ip_header->ip_p != IPPROTO_UDP) {
            continue;
        }

        udp_header = (struct udphdr *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);
        if (ntohs(udp_header->uh_dport) != VXLAN_PORT) {
            continue;
        }

        u_char *vxlan_packet = (u_char *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4 + sizeof(struct udphdr) + VXLAN_HDR_SIZE);
        struct pcap_pkthdr vxlan_header = header;
        vxlan_header.caplen -= (vxlan_packet - packet);
        vxlan_header.len -= (vxlan_packet - packet);
        pcap_dump((u_char *)outfile, &vxlan_header, vxlan_packet);
    }

    pcap_dump_close(outfile);
    pcap_close(handle);
    return(0);
}
