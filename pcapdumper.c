#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>   // getopt()
#include <stdlib.h>   // exit(), strdup(), free()
#include <string.h>   // strdup()

#ifndef TH_NS
#define TH_NS 0x100  /* Nonce Sum (RFC 3540) */
#endif
#ifndef TH_CWR
#define TH_CWR  0x80 /* Congestion Window Reduced */
#endif
#ifndef TH_ECE
#define TH_ECE  0x40 /* ECN-Echo */
#endif
#ifndef TH_PSH
#define TH_PSH  TH_PUSH /* Alias for portability */
#endif

/* Prototypes */
void print_packet_info(const u_char *packet, const struct pcap_pkthdr *hdr);

void packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
);

int main(int argc, char *argv[]) {
    char *interface = NULL;
    char *filter_exp = NULL;
    char *output_file = NULL;

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    pcap_dumper_t *dumper = NULL;
    int snapshot_length = BUFSIZ;
    int timeout_limit = 10000;

    int opt;
    while ((opt = getopt(argc, argv, "i:f:o:")) != -1) {
        switch (opt) {
            case 'i': interface   = strdup(optarg); break;
            case 'f': filter_exp  = strdup(optarg); break;
            case 'o': output_file = strdup(optarg); break;
            default:
                fprintf(stderr, "Usage: %s -i <interface> [-f <filter>] [-o <output_file.pcap>]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    /* Require -i and list interfaces if missing */
    if (interface == NULL) {
        fprintf(stderr, "Error: You must specify an interface with -i\n");
        fprintf(stderr, "Available interfaces:\n");

        pcap_if_t *alldevs, *d;
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "  [Error listing devices: %s]\n", errbuf);
        } else {
            for (d = alldevs; d != NULL; d = d->next) {
                fprintf(stderr, "  %s", d->name);
                if (d->description) fprintf(stderr, " — %s", d->description);
                fprintf(stderr, "\n");
            }
            pcap_freealldevs(alldevs);
        }
        exit(EXIT_FAILURE);
    }

    printf("Selected interface: %s\n", interface);
    if (filter_exp)  printf("Using filter: %s\n", filter_exp);
    if (output_file) printf("Writing output to: %s\n", output_file);

    /* Open device */
    handle = pcap_open_live(interface, snapshot_length, 1, timeout_limit, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", interface, error_buffer);
        free(interface); free(filter_exp); free(output_file);
        return 1;
    }

    /* Optional: open dumper if -o provided */
    if (output_file) {
        dumper = pcap_dump_open(handle, output_file);
        if (!dumper) {
            fprintf(stderr, "Error opening output file %s: %s\n", output_file, pcap_geterr(handle));
            pcap_close(handle);
            free(interface); free(filter_exp); free(output_file);
            return 1;
        }
    }

    /* Get netmask for BPF optimization (fallback to unknown if lookup fails) */
    bpf_u_int32 net = 0, mask = 0;
    if (pcap_lookupnet(interface, &net, &mask, error_buffer) == -1) {
        fprintf(stderr, "Warning: Couldn't get netmask for %s: %s\n", interface, error_buffer);
        mask = PCAP_NETMASK_UNKNOWN;
    }

    /* Compile/apply filter */
    if (filter_exp != NULL) {
        struct bpf_program filter;
        if (pcap_compile(handle, &filter, filter_exp, 1 /* optimize */, mask) == -1) {
            fprintf(stderr, "Error compiling BPF filter '%s': %s\n", filter_exp, pcap_geterr(handle));
            if (dumper) pcap_dump_close(dumper);
            pcap_close(handle);
            free(interface); free(filter_exp); free(output_file);
            return 1;
        }
        if (pcap_setfilter(handle, &filter) == -1) {
            fprintf(stderr, "Error setting BPF filter: %s\n", pcap_geterr(handle));
            pcap_freecode(&filter);
            if (dumper) pcap_dump_close(dumper);
            pcap_close(handle);
            free(interface); free(filter_exp); free(output_file);
            return 1;
        }
        pcap_freecode(&filter);
        printf("BPF filter applied: %s\n", filter_exp);
    }

    /* Capture */
    int status = pcap_loop(handle, 0, packet_handler, (u_char *)dumper);
    if (status == -1) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
    }

    /* Cleanup */
    if (dumper) pcap_dump_close(dumper);
    pcap_close(handle);
    free(interface);
    free(filter_exp);
    free(output_file);
    return 0;
}

void packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
) {
    /* Log to .pcap if dumper was provided */
    pcap_dumper_t *dumper = (pcap_dumper_t *)args;
    if (dumper) {
        pcap_dump((u_char *)dumper, packet_header, packet_body);
    }

    /* Also print parsed info */
    print_packet_info(packet_body, packet_header);
}

void print_packet_info(const u_char *packet, const struct pcap_pkthdr *hdr) {
    printf("Packet captured: Length: %u bytes\n", hdr->len);
    printf("Cap Length: %u\n", hdr->caplen);

    /* Ethernet */
    if (hdr->caplen < sizeof(struct ether_header)) { puts(""); return; }
    const struct ether_header *eth_header = (const struct ether_header *)packet;
    printf("Ether Type: 0x%04x\n", ntohs(eth_header->ether_type));

    /* IPv4 */
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        if (hdr->caplen < sizeof(struct ether_header) + sizeof(struct ip)) { puts(""); return; }
        const struct ip *ip_header = (const struct ip *)(packet + sizeof(struct ether_header));
        int ip_header_len = ip_header->ip_hl * 4;
        if (hdr->caplen < sizeof(struct ether_header) + (unsigned)ip_header_len) { puts(""); return; }

        printf("From: %s\n", inet_ntoa(ip_header->ip_src));
        printf("To: %s\n", inet_ntoa(ip_header->ip_dst));
        printf("Protocol: %d\n", ip_header->ip_p); // TCP=6 UDP=17 ICMP=1

        /* ICMP */
        if (ip_header->ip_p == IPPROTO_ICMP) {
            if (hdr->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct icmphdr)) { puts(""); return; }
            const struct icmphdr *icmp_header = (const struct icmphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
            printf("ICMP Type: %d\n", icmp_header->type);
            printf("ICMP Code: %d\n", icmp_header->code);
        }

        /* UDP (+ DNS) */
        if (ip_header->ip_p == IPPROTO_UDP) {
            if (hdr->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr)) { puts(""); return; }
            const struct udphdr *udp_header = (const struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
            uint16_t sport = ntohs(udp_header->source);
            uint16_t dport = ntohs(udp_header->dest);
            printf("UDP Src Port: %d\n", sport);
            printf("UDP Dst Port: %d\n", dport);

            if (sport == 53 || dport == 53) {
                struct dns_header {
                    uint16_t id;
                    uint16_t flags;
                    uint16_t qdcount;
                    uint16_t ancount;
                    uint16_t nscount;
                    uint16_t arcount;
                };
                if (hdr->caplen >= sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr) + sizeof(struct dns_header)) {
                    const struct dns_header *dns =
                        (const struct dns_header *)(packet + sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr));
                    printf("DNS ID: 0x%x, Questions: %d\n", ntohs(dns->id), ntohs(dns->qdcount));
                }
            }
        }

        /* TCP (all flags incl. NS) */
        if (ip_header->ip_p == IPPROTO_TCP) {
            if (hdr->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr)) { puts(""); return; }
            const struct tcphdr *tcp_header = (const struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
            uint16_t src_port = ntohs(tcp_header->source);
            uint16_t dst_port = ntohs(tcp_header->dest);
            printf("TCP Src Port: %d\n", src_port);
            printf("TCP Dst Port: %d\n", dst_port);

            uint16_t flags = ((uint16_t)tcp_header->th_flags) & 0x01FF; // 9 bits
            printf("Flags: ");
            if (flags & TH_NS)  printf("NS ");
            if (flags & TH_CWR) printf("CWR ");
            if (flags & TH_ECE) printf("ECE ");
            if (flags & TH_URG) printf("URG ");
            if (flags & TH_ACK) printf("ACK ");
            if (flags & TH_PSH) printf("PSH ");
            if (flags & TH_RST) printf("RST ");
            if (flags & TH_SYN) printf("SYN ");
            if (flags & TH_FIN) printf("FIN ");
            printf("\n");
        }
    } else {
        printf("Not an IP packet.\n");
    }

    printf("\n");
}
