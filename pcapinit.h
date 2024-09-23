/* pcapinit.h */
#ifndef PCAPINIT_H
#define PCAPINIT_H

#include <pcap.h>
#include <netinet/ip.h>     // For struct ip
#include <netinet/ip6.h>    // For struct ip6_hdr
#include <netinet/udp.h>    // For struct udphdr
#include "argparse.h"

extern int linktype;

/* Funkce pro inicializaci pcap handle */
pcap_t *initialize_pcap(Arguments *args);

/* Callback funkce pro zpracování paketů */
void packet_handler(u_char *args_ptr, const struct pcap_pkthdr *header, const u_char *packet);

void parse_dns_packet(const u_char *dns_payload, int dns_payload_length, Arguments *args,
                      const struct ip *ip_hdr, const struct ip6_hdr *ip6_hdr,
                      const struct udphdr *udp_hdr, const struct pcap_pkthdr *header);

int dns_extract_name(const u_char *dns_payload, int dns_payload_length, const u_char *ptr, char *output, int output_size);

void parse_resource_records(const u_char **ptr, int *remaining_length, int count,
                            const u_char *dns_payload, int dns_payload_length,
                            const char *section_name, Arguments *args);




#endif /* PCAPINIT_H */
