#ifndef PCAPINIT_H
#define PCAPINIT_H

#include <pcap.h>
#include <netinet/ip.h>     
#include <netinet/ip6.h>   
#include <netinet/udp.h>    
#include <arpa/nameser.h>
#include <resolv.h>
#include "argparse.h"

// For storing the link layer type
extern int linktype;

int is_supported_type(uint16_t type);

const char *rr_class_to_string(uint16_t rr_class);

const char *rr_type_to_string(uint16_t rr_type);

pcap_t *initialize_pcap(Arguments *args);

void packet_handler(u_char *args_ptr, const struct pcap_pkthdr *header, const u_char *packet);

void parse_dns_packet(const u_char *dns_payload, int dns_payload_length, Arguments *args,
                      const struct ip *ip_hdr, const struct ip6_hdr *ip6_hdr,
                      const struct udphdr *udp_hdr, const struct pcap_pkthdr *header);

int dns_extract_name(const u_char *dns_payload, int dns_payload_length, const u_char *ptr, char *output, int output_size);

void parse_resource_records(ns_msg *handle, ns_sect section, int count, const char *section_name, Arguments *args);

#endif /* PCAPINIT_H */
