/* pcapinit.c */
#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "pcapinit.h"
#include <arpa/nameser.h>
#include <stdlib.h>
#include <resolv.h>
#include <errno.h>
#include "dns_utils.h"

#define SIZE_ETHERNET 14       // Ethernet header size
#define SIZE_LINUX_SLL 16      // Linux cooked header size
#define SIZE_NULL_LOOPBACK 4   // Null/Loopback header size


int linktype = 0;

const char *rr_class_to_string(uint16_t rr_class) {
    switch (rr_class) {
        case ns_c_in:
            return "IN";
        case ns_c_chaos:
            return "CH";
        case ns_c_hs:
            return "HS";
        case ns_c_none:
            return "NONE";
        case ns_c_any:
            return "ANY";
        default:
            return NULL; 
    }
}

const char *rr_type_to_string(uint16_t rr_type) {
    switch (rr_type) {
        case ns_t_a:
            return "A";
        case ns_t_aaaa:
            return "AAAA";
        case ns_t_ns:
            return "NS";
        case ns_t_mx:
            return "MX";
        case ns_t_soa:
            return "SOA";
        case ns_t_cname:
            return "CNAME";
        case ns_t_srv:
            return "SRV";
        case ns_t_ptr:
            return "PTR";
        case ns_t_any: 
            return "ANY";
        default:
            return NULL;
    }
}


pcap_t *initialize_pcap(Arguments *args) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;

    if (args->interface) {
        // BUFSIZ 512bit, from book by matouska, 3.4
        handle = pcap_open_live(args->interface, BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            fprintf(stderr, "Error opening device %s: %s\n", args->interface, errbuf);
            return NULL;
        }
    } 
    else if (args->pcap_file) {
        // Open the PCAP file
        handle = pcap_open_offline(args->pcap_file, errbuf);
        if (!handle) {
            fprintf(stderr, "Error opening file %s: %s\n", args->pcap_file, errbuf);
            return NULL;
        }
    }

    // Get the datalink type (LinkType
    linktype = pcap_datalink(handle);

    return handle;
}

void packet_handler(u_char *args_ptr, const struct pcap_pkthdr *header, const u_char *packet) {
    Arguments *args = (Arguments *)args_ptr;
    const u_char *ip_packet;
    int ip_header_length;
    uint8_t ip_version;
    const struct ip *ip_hdr = NULL;
    const struct ip6_hdr *ip6_hdr = NULL;
    const struct udphdr *udp_hdr = NULL;
    const u_char *dns_payload;
    int dns_payload_length;
    int link_header_length = 0;

    // Set ip_packet based on linktype
    switch (linktype) {
        case DLT_EN10MB: { // Ethernet
            link_header_length = SIZE_ETHERNET;
            ip_packet = packet + link_header_length;
            break;
        }
        case DLT_LINUX_SLL: { // Linux cooked capture
            link_header_length = SIZE_LINUX_SLL;
            ip_packet = packet + link_header_length;
            break;
        }
        case DLT_NULL: // BSD loopback encapsulation
        case DLT_LOOP: { // OpenBSD loopback encapsulation
            link_header_length = SIZE_NULL_LOOPBACK;
            ip_packet = packet + link_header_length;
            break;
        }
        case DLT_RAW: { // Raw IP packet
            ip_packet = packet;
            break;
        }
        default: {
            // Unsupported link type
            fprintf(stderr, "Unsupported link type: %d\n", linktype);
            return;
        }
    }

    // Check if there is enough data for an IP header
    if (header->caplen < (bpf_u_int32)(link_header_length + 20)) { // 20 bytes for minimum IP header size
        fprintf(stderr, "Packet too short for IP header.\n");
        return;
    }

    // Get IP version
    ip_version = ip_packet[0] >> 4;
    if (ip_version == 4) {
        ip_hdr = (struct ip *)ip_packet;
        ip_header_length = ip_hdr->ip_hl * 4;

        // Ensure there is enough data for the full IPv4 header
        if (header->caplen < (bpf_u_int32)(link_header_length + ip_header_length)) {
            fprintf(stderr, "Packet too short for IPv4 header.\n");
            return;
        }

        // Check for UDP (should always be UDP, just in case...)
        if (ip_hdr->ip_p != IPPROTO_UDP) {
            return; 
        }

        udp_hdr = (struct udphdr *)(ip_packet + ip_header_length);

        // Ceheck if there is enough data for UDP header
        if (header->caplen < link_header_length + ip_header_length + sizeof(struct udphdr)) {
            fprintf(stderr, "Packet too short for UDP header.\n");
            return;
        }

        // Calculate DNS payload
        dns_payload = ip_packet + ip_header_length + sizeof(struct udphdr);
        dns_payload_length = ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr);

        // Check if there is enough data for DNS payload
        if (header->caplen < link_header_length + ip_header_length + sizeof(struct udphdr) + dns_payload_length) {
            fprintf(stderr, "Packet too short for DNS payload.\n");
            return;
        }

    } else if (ip_version == 6) {
        ip6_hdr = (struct ip6_hdr *)ip_packet;
        ip_header_length = 40; // IPv6 header is fixed at 40 bytes

        // Ensure there is enough data for the full IPv6 header
        if (header->caplen < (bpf_u_int32)(link_header_length + ip_header_length)) {
            fprintf(stderr, "Packet too short for IPv6 header.\n");
            return;
        }

        // Check if the next header is UDP
        if (ip6_hdr->ip6_nxt != IPPROTO_UDP) {
            return; // Not UDP
        }

        udp_hdr = (struct udphdr *)(ip_packet + ip_header_length);

        // Ensure there is enough data for UDP header
        if (header->caplen < link_header_length + ip_header_length + sizeof(struct udphdr)) {
            fprintf(stderr, "Packet too short for UDP header.\n");
            return;
        }

        // Calculate DNS payload
        dns_payload = ip_packet + ip_header_length + sizeof(struct udphdr);
        dns_payload_length = ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr);

        // Ensure there is enough data for DNS payload
        if (header->caplen < link_header_length + ip_header_length + sizeof(struct udphdr) + dns_payload_length) {
            fprintf(stderr, "Packet too short for DNS payload.\n");
            return;
        }

    } else {
        // Unknown IP version
        fprintf(stderr, "Unknown IP version: %d\n", ip_version);
        return;
    }

    // Process the DNS payload
    parse_dns_packet(dns_payload, dns_payload_length, args, ip_hdr, ip6_hdr, udp_hdr, header);
}


void parse_dns_packet(const u_char *dns_payload, int dns_payload_length, Arguments *args,
                      const struct ip *ip_hdr, const struct ip6_hdr *ip6_hdr,
                      const struct udphdr *udp_hdr, const struct pcap_pkthdr *header) {
    // Check if DNS payload length is valid
    if (dns_payload_length <= 0) {
        fprintf(stderr, "Invalid DNS payload length\n");
        return;
    }

    // Initialize parsing handle
    ns_msg handle;
    if (ns_initparse(dns_payload, dns_payload_length, &handle) < 0) {
        fprintf(stderr, "Error initializing DNS parsing: %s\n", strerror(errno));
        return;
    }

    // Extract DNS header information
    uint16_t id = ns_msg_id(handle);

    // Extract flags
    int qr = ns_msg_getflag(handle, ns_f_qr);
    int opcode = ns_msg_getflag(handle, ns_f_opcode);
    int aa = ns_msg_getflag(handle, ns_f_aa);
    int tc = ns_msg_getflag(handle, ns_f_tc);
    int rd = ns_msg_getflag(handle, ns_f_rd);
    int ra = ns_msg_getflag(handle, ns_f_ra);
    int ad = ns_msg_getflag(handle, ns_f_ad);
    int cd = ns_msg_getflag(handle, ns_f_cd);
    int rcode = ns_msg_getflag(handle, ns_f_rcode);

    // Get counts from the DNS header
    int qdcount = ns_msg_count(handle, ns_s_qd);
    int ancount = ns_msg_count(handle, ns_s_an);
    int nscount = ns_msg_count(handle, ns_s_ns);
    int arcount = ns_msg_count(handle, ns_s_ar);

    // Timestamp extraction and converting it
    char timestamp_str[20];
    struct tm ltime;
    //localtime_r(&header->ts.tv_sec, &ltime);
    gmtime_r(&header->ts.tv_sec, &ltime);
    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", &ltime);


    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    // Convert the IPvX to string and store to src/dst
    if (ip_hdr) {
        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
    } 
    else if (ip6_hdr) {
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
    } 
    else {
        // Should not happen but just in case
        fprintf(stderr, "Neither IPv4 or IPv6 header is available\n");
        return;
    }

    // Final Output (Header info)
    if (args->verbose) {
        printf("Timestamp: %s\n", timestamp_str);
        printf("SrcIP: %s\n", src_ip);
        printf("DstIP: %s\n", dst_ip);
        printf("SrcPort: UDP/%d\n", ntohs(udp_hdr->uh_sport));
        printf("DstPort: UDP/%d\n", ntohs(udp_hdr->uh_dport));
        printf("Identifier: 0x%X\n", id);
        printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n", qr, opcode, aa, tc, rd, ra, ad, cd, rcode);
        printf("\n"); 
    } 
    else {
        char qr_char = (qr == 0) ? 'Q' : 'R'; 
        printf("%s %s -> %s (%c %d/%d/%d/%d)\n", timestamp_str, src_ip, dst_ip, qr_char, qdcount, ancount, nscount, arcount);
    }

    // Parse Question Section
    if (qdcount > 0) {
        if (args->verbose) {
            printf("[Question Section]\n");
        }

        for (int i = 0; i < qdcount; i++) {
            ns_rr rr;
            if (ns_parserr(&handle, ns_s_qd, i, &rr) < 0) {
                fprintf(stderr, "Error parsing question section\n");
                return;
            }
            // TODO: maybe change to dn_expand???
            const char *domain_name = ns_rr_name(rr); // first occurence of domain name, should be uncompresssed anyways
            uint16_t qtype = ns_rr_type(rr);
            uint16_t qclass = ns_rr_class(rr);

            // Map QTYPE to string
            char type_str_buffer[16];
            const char *type_str = rr_type_to_string(qtype);
            if (type_str == NULL) {
                snprintf(type_str_buffer, sizeof(type_str_buffer), "TYPE%d", qtype);
                type_str = type_str_buffer;
            }

            // Map QCLASS to string
            char class_str_buffer[16];
            const char *class_str = rr_class_to_string(qclass);
            if (class_str == NULL) {
                snprintf(class_str_buffer, sizeof(class_str_buffer), "CLASS%d", qclass);
                class_str = class_str_buffer;
            }


            save_domain_name(domain_name, args);

            if (args->verbose) {
                printf("%s %s %s\n", domain_name, class_str, type_str);
            }
        }

        //if (args->verbose) {
        //    printf("\n"); 
        //}
    }

    // Parse Answer, Auth, Additional sections
    parse_resource_records(&handle, ns_s_an, ancount, "Answer Section", args);
    parse_resource_records(&handle, ns_s_ns, nscount, "Authority Section", args);
    parse_resource_records(&handle, ns_s_ar, arcount, "Additional Section", args);

    if (args->verbose) {
        printf("====================\n");
    }
}

int dns_extract_name(const u_char *dns_payload, int dns_payload_length,
                     const u_char *ptr, char *output, int output_size) {
    const u_char *msg = dns_payload;                
    const u_char *eom = dns_payload + dns_payload_length; 

    int len = dn_expand(msg, eom, ptr, output, output_size);
    if (len < 0) {
        fprintf(stderr, "Error expanding domain name using dn_expand\n");
        return -1;
    }

    return len;
}

void parse_resource_records(ns_msg *handle, ns_sect section, int count,
                            const char *section_name, Arguments *args) {
    // Empty RR, skip
    if (count <= 0) {
        return;
    }

    ns_rr rr; // Resource record structure.
    int records_printed = 0; // Printed rr counter
    char type_str_buffer[16]; // Buffer for type string, for printing unsupported types
    char class_str_buffer[16]; // Buffer for class string, for printing unsupported types

    for (int i = 0; i < count; i++) {

        if (ns_parserr(handle, section, i, &rr) < 0) {
            fprintf(stderr, "Error parsing resource record\n");
            return;
        }

        // Extract fields from the resource record.
        const char *domain_name = ns_rr_name(rr);   
        uint16_t rr_type = ns_rr_type(rr);          
        uint16_t rr_class = ns_rr_class(rr);        
        uint32_t rr_ttl = ns_rr_ttl(rr);            
        uint16_t rr_rdlength = ns_rr_rdlen(rr);     
        const u_char *rdata = ns_rr_rdata(rr);     

        //char rdata_str[1024];
        const char *rr_type_str = NULL; 
        const char *class_str = NULL;  
        int print_record = 0; // Flag for verbose mode

        // Map RR type to string
        rr_type_str = rr_type_to_string(rr_type);
        if (rr_type_str == NULL) {
            snprintf(type_str_buffer, sizeof(type_str_buffer), "TYPE%d", rr_type);
            rr_type_str = type_str_buffer;
        }

        // Map RR class to string
        class_str = rr_class_to_string(rr_class);
        if (class_str == NULL) {
            snprintf(class_str_buffer, sizeof(class_str_buffer), "CLASS%d", rr_class);
            class_str = class_str_buffer;
        }

        // Allocate rdata conversion buffer
        // * 4 so it can hold worst-case conversion, each byte can be string representation of 4, + 1 for null terminator
        size_t rdata_str_size = rr_rdlength * 4 + 1; 
        char *rdata_str = malloc(rdata_str_size);
        if (!rdata_str) {
            fprintf(stderr, "Memory allocation failed for RDATA string\n");
            continue;
        }
        rdata_str[0] = '\0';

        // RR Type parsing
        switch (rr_type) {
            case ns_t_a: { // A
                if (rr_rdlength != 4) {
                    // A records should have an RDATA length of 4 bytes, RFC 1035
                    continue;
                }
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, rdata, ip_str, sizeof(ip_str));
                snprintf(rdata_str, rdata_str_size, "%s", ip_str);

                save_translation(domain_name, ip_str, args);

                print_record = 1;
                break;
            }
            case ns_t_aaaa: { // AAAA
                if (rr_rdlength != 16) {
                    // AAAA records should have an RDATA length of 16 bytes, RFC 3596
                    continue;
                }
                char ip6_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, rdata, ip6_str, sizeof(ip6_str));
                snprintf(rdata_str, rdata_str_size, "%s", ip6_str);

                save_translation(domain_name, ip6_str, args);

                print_record = 1;
                break;
            }
            case ns_t_ns: { // NS
                char ns_name[256]; // 256; RFC 1035 3.3
                int len = dn_expand(ns_msg_base(*handle), ns_msg_end(*handle), rdata, ns_name, sizeof(ns_name));
                if (len < 0) {
                    fprintf(stderr, "Error expanding NS RDATA\n");
                    continue;
                }
                snprintf(rdata_str, rdata_str_size, "%s", ns_name);
                
                save_domain_name(ns_name, args);

                print_record = 1;
                break;
            }
            case ns_t_cname: { // CNAME
                char cname[256];
                int len = dn_expand(ns_msg_base(*handle), ns_msg_end(*handle), rdata, cname, sizeof(cname));
                if (len < 0) {
                    fprintf(stderr, "Error expanding CNAME RDATA\n");
                    continue;
                }
                snprintf(rdata_str, rdata_str_size, "%s", cname);

                save_domain_name(cname, args);
                
                print_record = 1;
                break;
            }
            case ns_t_mx: { // MX
                if (rr_rdlength < 3) { // Preference (2 bytes) + at least 1 byte for exchange domain name.
                    fprintf(stderr, "Invalid MX RDATA length\n");
                    continue;
                }

                // First two bytes = preference
                uint16_t preference = ns_get16(rdata);
                char exchange[256];
                // The rest is the exchange domain name.
                int len = dn_expand(ns_msg_base(*handle), ns_msg_end(*handle), rdata + 2, exchange, sizeof(exchange));
                if (len < 0) {
                    fprintf(stderr, "Error expanding MX RDATA\n");
                    continue;
                }
                snprintf(rdata_str, rdata_str_size, "%u %s", preference, exchange);
                
                save_domain_name(exchange, args);
                
                print_record = 1;
                break;
            }
            case ns_t_soa: { // SOA
                const u_char *soa_ptr = rdata;
                char mname[256], rname[256];
                
                // Expanding primary name server domain name
                int len = dn_expand(ns_msg_base(*handle), ns_msg_end(*handle), soa_ptr, mname, sizeof(mname));
                if (len < 0) {
                    fprintf(stderr, "Error expanding SOA MNAME\n");
                    continue;
                }
                soa_ptr += len;

                // Expanding responsible authority mailbox domain name
                len = dn_expand(ns_msg_base(*handle), ns_msg_end(*handle), soa_ptr, rname, sizeof(rname));
                if (len < 0) {
                    fprintf(stderr, "Error expanding SOA RNAME\n");
                    continue;
                }
                soa_ptr += len;

                // Cehck ifthere is enough space left for the rest of the SOA
                if ((soa_ptr + 20) > (rdata + rr_rdlength)) {
                    // 5 * 4byte fields = 20
                    fprintf(stderr, "Not enough data for SOA record\n");
                    continue;
                }

                // Extract the 5 fields (32bit)
                uint32_t serial = ns_get32(soa_ptr); soa_ptr += 4;
                uint32_t refresh = ns_get32(soa_ptr); soa_ptr += 4;
                uint32_t retry = ns_get32(soa_ptr); soa_ptr += 4;
                uint32_t expire = ns_get32(soa_ptr); soa_ptr += 4;
                uint32_t minimum = ns_get32(soa_ptr);

                snprintf(rdata_str, rdata_str_size, "%s %s %u %u %u %u %u", 
                         mname, rname, serial, refresh, retry, expire, minimum);
                
                save_domain_name(mname, args);
                // save_domain_name(rname, args);
                
                print_record = 1;
                break;
            }
            case ns_t_srv: { // SRV
                if (rr_rdlength < 7) { // Priority (2 bytes), Weight (2 bytes), Port (2 bytes), Target (>=1 byte).
                    fprintf(stderr, "Invalid SRV RDATA length\n");
                    continue;
                }
                
                uint16_t priority = ns_get16(rdata);
                uint16_t weight = ns_get16(rdata + 2);
                uint16_t port = ns_get16(rdata + 4);
                char target[256];
                
                // Expand the target domain name
                int len = dn_expand(ns_msg_base(*handle), ns_msg_end(*handle), rdata + 6, target, sizeof(target));
                if (len < 0) {
                    fprintf(stderr, "Error expanding SRV RDATA\n");
                    continue;
                }

                snprintf(rdata_str, rdata_str_size, "%u %u %u %s", priority, weight, port, target);
                
                save_domain_name(target, args);
                
                print_record = 1;
                break;
            }
            default: {
                // Unsupported RR types, don't parse
                strcpy(rdata_str, "[Data not parsed]");
                print_record = 1;
                break;
            }
        }

        // Domain name from Name field
        save_domain_name(domain_name, args);

        // Verbose output
        if (args->verbose && print_record) {
            // Print section header on first iteration
            if (records_printed == 0) {
                printf("\n[%s]\n", section_name); 
            }
            printf("%s %u %s %s %s\n", domain_name, rr_ttl, class_str, rr_type_str, rdata_str);
            records_printed++; // bogo binted 
        }
        free(rdata_str);
    }
}
