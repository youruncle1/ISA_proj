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
#include "dns_utils.h"


#define SIZE_ETHERNET 14

int linktype = 0;

pcap_t *initialize_pcap(Arguments *args) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;

    if (args->interface) {
        /* Otevření síťového rozhraní pro zachytávání 
        BUFSIZ 512bit, podla knihy od matouska 3.4 */
        handle = pcap_open_live(args->interface, BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            fprintf(stderr, "Error: Could not open device %s: %s\n", args->interface, errbuf);
            return NULL;
        }
    } else if (args->pcap_file) {
        /* Načtení PCAP souboru */
        handle = pcap_open_offline(args->pcap_file, errbuf);
        if (!handle) {
            fprintf(stderr, "Error: Could not open file %s: %s\n", args->pcap_file, errbuf);
            return NULL;
        }
    } else {
        /* Toto by nemělo nastat, protože argumenty jsou kontrolovány dříve */
        fprintf(stderr, "Error: No interface or PCAP file specified.\n");
        return NULL;
    }

    /* Zjištění linkového typu */
    linktype = pcap_datalink(handle);

    return handle;
}

void packet_handler(u_char *args_ptr, const struct pcap_pkthdr *header, const u_char *packet) {
    Arguments *args = (Arguments *)args_ptr;
    const u_char *ip_packet;
    int ip_header_length;
    uint8_t ip_version;
    const struct ip *ip_hdr;
    const struct ip6_hdr *ip6_hdr;
    const struct udphdr *udp_hdr;
    const u_char *dns_payload;
    int dns_payload_length;

    /* Posun na začátek IP hlavičky podle linkového typu */
    if (linktype == DLT_EN10MB) {
        /* Ethernetová hlavička je přítomna */
        ip_packet = packet + SIZE_ETHERNET;
    } else if (linktype == DLT_RAW) {
        /* Ethernetová hlavička není přítomna */
        ip_packet = packet;
    } else {
        fprintf(stderr, "Unsupported link type: %d\n", linktype);
        return;
    }

    /* Zjištění verze IP protokolu */
    ip_version = (ip_packet[0] & 0xF0) >> 4;

    if (ip_version == 4) {
        /* Zpracování IPv4 hlavičky */
        ip_hdr = (struct ip *)ip_packet;
        ip_header_length = ip_hdr->ip_hl * 4;

        /* Kontrola, zda je protokol UDP */
        if (ip_hdr->ip_p != IPPROTO_UDP) {
            fprintf(stderr, "Non-UDP packet, skipping...\n");
            return;
        }

        /* Zpracování UDP hlavičky */
        udp_hdr = (struct udphdr *)(ip_packet + ip_header_length);

        /* Získání DNS payloadu */
        dns_payload = (u_char *)(ip_packet + ip_header_length + sizeof(struct udphdr));
        dns_payload_length = ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr);

        /* Volání funkce pro parsování DNS zprávy */
        parse_dns_packet(dns_payload, dns_payload_length, args, ip_hdr, NULL, udp_hdr, header);
    } else if (ip_version == 6) {
        /* Zpracování IPv6 hlavičky */
        ip6_hdr = (struct ip6_hdr *)ip_packet;
        ip_header_length = sizeof(struct ip6_hdr);

        /* Zpracování rozšíření hlaviček IPv6 může být složité, pro jednoduchost předpokládáme, že následuje přímo UDP */
        if (ip6_hdr->ip6_nxt != IPPROTO_UDP) {
            fprintf(stderr, "Non-UDP packet, skipping...\n");
            return;
        }

        /* Zpracování UDP hlavičky */
        udp_hdr = (struct udphdr *)(ip_packet + ip_header_length);

        /* Získání DNS payloadu */
        dns_payload = (u_char *)(ip_packet + ip_header_length + sizeof(struct udphdr));
        dns_payload_length = ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr);

        /* Volání funkce pro parsování DNS zprávy */
        parse_dns_packet(dns_payload, dns_payload_length, args, NULL, ip6_hdr, udp_hdr, header);
    } else {
        fprintf(stderr, "Unknown IP version: %d\n", ip_version);
        return;
    }
}

void parse_dns_packet(const u_char *dns_payload, int dns_payload_length, Arguments *args,
                      const struct ip *ip_hdr, const struct ip6_hdr *ip6_hdr,
                      const struct udphdr *udp_hdr, const struct pcap_pkthdr *header) {
    /* Kontrola délky DNS payloadu */
    if (dns_payload_length <= 0) {
        fprintf(stderr, "Invalid DNS payload length\n");
        return;
    }

    /* Parsování DNS hlavičky */
    /* DNS hlavička má pevnou délku 12 bajtů */
    if (dns_payload_length < 12) {
        fprintf(stderr, "DNS payload too short for header\n");
        return;
    }

    /* Struktura DNS hlavičky */
    struct dns_header {
        uint16_t id;
        uint16_t flags;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
    };

    const struct dns_header *dns_hdr = (const struct dns_header *)dns_payload;

    /* Převod hodnot z síťového na hostitelský pořádek bajtů */
    uint16_t id = ntohs(dns_hdr->id);
    uint16_t flags = ntohs(dns_hdr->flags);
    uint16_t qdcount = ntohs(dns_hdr->qdcount);
    uint16_t ancount = ntohs(dns_hdr->ancount);
    uint16_t nscount = ntohs(dns_hdr->nscount);
    uint16_t arcount = ntohs(dns_hdr->arcount);

    /* Převod timestampu na požadovaný formát */
    char timestamp_str[20];
    struct tm *ltime;
    time_t local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestamp_str, sizeof timestamp_str, "%Y-%m-%d %H:%M:%S", ltime);


    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    if (ip_hdr) {
        /* IPv4 */
        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
    } else if (ip6_hdr) {
        /* IPv6 */
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
    } else {
        fprintf(stderr, "Neither IPv4 nor IPv6 header is available\n");
        return;
    }

    /* Kontrola, zda je povolen verbose režim */


    /* Extrakce příznaků */
    int qr = (flags & 0x8000) >> 15;
    int opcode = (flags & 0x7800) >> 11;
    int aa = (flags & 0x0400) >> 10;
    int tc = (flags & 0x0200) >> 9;
    int rd = (flags & 0x0100) >> 8;
    int ra = (flags & 0x0080) >> 7;
    //int z = (flags & 0x0040) >> 6; /* Rezervovaný bit */
    int ad = (flags & 0x0020) >> 5;
    int cd = (flags & 0x0010) >> 4;
    int rcode = flags & 0x000F;

    // printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
    //     qr, opcode, aa, tc, rd, ra, ad, cd, rcode);
    
        if (args->verbose) {
        /* Verbose output */
        printf("Timestamp: %s\n", timestamp_str);
        printf("SrcIP: %s\n", src_ip);
        printf("DstIP: %s\n", dst_ip);
        printf("SrcPort: UDP/%d\n", ntohs(udp_hdr->uh_sport));
        printf("DstPort: UDP/%d\n", ntohs(udp_hdr->uh_dport));
        printf("Identifier: 0x%X\n", id);
        printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
               qr, opcode, aa, tc, rd, ra, ad, cd, rcode);

        /* Empty line */
        printf("\n");

        /* Pointer to current position in DNS message */
        const u_char *ptr = dns_payload + 12; /* DNS header is 12 bytes */
        int remaining_length = dns_payload_length - 12;

        /* Parse Question Section */
        if (qdcount > 0) {
            printf("[Question Section]\n");
        }
        for (int i = 0; i < qdcount; i++) {
            char domain_name[256];
            int name_length = dns_extract_name(dns_payload, dns_payload_length, ptr, domain_name, sizeof(domain_name));
            if (name_length == -1) {
                fprintf(stderr, "Error parsing domain name in Question Section\n");
                return;
            }
            ptr += name_length;
            remaining_length -= name_length;

            if (remaining_length < 4) {
                fprintf(stderr, "Not enough data for Question Section\n");
                return;
            }

            uint16_t qtype = ntohs(*(uint16_t *)ptr);
            ptr += 2;
            //uint16_t qclass = ntohs(*(uint16_t *)ptr);
            ptr += 2;
            remaining_length -= 4;

            /* Map qtype to string */
            const char *type_str;
            char type_str_buffer[16];
            switch (qtype) {
                case 1:
                    type_str = "A";
                    break;
                case 28:
                    type_str = "AAAA";
                    break;
                case 2:
                    type_str = "NS";
                    break;
                case 5:
                    type_str = "CNAME";
                    break;
                case 6:
                    type_str = "SOA";
                    break;
                case 15:
                    type_str = "MX";
                    break;
                case 33:
                    type_str = "SRV";
                    break;
                default:
                    snprintf(type_str_buffer, sizeof(type_str_buffer), "TYPE%d", qtype);
                    type_str = type_str_buffer;
                    break;
            }

            /* Output question */
            printf("%s IN %s\n", domain_name, type_str);

            /* Save domain name */
            printf("Calling save_domain_name with domain_name: %s\n", domain_name);
            save_domain_name(domain_name, args);
        }

        /* Parse Resource Records */
        parse_resource_records(&ptr, &remaining_length, ancount, dns_payload, dns_payload_length, "Answer Section", args);
        parse_resource_records(&ptr, &remaining_length, nscount, dns_payload, dns_payload_length, "Authority Section", args);
        parse_resource_records(&ptr, &remaining_length, arcount, dns_payload, dns_payload_length, "Additional Section", args);

        /* Separator */
        printf("====================\n");
    } else {
        /* Simplified output */
        char qr_char = (qr == 0) ? 'Q' : 'R';
        printf("%s %s -> %s (%c %d/%d/%d/%d)\n",
               timestamp_str, src_ip, dst_ip, qr_char, qdcount, ancount, nscount, arcount);
    }
}



int dns_extract_name(const u_char *dns_payload, int dns_payload_length, const u_char *ptr, char *output, int output_size) {
    int total_length = 0;
    int label_length;
    int offset;
    int jumped = 0;
    //const u_char *original_ptr = ptr;
    const u_char *end = dns_payload + dns_payload_length;
    int output_pos = 0;

    while (ptr < end && (label_length = *ptr) != 0) {
        if ((label_length & 0xC0) == 0xC0) {
            /* Komprimovaný název */
            if (ptr + 1 >= end) {
                return -1;
            }
            if (!jumped) {
                total_length += 2;
            }
            offset = ((label_length & 0x3F) << 8) | *(ptr + 1);
            if (offset >= dns_payload_length) {
                return -1;
            }
            ptr = dns_payload + offset;
            jumped = 1;
        } else {
            /* Nekomprimovaný název */
            ptr++;
            if (ptr + label_length > end) {
                return -1;
            }
            if (output_pos + label_length + 1 >= output_size) {
                return -1;
            }
            memcpy(output + output_pos, ptr, label_length);
            output_pos += label_length;
            output[output_pos++] = '.';
            ptr += label_length;
            if (!jumped) {
                total_length += label_length + 1;
            }
        }
    }
    if (!jumped) {
        total_length += 1; /* Pro závěrečný nulový bajt */
    }
    if (output_pos > 0) {
        output[output_pos - 1] = '\0'; /* Nahradíme poslední tečku nulovým znakem */
    } else {
        output[0] = '\0';
    }
    if (!jumped) {
        ptr++; /* Posuneme se za závěrečný nulový bajt */
    }
    return total_length;
}

void parse_resource_records(const u_char **ptr, int *remaining_length, int count,
                            const u_char *dns_payload, int dns_payload_length,
                            const char *section_name, Arguments *args) {
    int section_printed = 0;

    for (int i = 0; i < count; i++) {
        /* Parse Resource Record */
        char domain_name[256];
        int name_length = dns_extract_name(dns_payload, dns_payload_length, *ptr, domain_name, sizeof(domain_name));
        if (name_length == -1) {
            fprintf(stderr, "Error parsing domain name in %s\n", section_name);
            return;
        }
        *ptr += name_length;
        *remaining_length -= name_length;

        if (*remaining_length < 10) {
            fprintf(stderr, "Not enough data for Resource Record\n");
            return;
        }

        uint16_t rr_type = ntohs(*(uint16_t *)(*ptr));
        *ptr += 2;
        //uint16_t rr_class = ntohs(*(uint16_t *)(*ptr));
        *ptr += 2;
        uint32_t rr_ttl = ntohl(*(uint32_t *)(*ptr));
        *ptr += 4;
        uint16_t rr_rdlength = ntohs(*(uint16_t *)(*ptr));
        *ptr += 2;

        *remaining_length -= 10;
        if (*remaining_length < rr_rdlength) {
            fprintf(stderr, "Not enough data for RDATA\n");
            return;
        }

        const u_char *rdata = *ptr;
        *ptr += rr_rdlength;
        *remaining_length -= rr_rdlength;

        /* Prepare strings for output */
        const char *rr_type_str = NULL;
        //char rr_type_buffer[16];
        char rdata_str[1024]; /* Increased size for SOA records */

        /* Determine rr_type_str and parse rdata */
        int print_record = 0;

        switch (rr_type) {
            case 1: { /* A */
                rr_type_str = "A";
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, rdata, ip_str, INET_ADDRSTRLEN);
                strcpy(rdata_str, ip_str);
                /* Save translation */
                save_translation(domain_name, ip_str, args);
                print_record = 1;
                break;
            }
            case 28: { /* AAAA */
                rr_type_str = "AAAA";
                char ip6_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, rdata, ip6_str, INET6_ADDRSTRLEN);
                strcpy(rdata_str, ip6_str);
                /* Save translation */
                save_translation(domain_name, ip6_str, args);
                print_record = 1;
                break;
            }
            case 2: { /* NS */
                rr_type_str = "NS";
                char ns_name[256];
                int ns_name_length = dns_extract_name(dns_payload, dns_payload_length, rdata, ns_name, sizeof(ns_name));
                if (ns_name_length == -1) {
                    fprintf(stderr, "Error parsing NS RDATA\n");
                    return;
                }
                strcpy(rdata_str, ns_name);
                print_record = 1;
                break;
            }
            case 5: { /* CNAME */
                rr_type_str = "CNAME";
                char cname[256];
                int cname_length = dns_extract_name(dns_payload, dns_payload_length, rdata, cname, sizeof(cname));
                if (cname_length == -1) {
                    fprintf(stderr, "Error parsing CNAME RDATA\n");
                    return;
                }
                strcpy(rdata_str, cname);
                print_record = 1;
                break;
            }
            case 15: { /* MX */
                rr_type_str = "MX";
                if (rr_rdlength < 2) {
                    fprintf(stderr, "Invalid MX RDATA length\n");
                    return;
                }
                uint16_t preference = ntohs(*(uint16_t *)rdata);
                char exchange[256];
                int exchange_length = dns_extract_name(dns_payload, dns_payload_length, rdata + 2, exchange, sizeof(exchange));
                if (exchange_length == -1) {
                    fprintf(stderr, "Error parsing MX RDATA\n");
                    return;
                }
                snprintf(rdata_str, sizeof(rdata_str), "%u %s", preference, exchange);
                print_record = 1;
                break;
            }
            case 6: { /* SOA */
                rr_type_str = "SOA";
                const u_char *soa_ptr = rdata;
                char mname[256], rname[256];
                int mname_length = dns_extract_name(dns_payload, dns_payload_length, soa_ptr, mname, sizeof(mname));
                if (mname_length == -1) {
                    fprintf(stderr, "Error parsing SOA MNAME\n");
                    return;
                }
                soa_ptr += mname_length;

                int rname_length = dns_extract_name(dns_payload, dns_payload_length, soa_ptr, rname, sizeof(rname));
                if (rname_length == -1) {
                    fprintf(stderr, "Error parsing SOA RNAME\n");
                    return;
                }
                soa_ptr += rname_length;

                if (soa_ptr + 20 > rdata + rr_rdlength) {
                    fprintf(stderr, "Not enough data for SOA record\n");
                    return;
                }

                uint32_t serial = ntohl(*(uint32_t *)soa_ptr);
                soa_ptr += 4;
                uint32_t refresh = ntohl(*(uint32_t *)soa_ptr);
                soa_ptr += 4;
                uint32_t retry = ntohl(*(uint32_t *)soa_ptr);
                soa_ptr += 4;
                uint32_t expire = ntohl(*(uint32_t *)soa_ptr);
                soa_ptr += 4;
                uint32_t minimum = ntohl(*(uint32_t *)soa_ptr);

                snprintf(rdata_str, sizeof(rdata_str),
                         "%s %s (\n        %u ; Serial\n        %u ; Refresh\n        %u ; Retry\n        %u ; Expire\n        %u ) ; Minimum",
                         mname, rname, serial, refresh, retry, expire, minimum);
                print_record = 1;
                break;
            }
            case 33: { /* SRV */
                rr_type_str = "SRV";
                if (rr_rdlength < 6) {
                    fprintf(stderr, "Invalid SRV RDATA length\n");
                    return;
                }
                uint16_t priority = ntohs(*(uint16_t *)rdata);
                uint16_t weight = ntohs(*(uint16_t *)(rdata + 2));
                uint16_t port = ntohs(*(uint16_t *)(rdata + 4));
                char target[256];
                int target_length = dns_extract_name(dns_payload, dns_payload_length, rdata + 6, target, sizeof(target));
                if (target_length == -1) {
                    fprintf(stderr, "Error parsing SRV RDATA\n");
                    return;
                }
                snprintf(rdata_str, sizeof(rdata_str), "%u %u %u %s", priority, weight, port, target);
                print_record = 1;
                break;
            }
            default:
                /* Ignore other record types */
                break;
        }

        /* Save domain name */
        printf("Calling save_domain_name with domain_name: %s\n", domain_name);
        save_domain_name(domain_name, args);

        /* Output the resource record */
        if (args->verbose && print_record) {
            /* Print section header if it hasn't been printed yet */
            if (!section_printed) {
                printf("\n[%s]\n", section_name);
                section_printed = 1;  // Ensure it only prints once
            }

            /* Now print the actual record */
            printf("%s %d IN %s %s\n", domain_name, rr_ttl, rr_type_str, rdata_str);
        }
    }
}



