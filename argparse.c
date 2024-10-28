/* 
Autor: Roman Poliačik
login: xpolia05 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>     
#include <sys/stat.h> 
#include <errno.h>
#include "argparse.h"

void print_usage() {
    fprintf(stderr, "Usage: ./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>] [-h]\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i <interface>       : Specify the network interface to listen on.\n");
    fprintf(stderr, "  -p <pcapfile>        : Specify the PCAP file to process.\n");
    fprintf(stderr, "  -v                   : Enable verbose mode.\n");
    fprintf(stderr, "  -d <domainsfile>     : Specify the file to save domain names.\n");
    fprintf(stderr, "  -t <translationsfile>: Specify the file to save domain-to-IP translations.\n");
    fprintf(stderr, "  -h                   : Display this help message.\n");
}

int parse_arguments(int argc, char *argv[], Arguments *args) {
    int opt;
    int i_flag = 0, p_flag = 0;
    int d_flag = 0, t_flag = 0;
    int v_flag = 0;

    memset(args, 0, sizeof(Arguments));

    while ((opt = getopt(argc, argv, "i:p:vd:t:h")) != -1) {
        switch (opt) {
            case 'h': 
                print_usage();
                return 0;
            case 'i':
                if (p_flag) {
                    fprintf(stderr, "Error: Cannot use -i and -p together.\n");
                    print_usage();
                    return -1;
                }
                if (i_flag) {
                    fprintf(stderr, "Error: Option -i can be used only once.\n");
                    print_usage();
                    return -1;
                }
                args->interface = optarg;
                i_flag = 1;
                break;
            case 'p':
                if (i_flag) {
                    fprintf(stderr, "Error: Cannot use -i and -p together.\n");
                    print_usage();
                    return -1;
                }
                if (p_flag) {
                    fprintf(stderr, "Error: Option -p can be used only once.\n");
                    print_usage();
                    return -1;
                }
                args->pcap_file = optarg;
                p_flag = 1;
                break;
            case 'v':
                if (v_flag) {
                    fprintf(stderr, "Error: Option -v can be used only once.\n");
                    print_usage();
                    return -1;
                }
                args->verbose = 1; 
                v_flag = 1;
                break;
            case 'd':
                if (d_flag) {
                    fprintf(stderr, "Error: Option -d can be used only once.\n");
                    print_usage();
                    return -1;
                }
                args->domains_file = optarg;
                d_flag = 1;
                break;
            case 't':
                if (t_flag) {
                    fprintf(stderr, "Error: Option -t can be used only once.\n");
                    print_usage();
                    return -1;
                }
                args->translations_file = optarg;
                t_flag = 1;
                break;
            case '?':
                print_usage();
                return -1;
            default:
                print_usage();
                return -1;
        }
    }

    if (!i_flag && !p_flag) {
        fprintf(stderr, "Error: You must specify either -i <interface> or -p <pcapfile>.\n");
        print_usage();
        return -1;
    }

    return 0;
}

int validate_arguments(Arguments *args) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Interface validation
    if (args->interface) {
        pcap_if_t *alldevs, *d;
        int found = 0;

        // Look into all available devs
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
            return -1;
        }
        // Iterate through the list and search for the interface
        for (d = alldevs; d != NULL; d = d->next) {
            if (strcmp(d->name, args->interface) == 0) {
                found = 1;
                break;
            }
        }

        pcap_freealldevs(alldevs);

        // If not found, error.
        if (!found) {
            fprintf(stderr, "Error: Interface '%s' not found.\n", args->interface);
            return -1;
        }
    }

    // PCAP file validation
    if (args->pcap_file) {
        struct stat buffer;
        if (stat(args->pcap_file, &buffer) != 0) {
            fprintf(stderr, "Error: PCAP file '%s' does not exist.\n", args->pcap_file);
            return -1;
        }
    }

    // Domains file validation
    if (args->domains_file) {
        FILE *file = fopen(args->domains_file, "w");
        if (!file) {
            fprintf(stderr, "Error: Cannot open domains file '%s' for writing: %s\n", args->domains_file, strerror(errno));
            return -1;
        }
        fclose(file);
    }

    // Translations file validation
    if (args->translations_file) {
        FILE *file = fopen(args->translations_file, "w");
        if (!file) {
            fprintf(stderr, "Error: Cannot open translations file '%s' for writing: %s\n", args->translations_file, strerror(errno));
            return -1;
        }
        fclose(file);
    }

    return 0;
}
