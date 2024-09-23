/* argparse.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>     // Pro práci s rozhraními a pcap soubory
#include <sys/stat.h> // Pro kontrolu existence souboru
#include <errno.h>

#include "argparse.h"

/* Funkce pro výpis nápovědy */
void print_usage() {
    fprintf(stderr, "Usage: ./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]\n");
}

/* Funkce pro parsování argumentů */
int parse_arguments(int argc, char *argv[], Arguments *args) {
    int opt;
    int i_flag = 0, p_flag = 0;

    /* Inicializace struktury */
    memset(args, 0, sizeof(Arguments));

    /* Zpracování argumentů */
    while ((opt = getopt(argc, argv, "i:p:vd:t:")) != -1) {
        switch (opt) {
            case 'i':
                if (p_flag) {
                    fprintf(stderr, "Error: Cannot use -i and -p together.\n");
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
                args->pcap_file = optarg;
                p_flag = 1;
                break;
            case 'v':
                args->verbose = 1;
                break;
            case 'd':
                args->domains_file = optarg;
                break;
            case 't':
                args->translations_file = optarg;
                break;
            default:
                print_usage();
                return -1;
        }
    }

    /* Kontrola povinných argumentů */
    if (!i_flag && !p_flag) {
        fprintf(stderr, "Error: You must specify either -i <interface> or -p <pcapfile>.\n");
        print_usage();
        return -1;
    }

    return 0;
}

/* Funkce pro validaci argumentů */
int validate_arguments(Arguments *args) {
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Ověření rozhraní (-i) */
    if (args->interface) {
        pcap_if_t *alldevs, *d;
        int found = 0;

        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
            return -1;
        }

        for (d = alldevs; d != NULL; d = d->next) {
            if (strcmp(d->name, args->interface) == 0) {
                found = 1;
                break;
            }
        }

        pcap_freealldevs(alldevs);

        if (!found) {
            fprintf(stderr, "Error: Interface '%s' not found.\n", args->interface);
            return -1;
        }
    }

    /* Ověření PCAP souboru (-p) */
    if (args->pcap_file) {
        struct stat buffer;
        if (stat(args->pcap_file, &buffer) != 0) {
            fprintf(stderr, "Error: PCAP file '%s' does not exist.\n", args->pcap_file);
            return -1;
        }
    }

    /* Ověření souboru s doménovými jmény (-d) */
    if (args->domains_file) {
        FILE *file = fopen(args->domains_file, "a");
        if (!file) {
            fprintf(stderr, "Error: Cannot open domains file '%s' for writing: %s\n", args->domains_file, strerror(errno));
            return -1;
        }
        fclose(file);
    }

    /* Ověření souboru s překlady (-t) */
    if (args->translations_file) {
        FILE *file = fopen(args->translations_file, "a");
        if (!file) {
            fprintf(stderr, "Error: Cannot open translations file '%s' for writing: %s\n", args->translations_file, strerror(errno));
            return -1;
        }
        fclose(file);
    }

    return 0;
}
