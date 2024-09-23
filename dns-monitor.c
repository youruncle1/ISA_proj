/* dns-monitor.c */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/ip.h>     // For struct ip
#include <netinet/ip6.h>    // For struct ip6_hdr
#include <netinet/udp.h>    // For struct udphdr
#include "argparse.h"
#include "pcapinit.h"
#include "dns_utils.h"

volatile sig_atomic_t stop = 0; /* Flag for signal handling */
pcap_t *handle = NULL;          /* Global pcap handle */

/* Signal handler for SIGINT */
void handle_sigint(int sig) {
    (void)sig;
    stop = 1; /* Set the stop flag */

    if (handle) {
        pcap_breakloop(handle); /* Break the pcap loop */
    }
}

int set_filter(pcap_t *handle) {
    struct bpf_program fp;
    char filter_exp[] = "udp port 53";
    bpf_u_int32 net = 0;

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error: Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error: Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }

    pcap_freecode(&fp);
    return 0;
}

int main(int argc, char *argv[]) {
    Arguments args;
    //pcap_t *handle;

    /* Parsování argumentů */
    if (parse_arguments(argc, argv, &args) != 0) {
        /* Chyba při parsování argumentů */
        return EXIT_FAILURE;
    }

    /* Validace argumentů */
    if (validate_arguments(&args) != 0) {
        /* Chyba při validaci argumentů */
        return EXIT_FAILURE;
    }

    /* Debug: Print the domains and translations file paths */
    printf("Domains File: %s\n", args.domains_file ? args.domains_file : "None");
    printf("Translations File: %s\n", args.translations_file ? args.translations_file : "None");

    /* Inicializace rozhraní nebo načtení PCAP souboru */
    handle = initialize_pcap(&args);
    if (!handle) {
        /* Chyba při inicializaci pcap */
        return EXIT_FAILURE;
    }

    /* Set up the signal handler for SIGINT */
    signal(SIGINT, handle_sigint);

    /* Nastavení filtru */
    if (set_filter(handle) != 0) {
        /* Chyba při nastavení filtru */
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    // printf("Interface: %s\n", args.interface ? args.interface : "None");
    // printf("PCAP File: %s\n", args.pcap_file ? args.pcap_file : "None");
    // printf("Verbose Mode: %s\n", args.verbose ? "Enabled" : "Disabled");
    // printf("Domains File: %s\n", args.domains_file ? args.domains_file : "None");
    // printf("Translations File: %s\n", args.translations_file ? args.translations_file : "None");

    /* Zpracování paketů */
    /* Zde implementujeme smyčku pro zpracování paketů */
    pcap_loop(handle, 0, packet_handler, (u_char *)&args);

    /* After pcap_loop exits */
    if (stop) {
        fprintf(stderr, "SIGINT received, exiting...\n");
    }

    /* Nezapomeňte uzavřít pcap handle před ukončením programu */
    pcap_close(handle);

    /* Na konci programu */
    close_domain_file();
    close_translations_file();

    return EXIT_SUCCESS;
}
