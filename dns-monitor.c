#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>  
#include <stdint.h>  
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <netinet/ip.h>     
#include <netinet/ip6.h>    
#include <netinet/udp.h>   
#include "argparse.h"
#include "pcapinit.h"
#include "dns_utils.h"

volatile sig_atomic_t stop = 0;
pcap_t *handle = NULL;          // pcap handle

// Signal handler for SIGINT, SIGTERM, SIGQUIT
void signal_handler(int sig) {
    (void)sig;
    stop = 1;

    if (handle) {
        pcap_breakloop(handle); // break the pcap loop
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

    // Parse args
    if (parse_arguments(argc, argv, &args) != 0) {
        return EXIT_FAILURE;
    }

    // Validate args
    if (validate_arguments(&args) != 0) {
        return EXIT_FAILURE;
    }

    // init interface or read pcap file
    handle = initialize_pcap(&args);
    if (!handle) {
        return EXIT_FAILURE;
    }

    // Signal handlers for SIGINT, SIGTERM, SIGQUIT
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    // Set filter(udp port 80)
    if (set_filter(handle) != 0) {
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    // Start processing packets
    pcap_loop(handle, 0, packet_handler, (u_char *)&args);

    // Signal stop
    if (stop) {
        fprintf(stderr, "Signal %d received, exiting...\n", stop);
    }

    // Close the handle
    pcap_close(handle);

    // Close (if needed) files and free linked lists
    close_domain_file();
    close_translations_file();

    return EXIT_SUCCESS;
}
