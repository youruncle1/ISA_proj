/* argparse.h */
#ifndef ARGPARSE_H
#define ARGPARSE_H

#include <pcap.h>  // Pro velikost errbuf v deklaracích

/* Struktura pro uložení argumentů */
typedef struct {
    char *interface;
    char *pcap_file;
    int verbose;
    char *domains_file;
    char *translations_file;
} Arguments;

/* Funkce pro výpis nápovědy */
void print_usage();

/* Funkce pro parsování argumentů */
int parse_arguments(int argc, char *argv[], Arguments *args);

/* Funkce pro validaci argumentů */
int validate_arguments(Arguments *args);

#endif /* ARGPARSE_H */
