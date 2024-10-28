/* 
Autor: Roman Poliačik
login: xpolia05 
*/

#ifndef ARGPARSE_H
#define ARGPARSE_H

#include <pcap.h>  

typedef struct {
    char *interface;
    char *pcap_file;
    int verbose;
    char *domains_file;
    char *translations_file;
} Arguments;

void print_usage();

int parse_arguments(int argc, char *argv[], Arguments *args);
int validate_arguments(Arguments *args);

#endif 
