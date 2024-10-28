/* 
Autor: Roman Poliačik
login: xpolia05 
*/

#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include "argparse.h"

void save_domain_name(const char *domain_name, Arguments *args);
void save_translation(const char *domain_name, const char *ip_address, Arguments *args);

void close_domain_file();
void close_translations_file();


#endif
