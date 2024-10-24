/* dns_utils.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns_utils.h"


typedef struct DomainNode {
    char domain_name[256];          // domain name
    struct DomainNode *next;        // the next node
} DomainNode;


typedef struct TranslationNode {
    char domain_name[256];          // domain name
    char ip_address[256];           // IP address
    struct TranslationNode *next;   // Pointer to the next node
} TranslationNode;

// Linked Lists
static DomainNode *domain_list = NULL;
static TranslationNode *translation_list = NULL;

// File pointers
static FILE *domains_fp = NULL;
static FILE *translations_fp = NULL;


void save_domain_name(const char *domain_name, Arguments *args) {
    // Check if domain_name is NULL or empty or root domain
    if (domain_name == NULL) {
        fprintf(stderr, "Warning: domain_name is NULL, skipping save.\n");
        return;
    }
    // Don't save empty
    if (domain_name[0] == '\0') {
        //printf("Debug: DOMAIN EMPTY");
        fprintf(stderr, "Warning: domain_name is empty, skipping save.\n");
        return;
    }
    //printf("Debug: BEFORE DOMAIN STRCMP");
    //Don't save root . 
    if (strcmp(domain_name, ".") == 0) {
        return;
    }
    //printf("Debug: AFTER DOMAIN STRCMP");
    // Don't save if no file is specified
    if (!args->domains_file) {
        return;
    }

    // Check if the domain is already in the LL
    DomainNode *current = domain_list;
    while (current != NULL) {
        if (strcmp(current->domain_name, domain_name) == 0) {
            return; // domain name exists, don't save
        }
        current = current->next;
    }

    // Add new domain to the Linekd List
    DomainNode *new_node = (DomainNode *)malloc(sizeof(DomainNode));
    if (!new_node) {
        fprintf(stderr, "Malloc error! skipping domain save\n");
        return;
    }
    strncpy(new_node->domain_name, domain_name, sizeof(new_node->domain_name));
    new_node->domain_name[sizeof(new_node->domain_name) - 1] = '\0';
    new_node->next = domain_list; 
    domain_list = new_node; 

    if (!domains_fp) {
        domains_fp = fopen(args->domains_file, "a");
        if (!domains_fp) {
            fprintf(stderr, "Error opening domains file: %s\n", args->domains_file);
            return;
        }
    }
    
    fprintf(domains_fp, "%s\n", domain_name);
    fflush(domains_fp); 
}

void save_translation(const char *domain_name, const char *ip_address, Arguments *args) {
    // Check the translations file argument
    if (!args->translations_file) {
        return;
    }

    // Check if the translation is already in the LL
    TranslationNode *current = translation_list;
    while (current != NULL) {
        if (strcmp(current->domain_name, domain_name) == 0 &&
            strcmp(current->ip_address, ip_address) == 0) {
            return; // translation exists
        }
        current = current->next;
    }

    // Add new translation to the Linked List
    TranslationNode *new_node = (TranslationNode *)malloc(sizeof(TranslationNode));
    if (!new_node) {
        fprintf(stderr, "Memory allocation failed for translation\n");
        return;
    }
    strncpy(new_node->domain_name, domain_name, sizeof(new_node->domain_name));
    new_node->domain_name[sizeof(new_node->domain_name) - 1] = '\0'; 
    strncpy(new_node->ip_address, ip_address, sizeof(new_node->ip_address));
    new_node->ip_address[sizeof(new_node->ip_address) - 1] = '\0'; 
    new_node->next = translation_list; 
    translation_list = new_node;

    
    if (!translations_fp) {
        translations_fp = fopen(args->translations_file, "a");
        if (!translations_fp) {
            fprintf(stderr, "Error opening translations file: %s\n", args->translations_file);
            return;
        }
    }

    fprintf(translations_fp, "%s %s\n", domain_name, ip_address);
    fflush(translations_fp); 
}

// Closes the file and frees the Linked List
void close_domain_file() {
    if (domains_fp) {
        fclose(domains_fp);
        domains_fp = NULL;
    }

    DomainNode *current = domain_list;
    while (current != NULL) {
        DomainNode *temp = current;
        current = current->next;
        free(temp); 
    }
    domain_list = NULL; 
}

// Close the translation file and free the Linked List
void close_translations_file() {
    if (translations_fp) {
        fclose(translations_fp);
        translations_fp = NULL;
    }
    
    TranslationNode *current = translation_list;
    while (current != NULL) {
        TranslationNode *temp = current;
        current = current->next;
        free(temp); 
    }
    translation_list = NULL; 
}
