#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns_utils.h"

/* Structures for linked lists */
typedef struct DomainNode {
    char domain_name[256];
    struct DomainNode *next;
} DomainNode;

typedef struct TranslationNode {
    char domain_name[256];
    char ip_address[256];
    struct TranslationNode *next;
} TranslationNode;

/* Global pointers to the head of the lists */
static DomainNode *domain_list = NULL;
static TranslationNode *translation_list = NULL;

/* File pointers */
static FILE *domains_fp = NULL;
static FILE *translations_fp = NULL;

/* Function to save unique domain names */
void save_domain_name(const char *domain_name, Arguments *args) {
    printf("save_domain_name called with domain_name: %s\n", domain_name);
    if (!args->domains_file) {
        return;
    }

    /* Check if the domain name is already in the list */
    DomainNode *current = domain_list;
    while (current != NULL) {
        if (strcmp(current->domain_name, domain_name) == 0) {
            return; /* Domain name already saved */
        }
        current = current->next;
    }

    /* Add new domain name to the list */
    DomainNode *new_node = (DomainNode *)malloc(sizeof(DomainNode));
    if (!new_node) {
        fprintf(stderr, "Memory allocation failed for domain name\n");
        return;
    }
    strncpy(new_node->domain_name, domain_name, sizeof(new_node->domain_name));
    new_node->domain_name[sizeof(new_node->domain_name) - 1] = '\0';
    new_node->next = domain_list;
    domain_list = new_node;

    /* Open the file for appending if it's not already open */
    if (!domains_fp) {
        domains_fp = fopen(args->domains_file, "a");
        if (!domains_fp) {
            fprintf(stderr, "Error opening domains file\n");
            return;
        }
    }

    /* Write the domain name to the file */
    fprintf(domains_fp, "%s\n", domain_name);
    fflush(domains_fp);
}

/* Function to save unique domain name to IP translations */
void save_translation(const char *domain_name, const char *ip_address, Arguments *args) {
    printf("save_translation called with domain_name: %s, ip_address: %s\n", domain_name, ip_address);
    if (!args->translations_file) {
        return;
    }

    /* Check if the translation is already in the list */
    TranslationNode *current = translation_list;
    while (current != NULL) {
        if (strcmp(current->domain_name, domain_name) == 0 &&
            strcmp(current->ip_address, ip_address) == 0) {
            return; /* Translation already saved */
        }
        current = current->next;
    }

    /* Add new translation to the list */
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

    /* Open the file for appending if it's not already open */
    if (!translations_fp) {
        translations_fp = fopen(args->translations_file, "a");
        if (!translations_fp) {
            fprintf(stderr, "Error opening translations file\n");
            return;
        }
    }

    /* Write the translation to the file */
    fprintf(translations_fp, "%s %s\n", domain_name, ip_address);
    fflush(translations_fp);
}

/* Function to close the domains file and free memory */
void close_domain_file() {
    if (domains_fp) {
        fclose(domains_fp);
        domains_fp = NULL;
    }

    /* Free the linked list */
    DomainNode *current = domain_list;
    while (current != NULL) {
        DomainNode *temp = current;
        current = current->next;
        free(temp);
    }
    domain_list = NULL;
}

/* Function to close the translations file and free memory */
void close_translations_file() {
    if (translations_fp) {
        fclose(translations_fp);
        translations_fp = NULL;
    }

    /* Free the linked list */
    TranslationNode *current = translation_list;
    while (current != NULL) {
        TranslationNode *temp = current;
        current = current->next;
        free(temp);
    }
    translation_list = NULL;
}
