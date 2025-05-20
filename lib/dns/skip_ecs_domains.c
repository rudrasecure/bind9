/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/log.h>
#include <isc/mem.h>
#include <isc/rwlock.h>
#include <isc/util.h>

#include <dns/skip_ecs_domains.h>

/*
 * Simple linked list to store domain patterns
 */
typedef struct dns_skip_ecs_domain {
    char *pattern;
    struct dns_skip_ecs_domain *next;
} dns_skip_ecs_domain_t;

/* Global variables */
static isc_mem_t *dns_skip_ecs_domains_mctx = NULL;
static dns_skip_ecs_domain_t *dns_skip_ecs_domains_list = NULL;
static isc_rwlock_t dns_skip_ecs_domains_rwlock;

void
dns_skip_ecs_domains_init(void) {
    isc_mem_create(&dns_skip_ecs_domains_mctx);
    isc_rwlock_init(&dns_skip_ecs_domains_rwlock);
    dns_skip_ecs_domains_list = NULL;
}

/*
 * Add a domain pattern to the skip list
 */
static bool
dns_skip_ecs_domains_add(const char *pattern) {
    dns_skip_ecs_domain_t *domain;
    
    if (pattern == NULL || pattern[0] == '\0' || pattern[0] == '#') {
        return false;
    }
    
    domain = isc_mem_get(dns_skip_ecs_domains_mctx, sizeof(dns_skip_ecs_domain_t));
    if (domain == NULL) {
        return false;
    }
    
    domain->pattern = isc_mem_strdup(dns_skip_ecs_domains_mctx, pattern);
    if (domain->pattern == NULL) {
        isc_mem_put(dns_skip_ecs_domains_mctx, domain, sizeof(dns_skip_ecs_domain_t));
        return false;
    }
    
    // Add to the beginning of the list
    domain->next = dns_skip_ecs_domains_list;
    dns_skip_ecs_domains_list = domain;
    
    return true;
}

bool
dns_skip_ecs_domains_parse_file(const char *filename) {
    FILE *file;
    char line[256];
    bool success = true;
    
    if (filename == NULL) {
        return false;
    }
    
    file = fopen(filename, "r");
    if (file == NULL) {
        isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, 
                     ISC_LOG_WARNING, "Could not open skip ECS domains file: %s", 
                     filename);
        return false;
    }
    
    WRLOCK(&dns_skip_ecs_domains_rwlock);
    
    // Clear existing list
    dns_skip_ecs_domains_clear();
    
    // Read and parse the file
    while (fgets(line, sizeof(line), file) != NULL) {
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[len - 1] = '\0';
        }
        if (len > 1 && (line[len - 2] == '\r')) {
            line[len - 2] = '\0';
        }
        
        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        
        // Add to the list
        if (!dns_skip_ecs_domains_add(line)) {
            isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, 
                         ISC_LOG_WARNING, "Failed to add domain pattern: %s", 
                         line);
            success = false;
        } else {
            isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, 
                         ISC_LOG_INFO, "Added skip ECS domain pattern: %s", 
                         line);
        }
    }
    
    WRUNLOCK(&dns_skip_ecs_domains_rwlock);
    
    fclose(file);
    return success;
}

bool
dns_skip_ecs_domains_check(const char *domain) {
    dns_skip_ecs_domain_t *current;
    bool match = false;
    
    if (domain == NULL) {
        return false;
    }
    
    RDLOCK(&dns_skip_ecs_domains_rwlock);
    
    current = dns_skip_ecs_domains_list;
    while (current != NULL) {
        if (strstr(domain, current->pattern) != NULL) {
            match = true;
            break;
        }
        current = current->next;
    }
    
    RDUNLOCK(&dns_skip_ecs_domains_rwlock);
    
    return match;
}

void
dns_skip_ecs_domains_clear(void) {
    dns_skip_ecs_domain_t *current, *next;
    
    // No need to lock here as this is called from functions that already have the lock
    
    current = dns_skip_ecs_domains_list;
    while (current != NULL) {
        next = current->next;
        isc_mem_free(dns_skip_ecs_domains_mctx, current->pattern);
        isc_mem_put(dns_skip_ecs_domains_mctx, current, sizeof(dns_skip_ecs_domain_t));
        current = next;
    }
    
    dns_skip_ecs_domains_list = NULL;
}

void
dns_skip_ecs_domains_cleanup(void) {
    WRLOCK(&dns_skip_ecs_domains_rwlock);
    
    dns_skip_ecs_domains_clear();
    
    WRUNLOCK(&dns_skip_ecs_domains_rwlock);
    
    isc_rwlock_destroy(&dns_skip_ecs_domains_rwlock);
    
    if (dns_skip_ecs_domains_mctx != NULL) {
        isc_mem_detach(&dns_skip_ecs_domains_mctx);
    }
}
