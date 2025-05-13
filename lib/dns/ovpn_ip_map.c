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

/*! \file */

/* Define DNS_OVPN_IP_MAP_MAIN before including the header to make EXTERN and INIT work */
#define DNS_OVPN_IP_MAP_MAIN 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <isc/result.h>
#include <isc/util.h>
#include <isc/mem.h>
#include <isc/hashmap.h>
#include <isc/log.h>
#include <dns/ovpn_ip_map.h>

/* The global hash map is already defined by the header due to DNS_OVPN_IP_MAP_MAIN being defined */

/* Forward declarations */
static void free_all_entries(void);

/*
 * Match function for IP addresses in the hashmap
 * Compares the OVPN IP in the entry with the key
 */
static bool
ovpn_ip_match(void *node, const void *key) {
    dns_ovpn_ip_map_entry_t *entry = (dns_ovpn_ip_map_entry_t *)node;
    const uint32_t *ip = (const uint32_t *)key;
    
    return (entry->ovpn_ip == *ip);
}

/* Initialize the hash map and set up the rwlock */
void
dns_ovpn_ip_map_init(void) {
    /* Create a memory context for the hash map */
    isc_mem_create(&dns_ovpn_ip_map_mctx);
    
    /* Create the hash map with 12 bits (4096 entries) */
    isc_hashmap_create(dns_ovpn_ip_map_mctx, 12, &dns_ovpn_ip_map);
    
    /* Initialize the read-write lock */
    isc_rwlock_init(&dns_ovpn_ip_map_rwlock);
}



/*
 * Parse an IP address string and convert it to a 32-bit integer in network byte order
 */
static isc_result_t
parse_ip_address(const char *ip_str, uint32_t *ip) {
    struct in_addr addr;
    
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return ISC_R_FAILURE;
    }
    
    *ip = addr.s_addr;
    return ISC_R_SUCCESS;
}

/*
 * Insert an entry into the hash map
 * Note: This function assumes the caller holds the write lock
 */
static isc_result_t
insert_entry(uint32_t ovpn_ip, uint32_t public_ip) {
    isc_result_t result;
    dns_ovpn_ip_map_entry_t *entry = NULL;
    dns_ovpn_ip_map_entry_t *existing_entry = NULL;
    
    /* Check if an entry with this OVPN IP already exists */
    result = isc_hashmap_find(dns_ovpn_ip_map, ovpn_ip, ovpn_ip_match, 
                             &ovpn_ip, (void **)&existing_entry);
    
    if (result == ISC_R_SUCCESS && existing_entry != NULL) {
        /* Update the existing entry */
        existing_entry->public_ip = public_ip;
        return ISC_R_SUCCESS;
    }
    
    /* Create a new entry */
    entry = isc_mem_get(dns_ovpn_ip_map_mctx, sizeof(dns_ovpn_ip_map_entry_t));
    if (entry == NULL) {
        return ISC_R_NOMEMORY;
    }
    
    /* Initialize the entry */
    entry->ovpn_ip = ovpn_ip;
    entry->public_ip = public_ip;
    
    /* Add the entry to the hash map */
    result = isc_hashmap_add(dns_ovpn_ip_map, ovpn_ip, ovpn_ip_match, 
                            &entry->ovpn_ip, entry, NULL);
    
    if (result != ISC_R_SUCCESS) {
        isc_mem_put(dns_ovpn_ip_map_mctx, entry, sizeof(dns_ovpn_ip_map_entry_t));
    }
    
    return result;
}

/*
 * Parse the OVPN IP to public IP mapping file and update the hash map
 */
isc_result_t
dns_ovpn_ip_map_parse_file(const char *filename) {
    FILE *file;
    char line[256];
    char ovpn_ip_str[16], public_ip_str[16];
    uint32_t ovpn_ip, public_ip;
    int entries_processed = 0;
    isc_result_t result;
    
    file = fopen(filename, "r");
    if (file == NULL) {
        isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_ERROR,
					"failed to parse OVPN IP mapping file at startup: '%s' - %s",
				    filename, strerror(errno)
				);
        return ISC_R_FILENOTFOUND;
    }
    
    isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_INFO,
					"parsing OVPN IP mapping file: '%s'",
				    filename
				);
    
    /* Acquire write lock before modifying the hash map */
    WRLOCK(&dns_ovpn_ip_map_rwlock);
    
    /* Make sure we have a memory context */
    if (dns_ovpn_ip_map_mctx == NULL) {
        isc_mem_create(&dns_ovpn_ip_map_mctx);
    }
    
    /* Check if the hashmap has been initialized */
    if (dns_ovpn_ip_map != NULL) {
        /* Free all entries and destroy the hash map */
        free_all_entries();
        isc_hashmap_destroy(&dns_ovpn_ip_map);
    }
    
    /* Create a new empty hash map */
    isc_hashmap_create(dns_ovpn_ip_map_mctx, 12, &dns_ovpn_ip_map);
    
    while (fgets(line, sizeof(line), file) != NULL) {
        /* Skip empty lines and comments */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }
        
        /* Parse line in format: ovpn_ip,public_ip */
        if (sscanf(line, "%15[^,],%15s", ovpn_ip_str, public_ip_str) != 2) {
            isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_ERROR,
						"invalid line format: '%s'",
						line
					);
            continue;
        }
        
        /* Convert IP strings to network byte order integers */
        result = parse_ip_address(ovpn_ip_str, &ovpn_ip);
        if (result != ISC_R_SUCCESS) {
            isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_ERROR,
						"invalid OVPN IP address: '%s'",
						ovpn_ip_str
					);
            continue;
        }
        
        result = parse_ip_address(public_ip_str, &public_ip);
        if (result != ISC_R_SUCCESS) {
            isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_ERROR,
						"invalid public IP address: '%s'",
						public_ip_str
					);
            continue;
        }
        
        /* Insert into hash map */
        result = insert_entry(ovpn_ip, public_ip);
        if (result != ISC_R_SUCCESS) {
            isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_ERROR,
						"failed to insert entry: '%s' -> '%s'",
						ovpn_ip_str, public_ip_str
					);
            if (result == ISC_R_NOSPACE) {
                isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_ERROR,
						"hash map is full");
                WRUNLOCK(&dns_ovpn_ip_map_rwlock);
                fclose(file);
                return result;
            }
            continue;
        }
        
        entries_processed++;
    }
    
    /* Release the write lock */
    WRUNLOCK(&dns_ovpn_ip_map_rwlock);
    
    fclose(file);
    
    isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_INFO,
				"successfully processed %d OVPN IP mapping entries", entries_processed);
    
    return ISC_R_SUCCESS;
}

/*
 * Lookup a public IP address for a given OVPN IP address
 */
bool
dns_ovpn_ip_map_lookup(uint32_t ovpn_ip, uint32_t *public_ip) {
    isc_result_t result;
    dns_ovpn_ip_map_entry_t *entry = NULL;
    bool found = false;
    
    /* Acquire read lock before accessing the hash map */
    RDLOCK(&dns_ovpn_ip_map_rwlock);
    
    /* Look up the OVPN IP in the hash map */
    result = isc_hashmap_find(dns_ovpn_ip_map, ovpn_ip, ovpn_ip_match, 
                             &ovpn_ip, (void **)&entry);
    
    if (result == ISC_R_SUCCESS && entry != NULL) {
        *public_ip = entry->public_ip;
        found = true;
    }
    
    /* Release the read lock */
    RDUNLOCK(&dns_ovpn_ip_map_rwlock);
    
    return found;
}

/*
 * Parse an IP address from a string in format "IP#PORT"
 */
bool
dns_ovpn_ip_map_parse_ip_from_string(const char *ip_port_str, uint32_t *ip_addr) {
    char ip_str[INET_ADDRSTRLEN];
    char *port_separator;
    struct in_addr addr;
    
    if (ip_port_str == NULL || ip_addr == NULL) {
        return false;
    }
    
    // Copy the string so we can modify it
    strncpy(ip_str, ip_port_str, sizeof(ip_str) - 1);
    ip_str[sizeof(ip_str) - 1] = '\0';
    
    // Find and remove the port part (after #)
    port_separator = strchr(ip_str, '#');
    if (port_separator != NULL) {
        *port_separator = '\0';
    }
    
    // Convert the IP string to a network byte order integer
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return false;
    }
    
    *ip_addr = addr.s_addr;
    return true;
}

/*
 * Get the public IP address for a client string in the format "IP#PORT".
 * Returns the public IP in network byte order if found, or 0 if not found.
 * 
 * This function is thread-safe as it calls dns_ovpn_ip_map_lookup which handles
 * proper locking of the hash map.
 */
uint32_t
dns_ovpn_ip_map_get_public_ip(const char *client_str) {
    char client_ip_str[INET_ADDRSTRLEN];
    char public_ip_str[INET_ADDRSTRLEN];
    uint32_t client_ip, public_ip = 0;
    
    // Check if we have a valid client string
    if (client_str == NULL || strcmp(client_str, "<unknown>") == 0) {
        return 0;
    }
    
    // Parse the client IP from the string (format: IP#PORT)
    if (dns_ovpn_ip_map_parse_ip_from_string(client_str, &client_ip)) {
        // Convert the IP to string for logging
        inet_ntop(AF_INET, &client_ip, client_ip_str, sizeof(client_ip_str));
        
        // Look up the client IP in the OVPN IP map
        if (dns_ovpn_ip_map_lookup(client_ip, &public_ip)) {
            inet_ntop(AF_INET, &public_ip, public_ip_str, sizeof(public_ip_str));
            isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
                ISC_LOG_DEBUG(3), "mapped OVPN IP %s to public IP %s",
                client_ip_str, public_ip_str);
            return public_ip;
        } else {
            isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
                ISC_LOG_DEBUG(3), "no mapping found for OVPN IP %s",
                client_ip_str);
            return 0;
        }
    } else {
        isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
                ISC_LOG_ERROR, "failed to parse client IP from string: %s",
            client_str);
        return 0;
    }
    
    return 0;
}

/*
 * Free all entries in the hashmap
 */
static void
free_all_entries(void) {
    isc_hashmap_iter_t *iter = NULL;
    isc_result_t result;
    
    /* Check if the hashmap is initialized */
    if (dns_ovpn_ip_map == NULL) {
        return;
    }
    
    isc_hashmap_iter_create(dns_ovpn_ip_map, &iter);
    
    for (result = isc_hashmap_iter_first(iter);
         result == ISC_R_SUCCESS;
         result = isc_hashmap_iter_next(iter))
    {
        void *value = NULL;  // Initialize value to NULL for each iteration
        isc_hashmap_iter_current(iter, &value);
        if (value != NULL) {
            dns_ovpn_ip_map_entry_t *entry = (dns_ovpn_ip_map_entry_t *)value;
            isc_mem_put(dns_ovpn_ip_map_mctx, entry, sizeof(dns_ovpn_ip_map_entry_t));
        }
    }
    
    isc_hashmap_iter_destroy(&iter);
}

/*
 * Clear the hash map
 */
void
dns_ovpn_ip_map_clear(void) {
    /* Acquire write lock before modifying the hash map */
    WRLOCK(&dns_ovpn_ip_map_rwlock);
    
    /* Check if the hashmap has been initialized */
    if (dns_ovpn_ip_map != NULL) {
        /* Free all entries and destroy the hash map */
        free_all_entries();
        isc_hashmap_destroy(&dns_ovpn_ip_map);
        
        /* Create a new empty hash map */
        isc_hashmap_create(dns_ovpn_ip_map_mctx, 12, &dns_ovpn_ip_map);
    } else if (dns_ovpn_ip_map_mctx != NULL) {
        /* Create a new empty hash map if we have a memory context */
        isc_hashmap_create(dns_ovpn_ip_map_mctx, 12, &dns_ovpn_ip_map);
    }
    
    /* Release the write lock */
    WRUNLOCK(&dns_ovpn_ip_map_rwlock);
}

/*
 * Clean up the hash map and free all resources
 */
void
dns_ovpn_ip_map_cleanup(void) {
    /* Acquire write lock before destroying the hash map */
    WRLOCK(&dns_ovpn_ip_map_rwlock);
    
    /* Check if the hashmap has been initialized */
    if (dns_ovpn_ip_map != NULL) {
        /* Free all entries and destroy the hash map */
        free_all_entries();
        isc_hashmap_destroy(&dns_ovpn_ip_map);
        dns_ovpn_ip_map = NULL;
    }
    
    /* Release the write lock */
    WRUNLOCK(&dns_ovpn_ip_map_rwlock);
    
    /* Destroy the rwlock */
    isc_rwlock_destroy(&dns_ovpn_ip_map_rwlock);
    
    /* Detach from the memory context if it exists */
    if (dns_ovpn_ip_map_mctx != NULL) {
        isc_mem_detach(&dns_ovpn_ip_map_mctx);
    }
}
