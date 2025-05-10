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
#include <dns/ovpn_ip_map.h>

/* The global hash map is already defined by the header due to DNS_OVPN_IP_MAP_MAIN being defined */

/* Initialize the hash map with zeros and set up the rwlock */
void
dns_ovpn_ip_map_init(void) {
    memset(dns_ovpn_ip_map, 0, sizeof(dns_ovpn_ip_map));
    
    /* Initialize the read-write lock */
    isc_rwlock_init(&dns_ovpn_ip_map_rwlock);
}

/*
 * Hash function for IP addresses
 * Using FNV-1a hash algorithm which is simple and effective for IP addresses
 */
static uint32_t
hash_ip(uint32_t ip) {
    // FNV-1a hash parameters
    const uint32_t FNV_PRIME = 16777619;
    const uint32_t FNV_OFFSET_BASIS = 2166136261;
    
    uint32_t hash = FNV_OFFSET_BASIS;
    unsigned char *bytes = (unsigned char *)&ip;
    
    for (int i = 0; i < 4; i++) {
        hash ^= bytes[i];
        hash *= FNV_PRIME;
    }
    
    return hash % DNS_OVPN_IP_MAP_SIZE;
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
    uint32_t index = hash_ip(ovpn_ip);
    uint32_t original_index = index;
    
    // Find an empty slot or an existing entry with the same OVPN IP
    while (dns_ovpn_ip_map[index].is_valid) {
        // If entry with same OVPN IP already exists, update it
        if (dns_ovpn_ip_map[index].ovpn_ip == ovpn_ip) {
            dns_ovpn_ip_map[index].public_ip = public_ip;
            return ISC_R_SUCCESS;
        }
        
        // Linear probing: try the next slot
        index = (index + 1) % DNS_OVPN_IP_MAP_SIZE;
        
        // If we've gone through the entire table, it's full
        if (index == original_index) {
            return ISC_R_NOSPACE;
        }
    }
    
    // Insert the new entry
    dns_ovpn_ip_map[index].ovpn_ip = ovpn_ip;
    dns_ovpn_ip_map[index].public_ip = public_ip;
    dns_ovpn_ip_map[index].is_valid = true;
    
    return ISC_R_SUCCESS;
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
        printf("Failed to open OVPN IP mapping file: %s - %s\n", filename, strerror(errno));
        return ISC_R_FILENOTFOUND;
    }
    
    printf("Parsing OVPN IP mapping file: %s\n", filename);
    
    /* Acquire write lock before modifying the hash map */
    WRLOCK(&dns_ovpn_ip_map_rwlock);
    
    /* Clear the existing hash map */
    memset(dns_ovpn_ip_map, 0, sizeof(dns_ovpn_ip_map));
    
    while (fgets(line, sizeof(line), file) != NULL) {
        /* Skip empty lines and comments */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }
        
        /* Parse line in format: ovpn_ip,public_ip */
        if (sscanf(line, "%15[^,],%15s", ovpn_ip_str, public_ip_str) != 2) {
            printf("Invalid line format: %s", line);
            continue;
        }
        
        /* Convert IP strings to network byte order integers */
        result = parse_ip_address(ovpn_ip_str, &ovpn_ip);
        if (result != ISC_R_SUCCESS) {
            printf("Invalid OVPN IP address: %s\n", ovpn_ip_str);
            continue;
        }
        
        result = parse_ip_address(public_ip_str, &public_ip);
        if (result != ISC_R_SUCCESS) {
            printf("Invalid public IP address: %s\n", public_ip_str);
            continue;
        }
        
        /* Insert into hash map */
        result = insert_entry(ovpn_ip, public_ip);
        if (result != ISC_R_SUCCESS) {
            printf("Failed to insert entry: %s -> %s\n", ovpn_ip_str, public_ip_str);
            if (result == ISC_R_NOSPACE) {
                printf("Hash map is full\n");
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
    printf("Successfully processed %d OVPN IP mapping entries\n", entries_processed);
    
    return ISC_R_SUCCESS;
}

/*
 * Lookup a public IP address for a given OVPN IP address
 */
bool
dns_ovpn_ip_map_lookup(uint32_t ovpn_ip, uint32_t *public_ip) {
    uint32_t index = hash_ip(ovpn_ip);
    uint32_t original_index = index;
    bool found = false;
    
    /* Acquire read lock before accessing the hash map */
    RDLOCK(&dns_ovpn_ip_map_rwlock);
    
    // Search for the entry using linear probing
    while (dns_ovpn_ip_map[index].is_valid) {
        if (dns_ovpn_ip_map[index].ovpn_ip == ovpn_ip) {
            *public_ip = dns_ovpn_ip_map[index].public_ip;
            found = true;
            break;
        }
        
        index = (index + 1) % DNS_OVPN_IP_MAP_SIZE;
        
        // If we've gone through the entire table, entry not found
        if (index == original_index) {
            break;
        }
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
            printf("OVPN IP %s mapped to public IP %s\n", client_ip_str, public_ip_str);
            return public_ip;
        } else {
            printf("No mapping found for OVPN IP %s\n", client_ip_str);
        }
    } else {
        printf("Failed to parse client IP from string: %s\n", client_str);
    }
    
    return 0;
}

/*
 * Clear the hash map
 */
void
dns_ovpn_ip_map_clear(void) {
    /* Acquire write lock before modifying the hash map */
    WRLOCK(&dns_ovpn_ip_map_rwlock);
    
    memset(dns_ovpn_ip_map, 0, sizeof(dns_ovpn_ip_map));
    
    /* Release the write lock */
    WRUNLOCK(&dns_ovpn_ip_map_rwlock);
}
