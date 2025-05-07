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

#pragma once

/*! \file */

#include <stdint.h>
#include <stdbool.h>
#include <isc/types.h>

#undef EXTERN
#undef INIT
#ifdef DNS_OVPN_IP_MAP_MAIN
#define EXTERN
#define INIT(v) = (v)
#else /* ifdef DNS_OVPN_IP_MAP_MAIN */
#define EXTERN extern
#define INIT(v)
#endif /* ifdef DNS_OVPN_IP_MAP_MAIN */

/*
 * Maximum number of entries in the OVPN IP to public IP mapping table
 */
#define DNS_OVPN_IP_MAP_SIZE 4096

/*
 * Structure to hold an OVPN IP to public IP mapping entry
 */
typedef struct dns_ovpn_ip_map_entry {
    uint32_t ovpn_ip;         /* OVPN IP address in network byte order */
    uint32_t public_ip;       /* Public IP address in network byte order */
    bool is_valid;            /* Whether this entry is valid */
} dns_ovpn_ip_map_entry_t;

/*
 * Global hash map that can be accessed by resolver.c
 */
EXTERN dns_ovpn_ip_map_entry_t dns_ovpn_ip_map[DNS_OVPN_IP_MAP_SIZE];

/*
 * Function to parse the OVPN IP to public IP mapping file and update the hash map
 */
isc_result_t dns_ovpn_ip_map_parse_file(const char *filename);

/*
 * Function to lookup a public IP address for a given OVPN IP address
 * Returns true if found, false otherwise
 */
bool dns_ovpn_ip_map_lookup(uint32_t ovpn_ip, uint32_t *public_ip);

/*
 * Function to parse an IP address from a string in format "IP#PORT"
 * Returns true if successful, false otherwise
 * The parsed IP address is returned in network byte order
 */
bool dns_ovpn_ip_map_parse_ip_from_string(const char *ip_port_str, uint32_t *ip_addr);

/*
 * Get the public IP address for a client string in the format "IP#PORT".
 * Returns the public IP in network byte order if found, or 0 if not found.
 */
uint32_t dns_ovpn_ip_map_get_public_ip(const char *client_str);

/*
 * Function to initialize the hash map
 */
void dns_ovpn_ip_map_init(void);

/*
 * Function to clear the hash map
 */
void dns_ovpn_ip_map_clear(void);

#undef EXTERN
#undef INIT
