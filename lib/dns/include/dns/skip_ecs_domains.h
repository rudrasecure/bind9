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

#include <stdbool.h>

/*
 * Initialize the skip ECS domains module.
 * This should be called once at server startup.
 */
void
dns_skip_ecs_domains_init(void);

/*
 * Parse the skip ECS domains file and update the internal list.
 * Returns true if the file was successfully parsed, false otherwise.
 */
bool
dns_skip_ecs_domains_parse_file(const char *filename);

/*
 * Check if a domain name should skip ECS.
 * Returns true if the domain matches any entry in the skip list.
 */
bool
dns_skip_ecs_domains_check(const char *domain);

/*
 * Clear all entries from the skip ECS domains list.
 */
void
dns_skip_ecs_domains_clear(void);

/*
 * Clean up the skip ECS domains module.
 * This should be called once at server shutdown.
 */
void
dns_skip_ecs_domains_cleanup(void);
