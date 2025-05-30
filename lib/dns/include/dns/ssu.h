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

/*! \file dns/ssu.h */

#include <stdbool.h>

#include <dns/acl.h>
#include <dns/types.h>

#include <dst/dst.h>

typedef enum {
	dns_ssumatchtype_name = 0,
	dns_ssumatchtype_subdomain = 1,
	dns_ssumatchtype_wildcard = 2,
	dns_ssumatchtype_self = 3,
	dns_ssumatchtype_selfsub = 4,
	dns_ssumatchtype_selfwild = 5,
	dns_ssumatchtype_selfkrb5 = 6,
	dns_ssumatchtype_selfms = 7,
	dns_ssumatchtype_subdomainms = 8,
	dns_ssumatchtype_subdomainkrb5 = 9,
	dns_ssumatchtype_tcpself = 10,
	dns_ssumatchtype_6to4self = 11,
	dns_ssumatchtype_external = 12,
	dns_ssumatchtype_local = 13,
	dns_ssumatchtype_selfsubms = 14,
	dns_ssumatchtype_selfsubkrb5 = 15,
	dns_ssumatchtype_subdomainselfkrb5rhs = 16,
	dns_ssumatchtype_subdomainselfmsrhs = 17,
	dns_ssumatchtype_max = 17, /* max value */

	dns_ssumatchtype_dlz = 18 /* intentionally higher than _max */
} dns_ssumatchtype_t;

typedef struct dns_ssuruletype {
	dns_rdatatype_t type; /* type allowed */
	unsigned int	max;  /* maximum number of records allowed. */
} dns_ssuruletype_t;

void
dns_ssutable_create(isc_mem_t *mctx, dns_ssutable_t **table);
/*%<
 *	Creates a table that will be used to store simple-secure-update rules.
 *	Note: all locking must be provided by the client.
 *
 *	Requires:
 *\li		'mctx' is a valid memory context
 *\li		'table' is not NULL, and '*table' is NULL
 */

void
dns_ssutable_createdlz(isc_mem_t *mctx, dns_ssutable_t **tablep,
		       dns_dlzdb_t *dlzdatabase);
/*%<
 * Create an SSU table that contains a dlzdatabase pointer, and a
 * single rule with matchtype dns_ssumatchtype_dlz. This type of SSU
 * table is used by writeable DLZ drivers to offload authorization for
 * updates to the driver.
 */

void
dns_ssutable_attach(dns_ssutable_t *source, dns_ssutable_t **targetp);
/*%<
 *	Attach '*targetp' to 'source'.
 *
 *	Requires:
 *\li		'source' is a valid SSU table
 *\li		'targetp' points to a NULL dns_ssutable_t *.
 *
 *	Ensures:
 *\li		*targetp is attached to source.
 */

void
dns_ssutable_detach(dns_ssutable_t **tablep);
/*%<
 *	Detach '*tablep' from its simple-secure-update rule table.
 *
 *	Requires:
 *\li		'tablep' points to a valid dns_ssutable_t
 *
 *	Ensures:
 *\li		*tablep is NULL
 *\li		If '*tablep' is the last reference to the SSU table, all
 *			resources used by the table will be freed.
 */

void
dns_ssutable_addrule(dns_ssutable_t *table, bool grant,
		     const dns_name_t *identity, dns_ssumatchtype_t matchtype,
		     const dns_name_t *name, unsigned int ntypes,
		     dns_ssuruletype_t *types, const char *debug);
/*%<
 *	Adds a new rule to a simple-secure-update rule table.  The rule
 *	either grants or denies update privileges of an identity (or set of
 *	identities) to modify a name (or set of names) or certain types present
 *	at that name.
 *
 *	Notes:
 *\li		If 'matchtype' is of SELF type, this rule only matches if the
 *              name to be updated matches the signing identity.
 *
 *\li		If 'ntypes' is 0, this rule applies to all types except
 *		NS, SOA, RRSIG, and NSEC.
 *
 *\li		If 'types' includes ANY, this rule applies to all types
 *		except NSEC.
 *
 *	Requires:
 *\li		'table' is a valid SSU table
 *\li		'identity' is a valid absolute name
 *\li		'matchtype' must be one of the defined constants.
 *\li		'name' is a valid absolute name
 *\li		If 'ntypes' > 0, 'types' must not be NULL
 *\li		'debug' must not be NULL
 */

bool
dns_ssutable_checkrules(dns_ssutable_t *table, const dns_name_t *signer,
			const dns_name_t *name, const isc_netaddr_t *addr,
			bool tcp, dns_aclenv_t *env, dns_rdatatype_t type,
			const dns_name_t *target, const dst_key_t *key,
			const dns_ssurule_t **rulep);
/*%<
 *	Checks that the attempted update of (name, type) is allowed according
 *	to the rules specified in the simple-secure-update rule table.  If
 *	no rules are matched, access is denied.
 *
 *	Notes:
 *		In dns_ssutable_checkrules(), 'addr' should only be
 *		set if the request received via TCP.  This provides a
 *		weak assurance that the request was not spoofed.
 *		'addr' is to to validate dns_ssumatchtype_tcpself
 *		and dns_ssumatchtype_6to4self rules.
 *
 *		In dns_ssutable_checkrules2(), 'addr' can also be passed for
 *		UDP requests and TCP is specified via the 'tcp' parameter.
 *		In addition to dns_ssumatchtype_tcpself and
 *		tcp_ssumatchtype_6to4self  rules, the address
 *		also be used to check dns_ssumatchtype_local rules.
 *		If 'addr' is set then 'env' must also be set so that
 *		requests from non-localhost addresses can be rejected.
 *
 *		For dns_ssumatchtype_tcpself the addresses are mapped to
 *		the standard reverse names under IN-ADDR.ARPA and IP6.ARPA.
 *		RFC 1035, Section 3.5, "IN-ADDR.ARPA domain" and RFC 3596,
 *		Section 2.5, "IP6.ARPA Domain".
 *
 *		For dns_ssumatchtype_6to4self, IPv4 address are converted
 *		to a 6to4 prefix (48 bits) per the rules in RFC 3056.  Only
 *		the top	48 bits of the IPv6 address are mapped to the reverse
 *		name. This is independent of whether the most significant 16
 *		bits match 2002::/16, assigned for 6to4 prefixes, or not.
 *
 *	Requires:
 *\li		'table' is a valid SSU table
 *\li		'signer' is NULL or a valid absolute name
 *\li		'addr' is NULL or a valid network address.
 *\li		'aclenv' is NULL or a valid ACL environment.
 *\li		'name' is a valid absolute name
 *\li		if 'addr' is not NULL, 'env' is not NULL.
 */

/*% Accessor functions to extract rule components */
bool
dns_ssurule_isgrant(const dns_ssurule_t *rule);

/*% Accessor functions to extract rule components */
dns_name_t *
dns_ssurule_identity(const dns_ssurule_t *rule);

/*% Accessor functions to extract rule components */
unsigned int
dns_ssurule_matchtype(const dns_ssurule_t *rule);

/*% Accessor functions to extract rule components */
dns_name_t *
dns_ssurule_name(const dns_ssurule_t *rule);

/*% Accessor functions to extract rule components */
unsigned int
dns_ssurule_types(const dns_ssurule_t *rule, dns_ssuruletype_t **types);

unsigned int
dns_ssurule_max(const dns_ssurule_t *rule, dns_rdatatype_t type);
/*%<
 * Returns the maximum number of records configured for type `type`.
 * If no maximum has been configured for `type` but one has been
 * configured for ANY, return that value instead. Otherwise, return
 * zero, which implies "unlimited".
 */

isc_result_t
dns_ssutable_firstrule(const dns_ssutable_t *table, dns_ssurule_t **rule);
/*%<
 * Initiates a rule iterator.  There is no need to maintain any state.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMORE
 */

isc_result_t
dns_ssutable_nextrule(dns_ssurule_t *rule, dns_ssurule_t **nextrule);
/*%<
 * Returns the next rule in the table.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMORE
 */

bool
dns_ssu_external_match(const dns_name_t *identity, const dns_name_t *signer,
		       const dns_name_t *name, const isc_netaddr_t *tcpaddr,
		       dns_rdatatype_t type, const dst_key_t *key,
		       isc_mem_t *mctx);
/*%<
 * Check a policy rule via an external application
 */

isc_result_t
dns_ssu_mtypefromstring(const char *str, dns_ssumatchtype_t *mtype);
/*%<
 * Set 'mtype' from 'str'
 *
 * Requires:
 *\li		'str' is not NULL.
 *\li		'mtype' is not NULL,
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOTFOUND
 */
