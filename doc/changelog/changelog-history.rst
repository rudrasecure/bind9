.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

Changes prior to 9.20.1
-----------------------

.. code-block:: none

		--- 9.20.0 released ---

	6404.	[placeholder]

	6403.	[security]	qctx-zversion was not being cleared when it should have
				been leading to an assertion failure if it needed to be
				reused. (CVE-2024-4076) [GL #4507]

	6402.	[security]	A malicious DNS client that sends many queries with a
				SIG(0)-signed message can cause the server to respond
				slowly or not respond at all to other clients. Use the
				offload threadpool for SIG(0) signature verifications,
				add the 'sig0checks-quota' configuration option to
				introduce a quota for SIG(0)-signed queries running in
				parallel and add the 'sig0checks-quota-exempt' option to
				exempt certain clients by their IP/network addresses.
				(CVE-2024-1975) [GL #4480]

	6401.	[security]	An excessively large number of rrtypes per owner can
				slow down database query processing, so a limit has been
				placed on the number of rrtypes that can be stored per
				owner (node) in a cache or zone database. This is
				configured with the new "max-rrtypes-per-name" option,
				and defaults to 100. (CVE-2024-1737)
				[GL #3403] [GL #4548]

	6400.	[security]	Excessively large rdatasets can slow down database
				query processing, so a limit has been placed on the
				number of records that can be stored per rdataset
				in a cache or zone database. This is configured
				with the new "max-records-per-type" option, and
				defaults to 100. (CVE-2024-1737)
				[GL #497] [GL #3405]

	6399.	[security]	Malicious DNS client that sends many queries over
				TCP but never reads responses can cause server to
				respond slowly or not respond at all for other
				clients. (CVE-2024-0760) [GL #4481]

	6398.	[bug]		Fix potential data races in our DoH implementation
				related to HTTP/2 session object management and
				endpoints set object management after reconfiguration.
				We would like to thank Dzintars and Ivo from nic.lv
				for bringing this to our attention. [GL #4473]

	6397.	[placeholder]

	6396.	[func]		Outgoing zone transfers are no longer enabled by
				default. To enable them, an "allow-transfer" ACL
				must be specified. [GL #4728]

	6395.	[bug]		Handle ISC_R_HOSTDOWN and ISC_R_NETDOWN in resolver.c.
				[GL #4736]

	6394.	[bug]		Named's -4 and -6 options now apply to zone primaries,
				also-notify and parental-agents.  Report when a zone
				has these options configured but does not have an IPv4
				or IPv6 address listed respectively. [GL #3472]

	6393.	[func]		Deal with uv_tcp_close_reset() error return codes
				more gracefully. [GL #4708]

	6392.	[bug]		Use a completely new memory context when flushing the
				cache. [GL #2744]

	6391.	[placeholder]

	6390.	[placeholder]

	6389.	[bug]		dnssec-verify and dnssec-signzone could fail if there
				was an obscured DNSKEY RRset at a delegatation.
				[GL #4517]

	6388.	[placeholder]

	6387.	[func]		Added a new statistics variable "recursive high-water"
				that reports the maximum number of simultaneous
				recursive clients BIND has handled while running.
				[GL #4668]

	6386.	[bug]		When shutting down catzs->view could point to freed
				memory. Obtain a reference to the view to prevent this.
				[GL #4502]

	6385.	[func]		Relax SVCB alias mode checks to allow parameters.
				[GL #4704]

	6384.	[bug]		Remove infinite loop when including a directory in a
				zone file. [GL #4357]

	6383.	[bug]		Address an infinite loop in $GENERATE when a negative
				value was converted in nibble mode. [GL #4353]

	6382.	[bug]		Fix RPZ response's SOA record TTL, which was incorrectly
				set to 1 if 'add-soa' is used. [GL #3323]

.. code-block:: none

		--- 9.19.24 released ---

	6381.	[bug]		dns_qp_lookup() could position the iterator at the
				wrong predecessor when searching for names with
				uncommon characters, which are encoded as two-octet
				sequences in QP trie keys. [GL #4702]

	6380.	[func]		Queries and responses now emit distinct dnstap entries
				for DoT and DoH. [GL #4523]

	6379.	[bug]		A QP iterator bug could result in DNSSEC validation
				failing because the wrong NSEC was returned. [GL #4659]

	6378.	[func]		The option to specify the number of UDP dispatches was
				previously removed. An attempt to use the option now
				prints a warning. [GL #1879]

	6377.	[func]		Introduce 'dnssec-ksr', a DNSSEC tool to create
				Key Signing Requests (KSRs) and Signed Key Responses
				(SKRs). [GL #1128]

	6376.	[func]		Allow 'dnssec-keygen' options '-f' and '-k' to be used
				together to create a subset of keys from the DNSSEC
				policy. [GL !8188]

	6375.	[func]		Allow multiple RNDC message to be processed from
				a single TCP read. [GL #4416]

	6374.	[func]		Don't count expired / future RRSIGs in verification
				failure quota. [GL #4586]

	6373.	[func]		Offload the isc_http response processing to worker
				thread. [GL #4680]

	6372.	[func]		Implement signature jitter for dnssec-policy. [GL #4554]

	6371.	[bug]		Access to the trust bytes in the ncache data needed to
				be made thread safe. [GL #4475]

	6370.	[bug]		Wrong source address used for IPv6 notify messages.
				[GL #4669]

.. code-block:: none

		--- 9.19.23 released ---

	6369.	[func]		The 'fixed' value for the 'rrset-order' option has
				been marked and documented as deprecated. [GL #4446]

	6368.	[func]		The 'sortlist' option has been marked and documented
				as deprecated. [GL #4593]

	6367.	[bug]		Since the dns_validator_destroy() function doesn't
				guarantee that it destroys the validator, rename it to
				dns_validator_shutdown() and require explicit
				dns_validator_detach() to follow. Implement an expected
				behavior of the function to release a name associated
				with the validator. [GL #4654]

	6366.	[bug]		An assertion could be triggered in the QPDB cache when
				encountering a delegation below a DNAME. [GL #4652]

	6365.	[placeholder]

	6364.	[protocol]	Add RESOLVER.ARPA to the built in empty zones.
				[GL #4580]

	6363.	[bug]		dig/mdig +ednsflags=<non-zero-value> did not re-enable
				EDNS if it had been disabled. [GL #4641]

	6362.	[bug]		Reduce memory consumption of QP-trie based databases
				by dynamically allocating the nodenames. [GL #4614]

	6361.	[bug]		Some invalid ISO 8601 durations were accepted
				erroneously. [GL #4624]

	6360.	[bug]		Don't return static-stub synthesised NS RRset.
				[GL #4608]

	6359.	[bug]		Fix bug in Depends (keymgr_dep) function. [GL #4552]

.. code-block:: none

		--- 9.19.22 released ---

	6358.	[bug]		Fix validate_dnskey_dsset when KSK is not signing,
				do not skip remainder of DS RRset. [GL #4625]

	6357.	[func]		The QP zone database implementation introduced in
				change #6355 has now been replaced with a version
				based on the multithreaded dns_qpmulti API, which
				is based on RCU and reduces the need for locking.
				The new implementation is called "qpzone". The
				previous "qp" implementation has been renamed
				"qpcache", and can only be used for the cache.
				[GL #4348]

	6356.	[bug]		Attach the loop also in the dns_cache_flush(), so
				the cache pruning still works after the flush.
				[GL #4621]

	6355.	[func]		The red-black tree data structure underlying the
				RBTDB has been replaced with QP-tries.  This is
				expected to improve scalability and reduce
				CPU consumption under load. It is currently known to
				have higher memory consumption than the traditional
				RBTDB; this will be addressed in future releases.

				Nodes in a QP-trie contain the full domain name,
				while nodes in a red-black tree only contain names
				relative to a parent.  Because of this difference,
				zone files dumped with masterfile-style "relative"
				will no longer have multiple different $ORIGIN
				statements throughout the file.

				This version is a minimal adaptation, keeping RBTDB
				code largely unchanged, except as needed to replace
				the underlying data structure. It uses the
				single-thread "dns_qp" interface with locks for
				synchronization. A future version will use the
				multithreaded "dns_qpmulti" interface instead,
				and will be renamed to QPDB.

				The RBT-based version of RBTDB is still in place
				for now, and can be used by specifying "database rbt"
				in a "zone" statement, or by compiling with
				"configure --with-zonedb=rbt --with-cachedb=rbt".
				[GL #4411]

	6354.	[bug]		Change 6035 introduced a regression when chasing DS
				records resulting in an assertion failure. [GL #4612]

	6353.	[bug]		Improve the TTL-based cleaning by removing the expired
				headers from the heap, so they don't block the next
				cleaning round and clean more than a single item for
				each new addition to the RBTDB. [GL #4591]

	6352.	[bug]		Revert change 6319 and decrease lock contention during
				RBTDB tree pruning by not cleaning up nodes recursively
				within a single prune_tree() call. [GL #4596]

	6351.	[protocol]	Support for the RESINFO record type has been added.
				[GL #4413]

	6350.	[bug]		Address use after free in expire_lru_headers. [GL #4495]

	6349.	[placeholder]

	6348.	[bug]		BIND could previously abort when trying to
				establish a connection to a remote server using an
				incorrect 'tls' configuration. That has been
				fixed. Thanks to Tobias Wolter for bringing
				the issue to our attention. [GL #4572]

	6347.	[func]		Disallow stale-answer-client-timeout non-zero values.
				[GL #4447]

	6346.	[bug]		Cleaned up several minor bugs in the RBTDB dbiterator
				implementation. [GL !8741]

	6345.	[bug]		Added missing dns_rdataset_disassociate calls in
				validator.c:findnsec3proofs. [GL #4571]

	6344.	[bug]		Fix case insensitive setting for isc_ht hashtable.
				[GL #4568]

	6343.	[bug]		Fix case insensitive setting for isc_ht hashtable.
				[GL #4568]

	6342.	[placeholder]

	6341.	[bug]		Address use after free in ccmsg_senddone. [GL #4549]

	6340.	[test]		Fix incorrectly reported errors when running tests
				with `make test` on platforms with older pytest.
				[GL #4560]

	6339.	[bug]		The alignas() can't be used on types larger than
				max_align_t; instead add padding into the structures
				where we want avoid false memory sharing. [GL #4187]

	6338.	[func]		Optimize slabheader placement, so the infrastructure
				records are put in the beginning of the slabheader
				linked list. [GL !8675]

	6337.	[bug]		Nsupdate could assert while shutting down. [GL #4529]

	6336.	[func]		Expose the zones with the 'first refresh' flag set in
				statistics channel's "Incoming Zone Transfers" section
				to indicate the zones that are not yet fully ready, and
				their first refresh is pending or is in-progress. Also
				expose the number of such zones in the output of the
				'rndc status' command. [GL #4241]

	6335.	[func]		The 'dnssec-validation yes' option now requires an
				explicitly configured 'trust-anchors' statement (or
				'managed-keys' or 'trusted-keys' statements, both
				deprecated). [GL #4373]

	6334.	[doc]		Improve ARM parental-agents definition. [GL #4531]

	6333.	[bug]		Fix the DNS_GETDB_STALEFIRST flag, which was defined
				incorrectly in lib/ns/query.c. [GL !8683]

	6332.	[bug]		Range-check the arguments to fetch-quota-param.
				[GL #362]

	6331.	[func]		Add HSM support for dnssec-policy. You can now
				configure keys with a key-store that allows you to
				set the directory to store key files and to set a
				PKCS #11 URI string. [GL #1129]

	6330.	[doc]		Update ZSK minimum lifetime documentation in ARM, also
				depends on signing delay. [GL #4510]

	6329.	[func]		Nsupdate can now set the UL EDNS option when sending
				UPDATE requests. [GL #4419]

	6328.	[func]		Add workaround to enforce dynamic linker to pull
				jemalloc earlier than libc to ensure all memory
				allocations are done via jemalloc. [GL #4404]

	6327.	[func]		Expose the TCP client count in statistics channel.
				[GL #4425]

	6326.	[bug]		Changes to "listen-on" statements were ignored on
				reconfiguration unless the port or interface address was
				changed, making it impossible to change a related
				listener transport type. Thanks to Thomas Amgarten.
				[GL #4518] [GL #4528]

	6325.	[func]		The 'tls' block was extended with a new
				'cipher-suites' option that allows setting
				allowed cipher suites for TLSv1.3.
				[GL #3504]

	6324.	[bug]		Fix a possible crash in 'dig +nssearch +nofail' and
				'host -C' commands when one of the name servers returns
				SERVFAIL. [GL #4508]

.. code-block:: none

		--- 9.19.21 released ---

	6323.	[placeholder]

	6322.	[security]	Specific DNS answers could cause a denial-of-service
				condition due to DNS validation taking a long time.
				(CVE-2023-50387) [GL #4424]

				The same code change also addresses another problem:
				preparing NSEC3 closest encloser proofs could exhaust
				available CPU resources. (CVE-2023-50868) [GL #4459]

	6321.	[security]	Change 6315 inadvertently introduced regressions that
				could cause named to crash. [GL #4234]

	6320.	[placeholder]

.. code-block:: none

		--- 9.19.20 released ---

	6319.	[func]		Limit isc_async_run() overhead for RBTDB tree pruning.
				[GL #4383]

	6318.	[placeholder]

	6317.	[security]	Restore DNS64 state when handling a serve-stale timeout.
				(CVE-2023-5679) [GL #4334]

	6316.	[security]	Specific queries could trigger an assertion check with
				nxdomain-redirect enabled. (CVE-2023-5517) [GL #4281]

	6315.	[security]	Speed up parsing of DNS messages with many different
				names. (CVE-2023-4408) [GL #4234]

	6314.	[bug]		Address race conditions in dns_tsigkey_find().
				[GL #4182]

	6313.	[bug]		When dnssec-policy is in effect the DNSKEY's TTLs in
				the zone where not being updated to match the policy.
				This lead to failures when DNSKEYs where updated as the
				TTLs mismatched. [GL #4466]

	6312.	[bug]		Conversion from NSEC3 signed to NSEC signed could
				temporarily put the zone into a state where it was
				treated as unsigned until the NSEC chain was built.
				Additionally conversion from one set of NSEC3 parameters
				to another could also temporarily put the zone into a
				state where it was treated as unsigned until the new
				NSEC3 chain was built. [GL #1794] [GL #4495]

	6311.	[func]		Zone content checks are now disabled by default
				when running named-compilezone. named-checkzone
				can still be used for checking zone integrity,
				or the former checks in named-compilezone can be
				re-enabled by using "named-compilezone -i full
				-k fail -n fail -r warn -m warn -M warn -S warn
				-T warn -W warn -C check-svcb:fail". [GL #4364]

	6310.	[bug]		Memory leak in zone.c:sign_zone. When named signed a
				zone it could leak dst_keys due to a misplaced
				'continue'. [GL #4488]

	6309.	[bug]		Changing a zone's primaries while a refresh was in
				progress could trigger an assertion. [GL #4310]

	6308.	[bug]		Prevent crashes caused by the zone journal getting
				destroyed before all changes from an incoming IXFR are
				written to it. [GL #4496]

	6307.	[bug]		Obtain a client->handle reference when calling
				async_restart. [GL #4439]

	6306.	[func]		Log more details about the cause of "not exact" errors.
				[GL #4500]

	6305.	[placeholder]

	6304.	[bug]		The wrong time was being used to determine what RRSIGs
				where to be generated when dnssec-policy was in use.
				[GL #4494]

	6303.	[bug]		Dig failed to correctly process a SIGINT received while
				waiting for a TCP connection to complete. [GL #4138]

	6302.	[func]		The "trust-anchor-telemetry" statement is no longer
				marked as experimental. This silences a relevant log
				message that was emitted even when the feature was
				explicitly disabled. [GL #4497]

	6301.	[bug]		Fix data races with atomic members of the xfrin
				structure in xfrin_start() and xfrin_send_request()
				functions. [GL #4493]

	6300.	[bug]		Fix statistics export to use full 64 bit signed numbers
				instead of truncating values to unsigned 32 bits.
				[GL #4467]

	6299.	[port]		NetBSD has added 'hmac' to libc which collides with our
				use of 'hmac'. [GL #4478]

	6298.	[bug]		Fix dns_qp_lookup bugs related to the iterator.
				[GL !8558]

.. code-block:: none

		--- 9.19.19 released ---

	6297.	[bug]		Improve LRU cleaning behaviour. [GL #4448]

	6296.	[func]		The "resolver-nonbackoff-tries" and
				"resolver-retry-interval" options have been removed;
				Using them is now a fatal error. [GL #4405]

	6295.	[bug]		Fix an assertion failure which could occur during
				shutdown when DNSSEC validation was running. [GL #4462]

	6294.	[bug]		BIND might sometimes crash after startup or
				re-configuration when one 'tls' entry is used multiple
				times to connect to remote servers due to initialisation
				attempts from contexts of multiple threads. That has
				been fixed. [GL #4464]

	6293.	[func]		Initial support for accepting the PROXYv2 protocol in
				all currently implemented DNS transports in BIND and
				complementary support for sending it in dig are included
				into this release. [GL #4388]

	6292.	[func]		Lower the maximum number of allowed NSEC3 iterations,
				from 150 to 50. DNSSEC responses with a higher
				iteration count are treated as insecure. For signing
				with dnssec-policy, iterations must be set to zero.
				[GL #4363]

	6291.	[bug]		SIGTERM failed to properly stop multiple outstanding
				lookup in dig. [GL #4457]

	6290.	[bug]		Dig +yaml will now report "no servers could be reached"
				also for UDP setup failure when no other servers or
				tries are left. [GL #1229]

	6289.	[test]		Remove legacy system test runner in favor of pytest.
				[GL #4251]

	6288.	[func]		Refactor the isc_mem overmem handling to always use
				isc_mem_isovermem and remove the water callback.
				[GL #4451]

	6287.	[bug]		Recognize escapes when reading the public key from file.
				[GL !8502]

	6286.	[bug]		Dig +yaml will now report "no servers could be reached"
				on TCP connection failure as well as for UDP timeouts.
				[GL #4396]

	6285.	[func]		Remove AES-based DNS cookies. [GL #4421]

	6284.	[bug]		Fix a catz db update notification callback registration
				logic error, which could cause an assertion failure when
				receiving an AXFR update for a catalog zone while the
				previous update process of the catalog zone was already
				running. [GL #4418]

	6283.	[bug]		Fix a data race in isc_hashmap by using atomics for the
				iterators number. [GL !8474]

	6282.	[func]		Deprecate AES-based DNS cookies. [GL #4421]

	6281.	[bug]		Fix a data race in dns_tsigkeyring_dump(). [GL #4328]

.. code-block:: none

		--- 9.19.18 released ---

	6280.	[bug]		Fix missing newlines in the output of "rndc nta -dump".
				[GL !8454]

	6279.	[func]		Use QNAME minimization when fetching nameserver
				addresses. [GL #4209]

	6278.	[bug]		The call to isc_mem_setwater() was incorrectly
				removed from dns_cache_setcachesize(), causing
				cache overmem conditions not to be detected. [GL #4340]

	6277.	[bug]		Take into account local authoritative zones when
				falling back to serve-stale. [GL #4355]

	6276.	[cleanup]	Remove both lock-file configuration option and the
				-X argument to named. [GL #4391]

	6275.	[bug]		Fix assertion failure when using lock-file configuration
				option together -X argument to named. [GL #4386]

	6274.	[bug]		The 'lock-file' file was being removed when it
				shouldn't have been making it ineffective if named was
				started 3 or more times. [GL #4387]

	6273.	[bug]		Don't reuse the existing TCP streams in dns_xfrin, so
				parallel TCP transfers works again. [GL #4379]

	6272.	[func]		Enable systemd units support with the 'notify-reload'
				service type by settng the MONOTONIC_USEC field when
				sending an sd_notify() message to the service manager
				to notify it about reloading the service. Note that the
				'NotifyAccess=all' option is required in the systemd
				unit file's '[Service]' section. [GL #4377]

	6271.	[bug]		Fix a shutdown race in dns__catz_update_cb(). [GL #4381]

	6270.	[bug]		Handle an assertion when the primary server returned
				NOTIMP to IXFR or FORMERR to EDNS to SOA/IXFR/AXFR
				request when transfering a zone. [GL #4372]

	6269.	[maint]		B.ROOT-SERVERS.NET addresses are now 170.247.170.2 and
				2801:1b8:10::b. [GL #4101]

	6268.	[func]		Offload the IXFR and AXFR processing to unblock
				the networking threads. [GL #4367]

	6267.	[func]		The timeouts for resending zone refresh queries over UDP
				were lowered to enable named to more quickly determine
				that a primary is down. [GL #4260]

	6266.	[func]		The zone option 'inline-signing' is ignored from now
				on iff there is no 'dnssec-policy' configured for the
				corresponding zone. [GL #4349]

	6265.	[bug]		Don't schedule resign operations on the raw version
				of an inline-signing zone. [GL #4350]

	6264.	[func]		Use atomics to handle some ADB entry members
				to reduce ADB locking contention. [GL #4326]

	6263.	[func]		Convert the RPZ summary database to use a QP trie
				instead of an RBT. [GL !8352]

	6262.	[bug]		Duplicate control sockets didn't generate a
				configuration failure leading to hard to diagnose
				rndc connection errors.  These are now caught by
				named-checkconf and named. [GL #4253]

	6261.	[bug]		Fix a possible assertion failure on an error path in
				resolver.c:fctx_query(), when using an uninitialized
				link. [GL #4331]

	6260.	[func]		Added options to the QP trie that will be needed
				when it is used as a zone or cache database: backward
				iteration, and retrieval of DNSSEC predecessor
				nodes and node chains. [GL !8338]

	6259.	[placeholder]

	6258.	[func]		Use explictly created external memory pools for
				dns_message in the ns_client and dns_resolver.
				[GL #4325]

	6257.	[func]		Expose the "Refresh SOA" query state (before the XFR)
				in the incoming zone transfers section of the
				statistics channel and show the local and remote
				addresses for that query. Also Improve the
				"Duration (s)" field to show the duration of the
				"Pending" and "Refresh SOA" states too, before the
				actual transfer starts. [GL !8305]

	6256.	[func]		Expose the SOA query transport type (used before/during
				XFR) in the incoming zone transfers section of the
				statistics channel. [GL !8240]

	6255.	[func]		Expose data about incoming zone transfers in progress
				using statistics channel. [GL #3883]

	6254.	[cleanup]	Add semantic patch to do an explicit cast from char
				to unsigned char in ctype.h class of functions.
				[GL #4327]

	6253.	[cleanup]	Remove the support for control channel over Unix
				Domain Sockets. [GL #4311]

	6252.	[test]		Python system tests have to be executed by invoking
				pytest directly. Executing them with the legacy test
				runner is no longer supported. [GL #4250]

	6251.	[bug]		Interating a hashmap could return the same element
				twice. [GL #3422]

	6250.	[bug]		The wrong covered value was being set by
				dns_ncache_current for RRSIG records in the returned
				rdataset structure. This resulted in TYPE0 being
				reported as the covered value of the RRSIG when dumping
				the cache contents. [GL #4314]

	6249.	[cleanup]	Reduce the number of reserved UDP dispatches
				to the number of loops, replace the round-robin
				mechanism in dns_dispatchset_t with dispatches
				pinned to loops, and use lock-free hash tables
				for looking up query IDs and active TCP
				connections. [GL !8304]

	6248.	[func]		Add an option "resolver-use-dns64", which enables
				application of DNS64 rules to server addresses
				when sending recursive queries. This allows
				resolution to be performed via NAT64. [GL #608]

	6247.	[func]		Implement incremental hashing in both isc_siphash
				and isc_hash units. [GL #4306]

.. code-block:: none

		--- 9.19.17 released ---

	6246.	[placeholder]

	6245.	[security]	Limit the amount of recursion that can be performed
				by isccc_cc_fromwire. (CVE-2023-3341) [GL #4152]

	6244.	[bug]		Adjust log levels on malformed messages to NOTICE when
				transferring in a zone. [GL #4290]

	6243.	[bug]		Restore the call order of dns_validator_destroy and
				fetchctx_detach to prevent use after free. [GL #4214]

	6242.	[func]		Ignore jemalloc versions before 4.0.0 as we now
				need explicit memory arenas and tcache support.
				[GL #4296]

	6241.	[placeholder]

	6240.	[bug]		Use dedicated per-worker thread jemalloc memory
				arenas for send buffers allocation to reduce memory
				consumption and avoid lock contention. [GL #4038]

	6239.	[func]		Deprecate the 'dnssec-must-be-secure' option.
				[GL #3700]

	6238.	[cleanup]	Refactor several objects relying on dns_rbt trees
				to instead of dns_nametree, a wrapper around dns_qp.
				[GL !8213]

	6237.	[bug]		Address memory leaks due to not clearing OpenSSL error
				stack. [GL #4159]

	6236.	[func]		Add isc_mem_cget() and isc_mem_cput() calloc-like
				functions that take nmemb and size, do checked
				multiplication and zero the memory before returning
				it to the user.  Replace isc_mem_getx(..., ISC_MEM_ZERO)
				with isc_mem_cget(...) usage. [GL !8237]

	6235.	[doc]		Clarify BIND 9 time formats. [GL #4266]

	6234.	[bug]		Restore stale-refresh-time value after flushing the
				cache. [GL #4278]

	6233.	[func]		Extend client side support for the EDNS EXPIRE option
				to IXFR and AXFR query types. [GL #4170]

	6232.	[bug]		Following the introduction of krb5-subdomain-self-rhs
				and ms-subdomain-self-rhs update rules, removal of
				nonexistent PTR and SRV records via UPDATE could fail.
				[GL #4280]

	6231.	[func]		Make nsupdate honor -v for SOA requests only if the
				server is specified. [GL #1181]

	6230.	[bug]		Prevent an unnecessary query restart if a synthesized
				CNAME target points to the CNAME owner. [GL #3835]

	6229.	[func]		Add basic USDT framework for adding static
				tracing points. [GL #4041]

	6228.	[func]		Limit the number of inactive network manager handles
				and uvreq objects that we keep around for reusing
				later. [GL #4265]

	6227.	[bug]		Check the statistics-channel HTTP Content-length
				to prevent negative or overflowing values from
				causing a crash. [GL #4125]

	6226.	[bug]		Attach dispatchmgr in the dns_view object to prevent
				use-after-free when shutting down. [GL #4228]

	6225.	[func]		Convert dns_nta, dns_forward and dns_keytable units
				to use QP trie instead of an RBT. [GL !7811]

	6224.	[bug]		Check the If-Modified-Since value length to prevent
				out-of-bounds write. [GL #4124]

	6223.	[func]		Make -E engine option for OpenSSL Engine API use only.
				OpenSSL Provider API will now require engine to not be
				set. [GL #8153]

	6222.	[func]		Fixes to provider/engine based ECDSA key handling.
				[GL !8152]

.. code-block:: none

		--- 9.19.16 released ---

	6221.	[cleanup]	Refactor dns_rdataset internals, move rdatasetheader
				declarations out of rbtdb.c so they can be used by other
				databases in the future, and split the zone and cache
				functions from rbtdb.c into separate modules. [GL !7873]

	6220.	[func]		Deprecate the 'dialup' and 'heartbeat-interval'
				options. [GL #3700]

	6219.	[bug]		Ignore 'max-zone-ttl' on 'dnssec-policy insecure'.
				[GL #4032]

	6218.	[func]		Add inline-signing to dnssec-policy. [GL #3677]

	6217.	[func]		The dns_badcache unit was refactored to use cds_lfht
				instead of hand-crafted locked hashtable. [GL #4223]

	6216.	[bug]		Pin dns_request events to the originating loop
				to serialize access to the data. [GL #4086]

	6215.	[protocol]	Return REFUSED to GSS-API TKEY requests if GSS-API
				support is not configured. [GL #4225]

	6214.	[bug]		Fix the memory leak in for struct stub_glue_request
				allocated in stub_request_nameserver_address() but not
				freed in stub_glue_response(). [GL #4227]

	6213.	[bug]		Mark a primary server as temporarily unreachable if the
				TCP connection attempt times out. [GL #4215]

	6212.	[placeholder]

	6211.	[func]		Remove 'auto-dnssec'. This obsoletes the configuration
				options 'dnskey-sig-validity', 'dnssec-dnskey-kskonly',
				'dnssec-update-mode', 'sig-validity-interval', and
				'update-check-ksk'. [GL #3672]

	6210.	[func]		Don't add signing records for DNSKEY added with dynamic
				update. The dynamic update DNSSEC management feature was
				removed with GL #3686. [GL !8070]

	6209.	[func]		Reduce query-response latency by making recursive
				queries (CNAME, DNAME, NSEC) asynchronous instead
				of directly calling the respective functions. [GL #4185]

	6208.	[func]		Return BADCOOKIE for out-of-date or otherwise bad, well
				formed DNS SERVER COOKIES. [GL #4194]

.. code-block:: none

		--- 9.19.15 released ---

	6207.	[cleanup]	The code implementing TSIG/TKEY support has been cleaned
				up and refactored for improved robustness, readability,
				and consistency with other code modules. [GL !7828]

	6206.	[bug]		Add shutdown checks in dns_catz_dbupdate_callback() to
				avoid a race with dns_catz_shutdown_catzs(). [GL #4171]

	6205.	[bug]		Restore support to read legacy HMAC-MD5 K file pairs.
				[GL #4154]

	6204.	[bug]		Use NS records for relaxed QNAME-minimization mode.
				This reduces the number of queries named makes when
				resolving, as it allows the non-existence of NS RRsets
				at non-referral nodes to be cached in addition to the
				referrals that are normally cached. [GL #3325]

	6203.	[cleanup]	Ensure that the size calculation does not overflow
				when allocating memory for an array.
				[GL #4120] [GL #4121] [GL #4122]

	6202.	[func]		Use per-loop memory contexts for dns_resolver
				objects. [GL !8015]

	6201.	[bug]		The free_all_cpu_call_rcu_data() call at the end
				of isc_loopmgr_run() was causing ~200 ms extra
				latency. [GL #4163]

	6200.	[placeholder]

	6199.	[bug]		Improve HTTP Connection: header protocol conformance
				in the statistics channel. [GL #4126]

	6198.	[func]		Remove the holes in the isc_result_t enum to compact
				the isc_result tables. [GL #4149]

	6197.	[bug]		Fix a data race between the dns_zone and dns_catz
				modules when registering/unregistering a database
				update notification callback for a catalog zone.
				[GL #4132]

	6196.	[cleanup]	Report "permission denied" instead of "unexpected error"
				when trying to update a zone file on a read-only file
				system. Thanks to Midnight Veil. [GL #4134]

	6195.	[bug]		Use rcu to reference view->adb. [GL #4021]

	6194.	[func]		Change function 'find_zone_keys()' to look for signing
				keys by looking for key files instead of a DNSKEY
				RRset lookup. [GL #4141]

	6193.	[bug]		Fix a catz db update notification callback registration
				logic error, which could crash named when receiving an
				AXFR update for a catalog zone while the previous update
				process of the catalog zone was already running.
				[GL #4136]

.. code-block:: none

		--- 9.19.14 released ---

	6192.	[placeholder]

	6191.	[placeholder]

	6190.	[security]	Improve the overmem cleaning process to prevent the
				cache going over the configured limit. (CVE-2023-2828)
				[GL #4055]

	6189.	[bug]		Fix an extra dns_validator deatch when encountering
				deadling which would lead to assertion failure.
				[GL #4115]

	6188.	[performance]	Reduce memory consumption by allocating properly
				sized send buffers for stream-based transports.
				[GL #4038]

	6187.	[bug]		Address view shutdown INSIST when accessing the
				zonetable. [GL #4093]

	6186.	[bug]		Fix a 'clients-per-query' miscalculation bug. When the
				'stale-answer-enable' options was enabled and the
				'stale-answer-client-timeout' option was enabled and
				larger than 0, named was taking two places from the
				'clients-per-query' limit for each client and was
				failing to gradually auto-tune its value, as configured.
				[GL #4074]

	6185.	[func]		Add "ClientQuota" statistics channel counter, which
				indicates the number of the resolver's spilled queries
				due to reaching the clients per query quota. [GL !7978]

	6184.	[func]		Special-case code that was added to allow GSS-TSIG
				to work around bugs in the Windows 2000 version of
				Active Directory has been removed. The 'nsupdate -o'
				option and 'oldgsstsig' command have been
				deprecated, and are now treated as synonyms for
				'nsupdate -g' and 'gsstsig' respectively. [GL #4012]

	6183.	[bug]		Fix a serve-stale bug where a delegation from cache
				could be returned to the client. [GL #3950]

	6182.	[cleanup]	Remove configure checks for epoll, kqueue and
				/dev/poll. [GL #4098]

	6181.	[placeholder]

	6180.	[bug]		The session key object could be incorrectly added
				to multiple different views' keyrings. [GL #4079]

	6179.	[bug]		Fix an interfacemgr use-after-free error in
				zoneconf.c:isself(). [GL #3765]

	6178.	[func]		Add support for the multi-signer model 2 (RFC 8901) when
				using inline-signing. [GL #2710]

	6177.	[placeholder]

	6176.	[test]		Add support for using pytest & pytest-xdist to
				execute the system test suite. [GL #3978]

	6175.	[test]		Fix the `upforwd` system test to be more reliable,

	6174.	[placeholder]

	6173.	[bug]		Properly process extra "nameserver" lines in
				resolv.conf otherwise the next line is not properly
				processed. [GL #4066]

	6172.	[cleanup]	Refactor the loop manager and qp-trie code to remove
				isc_qsbr and use liburcu instead. [GL #3936]

	6171.	[cleanup]	Remove the stack implementation added in change 6108:
				we are using the liburcu concurrent data structures
				instead. [GL !7920]

	6170.	[func]		The 'rndc -t' option allows a timeout to be set in
				seconds, so that commands that take a long time to
				complete (e.g., reloading a very large configuration)
				can be given time to do so. The default is 60
				seconds. [GL #4046]

	6169.	[bug]		named could crash when deleting inline-signing zones
				with "rndc delzone". [GL #4054]

	6168.	[func]		Refactor the glue cache to store list of the GLUE
				directly in the rdatasetheader instead of keeping
				it in the hashtable indexed by the node pointer.
				[GL #4045]

	6167.	[func]		Add 'cdnskey' configuration option. [GL #4050]

	6166.	[func]		Retry without DNS COOKIE on FORMERR if it appears that
				the FORMERR was due to the presence of a DNS COOKIE
				option. [GL #4049]

	6165.	[bug]		Fix a logic error in dighost.c which could call the
				dighost_shutdown() callback twice and cause problems
				if the callback function was not idempotent. [GL #4039]

.. code-block:: none

		--- 9.19.13 released ---

	6164.	[bug]		Set the rndc idle read timeout back to 60 seconds,
				from the netmgr default of 30 seconds, in order to
				match the behavior of 9.16 and earlier. [GL #4046]

	6163.	[func]		Add option to dnstap-read to use timestamps in
				milliseconds (thanks to Oliver Ford). [GL #2360]

	6162.	[placeholder]

	6161.	[bug]		Fix log file rotation when using absolute path as
				file. [GL #3991]

	6160.	[bug]		'delv +ns' could print duplicate output. [GL #4020]

	6159.	[bug]		Fix use-after-free bug in TCP accept connection
				failure. [GL #4018]

	6158.	[func]		Add ISC_LIST_FOREACH() and ISC_LIST_FOREACH_SAFE()
				to walk the ISC_LIST() in a unified manner and use
				the safe macro to fix the potential UAF when shutting
				down the isc_httpd. [GL #4031]

	6157.	[bug]		When removing delegations in an OPTOUT range
				empty-non-terminal NSEC3 records generated by
				those delegations were not removed. [GL #4027]

	6156.	[bug]		Reimplement the maximum and idle timeouts for incoming
				zone tranfers. [GL #4004]

	6155.	[bug]		Treat ISC_R_INVALIDPROTO as a networking error
				in the dispatch code to avoid retrying with the
				same server. [GL #4005]

	6154.	[func]		Add spinlock implementation.  The spinlock is much
				smaller (8 bytes) than pthread_mutex (40 bytes), so
				it can be easily embedded into objects for more
				fine-grained locking (per-object vs per-bucket).

				On the other hand, the spinlock is unsuitable for
				situations where the lock might be held for a long
				time as it keeps the waiting threads in a spinning
				busy loop. [GL #3977]

	6153.	[bug]		Fix the streaming protocols (TCP, TLS) shutdown
				sequence. [GL #4011]

	6152.	[bug]		In dispatch, honour the configured source-port
				selection when UDP connection fails with address
				in use error.

				Also treat ISC_R_NOPERM same as ISC_R_ADDRINUSE.
				[GL #3986]

	6151.	[bug]		When the same ``notify-source`` address and port number
				was configured for multiple destinations and zones, an
				unresponsive server could tie up the socket until it
				timed out; in the meantime, NOTIFY messages for other
				servers silently failed.``named`` will now retry these
				failing messages over TCP.  NOTIFY failures are now
				logged at level INFO. [GL #4001] [GL #4002]

	6150.	[bug]		If the zones have active upstream forwards, the
				shutting down the server might cause assertion
				failures as the forward were all canceled from
				the main loop instead from the loops associated
				with the zone. [GL #4015]

	6149.	[test]		As a workaround, include an OpenSSL header file before
				including cmocka.h in the unit tests, because OpenSSL
				3.1.0 uses __attribute__(malloc), conflicting with a
				redefined malloc in cmocka.h. [GL #4000]

	6148.	[bug]		Fix a use-after-free bug in dns_xfrin_create().
				[GL !7832]

	6147.	[performance]	Fix the TCP server parent quota use. [GL #3985]

.. code-block:: none

		--- 9.19.12 released ---

	6146.	[performance]	Replace the zone table red-black tree and associated
				locking with a lock-free qp-trie. [GL !7582]

	6145.	[bug]		Fix a possible use-after-free bug in the
				dns__catz_done_cb() function. [GL #3997]

	6144.	[bug]		A reference counting problem (double detach) might
				occur when shutting down zone transfer early after
				switching the dns_xfrin to use dns_dispatch API.
				[GL #3984]

	6143.	[bug]		A reference counting problem on the error path in
				the xfrin_connect_done() might cause an assertion
				failure on shutdown.  [GL #3989]

	6142.	[bug]		Reduce the number of dns_dnssec_verify calls made
				determining if revoked keys needs to be removed from
				the trust anchors. [GL #3981]

	6141.	[bug]		Fix several issues in nsupdate timeout handling and
				update the -t option's documentation. [GL #3674]

	6140.	[func]		Implement automatic parental-agents ('checkds yes').
				[GL #3901]

	6139.	[func]		Add isc_histo_t general-purpose log-linear histograms,
				and use them for message size statistics. [GL !7696]

	6138.	[doc]		Fix the DF-flag documentation on the outgoing
				UDP packets. [GL #3710]

	6137.	[cleanup]	Remove the trampoline jump when spawning threads.
				[GL !7293]

	6136.	[cleanup]	Remove the isc_fsaccess API in favor of creating
				temporary file first and atomically replace the key
				with non-truncated content. [GL #3982]

	6135.	[cleanup]	Change isc_stdtime_get(&t) to t = isc_stdtime_now().
				[GL !7757]

	6134.	[bug]		Fix a crash when dig or host receive a signal.
				[GL #3970]

	6133.	[cleanup]	Refactor the isc_job_run() to not make any allocations
				by embedding isc_job_t into callback argument, and
				running it directly.  As a side-effect, isc_async_run
				and isc_job_run now executes jobs in the natural order.

				Use the new improved API to execute connect, read and
				send callbacks from netmgr in more straightforward
				manner, speeding up the networking. [GL #3961]

	6132.	[doc]		Remove a dead link in the DNSSEC guide. [GL #3967]

	6131.	[test]		Add a minimal test-only library to allow testing
				of the DNSRPS API without FastRPZ installed.
				Thanks to Farsight Securty. [GL !7693]

	6130.	[func]		The new "delv +ns" option activates name server mode,
				in which delv sets up an internal recursive
				resolver and uses that, rather than an external
				server, to look up the requested data. All messages
				sent and received during the resolution and
				validation process are logged. This can be used in
				place of "dig +trace"; it more accurately
				replicates the behavior of named when resolving
				a query. [GL #3842]

	6129.	[cleanup]	Value stored to 'source' during its initialization is
				never read. [GL #3965]

	6128.	[bug]		Fix an omission in an earlier commit to avoid a race
				between the 'dns__catz_update_cb()' and
				'dns_catz_dbupdate_callback()' functions. [GL #3968]

	6127.	[cleanup]	Refactor network manager netievent callbacks to
				use isc_job_run()/isc_async_run(). [GL #3964]

	6126.	[func]		Remove zone type "delegation-only" and the
				"delegation-only" and "root-delegation-only"
				options. [GL #3953]

	6125.	[bug]		Hold a catz reference while the update process is
				running, so that the catalog zone is not destroyed
				during shutdown until the update process is finished or
				properly canceled by the activated 'shuttingdown' flag.
				[GL #3955]

	6124.	[bug]		When changing from a NSEC3 capable DNSSEC algorithm to
				an NSEC3 incapable DNSSEC algorithm using KASP the zone
				could sometimes be incompletely signed. [GL #3937]

	6123.	[placeholder]

	6122.	[func]		BIND now requires liburcu for lock-free data structures
				and concurrent safe memory reclamation. It replaces the
				home-grown lock-free linked list and QSBR machinery
				added in changes 6108 and 6109.  [GL #3935]

	6121.	[cleanup]	Remove support for TKEY Mode 2 (Diffie-Hellman Exchanged
				Keying). [GL #3905]

.. code-block:: none

		--- 9.19.11 released ---

	6120.	[bug]		Use two pairs of dns_db_t and dns_dbversion_t in a
				catalog zone structure to avoid a race between the
				dns__catz_update_cb() and dns_catz_dbupdate_callback()
				functions. [GL #3907]

	6119.	[bug]		Make sure to revert the reconfigured zones to the
				previous version of the view, when the new view
				reconfiguration fails during the configuration of
				one of the configured zones. [GL #3911]

	6118.	[func]		Add 'cds-digest-types' configuration option. Also allow
				dnssec-signzone to create multple CDS records.
				[GL #3837]

	6117.	[func]		Add a qp-trie data structure. This is a foundation for
				our plan to replace, in stages, BIND's red-black tree.
				The qp-trie has lock-free multithreaded reads, using
				QSBR for safe memory reclamation. [GL !7130]

	6116.	[placeholder]

	6115.	[bug]		Unregister db update notify callback before detaching
				from the previous db inside the catz update notify
				callback. [GL #3777]

	6114.	[func]		Run the catalog zone update process on the offload
				threads. [GL #3881]

	6113.	[func]		Add shutdown signaling for catalog zones. [GL !7571]

	6112.	[func]		Add reference count tracing for dns_catz_zone_t and
				dns_catz_zones_t. [GL !7570]

	6111.	[cleanup]	Move irs_resconf into libdns, and remove the
				now empty libirs. [GL !7463]

	6110.	[cleanup]	Refactor the dns_xfrin module to use dns_dispatch
				to set up TCP connections and send and receive
				messages. [GL #3886]

	6109.	[func]		Infrastructure for QSBR, asynchronous safe memory
				reclamation for lock-free data structures. [GL !7471]

	6108.	[func]		Support for simple lock-free singly-linked stacks.
				[GL !7470]

	6107.	[cleanup]	Remove the dns_sdb API and rewrite the named
				builtin databases to implement dns_db directly.
				[GL #3882]

	6106.	[cleanup]	Move bind9_getaddresses() to isc_getaddresses()
				and remove the now empty libbind9. [GL !7462]

	6105.	[bug]		Detach 'rpzs' and 'catzs' from the previous view in
				configure_rpz() and configure_catz(), respectively,
				just after attaching it to the new view. [GL #3880]

	6104.	[cleanup]	Move libbind9's configuration checking code into
				libisccfg alongside the other configuration code.
				[GL !7461]

	6103.	[func]		All uses of the isc_task and isc_event APIs have
				been refactored to use isc_loop instead, and the
				original APIs have been removed. [GL #3797]

	6102.	[cleanup]	Several nugatory headers have been removed from libisc.
				[GL !7464]

	6101.	[port]		Clarify the portability dodge needed for `strerror_r()`
				[GL !7465]

	6100.	[cleanup]	Deprecate <isc/deprecated.h>, because obsolete
				functions are now deleted instead of marked with
				an attribute. [GL !7466]

	6099.	[performance]	Change the internal read-write lock to modified C-RW-WP
				algorithm that is more reader-writer fair and has better
				performance for our workloads. [GL #1609]

	6098.	[test]		Don't test HMAC-MD5 when not supported by libcrypto.
				[GL #3871]

	6097.	[port]		Improve support for yield / pause instructions in spin
				loops on AArch64 platforms. [GL !7469]

	6096.	[bug]		Fix RPZ reference counting error on shutdown in
				dns__rpz_timer_cb(). [GL #3866]

	6095.	[test]		Test various 'islands of trust' configurations when
				using managed keys. [GL #3662]

	6094.	[bug]		Building against (or running with) libuv versions
				1.35.0 and 1.36.0 is now a fatal error.  The rules for
				mixing and matching compile-time and run-time libuv
				versions have been tightened for libuv versions between
				1.35.0 and 1.40.0. [GL #3840]

	6093.	[performance]	Reduce the size of each rdataset header object
				by 16 bytes. [GL !7505]

	6092.	[bug]		dnssec-cds failed to cleanup properly. [GL #3831]

	6091.	[cleanup]	Drop RHEL 7 and clones support. [GL #3729]

	6090.	[bug]		Fix a bug in resolver's resume_dslookup() function by
				making sure that dns_resolver_createfetch() is called
				with valid parameters, as required by the function.
				[GL #3839]

	6089.	[bug]		Source ports configured for query-source,
				transfer-source, etc, were being ignored. (This
				feature is deprecated, but it is not yet removed,
				so the bug still needed fixing.) [GL #3790]

	6088.	[cleanup]	/etc/bind.keys is no longer needed and has been
				removed from the distribution. named and delv can
				still load keys from a file for testing purposes,
				but they no longer do so by default. [GL #3850]

	6087.	[cleanup]	Remove support for the `DNS_NAME_DOWNCASE` option to
				the various dns_*_fromwire() functions. It has long
				been unused and is unsupported since change 6022.
				[GL !7467]

	6086.	[cleanup]	Remove some remnants of bitstring labels. [GL !7196]

	6085.	[func]		Add isc_time_monotonic() to simplify time measurements.
				[GL !7468]

	6084.	[bug]		When BIND was built without jemalloc, the allocator flag
				ISC_MEM_ZERO could return non-zero memory. [GL #3845]

.. code-block:: none

		--- 9.19.10 released ---

	6083.	[bug]		Fix DNSRPS-enabled builds as they were inadvertently
				broken by changes 5949 and 6042. [GL #3827]

	6082.	[test]		fuzz/dns_message_checksig leaked memory when shutting
				down. [GL #3828]

	6081.	[bug]		Handle primary server address lookup failures in
				nsupdate more gracefully. [GL #3830]

	6080.	[bug]		'named -V' leaked memory. [GL #3829]

	6079.	[bug]		Force set the DS state after a 'rdnc dnssec -checkds'
				command. [GL #3822]

	6078.	[func]		Cleanup the memory statistic counters to a bare
				minumum - InUse with Malloced as alias. [GL #3718]

	6077.	[func]		Implement query forwarding to DoT-enabled upstream
				servers. [GL #3726]

	6076.	[bug]		Handle OS errors when creating UDP and TCP sockets
				more gracefully. [GL #3800]

	6075.	[bug]		Add missing node lock when setting node->wild in
				add_wildcard_magic. [GL #3799]

	6074.	[func]		Refactor the isc_nm_xfr_allowed() function to return
				isc_result_t instead of boolean. [GL #3808]

	6073.	[bug]		Set RD=1 on DS requests to parental-agents. [GL #3783]

	6072.	[bug]		Avoid the OpenSSL lock contention when initializing
				Message Digest Contexts by using explicit algorithm
				fetching, initializing static contexts for every
				supported algorithms, and initializing the new context
				by copying the static copy. [GL #3795]

	6071.	[func]		The use of "port" when configuring query-source,
				transfer-source, notify-source and parental-source
				addresses has been deprecated, along with the
				use-v[46]-udp-ports and avoid-v[46]-udp-ports
				options. A warning will be logged when these
				options are used. In a future release, they
				will be removed. [GL #3781]

	6070.	[func]		DSCP parsing has now been fully removed, and
				configuration of DSCP values in named.conf is a
				configuration error. [GL #3789]

	6069.	[bug]		Detach from the view in zone_shutdown() to
				release the memory held by the dead view
				early. [GL #3801]

	6068.	[bug]		Downloading a zone via TLS from a server which does
				not negotiate "dot" ALPN token could crash BIND
				on shutdown. That has been fixed. [GL #3767]

.. code-block:: none

		--- 9.19.9 released ---

	6067.	[security]	Fix serve-stale crash when recursive clients soft quota
				is reached. (CVE-2022-3924) [GL #3619]

	6066.	[security]	Handle RRSIG lookups when serve-stale is active.
				(CVE-2022-3736) [GL #3622]

	6065.	[placeholder]

	6064.	[security]	An UPDATE message flood could cause named to exhaust all
				available memory. This flaw was addressed by adding a
				new "update-quota" statement that controls the number of
				simultaneous UPDATE messages that can be processed or
				forwarded. The default is 100. A stats counter has been
				added to record events when the update quota is
				exceeded, and the XML and JSON statistics version
				numbers have been updated. (CVE-2022-3094) [GL #3523]

	6063.	[cleanup]	The RSA and ECDSA parts of the DNSSEC has been
				refactored for a better OpenSSL 3.x integration and
				preliminary PKCS#11 support via for OpenSSL Providers
				has been added. [GL #3785]

	6062.	[func]		The DSCP implementation, which has been
				nonfunctional for some time, is now marked as
				obsolete and the implementation has been removed.
				Configuring DSCP values in named.conf has no
				effect, and a warning will be logged that
				the feature should no longer be used. [GL #3773]

	6061.	[bug]		Fix unexpected "Prohibited" extended DNS error
				on allow-recursion. [GL #3743]

	6060.	[bug]		Fix a use-after-free bug in dns_zonemgr_releasezone()
				by detaching from the zone manager outside of the write
				lock. [GL #3768]

	6059.	[bug]		In some serve stale scenarios, like when following an
				expired CNAME record, named could return SERVFAIL if the
				previous request wasn't successful. Consider non-stale
				data when in serve-stale mode. [GL #3678]

	6058.	[bug]		Prevent named from crashing when "rndc delzone"
				attempts to delete a zone added by a catalog zone.
				[GL #3745]

	6057.	[bug]		Fix shutdown and error path bugs in the rpz unit.
				[GL #3735]

	6056.	[bug]		Fix a race in adb.c:clean_namehooks(), so that an ADB
				entry does not expire without holding the entries lock.
				[GL #3754]

	6055.	[cleanup]	Remove setting alternate transfer sources, make options
				alt-transfer-source, alt-transfer-transfer-source-v6,
				and use-alt-transfer-source ancient. [GL #3714]

	6054.	[func]		Refactor remote servers (primaries, parental-agents)
				in zone.c. Store common code in new source files
				remote.c and remote.h. Introduce a new way to set the
				source address and port. [GL !7110]

	6053.	[bug]		Fix an ADB quota management bug in resolver. [GL #3752]

	6052.	[func]		Replace DNS over TCP and DNS over TLS transports
				code with a new, unified transport implementation.
				[GL #3374]

	6051.	[bug]		Improve thread safety in the dns_dispatch unit.
				[GL #3178] [GL #3636]

	6050.	[bug]		Changes to the RPZ response-policy min-update-interval
				and add-soa options now take effect as expected when
				named is reconfigured. [GL #3740]

	6049.	[bug]		Exclude ABD hashtables from the ADB memory
				overmem checks and don't clean ADB names
				and ADB entries used in the last 10 seconds
				(ADB_CACHE_MINIMUM). [GL #3739]

	6048.	[bug]		Fix a log message error in dns_catz_update_from_db(),
				where serials with values of 2^31 or larger were logged
				incorrectly as negative numbers. [GL #3742]

	6047.	[bug]		Try the next server instead of trying the same
				server again on an outgoing query timeout.
				[GL #3637]

	6046.	[bug]		TLS session resumption might lead to handshake
				failures when client certificates are used for
				authentication (Mutual TLS).  This has been fixed.
				[GL #3725]

	6045.	[cleanup]	The list of supported DNSSEC algorithms changed log
				level from "warning" to "notice" to match named's other
				startup messages. [GL !7217]

	6044.	[bug]		There was an "RSASHA236" typo in a log message.
				[GL !7206]

.. code-block:: none

		--- 9.19.8 released ---

	6043.	[bug]		The key file IO locks objects would never get
				deleted from the hashtable due to off-by-one error.
				[GL #3727]

	6042.	[bug]		ANY responses could sometimes have the wrong TTL.
				[GL #3613]

	6041.	[func]		Set the RLIMIT_NOFILE to rlim_max returned from
				getrlimit() instead of trying to guess the maximum
				allowed value. [GL #3676]

	6040.	[bug]		Speed up the named shutdown time by explicitly
				canceling all recursing ns_client objects for
				each ns_clientmgr. [GL #3183]

	6039.	[bug]		Removing a catalog zone from catalog-zones without
				also removing the referenced zone could leave a
				dangling pointer. [GL #3683]

	6038.	[placeholder]

	6037.	[func]		Reject zones which have DS records not at delegation
				points. [GL #3697]

	6036.	[bug]		nslookup and host were not honoring the selected port
				in TCP mode. [GL #3721]

	6035.	[bug]		Refactor the dns_resolver unit to store the fetch
				contexts and zone counter directly in the hash
				tables without buckets and implement effective
				cleaning of both objects. [GL #3709]

	6034.	[func]		Deprecate alt-transfer-source, alt-transfer-source-v6
				and use-alt-transfer-source. [GL #3694]

	6033.	[func]		Log messages related to serve-stale now include the RR
				type involved. [GL !7145]

	6032.	[bug]		After change 5995, zone transfers were using a small
				compression context that only had space for the first
				few dozen names in each message. They now use a large
				compression context with enough space for every name.
				[GL #3706]

	6031.	[bug]		Move the "final reference detached" log message
				from dns_zone unit to the DEBUG(1) log level.
				[GL #3707]

	6030.	[bug]		Refactor the ADB to use a global LRU queue, store
				the ADB names and ADB entries directly in the hash
				tables instead of buckets, and properly clean the
				ADB names and entries when not in use. [GL #3239]
				[GL #3238] [GL #2615] [GL #2078] [GL #2437]
				[GL #3312] [GL #2441]

	6029.	[cleanup]	Remove the unused external cache cleaning mechanism
				as RBTDB has its own internal cache cleaning
				mechanism and we don't support any other database
				implementations. [GL #3639]

	6028.	[performance]	Build-time code generation of DNS RRtype switches
				is now much faster. [GL !7121]

	6027.	[bug]		Fix assertion failure in isc_http API used by
				statschannel if the read callback would be called
				on HTTP request that has been already closed.
				[GL #3693]

	6026.	[cleanup]	Deduplicate time unit conversion factors.
				[GL !7033]

	6025.	[bug]		Copy TLS identifier when setting up primaries for
				catalog member zones. [GL #3638]

	6024.	[func]		Deprecate 'auto-dnssec'. [GL #3667]

	6023.	[func]		Remove dynamic update DNSSEC management feature.
				[GL #3686]

	6022.	[performance]	The decompression implementation in dns_name_fromwire()
				is now smaller and faster. [GL #3655]

	6021.	[bug]		Use the current domain name when checking answers from
				a dual-stack-server. [GL #3607]

	6020.	[bug]		Ensure 'named-checkconf -z' respects the check-wildcard
				option when loading a zone.  [GL #1905]

	6019.	[func]		Deprecate `coresize`, `datasize`, `files`, and
				`stacksize` named.conf options. [GL #3676]

	6018.	[cleanup]	Remove the --with-tuning configure option.
				[GL #3664]

	6017.	[bug]		The view's zone table was not locked when it should
				have been leading to race conditions when external
				extensions that manipulate the zone table where in
				use. [GL #3468]

	6016.	[func]		Change NSEC3PARAM TTL to match the SOA MINIMUM.
				[GL #3570]

	6015.	[bug]		Some browsers (Firefox) send more than 10 HTTP
				headers.  Bump the number of allowed HTTP headers
				to 100. [GL #3670]

	6014.	[func]		Add isc_hashmap API implementation that implements
				Robin Hood hashing.  The API requires the keys to
				be stored with the stored value.  [GL !6790]

.. code-block:: none

		--- 9.19.7 released ---

	6013.	[bug]		Fix a crash that could happen when you change
				a dnssec-policy zone with NSEC3 to start using
				inline-signing. [GL #3591]

	6012.	[placeholder]

	6011.	[func]		Refactor the privilege setting part of named_os unit
				to make libcap on Linux mandatory and use setreuid
				and setregid if available. [GL #3583]

	6010.	[func]		Make the initial interface scan happen before
				dropping the privileges.  This requires exiting
				exclusive mode before scanning the interfaces
				and re-entering it again when we are done.  This
				is because starting the listening on interfaces
				requires the loopmgr to be running and not paused.
				[GL #3583]

	6009.	[bug]		Don't trust a placeholder KEYDATA from the managed-keys
				zone by adding it into secroots. [GL #2895]

	6008.	[bug]		Fixed a race condition that could cause a crash
				in dns_zone_synckeyzone(). [GL #3617]

	6007.	[cleanup]	Don't enforce the jemalloc use on NetBSD. [GL #3634]

	6006.	[cleanup]	The zone dumping was using isc_task API to launch
				the zonedump on the offloaded threadpool.  Remove
				the task and launch the offloaded work directly.
				[GL #3628]

	6005.	[func]		The zone loading has been moved to the offload
				threadpool instead of doing incremental repeated
				tasks, so zone loading scheduling is now driven
				by the operating system scheduler rather than fixed
				(100) quantum. [GL #3625]

	6004.	[func]		Add check-svcb to control the checking of additional
				constraints on SVBC records.  This change impacts on
				named, named-checkconf, named-checkzone,
				named-compilezone and nsupdate. [GL #3576]

	6003.	[bug]		Fix an inheritance bug when setting the port on
				remote servers in configuration. [GL #3627]

	6002.	[bug]		Fix a resolver prefetch bug when the record's TTL value
				is equal to the configured prefetch eligibility value,
				but the record was erroneously not treated as eligible
				for prefetching. [GL #3603]

	6001.	[bug]		Always call dns_adb_endudpfetch() after calling
				dns_adb_beginudpfetch() for UDP queries in resolver.c,
				in order to adjust back the quota. [GL #3598]

	6000.	[bug]		Fix a startup issue on Solaris systems with many
				(reportedly > 510) CPUs. Thanks to Stacey Marshall from
				Oracle for deep investigation of the problem. [GL #3563]

	5999.	[bug]		rpz-ip rules could be ineffective in some scenarios
				with CD=1 queries. [GL #3247]

	5998.	[placeholder]

	5997.	[cleanup]	Less ceremonial UNEXPECTED_ERROR() and FATAL_ERROR()
				reporting macros. [GL !6914]

	5996.	[bug]		Fix a couple of bugs in cfg_print_duration(), which
				could result in generating incomplete duration values
				when printing the configuration using named-checkconf.
				[GL !6880]

	5995.	[performance]	A new algorithm for DNS name compression based on a
				hash set of message offsets. Name compression is now
				more complete as well as being generally faster, and
				the implementation is less complicated and requires
				much less memory. [GL !6517]

	5994.	[func]		Refactor the isc_httpd implementation used in the
				statistics channel. [GL !6879]

	5993.	[cleanup]	Store dns_name_t attributes as boolean members of
				the structure. Remove DNS_NAMEATTR_* macros.
				Fix latent attribute handling bug in RBT. [GL !6902]

.. code-block:: none

		--- 9.19.6 released ---

	5992.	[func]		Introduce the new isc_mem_*x() APIs that takes extra
				flags as the last argument.  Currently ISC_MEM_ZERO
				and ISC_MEM_ALIGN(n) flags have been implemented that
				clears the memory to avoid the isc_mem_get()/memset()
				pattern and make aligned allocation which replaces the
				previous isc_mem_*_aligned() calls. [GL !6398]

	5991.	[protocol]	Add support for parsing and validating "dohpath" to
				SVCB. [GL #3544]

	5990.	[test]		fuzz/dns_message_checksig now creates the key directory
				it uses when testing in /tmp at run time. [GL #3569]

	5989.	[func]		Implement support for DDNS update forwarding using DoT
				to TLS-enabled primary servers. [GL #3512]

	5988.	[bug]		Some out of memory conditions in opensslrsa_link.c
				could lead to memory leaks. [GL #3551]

	5987.	[func]		Provide custom isc_mem based allocators for libuv,
				OpenSSL and libxml2 libraries that support replacing
				the internal allocators. [GL #3559]

	5986.	[func]		Make the memory context debugging options local to
				the memory context and make it immutable for the memory
				context lifetime. [GL #3559]

	5985.	[func]		Bump the minimal libuv version to 1.34.0. [GL #3567]

	5984.	[func]		'named -V' now reports the list of supported
				DNSSEC/DS/HMAC algorithms and the supported TKEY modes.
				[GL #3541]

	5983.	[bug]		Changing just the TSIG key names for primaries in
				catalog zones' member zones was not effective.
				[GL #3557]

	5982.	[func]		Extend dig to allow requests to be signed using SIG(0)
				as well as providing a mechanism to specify the signing
				time. [GL !5923]

	5981.	[test]		Add dns_message_checksig fuzzer to check messages
				signed using TSIG or SIG(0). [GL !5923]

	5980.	[func]		The internal isc_entropy API provider has been
				changed from OpenSSL RAND_bytes() to uv_random()
				to use system provided entropy. [GL !6803]

	5979.	[func]		Implement DoT support for nsupdate. [GL #1781]

	5978.	[port]		The ability to use pkcs11 via engine_pkcs11 has been
				restored, by only using deprecated APIs in
				OpenSSL 3.0.0. BIND needs to be compiled with
				'-DOPENSSL_API_COMPAT=10100' specified in the CFLAGS
				at compile time. [GL !6711]

	5977.	[bug]		named could incorrectly return non-truncated, glueless
				referrals for responses whose size was close to the UDP
				packet size limit. [GL #1967]

	5976.	[cleanup]	isc_timer_t objects are now created, started and
				destroyed in a particular loop, and timer callbacks
				run in that loop. isc_timer_stop() can still be called
				from any loop; when run from a different loop than
				the one associated with the timer, the request will
				be recorded in atomic variable and the timer will
				be stopped on the next callback call. [GL #3202]

	5975.	[func]		Implement TLS transport support for dns_request and
				dns_dispatch. [GL #3529]

	5974.	[bug]		Fix an assertion failure in dispatch caused by
				extra read callback call. [GL #3545]

	5973.	[bug]		Fixed a possible invalid detach in UPDATE
				processing. [GL #3522]

	5972.	[bug]		Gracefully handle when the statschannel HTTP connection
				gets cancelled during sending data back to the client.
				[GL #3542]

	5971.	[func]		Add libsystemd sd_notify() support. [GL #1176]

	5970.	[func]		Log the reason why a query was refused. [GL !6669]

	5969.	[bug]		DNSSEC signing statistics failed to identify the
				algorithm involved.  The key names have been changed
				to be the algorithm number followed by "+" followed
				by the key id (e.g. "8+54274"). [GL #3525]

	5968.	[cleanup]	Remove 'resolve' binary from tests. [GL !6733]

	5967.	[cleanup]	Flagged the obsolete "random-device" option as
				ancient; it is now an error to configure it. [GL #3399]

	5966.	[func]		You can now specify if a server must return a DNS
				COOKIE before accepting the response over UDP.
				[GL #2295]

				server <prefix> { require-cookie <yes_or_no>; };

	5965.	[cleanup]	Move the duplicated ASCII case conversion tables to
				isc_ascii where they can be shared, and replace the
				various hot-path tolower() loops with calls to new
				isc_ascii implementations. [GL !6516]

	5964.	[func]		When an international domain name is not valid, DiG will
				now pass it through unchanged, instead of stopping with
				an error message. [GL #3527]

	5963.	[bug]		Ensure struct named_server is properly initialized.
				[GL #6531]

.. code-block:: none

		--- 9.19.5 released ---

	5962.	[security]	Fix memory leak in EdDSA verify processing.
				(CVE-2022-38178) [GL #3487]

	5961.	[placeholder]

	5960.	[security]	Fix serve-stale crash that could happen when
				stale-answer-client-timeout was set to 0 and there was
				a stale CNAME in the cache for an incoming query.
				(CVE-2022-3080) [GL #3517]

	5959.	[security]	Fix memory leaks in the DH code when using OpenSSL 3.0.0
				and later versions. The openssldh_compare(),
				openssldh_paramcompare(), and openssldh_todns()
				functions were affected. (CVE-2022-2906) [GL #3491]

	5958.	[security]	When an HTTP connection was reused to get
				statistics from the stats channel, and zlib
				compression was in use, each successive
				response sent larger and larger blocks of memory,
				potentially reading past the end of the allocated
				buffer. (CVE-2022-2881) [GL #3493]

	5957.	[security]	Prevent excessive resource use while processing large
				delegations. (CVE-2022-2795) [GL #3394]

	5956.	[func]		Make RRL code treat all QNAMEs that are subject to
				wildcard processing within a given zone as the same
				name. [GL #3459]

	5955.	[port]		The libxml2 library has deprecated the usage of
				xmlInitThreads() and xmlCleanupThreads() functions. Use
				xmlInitParser() and xmlCleanupParser() instead.
				[GL #3518]

	5954.	[func]		Fallback to IDNA2003 processing in dig when IDNA2008
				conversion fails. [GL #3485]

	5953.	[bug]		Fix a crash on shutdown in delete_trace_entry(). Add
				mctx attach/detach pair to make sure that the memory
				context used by a memory pool is not destroyed before
				the memory pool itself. [GL #3515]

	5952.	[bug]		Use quotes around address strings in YAML output.
				[GL #3511]

	5951.	[bug]		In some cases, the dnstap query_message field was
				erroneously set when logging response messages.
				[GL #3501]

	5950.	[func]		Implement a feature to set an Extended DNS Error (EDE)
				code on responses modified by RPZ. [GL #3410]

	5949.	[func]		Add new isc_loopmgr API that runs the application
				event loops and completely replaces the isc_app
				API. Refactor the isc_taskmgr, isc_timermgr and
				isc_netmgr to use the isc_loopmgr event loops.
				[GL #3508]

	5948.	[bug]		Fix nsec3.c:dns_nsec3_activex() function, add a missing
				dns_db_detachnode() call. [GL #3500]

	5947.	[func]		Change dnssec-policy to allow graceful transition from
				an NSEC only zone to NSEC3. [GL #3486]

	5946.	[bug]		Fix statistics channel's handling of multiple HTTP
				requests in a single connection which have non-empty
				request bodies. [GL #3463]

	5945.	[bug]		If parsing /etc/bind.key failed, delv could assert
				when trying to parse the built in trust anchors as
				the parser hadn't been reset. [GL !6468]

	5944.	[bug]		Fix +http-plain-get and +http-plain-post options
				support in dig. Thanks to Marco Davids at SIDN for
				reporting the problem. [GL !6672]

	5943.	[placeholder]

	5942.	[bug]		Fix tkey.c:buildquery() function's error handling by
				adding the missing cleanup code. [GL #3492]

	5941.	[func]		Zones with dnssec-policy now require dynamic DNS or
				inline-siging to be configured explicitly. [GL #3381]

	5940.	[placeholder]

	5939.	[placeholder]

	5938.	[bug]		An integer type overflow could cause an assertion
				failure when freeing memory. [GL #3483]

	5937.	[cleanup]	The dns_rdatalist_tordataset() and
				dns_rdatalist_fromrdataset() functions can no
				longer fail. Clean up their prototypes and error
				handling, and that of other calling functions that
				subsequently cannot fail, including
				dns_message_setquerytsig(). [GL #3467]

	5936.	[bug]		Don't enable serve-stale for lookups that error because
				it is a duplicate query or a query that would be
				dropped. [GL #2982]

	5935.	[bug]		Fix DiG lookup reference counting bug, which could
				be observed in NSSEARCH mode. [GL #3478]

.. code-block:: none

		--- 9.19.4 released ---

	5934.	[func]		Improve fetches-per-zone fetch limit logging to log
				the final allowed and spilled values of the fetch
				counters before the counter object gets destroyed.
				[GL #3461]

	5933.	[port]		Automatically disable RSASHA1 and NSEC3RSASHA1 in
				named on Fedorda 33, Oracle Linux 9 and RHEL9 when
				they are disabled by the security policy. [GL #3469]

	5932.	[bug]		Fix rndc dumpdb -expired and always include expired
				RRsets, not just for RBTDB_VIRTUAL time window.
				[GL #3462]

	5931.	[bug]		Fix DiG query error handling robustness in NSSEARCH
				mode by making sure that udp_ready(), tcp_connected(),
				and send_done() callbacks start the next query in chain
				even if there is some kind of error with the previous
				query. [GL #3419]

	5930.	[bug]		Fix DiG query retry and fail-over bug in UDP mode.
				Also simplify the overall retry and fail-over logic to
				make it behave predictably, and always respect the
				documented +retry/+tries count set by a command-line
				option (or use the default values of 2 or 3
				respectively). [GL #3407]

	5929.	[func]		The use of the "max-zone-ttl" option in "zone" and
				"options" blocks is now deprecated; this should
				now be configured as part of "dnssec-policy"
				instead. The old option still works in zones
				with no "dnssec-policy" configured, but a warning
				will be logged when loading configuration. Its
				functionality will be removed in a future release.
				Using "max-zone-ttl" and "dnssec-policy" in the
				same zone is now a fatal error. [GL #2918]

	5928.	[placeholder]

	5927.	[bug]		A race was possible in dns_dispatch_connect()
				that could trigger an assertion failure if two
				threads called it near-simultaneously. [GL #3456]

	5926.	[func]		Handle transient TCP connect() EADDRINUSE failures
				on FreeBSD (and possibly other BSDs) by trying three
				times before giving up. [GL #3451]

	5925.	[bug]		With a forwarder configured for all queries, resolution
				failures encountered during DS chasing could trigger
				assertion failures due to a logic bug in
				resume_dslookup() that caused it to call
				dns_resolver_createfetch() with an invalid name.
				[GL #3439]

	5924.	[func]		When it's necessary to use AXFR to respond to an
				IXFR request, a message explaining the reason
				is now logged at level info. [GL #2683]

	5923.	[bug]		Fix inheritance for dnssec-policy when checking for
				inline-signing. [GL #3438]

	5922.	[bug]		Forwarding of UPDATE message could fail with the
				introduction of netmgr. This has been fixed. [GL #3389]

	5921.	[test]		Convert system tests to use a default DNSKEY algorithm
				where the test is not DNSKEY algorithm specific.
				[GL #3440]

	5920.	[bug]		Don't pass back the current name offset when the
				compression is disabled in the non-improving case.
				[GL #3423]

.. code-block:: none

		--- 9.19.3 released ---

	5919.	[func]		The "rndc fetchlimit" command lists name servers
				and domain names that are being rate-limited by
				"fetches-per-server" or "fetches-per-zone" limits.
				[GL #665]

	5918.	[test]		Convert system tests to use a default HMAC algorithm
				where the test is not HMAC specific. [GL #3433]

	5917.	[bug]		Update ifconfig.sh script as is miscomputed interface
				identifiers when destroying interfaces. [GL #3061]

	5916.	[bug]		When resolving a name, don't give up immediately if an
				authoritative server returns FORMERR; try the other
				servers first. [GL #3152]

	5915.	[bug]		Detect missing closing brace (}) and computational
				overflows in $GENERATE directives. [GL #3429]

	5914.	[bug]		When synth-from-dnssec generated a response using
				records from a higher zone, it could unexpectedly prove
				non-existance of records in a subordinate grafted-on
				namespace. [GL #3402]

	5913.	[placeholder]

	5912.	[cleanup]	The "glue-cache" option has been removed. The glue cache
				feature still works and is now permanently enabled.
				[GL #2147]

	5911.	[bug]		Update HTTP listener settings on reconfiguration.
				[GL #3415]

	5910.	[cleanup]	Move built-in dnssec-policies into the defaultconf.
				These are now printed with 'named -C'. [GL !6467]

	5909.	[bug]		The server-side destination port was missing from dnstap
				captures of client traffic. [GL #3309]

	5908.	[bug]		Fix race conditions in route_connected(). [GL #3401]

	5907.	[bug]		Fix a crash in dig NS search mode when one of the NS
				server queries fail. [GL #3207]

	5906.	[cleanup]	Various features (e.g. prefetch, RPZ) no longer share
				common pointers when initiating recursion. This
				rationalizes recursion quota handling and makes the
				value of the RecursClients statistics counter more
				accurate. [GL #3168]

	5905.	[bug]		When the TCP connection would be closed/reset between
				the connect/accept and the read, the uv_read_start()
				return value would be unexpected and cause an assertion
				failure. [GL #3400]

	5904.	[func]		Changed dnssec-signzone -H default to 0 additional
				NSEC3 iterations. [GL #3395]

	5903.	[bug]		When named checks that the OPCODE in a response matches
				that of the request, if there is a mismatch named logs
				an error.  Some of those error messages incorrectly
				used RCODE instead of OPCODE to lookup the nemonic.
				This has been corrected. [GL !6420]

	5902.	[func]		NXDOMAIN cache records are no longer retained in
				the cache after expiry, even when serve-stale is
				in use. [GL #3386]

	5901.	[bug]		When processing a catalog zone member zone make sure
				that there is no configured pre-existing forward-only
				forward zone with that name. [GL #2506]

	5900.	[placeholder]

.. code-block:: none

		--- 9.19.2 released ---

	5899.	[func]		Don't try to process DNSSEC-related and ZONEMD records
				in catz. [GL #3380]

	5898.	[cleanup]	Simplify BIND's internal DNS name compression API. As
				RFC 6891 explains, it isn't practical to deploy new
				label types or compression methods, so it isn't
				necessary to have an API designed to support them.
				Remove compression terminology that refers to Internet
				Drafts that expired in the 1990s. [GL !6270]

	5897.	[bug]		Views that weren't configured to use RFC 5011 key
				management would still set up an empty managed-keys
				zone. This has been fixed. [GL #3349]

	5896.	[func]		Add some more dnssec-policy checks to detect weird
				policies. [GL #1611]

	5895.	[test]		Add new set of unit test macros and move the unit
				tests under single namespace in /tests/. [GL !6243]

	5894.	[func]		Avoid periodic interface re-scans on Linux by
				default, where a reliable event-based mechanism for
				detecting interface state changes is available.
				[GL #3064]

	5893.	[func]		Add TLS session resumption support to the client-side
				TLS code. [GL !6274]

	5892.	[cleanup]	Refactored the the hash tables in resolver.c to
				use the isc_ht API. [GL !6271]

	5891.	[func]		Key timing options for `dnssec-settime` and related
				utilities now accept "UNSET" times as printed by
				`dnssec-settime -p`. [GL #3361]

	5890.	[bug]		When the fetches-per-server quota was adjusted
				because of an authoritative server timing out more
				or less frequently, it was incorrectly set to 1
				rather than the intended value.  This has been
				fixed. [GL #3327]

	5889.	[cleanup]	Refactored and simplified the shutdown processes in
				dns_view, dns_resolver, dns_requestmgr, and dns_adb
				by reducing interdependencies between the objects.
				[GL !6278]

	5888.	[bug]		Only write key files if the dnssec-policy keymgr has
				changed the metadata. [GL #3302]

	5887.	[cleanup]	Remove the on-shutdown mechanics from isc_task API.
				Replace it by isc_task_send() when we are shutting
				down. [GL !6275]

.. code-block:: none

		--- 9.19.1 released ---

	5886.	[security]	Fix a crash in DNS-over-HTTPS (DoH) code caused by
				premature TLS stream socket object deletion.
				(CVE-2022-1183) [GL #3216]

	5885.	[bug]		RPZ NSIP and NSDNAME rule processing didn't handle stub
				and static-stub zones at or above the query name.  This
				has now been addressed. [GL #3232]

	5884.	[cleanup]	Reduce struct padding in ADB address entries, and use a
				binary hash function to find addresses. [GL !6219]

	5883.	[cleanup]	Move netmgr/uv-compat.{c,h} to <isc/uv.h>, so
				the compatibility libuv shims could be used outside
				the network manager. [GL !6199]

	5882.	[contrib]	Avoid name space collision in dlz modules by prefixing
				functions with 'dlz_'. [GL !5778]

	5881.	[placeholder]

	5880.	[func]		Add new named command-line option -C to print built-in
				defaults. [GL #1326]

	5879.	[contrib]	dlz: Add FALLTHROUGH and UNREACHABLE macros. [GL #3306]

	5878.	[func]		Check the algorithm name or OID embedded at the start
				of the signature field for PRIVATEDNS and PRIVATEOID
				SIG and RRSIG records are well formed. [GL #3296]

	5877.	[func]		Introduce the concept of broken catalog zones described
				in the DNS catalog zones draft version 5 document.
				[GL #3224]

	5876.	[func]		Add DNS Extended Errors when stale answers are returned
				from cache. [GL #2267]

	5875.	[bug]		Fixed a deadlock that could occur if an rndc
				connection arrived during the shutdown of network
				interfaces. [GL #3272]

	5874.	[placeholder]

	5873.	[bug]		Refactor the fctx_done() function to set fctx to
				NULL after detaching, so that reference counting
				errors will be easier to avoid. [GL #2969]

	5872.	[bug]		udp_recv() in dispatch could trigger an INSIST when the
				callback's result indicated success but the response
				was canceled in the meantime. [GL #3300]

	5871.	[bug]		Fix dig hanging on TLS context creation errors.
				[GL #3285]

	5870.	[cleanup]	Remove redundant macros in the RBT implementation.
				[GL !6158]

	5869.	[func]		Enable use of IP(V6)_RECVERR on Linux that allows
				the kernel to report destination host/network
				unreachable errors to the userspace application.
				[GL #4251]

	5868.	[cleanup]	Use Daniel Lemire's "nearly divisionless" algorithm
				for unbiased bounded random numbers, and move
				re-seeding out of the hot path. [GL !6161]

	5867.	[bug]		Fix assertion failure triggered by attaching to dns_adb
				in dns_adb_createfind() that has been triggered to shut
				down in different thread between the check for shutting
				down condition and the attach to dns_adb. [GL #3298]

	5866.	[bug]		Work around a jemalloc quirk which could trigger an
				out-of-memory condition in named over time. [GL #3287]

	5865.	[func]		Make statistics channel and control channel listen
				on a single network manager thread. [GL !6032]

	5864.	[func]		The OID embedded at the start of a PRIVATEOID public
				key in a KEY, DNSKEY, CDNSKEY, or RKEY RR is now
				checked for validity when reading from wire or from
				zone files, and the OID is printed when
				'dig +rrcomments' is used. Similarly, the name
				embedded at the start of a PRIVATEDNS public key
				is also checked for validity. [GL #3234]

	5863.	[bug]		If there was a pending negative cache DS entry,
				validations depending upon it could fail. [GL #3279]

	5862.	[bug]		dig returned a 0 exit status on UDP connection failure.
				[GL #3235]

	5861.	[func]		Implement support for catalog zones change of ownership
				(coo) mechanism described in the DNS catalog zones draft
				version 5 document. [GL #3223]

	5860.	[func]		Implement support for catalog zones options new syntax
				based on catalog zones custom properties with "ext"
				suffix described in the DNS catalog zones draft version
				5 document. [GL #3222]

	5859.	[bug]		Fix an assertion failure when using dig with +nssearch
				and +tcp options by starting the next query in the
				send_done() callback (like in the UDP mode) instead
				of doing that recursively in start_tcp(). Also
				ensure that queries interrupted while connecting
				are detached properly. [GL #3144]

	5858.	[bug]		Don't remove CDS/CDNSKEY DELETE records on zone sign
				when using 'auto-dnssec maintain;'. [GL #2931]

	5857.	[bug]		Fixed a possible crash during shutdown due to ADB
				entries being unlinked from the hash table too
				soon. [GL #3256]

.. code-block:: none

		--- 9.19.0 released ---

	5856.	[bug]		The "starting maxtime timer" message related to outgoing
				zone transfers was incorrectly logged at the ERROR level
				instead of DEBUG(1). [GL #3208]

	5855.	[bug]		Ensure that zone maintenance queries have a retry limit.
				[GL #3242]

	5854.	[func]		Implement reference counting for TLS contexts and
				allow reloading of TLS certificates on reconfiguration
				without destroying the underlying TCP listener sockets
				for TLS-based DNS transports. [GL #3122]

	5853.	[bug]		When using both the `+qr` and `+y` options `dig` could
				crash if the connection to the first server was not
				successful. [GL #3244]

	5852.	[func]		Add new "reuseport" option to enable/disable load
				balancing of sockets. [GL #3249]

	5851.	[placeholder]

	5850.	[func]		Run the RPZ update process on the offload threads.
				[GL #3190]

	5849.	[cleanup]	Remove use of exclusive mode in ns_interfacemgr in
				favor of rwlocked access to localhost and localnets
				members of dns_aclenv_t structure. [GL #3229]

	5848.	[bug]		dig could hang in some cases involving multiple servers
				in a lookup, when a request fails and the next one
				refuses to start for some reason, for example if it was
				an IPv4 mapped IPv6 address. [GL #3248]

	5847.	[cleanup]	Remove task privileged mode in favor of processing
				all events in the loadzone task in a single run
				by setting the quantum to UINT_MAX. [GL #3253]

	5846.	[func]		In dns_zonemgr, create per-thread task, zonetask, and
				loadtask and pin the zones to individual threads,
				instead of having "many", spreading the zones among
				them and hoping for the best.  This also removes any
				need to dynamically reallocate the pools with memory
				contexts and tasks. [GL #3226]

	5845.	[bug]		Refactor the timer to keep track of posted events
				as to use isc_task_purgeevent() instead of using
				isc_task_purgerange().  The isc_task_purgeevent()
				has been refactored to purge a single event instead
				of walking through the list of posted events.
				[GL #3252]

	5844.	[bug]		dig +nssearch was hanging until manually interrupted.
				[GL #3145]

	5843.	[bug]		When an UPDATE targets a zone that is not configured,
				the requested zone name is now logged in the "not
				authoritative" error message, so that it is easier to
				track down problematic update clients. [GL #3209]

	5842.	[cleanup]	Remove the task exclusive mode use in ns_clientmgr.
				[GL #3230]

	5841.	[bug]		Refactor the address database:
				- Use self-resizing hash tables, eliminating the
				  need to go into task-exclusive mode when resizing.
				- Simplify reference counting of ADB objects
				  and the process for shutting down. [GL #3213]

	5840.	[cleanup]	Remove multiple application context use in dns_client
				unit. [GL !6041]

	5839.	[func]		Add support for remote TLS certificates
				verification, both to BIND and dig, making it possible
				to implement Strict and Mutual TLS authentication,
				as described in RFC 9103, Section 9.3. [GL #3163]

	5838.	[cleanup]	When modifying a member zone in a catalog zone, and it
				is detected that the zone exists and was not created by
				the current catalog zone, distinguish the two cases when
				the zone was not added by a catalog zone at all, and
				when the zone was added by a different catalog zone,
				and log a warning message accordingly. [GL #3221]

	5837.	[func]		Key timing options for `dnssec-keygen` and
				`dnssec-settime` now accept times as printed by
				`dnssec-settime -p`. [GL !2947]

	5836.	[bug]		Quote the dns64 prefix in error messages that complain
				about problems with it, to avoid confusion with the
				following dns64 ACLs. [GL #3210]

	5835.	[cleanup]	Remove extrahandlesize from the netmgr, the callers
				now have to allocate the object before calling
				isc_nm_setdata() and deallocate the memory in the close
				callback passed to isc_nm_setdata(). [GL #3227]

	5834.	[cleanup]	C99 variable-length arrays are difficult to use safely,
				so avoid them except in test code. [GL #3201]

	5833.	[bug]		When encountering socket error while trying to initiate
				a TCP connection to a server, dig could hang
				indefinitely, when there were more servers to try.
				[GL #3205]

	5832.	[bug]		When timing-out or having other types of socket errors
				during a query, dig wasn't trying to perform the lookup
				using other servers, in case they exist. [GL #3128]

	5831.	[bug]		When resending a UDP request in the result of a timeout,
				the recv_done() function in dighost.c was prepending
				the new query into the loookup's queries list instead
				of inserting, which could cause an assertion failure
				when the resent query's result was SERVFAIL. [GL #3020]

	5830.	[func]		Implement incremental resizing of isc_ht hash tables to
				perform the rehashing gradually. The catalog zone
				implementation has been optimized to work with hundreds
				of thousands of member zones. [GL #3212] [GL #3744]

	5829.	[func]		Refactor and simplify isc_timer API in preparation
				for further refactoring on top of network manager
				loops. [GL #3202]

	5828.	[bug]		Replace single TCP write timer with per-TCP write
				timers. [GL #3200]

	5827.	[cleanup]	The command-line utilities printed their version numbers
				inconsistently; they all now print to stdout. (They are
				still inconsistent abotut whether you use `-v` or `-V`
				to request the version). [GL #3189]

	5826.	[cleanup]	Stop dig from complaining about lack of IDN support when
				the user asks for no IDN translation. [GL #3188]

	5825.	[func]		Set the minimum MTU on UDPv6 and TCPv6 sockets and
				limit TCP maximum segment size (TCP_MAXSEG) to (1220)
				for both TCPv4 and TCPv6 sockets. [GL #2201]

	5824.	[bug]		Invalid dnssec-policy definitions were being accepted
				where the defined keys did not cover both KSK and ZSK
				roles for a given algorithm.  This is now checked for
				and the dnssec-policy is rejected if both roles are
				not present for all algorithms in use. [GL #3142]

	5823.	[func]		Replace hazard pointers based lock-free list with
				locked-list based queue that's simpler and has no or
				little performance impact. [GL #3180]

	5822.	[bug]		When calling dns_dispatch_send(), attach/detach
				dns_request_t object as the read callback could
				be called before send callback dereferencing
				dns_request_t object too early. [GL #3105]

	5821.	[bug]		Fix query context management issues in the TCP part
				of dig. [GL #3184]

	5820.	[security]	An assertion could occur in resume_dslookup() if the
				fetch had been shut down earlier. (CVE-2022-0667)
				[GL #3129]

	5819.	[security]	Lookups involving a DNAME could trigger an INSIST when
				"synth-from-dnssec" was enabled. (CVE-2022-0635)
				[GL #3158]

	5818.	[security]	A synchronous call to closehandle_cb() caused
				isc__nm_process_sock_buffer() to be called recursively,
				which in turn left TCP connections hanging in the
				CLOSE_WAIT state blocking indefinitely when
				out-of-order processing was disabled. (CVE-2022-0396)
				[GL #3112]

	5817.	[security]	The rules for acceptance of records into the cache
				have been tightened to prevent the possibility of
				poisoning if forwarders send records outside
				the configured bailiwick. (CVE-2021-25220) [GL #2950]

	5816.	[bug]		Make BIND compile with LibreSSL 3.5.0, as it was using
				not very accurate pre-processor checks for using shims.
				[GL #3172]

	5815.	[bug]		If an oversized key name of a specific length was used
				in the text form of an HTTP or SVBC record, an INSIST
				could be triggered when parsing it. [GL #3175]

	5814.	[bug]		The RecursClients statistics counter could underflow
				in certain resolution scenarios. [GL #3147]

	5813.	[func]		The "keep-response-order" ACL has been declared
				obsolete, and is now non-operational. [GL #3140]

	5812.	[func]		Drop the artificial limit on the number of queries
				processed in a single TCP read callback. [GL #3141]

	5811.	[bug]		Reimplement the maximum and idle timeouts for outgoing
				zone tranfers. [GL #1897]

	5810.	[func]		New option '-J' for dnssec-signzone and dnssec-verify
				allows loading journal files. [GL #2486]

	5809.	[bug]		Reset client TCP connection when data received cannot
				be parsed as a valid DNS request. [GL #3149]

	5808.	[bug]		Certain TCP failures were not caught and handled
				correctly by the dispatch manager, causing
				connections to time out rather than returning
				SERVFAIL. [GL #3133]

	5807.	[bug]		Add a TCP "write" timer, and time out writing
				connections after the "tcp-idle-timeout" period
				has elapsed. [GL #3132]

	5806.	[bug]		An error in checking the "blackhole" ACL could cause
				DNS requests sent by named to fail if the
				destination address or prefix was specifically
				excluded from the ACL. [GL #3157]

	5805.	[func]		The result of each resolver priming attempt is now
				included in the "resolver priming query complete" log
				message. [GL #3139]

	5804.	[func]		Add a debug log message when starting and ending
				the task exclusive mode. [GL #3137]

	5803.	[func]		Use compile-time paths in the documentation.
				[GL #2717]

	5802.	[test]		Add system test to test engine_pkcs11. [GL !5727]

	5801.	[bug]		Log "quota reached" message when hard quota
				is reached when accepting a connection. [GL #3125]

	5800.	[func]		Add ECS support to the DLZ interface. [GL #3082]

	5799.	[bug]		Use L1 cache-line size detected at runtime. [GL #3108]

	5798.	[test]		Add system test to test dnssec-keyfromlabel. [GL #3092]

	5797.	[bug]		A failed view configuration during a named
				reconfiguration procedure could cause inconsistencies
				in BIND internal structures, causing a crash or other
				unexpected errors. [GL #3060]

	5796.	[bug]		Ignore the invalid (<= 0) values returned
				by the sysconf() check for the L1 cache line
				size.  [GL #3108]

	5795.	[bug]		rndc could crash when interrupted by a signal
				before receiving a response. [GL #3080]

	5794.	[func]		Set the IPV6_V6ONLY on all IPv6 sockets to
				restrict the IPv6 sockets to sending and
				receiving IPv6 packets only. [GL #3093]

	5793.	[bug]		Correctly detect and enable UDP recvmmsg support
				in all versions of libuv that support it. [GL #3095]

	5792.	[bug]		Don't schedule zone events on ISC_R_SHUTTINGDOWN
				event failures. [GL #3084]

	5791.	[func]		Remove workaround for servers returning FORMERR
				when receiving NOTIFY query with SOA record in
				ANSWER section. [GL #3086]

	5790.	[bug]		The control channel was incorrectly looking for
				ISC_R_CANCELED as a signal that the named is
				shutting down.  In the dispatch refactoring,
				the result code returned from network manager
				is now ISC_R_SHUTTINGDOWN.  Change the control
				channel code to use ISC_R_SHUTTINGDOWN result
				code to detect named being shut down. [GL #3079]

.. code-block:: none

		--- 9.17.22 released ---

	5789.	[bug]		Allow replacing expired zone signatures with
				signatures created by the KSK. [GL #3049]

	5788.	[bug]		An assertion could occur if a catalog zone event was
				scheduled while the task manager was being shut
				down. [GL #3074]

	5787.	[doc]		Update 'auto-dnssec' documentation, it may only be
				activated at zone level. [GL #3023]

	5786.	[bug]		Defer detaching from zone->raw in zone_shutdown() if
				the zone is in the process of being dumped to disk, to
				ensure that the unsigned serial number information is
				always written in the raw-format header of the signed
				version on an inline-signed zone. [GL #3071]

	5785.	[bug]		named could leak memory when two dnssec-policy clauses
				had the same name. named failed to log this error.
				[GL #3085]

	5784.	[func]		Implement TLS-contexts reuse. Reusing the
				previously created TLS context objects can reduce
				initialisation time for some configurations and enables
				TLS session resumption for incoming zone transfers over
				TLS (XoT). [GL #3067]

	5783.	[func]		named is now able to log TLS pre-master secrets for
				debugging purposes. This requires setting the
				SSLKEYLOGFILE environment variable appropriately.
				[GL #2723]

	5782.	[func]		Use ECDSA P-256 instead of a 4096-bit RSA when
				generating ephemeral key and certificate for the
				'tls ephemeral' configuration. [GL #2264]

	5781.	[bug]		Make BIND work with OpenSSL 3.0.1 as it is now
				enforcing minimum buffer lengths in EVP_MAC_final and
				hence EVP_DigestSignFinal.  rndc and TSIG at a minimum
				were broken by this change. [GL #3057]

	5780.	[bug]		The Linux kernel may send netlink messages
				indicating that network interfaces have changed
				when they have not. This caused frequent unnecessary
				re-scans of the interfaces.  Netlink messages now
				only trigger re-scanning if a new address is seen
				or an existing address is removed. [GL #3055]

	5779.	[test]		Drop cppcheck suppressions and workarounds. [GL #2886]

	5778.	[bug]		Destroyed TLS contexts could have been used after a
				reconfiguration, making BIND unable to serve queries
				over TLS and HTTPS. [GL #3053]

	5777.	[bug]		TCP connections could hang after receiving
				non-matching responses. [GL #3042]

	5776.	[bug]		Add a missing isc_condition_destroy() for nmsocket
				condition variable and add missing isc_mutex_destroy()
				for nmworker lock. [GL #3051]

.. code-block:: none

		--- 9.17.21 released ---

	5775.	[bug]		Added a timer in the resolver to kill fetches that
				have deadlocked as a result of dependency loops
				with the ADB or the validator. This condition is
				now logged with the message "shut down hung fetch
				while resolving '<name>/<type>'". [GL #3040]

	5774.	[func]		Restore NSEC Aggressive Cache ("synth-from-dnssec")
				as active by default. It is limited to NSEC only
				and by default ignores NSEC records with next name
				in form \000.domain. [GL #1265]

	5773.	[func]		Change the message when accepting TCP connection has
				failed to say "Accepting TCP connection failed" and
				change the log level for ISC_R_NOTCONNECTED, ISC_R_QUOTA
				and ISC_R_SOFTQUOTA results codes from ERROR to INFO.
				[GL #2700]

	5772.	[bug]		The resolver could hang on shutdown due to dispatch
				resources not being cleaned up when a TCP connection
				was reset. [GL #3026]

	5771.	[bug]		Use idn2 UseSTD3ASCIIRules=false to disable additional
				unicode validity checks because enabling the additional
				checks would break valid domain names that contains
				non-alphanumerical characters such as underscore
				character (_) or wildcard (*).  This reverts change
				[GL !5738] from the previous release. [GL #1610]

	5770.	[func]		BIND could abort on startup on systems using old
				OpenSSL versions when 'protocols' option is used inside
				a 'tls' statement. [GL !5602]

	5769.	[func]		Added support for client-side 'tls' parameters when
				doing incoming zone transfers via XoT. [GL !5602]

	5768.	[bug]		dnssec-dsfromkey failed to omit revoked keys. [GL #853]

	5767.	[func]		Extend allow-transfer option with 'port' and
				'transport' options to restrict zone transfers to
				a specific port and DNS transport protocol.
				[GL #2776]

	5766.	[func]		Unused 'tls' clause options 'ca-file' and 'hostname'
				were disabled. [GL !5600]

	5765.	[bug]		Fix a bug in DoH implementation making 'dig'
				abort when ALPN negotiation fails. [GL #3022]

	5764.	[bug]		dns_sdlz_putrr failed to process some valid resource
				records. [GL #3021]

	5763.	[bug]		Fix a bug in DoT code leading to an abort when
				a zone transfer ends with an unexpected DNS message.
				[GL #3004]

	5762.	[bug]		Fix a "named" crash related to removing and restoring a
				`catalog-zone` entry in the configuration file and
				running `rndc reconfig`. [GL #1608]

	5761.	[bug]		OpenSSL 3.0.0 support could fail to correctly read
				ECDSA private keys leading to incorrect signatures
				being generated. [GL #3014]

	5760.	[bug]		Prevent a possible use-after-free error in resolver.
				[GL #3018]

	5759.	[func]		Set Extended DNS Error Code 18 - Prohibited if query
				access is denied to the specific client. [GL #1836]

	5758.	[bug]		mdig now honors the operating system's preferred
				ephemeral port range. [GL #2374]

	5757.	[test]		Replace sed in nsupdate system test with awk to
				construct the nsupdate command.  The sed expression
				was not reliably changing the ttl. [GL #3003]

	5756.	[func]		Assign HTTP freshness lifetime to responses sent
				via DNS-over-HTTPS, according to the recommendations
				given in RFC 8484. [GL #2854]

.. code-block:: none

		--- 9.17.20 released ---

	5755.	[bug]		The statistics channel wasn't correctly handling
				multiple HTTP requests, or pipelined or truncated
				requests. [GL #2973]

	5754.	[bug]		"tls" statements may omit "key-file" and "cert-file",
				but if either one is specified, then both must be.
				[GL #2986]

	5753.	[placeholder]

	5752.	[bug]		Fix an assertion failure caused by missing member zones
				during a reload of a catalog zone. [GL #2308]

	5751.	[port]		Add support for OpenSSL 3.0.0.  OpenSSL 3.0.0
				deprecated 'engine' support.  If OpenSSL 3.0.0 has
				been built without support for deprecated functionality
				pkcs11 via engine_pkcs11 is no longer available.
				[GL #2843]

	5750.	[bug]		Fix a bug when comparing two RSA keys. There was a typo
				which caused the "p" prime factors to not being
				compared. [GL #2972]

	5749.	[bug]		Handle duplicate references to the same catalog
				zone gracefully. [GL #2916]

	5748.	[func]		Update "nsec3param" defaults to iterations 0, salt
				length 0. [GL #2956]

	5747.	[func]		Update rndc serve-stale status output to be less
				confusing. [GL #2742]

	5746.	[bug]		A lame server delegation could lead to a loop in which
				a resolver fetch depends on an ADB find which depends
				on the same resolver fetch. Previously, this would
				cause the fetch to hang until timing out, but after
				change #5730 it would hang forever. The condition is
				now detected and avoided. [GL #2927]

	5745.	[bug]		Fetch context objects now use attach/detach
				semantics to make it easier to find and debug
				reference-counting errors, and several such errors
				have been fixed. [GL #2953]

	5744.	[func]		The network manager is now used for netlink sockets
				to monitor network interface changes. This was the
				last remaining use of the old isc_socket and
				isc_socketmgr APIs, so they have now been removed.
				The "named -S" argument and the "reserved-sockets"
				option in named.conf have no function now, and are
				deprecated. "socketmgr" statistics are no longer
				reported in the statistics channel. [GL #2926]

	5743.	[func]		Add finer-grained "update-policy" rules,
				"krb5-subdomain-self-rhs" and "ms-subdomain-self-rhs",
				which restrict SRV and PTR record changes, allowing
				only records whose content matches the machine name
				embedded in the Kerberos principal making the change.
				[GL #481]

	5742.	[func]		ISC_LIKELY() and ISC_UNLIKELY() macros have been
				removed. [GL #2952]

	5741.	[bug]		Log files with "timestamp" suffixes could be left in
				place after rolling, even if the number of preserved
				log files exceeded the configured "versions" limit.
				[GL #828]

	5740.	[func]		Implement incremental resizing of RBT hash table to
				perform the rehashing gradually. [GL #2941]

	5739.	[func]		Change default of 'dnssec-dnskey-kskonly' to 'yes'.
				[GL #1316]

	5738.	[bug]		Enable idn2 UseSTD3ASCIIRules=true to implement
				additional unicode validity checks. [GL #1610]

	5737.	[bug]		Address Coverity warning in lib/dns/dnssec.c.
				[GL #2935]

.. code-block:: none

		--- 9.17.19 released ---

	5736.	[security]	The "lame-ttl" option is now forcibly set to 0. This
				effectively disables the lame server cache, as it could
				previously be abused by an attacker to significantly
				degrade resolver performance. (CVE-2021-25219)
				[GL #2899]

	5735.	[cleanup]	The result codes which BIND 9 uses internally are now
				all defined as a single list of enum values rather than
				as multiple sets of integers scattered around shared
				libraries. This prevents the need for locking in some
				functions operating on result codes, and makes result
				codes more debugger-friendly. [GL #719]

	5734.	[bug]		Fix intermittent assertion failures in dig which were
				triggered during zone transfers. [GL #2884]

	5733.	[func]		Require the "dot" Application-Layer Protocol Negotiation
				(ALPN) token to be selected in the TLS handshake for
				zone transfers over TLS (XoT), as required by RFC 9103
				section 7.1. [GL #2794]

	5732.	[cleanup]	Remove the dns_lib_init(), dns_lib_shutdown(),
				ns_lib_init(), and ns_lib_shutdown() functions, as they
				no longer served any useful purpose. [GL #88]

	5731.	[bug]		Disallow defining "http" configuration clauses called
				"default" as they were silently ignored. [GL #2925]

	5730.	[func]		The resolver and the request and dispatch managers have
				been substantially refactored, and are now based on the
				network manager instead of the old isc_socket API. All
				outgoing DNS queries and requests now use the new API;
				isc_socket is only used to monitor for network interface
				changes. [GL #2401]

	5729.	[func]		Allow finer control over TLS protocol configuration by
				implementing new options for "tls" configuration clauses
				("dhparam-file", "ciphers", "prefer-server-ciphers",
				"session-tickets"). These options make achieving perfect
				forward secrecy (PFS) possible for DNS-over-TLS (DoT)
				and DNS-over-HTTPS (DoH). [GL #2796]

	5728.	[func]		Allow specifying supported TLS protocol versions for
				each "tls" configuration clause. [GL #2795]

	5727.	[placeholder]

	5726.	[bug]		Fix a use-after-free bug which was triggered while
				checking for duplicate "http" configuration clauses.
				[GL #2924]

	5725.	[bug]		Fix an assertion failure triggered by passing an invalid
				HTTP path to dig. [GL #2923]

	5724.	[bug]		Address a potential deadlock when checking zone content
				consistency. [GL #2908]

	5723.	[bug]		Change 5709 broke backward compatibility for the
				"check-names master ..." and "check-names slave ..."
				options. This has been fixed. [GL #2911]

	5722.	[bug]		Preserve the contents of the receive buffer for TCPDNS
				and TLSDNS when growing its size. [GL #2917]

	5721.	[func]		A new realloc()-like function, isc_mem_reget(), was
				added to the libisc API for resizing memory chunks
				allocated using isc_mem_get(). Memory (re)allocation
				functions are now guaranteed to return non-NULL pointers
				for zero-sized allocation requests. [GL !5440]

	5720.	[contrib]	Remove old-style DLZ drivers that had to be enabled at
				build time. [GL #2814]

	5719.	[func]		Remove support for the "map" zone file format.
				[GL #2882]

	5718.	[bug]		The "sig-signing-type" zone configuration option was
				processed incorrectly, causing valid configurations to
				be rejected. This has been fixed. [GL #2906]

	5717.	[func]		The "cache-file" option, which was documented as "for
				testing purposes only" and not to be used, has been
				removed. [GL #2903]

	5716.	[placeholder]

	5715.	[func]		Add a check for ports specified in "*-source(-v6)"
				options clashing with a global listening port. Such a
				configuration was already unsupported, but it failed
				silently; it is now treated as an error. [GL #2888]

	5714.	[bug]		Remove the "adjust interface" mechanism which was
				responsible for setting up listeners on interfaces when
				the "*-source(-v6)" address and port were the same as
				the "listen-on(-v6)" address and port. Such a
				configuration is no longer supported; under certain
				timing conditions, that mechanism could prevent named
				from listening on some TCP ports. This has been fixed.
				[GL #2852]

	5713.	[func]		Add "primaries" as a synonym for "masters" and
				"default-primaries" as a synonym for "default-masters"
				in catalog zone configuration options. [GL #2818]

	5712.	[func]		Remove native PKCS#11 support in favor of engine_pkcs11
				from the OpenSC project. [GL #2691]

.. code-block:: none

		--- 9.17.18 released ---

	5711.	[bug]		"map" files exceeding 2GB in size failed to load due to
				a size comparison that incorrectly treated the file size
				as a signed integer. [GL #2878]

	5710.	[placeholder]

	5709.	[func]		When reporting zone types in the statistics channel, the
				terms "primary" and "secondary" are now used instead of
				"master" and "slave", respectively. Enum values
				throughout the code have been updated to use this
				terminology as well. [GL #1944]

	5708.	[placeholder]

	5707.	[bug]		A bug was fixed which prevented dig from querying
				DNS-over-HTTPS (DoH) servers via IPv6. [GL #2860]

	5706.	[cleanup]	Support for external applications to register with
				libisc and use it has been removed. Export versions of
				BIND 9 libraries have not been supported for some time,
				but the isc_lib_register() function was still available;
				it has now been removed. [GL !2420]

	5705.	[bug]		Change #5686 altered the internal memory structure of
				zone databases, but neglected to update the MAPAPI value
				for zone files in "map" format. This caused named to
				attempt to load incompatible map files, triggering an
				assertion failure on startup. The MAPAPI value has now
				been updated, so named rejects outdated files when
				encountering them. [GL #2872]

	5704.	[bug]		Change #5317 caused the EDNS TCP Keepalive option to be
				ignored inadvertently in client requests. It has now
				been fixed and this option is handled properly again.
				[GL #1927]

	5703.	[bug]		Fix a crash in dig caused by closing an HTTP/2 socket
				associated with an unused HTTP/2 session. [GL #2858]

	5702.	[bug]		Improve compatibility with DNS-over-HTTPS (DoH) clients
				by allowing HTTP/2 request headers in any order.
				[GL #2875]

	5701.	[bug]		named-checkconf failed to detect syntactically invalid
				values of the "key" and "tls" parameters used to define
				members of remote server lists. [GL #2461]

	5700.	[bug]		When a member zone was removed from a catalog zone,
				journal files for the former were not deleted.
				[GL #2842]

	5699.	[func]		Data structures holding DNSSEC signing statistics are
				now grown and shrunk as necessary upon key rollover
				events. [GL #1721]

	5698.	[bug]		When a DNSSEC-signed zone which only has a single
				signing key available is migrated to use KASP, that key
				is now treated as a Combined Signing Key (CSK).
				[GL #2857]

	5697.	[func]		dnssec-cds now only generates SHA-2 DS records by
				default and avoids copying deprecated SHA-1 records from
				a child zone to its delegation in the parent. If the
				child zone does not publish SHA-2 CDS records,
				dnssec-cds will generate them from the CDNSKEY records.
				The "-a algorithm" option now affects the process of
				generating DS digest records from both CDS and CDNSKEY
				records. Thanks to Tony Finch. [GL #2871]

	5696.	[protocol]	Support for HTTPS and SVCB record types has been added.
				[GL #1132]

	5695.	[func]		Add a new dig command-line option, "+showbadcookie",
				which causes a BADCOOKIE response message to be
				displayed when it is received from the server.
				[GL #2319]

	5694.	[bug]		Stale data in the cache could cause named to send
				non-minimized queries despite QNAME minimization being
				enabled. [GL #2665]

	5693.	[func]		Restore support for reading "timeout" and "attempts"
				options from /etc/resolv.conf, and use their values in
				dig, host, and nslookup. (This was previously supported
				by liblwres, and was still mentioned in the man pages,
				but had stopped working after liblwres was deprecated in
				favor of libirs.) [GL #2785]

	5692.	[bug]		Fix a rare crash in DNS-over-HTTPS (DoH) code caused by
				detaching from an HTTP/2 session handle too early when
				sending data. [GL #2851]

	5691.	[bug]		When a dynamic zone was made available in another view
				using the "in-view" statement, running "rndc freeze"
				always reported an "already frozen" error even though
				the zone was successfully frozen. [GL #2844]

	5690.	[func]		dnssec-signzone now honors Predecessor and Successor
				metadata found in private key files: if a signature for
				an RRset generated by the inactive predecessor exists
				and does not need to be replaced, no additional
				signature is now created for that RRset using the
				successor key. This enables dnssec-signzone to gradually
				replace RRSIGs during a ZSK rollover. [GL #1551]

.. code-block:: none

		--- 9.17.17 released ---

	5689.	[security]	An assertion failure occurred when named attempted to
				send a UDP packet that exceeded the MTU size, if
				Response Rate Limiting (RRL) was enabled.
				(CVE-2021-25218) [GL #2856]

	5688.	[bug]		Zones using KASP and inline-signed zones failed to apply
				changes from the unsigned zone to the signed zone under
				certain circumstances. This has been fixed. [GL #2735]

	5687.	[bug]		"rndc reload <zonename>" could trigger a redundant
				reload for an inline-signed zone whose zone file was not
				modified since the last "rndc reload". This has been
				fixed. [GL #2855]

	5686.	[func]		The number of internal data structures allocated for
				each zone was reduced. [GL #2829]

	5685.	[bug]		named failed to check the opcode of responses when
				performing zone refreshes, stub zone updates, and UPDATE
				forwarding. This has been fixed. [GL #2762]

	5684.	[func]		The DNS-over-HTTP (DoH) configuration syntax was
				extended:
				- The maximum number of active DoH connections can now
				  be set using the "http-listener-clients" option. The
				  default is 300.
				- The maximum number of concurrent HTTP/2 streams per
				  connection can now be set using the
				  "http-streams-per-connection" option. The default is
				  100.
				- Both of these values can also be set on a per-listener
				  basis using the "listener-clients" and
				  "streams-per-connection" parameters in an "http"
				  statement.
				[GL #2809]

	5683.	[bug]		The configuration-checking code now verifies HTTP paths.
				[GL !5231]

	5682.	[bug]		Some changes to "zone-statistics" settings were not
				properly processed by "rndc reconfig". This has been
				fixed. [GL #2820]

	5681.	[func]		Relax the checks in the dns_zone_cdscheck() function to
				allow CDS and CDNSKEY records in the zone that do not
				match an existing DNSKEY record, as long as the
				algorithm matches. This allows a clean rollover from one
				provider to another in a multi-signer DNSSEC
				configuration. [GL #2710]

	5680.	[bug]		HTTP GET requests without query strings caused a crash
				in DoH code. This has been fixed. [GL !5268]

	5679.	[func]		Thread affinity is no longer set. [GL #2822]

	5678.	[bug]		The "check DS" code failed to release all resources upon
				named shutdown when a refresh was in progress. This has
				been fixed. [GL #2811]

	5677.	[func]		Previously, named accepted FORMERR responses both with
				and without an OPT record, as an indication that a given
				server did not support EDNS. To implement full
				compliance with RFC 6891, only FORMERR responses without
				an OPT record are now accepted. This intentionally
				breaks communication with servers that do not support
				EDNS and that incorrectly echo back the query message
				with the RCODE field set to FORMERR and the QR bit set
				to 1. [GL #2249]

	5676.	[func]		Memory allocation has been substantially refactored; it
				is now based on the memory allocation API provided by
				the jemalloc library, which is a new optional build
				dependency for BIND 9. [GL #2433]

	5675.	[bug]		Compatibility with DoH clients has been improved by
				ignoring the value of the "Accept" HTTP header.
				[GL !5246]

	5674.	[bug]		A shutdown hang was triggered by DoH clients prematurely
				aborting HTTP/2 streams. This has been fixed. [GL !5245]

	5673.	[func]		Add a new build-time option, --disable-doh, to allow
				building BIND 9 without the libnghttp2 library.
				[GL #2478]

	5672.	[bug]		Authentication of rndc messages could fail if a
				"controls" statement was configured with multiple key
				algorithms for the same listener. This has been fixed.
				[GL #2756]

.. code-block:: none

		--- 9.17.16 released ---

	5671.	[bug]		A race condition could occur where two threads were
				competing for the same set of key file locks, leading to
				a deadlock. This has been fixed. [GL #2786]

	5670.	[bug]		create_keydata() created an invalid placeholder keydata
				record upon a refresh failure, which prevented the
				database of managed keys from subsequently being read
				back. This has been fixed. [GL #2686]

	5669.	[func]		KASP support was extended with the "check DS" feature.
				Zones with "dnssec-policy" and "parental-agents"
				configured now check for DS presence and can perform
				automatic KSK rollovers. [GL #1126]

	5668.	[bug]		Rescheduling a setnsec3param() task when a zone failed
				to load on startup caused a hang on shutdown. This has
				been fixed. [GL #2791]

	5667.	[bug]		The configuration-checking code failed to account for
				the inheritance rules of the "dnssec-policy" option.
				This has been fixed. [GL #2780]

	5666.	[doc]		The safe "edns-udp-size" value was tweaked to match the
				probing value from BIND 9.16 for better compatibility.
				[GL #2183]

	5665.	[bug]		If nsupdate sends an SOA request and receives a REFUSED
				response, it now fails over to the next available
				server. [GL #2758]

	5664.	[func]		For UDP messages larger than the path MTU, named now
				sends an empty response with the TC (TrunCated) bit set.
				In addition, setting the DF (Don't Fragment) flag on
				outgoing UDP sockets was re-enabled. [GL #2790]

	5663.	[bug]		Non-zero OPCODEs are now properly handled when receiving
				queries over DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH)
				channels. [GL #2787]

	5662.	[bug]		Views with recursion disabled are now configured with a
				default cache size of 2 MB unless "max-cache-size" is
				explicitly set. This prevents cache RBT hash tables from
				being needlessly preallocated for such views. [GL #2777]

	5661.	[bug]		Change 5644 inadvertently introduced a deadlock: when
				locking the key file mutex for each zone structure in a
				different view, the "in-view" logic was not considered.
				This has been fixed. [GL #2783]

	5660.	[bug]		The configuration-checking code failed to account for
				the inheritance rules of the "key-directory" option.
				[GL #2778]

				This change was included in BIND 9.17.15.

	5659.	[bug]		When preparing DNS responses, named could replace the
				letters 'W' (uppercase) and 'w' (lowercase) with '\000'.
				This has been fixed. [GL #2779]

				This change was included in BIND 9.17.15.

	5658.	[bug]		Increasing "max-cache-size" for a running named instance
				(using "rndc reconfig") did not cause the hash tables
				used by cache databases to be grown accordingly. This
				has been fixed. [GL #2770]

	5657.	[cleanup]	Support was removed for both built-in atomics in old
				versions of Clang (< 3.6.0) and GCC (< 4.7.0), and
				atomics emulated with a mutex. [GL #2606]

	5656.	[bug]		Named now ensures that large responses work correctly
				over DNS-over-HTTPS (DoH), and that zone transfer
				requests over DoH are explicitly rejected. [GL !5148]

	5655.	[bug]		Signed, insecure delegation responses prepared by named
				either lacked the necessary NSEC records or contained
				duplicate NSEC records when both wildcard expansion and
				CNAME chaining were required to prepare the response.
				This has been fixed. [GL #2759]

	5654.	[port]		Windows support has been removed. [GL #2690]

	5653.	[bug]		A bug that caused the NSEC3 salt to be changed on every
				restart for zones using KASP has been fixed. [GL #2725]

.. code-block:: none

		--- 9.17.14 released ---

	5652.	[bug]		A copy-and-paste error in change 5584 caused the
				IP_DONTFRAG socket option to be enabled instead of
				disabled. This has been fixed. [GL #2746]

	5651.	[func]		Refactor zone dumping to be processed asynchronously via
				the uv_work_t thread pool API. [GL #2732]

	5650.	[bug]		Prevent a crash that could occur if serve-stale was
				enabled and a prefetch was triggered during a query
				restart. [GL #2733]

	5649.	[bug]		If a query was answered with stale data on a server with
				DNS64 enabled, an assertion could occur if a non-stale
				answer arrived afterward. [GL #2731]

	5648.	[bug]		The calculation of the estimated IXFR transaction size
				in dns_journal_iter_init() was invalid. [GL #2685]

	5647.	[func]		The interface manager has been refactored to use fewer
				client manager objects, which in turn use fewer memory
				contexts and tasks. This should result in less
				fragmented memory and better startup performance.
				[GL #2433]

	5646.	[bug]		The default TCP timeout for rndc has been increased to
				60 seconds. This was its original value, but it had been
				inadvertently lowered to 10 when rndc was updated to use
				the network manager. [GL #2643]

	5645.	[cleanup]	Remove the rarely-used dns_name_copy() function and
				rename dns_name_copynf() to dns_name_copy(). [GL !5081]

	5644.	[bug]		Fix a race condition in reading and writing key files
				for zones using KASP and configured in multiple views.
				[GL #1875]

	5643.	[placeholder]

	5642.	[bug]		Zones which are configured in multiple views with
				different values set for "dnssec-policy" and with
				identical values set for "key-directory" are now
				detected and treated as a configuration error.
				[GL #2463]

	5641.	[bug]		Address a potential memory leak in
				dst_key_fromnamedfile(). [GL #2689]

	5640.	[func]		Add new configuration options for setting the size of
				receive and send buffers in the operating system:
				"tcp-receive-buffer", "tcp-send-buffer",
				"udp-receive-buffer", and "udp-send-buffer". [GL #2313]

	5639.	[bug]		Check that the first and last SOA record of an AXFR are
				consistent. [GL #2528]

.. code-block:: none

		--- 9.17.13 released ---

	5638.	[bug]		Improvements related to network manager/task manager
				integration:
				- isc_managers_create() and isc_managers_destroy()
				  functions were added to handle setup and teardown of
				  netmgr, taskmgr, timermgr, and socketmgr, since these
				  require a precise order of operations now.
				- Event queue processing is now quantized to prevent
				  infinite looping.
				- The netmgr can now be paused from within a netmgr
				  thread.
				- Deadlocks due to a conflict between netmgr's
				  pause/resume and listen/stoplistening operations were
				  fixed.
				[GL #2654]

	5637.	[placeholder]

	5636.	[bug]		named and named-checkconf did not report an error when
				multiple zones with the "dnssec-policy" option set were
				using the same zone file. This has been fixed.
				[GL #2603]

	5635.	[bug]		Journal compaction could fail when a journal with
				invalid transaction headers was not detected at startup.
				This has been fixed. [GL #2670]

	5634.	[bug]		If "dnssec-policy" was active and a private key file was
				temporarily offline during a rekey event, named could
				incorrectly introduce replacement keys and break a
				signed zone. This has been fixed. [GL #2596]

	5633.	[doc]		The "inline-signing" option was incorrectly described as
				being inherited from the "options"/"view" levels and was
				incorrectly accepted at those levels without effect.
				This has been fixed. [GL #2536]

	5632.	[func]		Add a new built-in KASP, "insecure", which is used to
				transition a zone from a signed to an unsigned state.
				The existing built-in KASP "none" should no longer be
				used to unsign a zone. [GL #2645]

	5631.	[protocol]	Update the implementation of the ZONEMD RR type to match
				RFC 8976. [GL #2658]

	5630.	[func]		Treat DNSSEC responses containing NSEC3 records with
				iteration counts greater than 150 as insecure.
				[GL #2445]

	5629.	[func]		Reduce the maximum supported number of NSEC3 iterations
				that can be configured for a zone to 150. [GL #2642]

	5628.	[bug]		Host and nslookup could crash upon receiving a SERVFAIL
				response. This has been fixed. [GL #2564]

	5627.	[bug]		RRSIG(SOA) RRsets placed anywhere other than at the zone
				apex were triggering infinite resigning loops. This has
				been fixed. [GL #2650]

	5626.	[bug]		When generating zone signing keys, KASP now also checks
				for key ID conflicts among newly created keys, rather
				than just between new and existing ones. [GL #2628]

	5625.	[bug]		A deadlock could occur when multiple "rndc addzone",
				"rndc delzone", and/or "rndc modzone" commands were
				invoked simultaneously for different zones. This has
				been fixed. [GL #2626]

	5624.	[func]		Task manager events are now processed inside network
				manager loops. The task manager no longer needs its own
				set of worker threads, which improves resolver
				performance. [GL #2638]

	5623.	[bug]		When named was shut down during an ongoing zone
				transfer, xfrin_fail() could incorrectly be called
				twice. This has been fixed. [GL #2630]

	5622.	[cleanup]	The lib/samples/ directory has been removed, as export
				versions of libraries are no longer maintained.
				[GL !4835]

	5621.	[placeholder]

	5620.	[bug]		If zone journal files written by BIND 9.16.11 or earlier
				were present when BIND was upgraded, the zone file for
				that zone could have been inadvertently rewritten with
				the current zone contents. This caused the original zone
				file structure (e.g. comments, $INCLUDE directives) to
				be lost, although the zone data itself was preserved.
				This has been fixed. [GL #2623]

	5619.	[protocol]	Implement draft-vandijk-dnsop-nsec-ttl, updating the
				protocol such that NSEC(3) TTL values are set to the
				minimum of the SOA MINIMUM value or the SOA TTL.
				[GL #2347]

	5618.	[bug]		Change 5149 introduced some inconsistencies in the way
				record TTLs were presented in cache dumps. These
				inconsistencies have been eliminated. [GL #389]
				[GL #2289]

.. code-block:: none

		--- 9.17.12 released ---

	5617.	[placeholder]

	5616.	[security]	named crashed when a DNAME record placed in the ANSWER
				section during DNAME chasing turned out to be the final
				answer to a client query. (CVE-2021-25215) [GL #2540]

	5615.	[security]	Insufficient IXFR checks could result in named serving a
				zone without an SOA record at the apex, leading to a
				RUNTIME_CHECK assertion failure when the zone was
				subsequently refreshed. This has been fixed by adding an
				owner name check for all SOA records which are included
				in a zone transfer. (CVE-2021-25214) [GL #2467]

	5614.	[bug]		Ensure all resources are properly cleaned up when a call
				to gss_accept_sec_context() fails. [GL #2620]

	5613.	[bug]		It was possible to write an invalid transaction header
				in the journal file for a managed-keys database after
				upgrading. This has been fixed. Invalid headers in
				existing journal files are detected and named is able
				to recover from them. [GL #2600]

	5612.	[bug]		Continued refactoring of the network manager:
				- allow recovery from read and connect timeout events,
				- ensure that calls to isc_nm_*connect() always
				  return the connection status via a callback
				  function.
				[GL #2401]

	5611.	[func]		Set "stale-answer-client-timeout" to "off" by default.
				[GL #2608]

	5610.	[bug]		Prevent a crash which could happen when a lookup
				triggered by "stale-answer-client-timeout" was attempted
				right after recursion for a client query finished.
				[GL #2594]

	5609.	[func]		The ISC implementation of SPNEGO was removed from BIND 9
				source code. It was no longer necessary as all major
				contemporary Kerberos/GSSAPI libraries include support
				for SPNEGO. [GL #2607]

	5608.	[bug]		When sending queries over TCP, dig now properly handles
				"+tries=1 +retry=0" by not retrying the connection when
				the remote server closes the connection prematurely.
				[GL #2490]

	5607.	[bug]		As "rndc dnssec -checkds" and "rndc dnssec -rollover"
				commands may affect the next scheduled key event,
				reconfiguration of zone keys is now triggered after
				receiving either of these commands to prevent
				unnecessary key rollover delays. [GL #2488]

	5606.	[bug]		CDS/CDNSKEY DELETE records are now removed when a zone
				transitions from a secure to an insecure state.
				named-checkzone also no longer reports an error when
				such records are found in an unsigned zone. [GL #2517]

	5605.	[bug]		"dig -u" now uses the CLOCK_REALTIME clock source for
				more accurate time reporting. [GL #2592]

	5604.	[experimental]	A "filter-a.so" plugin, which is similar to the
				"filter-aaaa.so" plugin but which omits A records
				instead of AAAA records, has been added. Thanks to
				GitLab user @treysis. [GL #2585]

	5603.	[placeholder]

	5602.	[bug]		Fix TCPDNS and TLSDNS timers in Network Manager. This
				makes the "tcp-initial-timeout" and "tcp-idle-timeout"
				options work correctly again. [GL #2583]

	5601.	[bug]		Zones using KASP could not be thawed after they were
				frozen using "rndc freeze". This has been fixed.
				[GL #2523]

	5600.	[bug]		Send a full certificate chain instead of just the leaf
				certificate to DNS-over-TLS (DoT) and DNS-over-HTTPS
				(DoH) clients. This makes BIND 9 DoT/DoH servers
				compatible with a broader set of clients. [GL #2514]

	5599.	[bug]		Fix a named crash which occurred after skipping a
				primary server while transferring a zone over TLS.
				[GL #2562]

	5598.	[port]		Silence -Wchar-subscripts compiler warnings triggered on
				some platforms due to calling character classification
				functions declared in the <ctype.h> header with
				arguments of type char. [GL #2567]

.. code-block:: none

		--- 9.17.11 released ---

	5597.	[bug]		When serve-stale was enabled and starting the recursive
				resolution process for a query failed, a named instance
				could crash if it was configured as both a recursive and
				authoritative server. This problem was introduced by
				change 5573 and has now been fixed. [GL #2565]

	5596.	[func]		Client-side support for DNS-over-HTTPS (DoH) has been
				added to dig. "dig +https" can now query a server via
				HTTP/2. [GL #1641]

	5595.	[cleanup]	Public header files for BIND 9 libraries no longer
				directly include third-party library headers. This
				prevents the need to include paths to third-party header
				files in CFLAGS whenever BIND 9 public header files are
				used, which could cause build-time issues on hosts with
				older versions of BIND 9 installed. [GL #2357]

	5594.	[bug]		Building with --enable-dnsrps --enable-dnsrps-dl failed.
				[GL #2298]

	5593.	[bug]		Journal files written by older versions of named can now
				be read when loading zones, so that journal
				incompatibility does not cause problems on upgrade.
				Outdated journals are updated to the new format after
				loading. [GL #2505]

	5592.	[bug]		Prevent hazard pointer table overflows on machines with
				many cores, by allowing the thread IDs (serving as
				indices into hazard pointer tables) of finished threads
				to be reused by those created later. [GL #2396]

	5591.	[bug]		Fix a crash that occurred when
				"stale-answer-client-timeout" was triggered without any
				(stale) data available in the cache to answer the query.
				[GL #2503]

	5590.	[bug]		NSEC3 records were not immediately created for dynamic
				zones using NSEC3 with "dnssec-policy", resulting in
				such zones going bogus. Add code to process the
				NSEC3PARAM queue at zone load time so that NSEC3 records
				for such zones are created immediately. [GL #2498]

	5589.	[placeholder]

	5588.	[func]		Add a new "purge-keys" option for "dnssec-policy". This
				option determines the period of time for which key files
				are retained after they become obsolete. [GL #2408]

	5587.	[bug]		A standalone libtool script no longer needs to be
				present in PATH to build BIND 9 from a source tarball
				prepared using "make dist". [GL #2504]

	5586.	[bug]		An invalid direction field in a LOC record resulted in
				an INSIST failure when a zone file containing such a
				record was loaded. [GL #2499]

	5585.	[func]		Memory contexts and memory pool implementations were
				refactored to reduce lock contention for shared memory
				contexts by replacing mutexes with atomic operations.
				The internal memory allocator was simplified so that it
				is only a thin wrapper around the system allocator. This
				change made the "-M external" named option redundant and
				it was therefore removed. [GL #2433]

	5584.	[bug]		No longer set the IP_DONTFRAG option on UDP sockets, to
				prevent dropping outgoing packets exceeding
				"max-udp-size". [GL #2466]

	5583.	[func]		Changes to DNS-over-HTTPS (DoH) configuration syntax:
				- When "http" is specified in "listen-on" or
				  "listen-on-v6" statements, "tls" must also now be
				  specified. If an unencrypted connection is desired
				  (for example, when running behind a reverse proxy),
				  use "tls none".
				- "http default" can now be specified in "listen-on" and
				  "listen-on-v6" statements to use the default HTTP
				  endpoint of "/dns-query". It is no longer necessary to
				  include an "http" statement in named.conf unless
				  overriding this value.
				[GL #2472]

	5582.	[bug]		BIND 9 failed to build when static OpenSSL libraries
				were used and the pkg-config files for libssl and/or
				libcrypto were unavailable. This has been fixed by
				ensuring that the correct linking order for libssl and
				libcrypto is always used. [GL #2402]

	5581.	[bug]		Fix a memory leak that occurred when inline-signed zones
				were added to the configuration, followed by a
				reconfiguration of named. [GL #2041]

	5580.	[test]		The system test framework no longer differentiates
				between SKIPPED and UNTESTED system test results. Any
				system test which is not run is now marked as SKIPPED.
				[GL !4517]

	5579.	[bug]		If an invalid key name (e.g. "a..b") was specified in a
				primaries list in named.conf, the wrong size was passed
				to isc_mem_put(), resulting in the returned memory being
				put on the wrong free list. This prevented named from
				starting up. [GL #2460]

.. code-block:: none

		--- 9.17.10 released ---

	5578.	[protocol]	Make "check-names" accept A records below "_spf",
				"_spf_rate", and "_spf_verify" labels in order to cater
				for the "exists" SPF mechanism specified in RFC 7208
				section 5.7 and appendix D.1. [GL #2377]

	5577.	[bug]		Fix the "three is a crowd" key rollover bug in KASP by
				correctly implementing Equation (2) of the "Flexible and
				Robust Key Rollover" paper. [GL #2375]

	5576.	[experimental]	Initial server-side implementation of DNS-over-HTTPS
				(DoH). Support for both TLS-encrypted and unencrypted
				HTTP/2 connections has been added to the network manager
				and integrated into named. (Note: there is currently no
				client-side support for DNS-over-HTTPS; this will be
				added to dig in a future release.) [GL #1144]

	5575.	[bug]		When migrating to KASP, BIND 9 considered keys with the
				"Inactive" and/or "Delete" timing metadata to be
				possible active keys. This has been fixed. [GL #2406]

	5574.	[func]		Incoming zone transfers can now use TLS. Addresses in a
				"primaries" list take an optional "tls" argument,
				specifying either a previously configured "tls" block or
				"ephemeral"; SOA queries and zone transfer requests are
				then sent via TLS. [GL #2392]

	5573.	[func]		When serve-stale is enabled and stale data is available,
				named now returns stale answers upon encountering any
				unexpected error in the query resolution process.
				However, the "stale-refresh-time" window is still only
				started upon a timeout. [GL #2434]

	5572.	[bug]		Address potential double free in generatexml().
				[GL #2420]

	5571.	[bug]		named failed to start when its configuration included a
				zone with a non-builtin "allow-update" ACL attached.
				[GL #2413]

	5570.	[bug]		Improve performance of the DNSSEC verification code by
				reducing the number of repeated calls to
				dns_dnssec_keyfromrdata(). [GL #2073]

	5569.	[bug]		Emit useful error message when "rndc retransfer" is
				applied to a zone of inappropriate type. [GL #2342]

	5568.	[bug]		Fixed a crash in "dnssec-keyfromlabel" when using ECDSA
				keys. [GL #2178]

	5567.	[bug]		Dig now reports unknown dash options while pre-parsing
				the options. This prevents "-multi" instead of "+multi"
				from reporting memory usage before ending option parsing
				with "Invalid option: -lti". [GL #2403]

	5566.	[func]		Add "stale-answer-client-timeout" option, which is the
				amount of time a recursive resolver waits before
				attempting to answer the query using stale data from
				cache. [GL #2247]

	5565.	[func]		The SONAMEs for BIND 9 libraries now include the current
				BIND 9 version number, in an effort to tightly couple
				internal libraries with a specific release. [GL #2387]

	5564.	[cleanup]	Network manager's TLSDNS module was refactored to use
				libuv and libssl directly instead of a stack of TCP/TLS
				sockets. [GL #2335]

	5563.	[cleanup]	Changed several obsolete configuration options to
				ancient, making them fatal errors. Also cleaned up the
				number of clause flags in the configuration parser.
				[GL #1086]

	5562.	[placeholder]

	5561.	[bug]		KASP incorrectly set signature validity to the value of
				the DNSKEY signature validity. This is now fixed.
				[GL #2383]

	5560.	[func]		The default value of "max-stale-ttl" has been changed
				from 12 hours to 1 day and the default value of
				"stale-answer-ttl" has been changed from 1 second to 30
				seconds, following RFC 8767 recommendations. [GL #2248]

.. code-block:: none

		--- 9.17.9 released ---

	5559.	[bug]		The --with-maxminddb=PATH form of the build-time option
				enabling support for libmaxminddb was not working
				correctly. This has been fixed. [GL #2366]

	5558.	[bug]		Asynchronous hook modules could trigger an assertion
				failure when the fetch handle was detached too late.
				Thanks to Jinmei Tatuya at Infoblox. [GL #2379]

	5557.	[bug]		Prevent RBTDB instances from being destroyed by multiple
				threads at the same time. [GL #2317]

	5556.	[bug]		Further tweak newline printing in dnssec-signzone and
				dnssec-verify. [GL #2359]

	5555.	[placeholder]

	5554.	[bug]		dnssec-signzone and dnssec-verify were missing newlines
				between log messages. [GL #2359]

	5553.	[bug]		When reconfiguring named, removing "auto-dnssec" did not
				turn off DNSSEC maintenance. [GL #2341]

	5552.	[func]		When switching to "dnssec-policy none;", named now
				permits a safe transition to insecure mode and publishes
				the CDS and CDNSKEY DELETE records, as described in RFC
				8078. [GL #1750]

	5551.	[bug]		named no longer attempts to assign threads to CPUs
				outside the CPU affinity set. Thanks to Ole Bjørn
				Hessen. [GL #2245]

	5550.	[func]		dnssec-signzone and named now log a warning when falling
				back to the "increment" SOA serial method. [GL #2058]

	5549.	[protocol]	ipv4only.arpa is now served when DNS64 is configured.
				[GL #385]

	5548.	[placeholder]

	5547.	[placeholder]

.. code-block:: none

		--- 9.17.8 released ---

	5546.	[placeholder]

	5545.	[func]		OS support for load-balanced sockets is no longer
				required to receive incoming queries in multiple netmgr
				threads. [GL #2137]

	5544.	[func]		Restore the default value of "nocookie-udp-size" to 4096
				bytes. [GL #2250]

	5543.	[bug]		Fix UDP performance issues caused by making netmgr
				callbacks asynchronous-only. [GL #2320]

	5542.	[bug]		Refactor netmgr. [GL #1920] [GL #2034] [GL #2061]
				[GL #2194] [GL #2221] [GL #2266] [GL #2283] [GL #2318]
				[GL #2321]

	5541.	[func]		Adjust the "max-recursion-queries" default from 75 to
				100. [GL #2305]

	5540.	[port]		Fix building with native PKCS#11 support for AEP Keyper.
				[GL #2315]

	5539.	[bug]		Tighten handling of missing DNS COOKIE responses over
				UDP by falling back to TCP. [GL #2275]

	5538.	[func]		Add NSEC3 support to KASP. A new option for
				"dnssec-policy", "nsec3param", can be used to set the
				desired NSEC3 parameters. NSEC3 salt collisions are
				automatically prevented during resalting. Salt
				generation is now logged with zone context. [GL #1620]

	5537.	[func]		The query plugin mechanism has been extended
				to support asynchronous operations. For example, a
				plugin can now trigger recursion and resume
				processing when it is complete. Thanks to Jinmei
				Tatuya at Infoblox. [GL #2141]

	5536.	[func]		Dig can now report the DNS64 prefixes in use
				(+dns64prefix). [GL #1154]

	5535.	[bug]		dig/nslookup/host could crash on shutdown after an
				interrupt. [GL #2287] [GL #2288]

	5534.	[bug]		The CNAME synthesized from a DNAME was incorrectly
				followed when the QTYPE was CNAME or ANY. [GL #2280]

.. code-block:: none

		--- 9.17.7 released ---

	5533.	[func]		Add the "stale-refresh-time" option, a time window that
				starts after a failed lookup, during which a stale RRset
				is served directly from cache before a new attempt to
				refresh it is made. [GL #2066]

	5532.	[cleanup]	Unused header files were removed:
				bin/rndc/include/rndc/os.h, lib/isc/timer_p.h,
				lib/isccfg/include/isccfg/dnsconf.h and code related
				to those files. [GL #1913]

	5531.	[func]		Add support for DNS over TLS (DoT) to dig and named.
				dig output now includes the transport protocol used.
				[GL #1816] [GL #1840]

	5530.	[bug]		dnstap did not capture responses to forwarded UPDATE
				requests. [GL #2252]

	5529.	[func]		The network manager API is now used by named to send
				zone transfer requests. [GL #2016]

	5528.	[func]		Convert dig, host, and nslookup to use the network
				manager API. As a side effect of this change, "dig
				+unexpected" no longer works, and has been disabled.
				[GL #2140]

	5527.	[bug]		A NULL pointer dereference occurred when creating an NTA
				recheck query failed. [GL #2244]

	5526.	[bug]		Fix a race/NULL dereference in TCPDNS read. [GL #2227]

	5525.	[placeholder]

	5524.	[func]		Added functionality to the network manager to support
				outgoing DNS queries in addition to incoming ones.
				[GL #2235]

	5523.	[bug]		The initial lookup in a zone transitioning to/from a
				signed state could fail if the DNSKEY RRset was not
				found. [GL #2236]

	5522.	[bug]		Fixed a race/NULL dereference in TCPDNS send. [GL #2227]

	5521.	[func]		All use of libltdl was dropped. libuv's shared library
				handling interface is now used instead. [GL !4278]

	5520.	[bug]		Fixed a number of shutdown races, reference counting
				errors, and spurious log messages that could occur
				in the network manager. [GL #2221]

	5519.	[cleanup]	Unused source code was removed: lib/dns/dbtable.c,
				lib/dns/portlist.c, lib/isc/bufferlist.c, and code
				related to those files. [GL #2060]

	5518.	[bug]		Stub zones now work correctly with primary servers using
				"minimal-responses yes". [GL #1736]

	5517.	[bug]		Do not treat UV_EOF as a TCP4RecvErr or a TCP6RecvErr.
				[GL #2208]

.. code-block:: none

		--- 9.17.6 released ---

	5516.	[func]		The default EDNS buffer size has been changed from 4096
				to 1232 bytes, the EDNS buffer size probing has been
				removed, and named now sets the DF (Don't Fragment) flag
				on outgoing UDP packets. [GL #2183]

	5515.	[func]		Add 'rndc dnssec -rollover' command to trigger a manual
				rollover for a specific key. [GL #1749]

	5514.	[bug]		Fix KASP expected key size for Ed25519 and Ed448.
				[GL #2171]

	5513.	[doc]		The ARM section describing the "rrset-order" statement
				was rewritten to make it unambiguous and up-to-date with
				the source code. [GL #2139]

	5512.	[bug]		"rrset-order" rules using "order none" were causing
				named to crash despite named-checkconf treating them as
				valid. [GL #2139]

	5511.	[bug]		'dig -u +yaml' failed to display timestamps to the
				microsecond. [GL #2190]

	5510.	[bug]		Implement the attach/detach semantics for dns_message_t
				to fix a data race in accessing an already-destroyed
				fctx->rmessage. [GL #2124]

	5509.	[bug]		filter-aaaa: named crashed upon shutdown if it was in
				the process of recursing for A RRsets. [GL #1040]

	5508.	[func]		Added new parameter "-expired" for "rndc dumpdb" that
				also prints expired RRsets (awaiting cleanup) to the
				dump file. [GL #1870]

	5507.	[bug]		Named could compute incorrect SIG(0) responses.
				[GL #2109]

	5506.	[bug]		Properly handle failed sysconf() calls, so we don't
				report invalid memory size. [GL #2166]

	5505.	[bug]		Updating contents of a mixed-case RPZ could cause some
				rules to be ignored. [GL #2169]

	5504.	[func]		The "glue-cache" option has been marked as deprecated.
				The glue cache feature will be permanently enabled in a
				future release. [GL #2146]

	5503.	[bug]		Cleaned up reference counting of network manager
				handles, now using isc_nmhandle_attach() and _detach()
				instead of _ref() and _unref(). [GL #2122]

.. code-block:: none

		--- 9.17.5 released ---

	5502.	[func]		'dig +bufsize=0' no longer disables EDNS. [GL #2054]

	5501.	[func]		Log CDS/CDNSKEY publication. [GL #1748]

	5500.	[bug]		Fix (non-)publication of CDS and CDNSKEY records.
				[GL #2103]

	5499.	[func]		Add '-P ds' and '-D ds' arguments to dnssec-settime.
				[GL #1748]

	5498.	[test]		The --with-gperftools-profiler configure option was
				removed. [GL !4045]

	5497.	[placeholder]

	5496.	[bug]		Address a TSAN report by ensuring each rate limiter
				object holds a reference to its task. [GL #2081]

	5495.	[bug]		With query minimization enabled, named failed to
				resolve ip6.arpa. names that had extra labels to the
				left of the IPv6 part. [GL #1847]

	5494.	[bug]		Silence the EPROTO syslog message on older systems.
				[GL #1928]

	5493.	[bug]		Fix off-by-one error when calculating new hash table
				size. [GL #2104]

	5492.	[bug]		Tighten LOC parsing to reject a period (".") and/or "m"
				as a value. Fix handling of negative altitudes which are
				not whole meters. [GL #2074]

	5491.	[bug]		rbtversion->glue_table_size could be read without the
				appropriate lock being held. [GL #2080]

	5490.	[func]		Refactor readline support to use pkg-config and add
				support for the editline library. [GL !3942]

	5489.	[bug]		Named erroneously accepted certain invalid resource
				records that were incorrectly processed after
				subsequently being written to disk and loaded back, as
				the wire format differed. Such records include: CERT,
				IPSECKEY, NSEC3, NSEC3PARAM, NXT, SIG, TLSA, WKS, and
				X25. [GL !3953]

	5488.	[bug]		NTA code needed to have a weak reference on its
				associated view to prevent the latter from being deleted
				while NTA tests were being performed. [GL #2067]

	5487.	[cleanup]	Update managed keys log messages to be less confusing.
				[GL #2027]

	5486.	[func]		Add 'rndc dnssec -checkds' command, which signals to
				named that the DS record for a given zone or key has
				been updated in the parent zone. [GL #1613]

.. code-block:: none

		--- 9.17.4 released ---

	5485.	[placeholder]

	5484.	[func]		Expire zero TTL records quickly rather than using them
				for stale answers. [GL #1829]

	5483.	[func]		Keeping "stale" answers in cache has been disabled by
				default and can be re-enabled with a new configuration
				option "stale-cache-enable". [GL #1712]

	5482.	[bug]		If the Duplicate Address Detection (DAD) mechanism had
				not yet finished after adding a new IPv6 address to the
				system, BIND 9 would fail to bind to IPv6 addresses in a
				tentative state. [GL #2038]

	5481.	[security]	"update-policy" rules of type "subdomain" were
				incorrectly treated as "zonesub" rules, which allowed
				keys used in "subdomain" rules to update names outside
				of the specified subdomains. The problem was fixed by
				making sure "subdomain" rules are again processed as
				described in the ARM. (CVE-2020-8624) [GL #2055]

	5480.	[security]	When BIND 9 was compiled with native PKCS#11 support, it
				was possible to trigger an assertion failure in code
				determining the number of bits in the PKCS#11 RSA public
				key with a specially crafted packet. (CVE-2020-8623)
				[GL #2037]

	5479.	[security]	named could crash in certain query resolution scenarios
				where QNAME minimization and forwarding were both
				enabled. (CVE-2020-8621) [GL #1997]

	5478.	[security]	It was possible to trigger an assertion failure by
				sending a specially crafted large TCP DNS message.
				(CVE-2020-8620) [GL #1996]

	5477.	[bug]		The idle timeout for connected TCP sockets, which was
				previously set to a high fixed value, is now derived
				from the client query processing timeout configured for
				a resolver. [GL #2024]

	5476.	[security]	It was possible to trigger an assertion failure when
				verifying the response to a TSIG-signed request.
				(CVE-2020-8622) [GL #2028]

	5475.	[bug]		Wildcard RPZ passthru rules could incorrectly be
				overridden by other rules that were loaded from RPZ
				zones which appeared later in the "response-policy"
				statement. This has been fixed. [GL #1619]

	5474.	[bug]		dns_rdata_hip_next() failed to return ISC_R_NOMORE
				when it should have. [GL !3880]

	5473.	[func]		The RBT hash table implementation has been changed
				to use a faster hash function (HalfSipHash2-4) and
				Fibonacci hashing for better distribution. Setting
				"max-cache-size" now preallocates a fixed-size hash
				table so that rehashing does not cause resolution
				brownouts while the hash table is grown. [GL #1775]

	5472.	[func]		The statistics channel has been updated to use the
				new network manager. [GL #2022]

	5471.	[bug]		The introduction of KASP support inadvertently caused
				the second field of "sig-validity-interval" to always be
				calculated in hours, even in cases when it should have
				been calculated in days. This has been fixed. (Thanks to
				Tony Finch.) [GL !3735]

	5470.	[port]		gsskrb5_register_acceptor_identity() is now only called
				if gssapi_krb5.h is present. [GL #1995]

	5469.	[port]		On illumos, a constant called SEC is already defined in
				<sys/time.h>, which conflicts with an identically named
				constant in libbind9. This conflict has been resolved.
				[GL #1993]

	5468.	[bug]		Addressed potential double unlock in process_fd().
				[GL #2005]

	5467.	[func]		The control channel and the rndc utility have been
				updated to use the new network manager. To support
				this, the network manager was updated to enable
				the initiation of client TCP connections. Its
				internal reference counting has been refactored.

				Note: As a side effect of this change, rndc cannot
				currently be used with UNIX-domain sockets, and its
				default timeout has changed from 60 seconds to 30.
				These will be addressed in a future release.
				[GL #1759]

	5466.	[bug]		Addressed an error in recursive clients stats reporting.
				[GL #1719]

	5465.	[func]		Added fallback to built-in trust-anchors, managed-keys,
				or trusted-keys if the bindkeys-file (bind.keys) cannot
				be parsed. [GL #1235]

	5464.	[bug]		Requesting more than 128 files to be saved when rolling
				dnstap log files caused a buffer overflow. This has been
				fixed. [GL #1989]

	5463.	[placeholder]

	5462.	[bug]		Move LMDB locking from LMDB itself to named. [GL #1976]

	5461.	[bug]		The STALE rdataset header attribute was updated while
				the write lock was not being held, leading to incorrect
				statistics. The header attributes are now converted to
				use atomic operations. [GL #1475]

	5460.	[cleanup]	tsig-keygen was previously an alias for
				ddns-confgen and was documented in the ddns-confgen
				man page. This has been reversed; tsig-keygen is
				now the primary name. [GL #1998]

	5459.	[bug]		Fixed bad isc_mem_put() size when an invalid type was
				specified in an "update-policy" rule. [GL #1990]

.. code-block:: none

		--- 9.17.3 released ---

	5458.	[bug]		Prevent a theoretically possible NULL dereference caused
				by a data race between zone_maintenance() and
				dns_zone_setview_helper(). [GL #1627]

	5457.	[placeholder]

	5456.	[func]		Added "primaries" as a synonym for "masters" in
				named.conf, and "primary-only" as a synonym for
				"master-only" in the parameters to "notify", to bring
				terminology up-to-date with RFC 8499. [GL #1948]

	5455.	[bug]		named could crash when cleaning dead nodes in
				lib/dns/rbtdb.c that were being reused. [GL #1968]

	5454.	[bug]		Address a startup crash that occurred when the server
				was under load and the root zone had not yet been
				loaded. [GL #1862]

	5453.	[bug]		named crashed on shutdown when a new rndc connection was
				received during shutdown. [GL #1747]

	5452.	[bug]		The "blackhole" ACL was accidentally disabled for client
				queries. [GL #1936]

	5451.	[func]		Add 'rndc dnssec -status' command. [GL #1612]

	5450.	[placeholder]

	5449.	[bug]		Fix a socket shutdown race in netmgr udp. [GL #1938]

	5448.	[bug]		Fix a race condition in isc__nm_tcpdns_send().
				[GL #1937]

	5447.	[bug]		IPv6 addresses ending in "::" could break YAML
				parsing. A "0" is now appended to such addresses
				in YAML output from dig, mdig, delv, and dnstap-read.
				[GL #1952]

	5446.	[bug]		The validator could fail to accept a properly signed
				RRset if an unsupported algorithm appeared earlier in
				the DNSKEY RRset than a supported algorithm. It could
				also stop if it detected a malformed public key.
				[GL #1689]

	5445.	[cleanup]	Disable and disallow static linking. [GL #1933]

	5444.	[bug]		'rndc dnstap -roll <value>' did not limit the number of
				saved files to <value>. [GL !3728]

	5443.	[bug]		The "primary" and "secondary" keywords, when used
				as parameters for "check-names", were not
				processed correctly and were being ignored. [GL #1949]

	5442.	[func]		Add support for outgoing TCP connections in netmgr.
				[GL #1958]

	5441.	[placeholder]

	5440.	[placeholder]

	5439.	[bug]		The DS RRset returned by dns_keynode_dsset() was used in
				a non-thread-safe manner. [GL #1926]

.. code-block:: none

		--- 9.17.2 released ---

	5438.	[bug]		Fix a race in TCP accepting code. [GL #1930]

	5437.	[bug]		Fix a data race in lib/dns/resolver.c:log_formerr().
				[GL #1808]

	5436.	[security]	It was possible to trigger an INSIST when determining
				whether a record would fit into a TCP message buffer.
				(CVE-2020-8618) [GL #1850]

	5435.	[tests]		Add RFC 4592 responses examples to the wildcard system
				test. [GL #1718]

	5434.	[security]	It was possible to trigger an INSIST in
				lib/dns/rbtdb.c:new_reference() with a particular zone
				content and query patterns. (CVE-2020-8619) [GL #1111]
				[GL #1718]

	5433.	[placeholder]

	5432.	[bug]		Check the question section when processing AXFR, IXFR,
				and SOA replies when transferring a zone in. [GL #1683]

	5431.	[func]		Reject DS records at the zone apex when loading
				master files. Log but otherwise ignore attempts to
				add DS records at the zone apex via UPDATE. [GL #1798]

	5430.	[doc]		Update docs - with netmgr, a separate listening socket
				is created for each IPv6 interface (just as with IPv4).
				[GL #1782]

	5429.	[cleanup]	Move BIND binaries which are neither daemons nor
				administrative programs to $bindir. [GL #1724]

	5428.	[bug]		Clean up GSSAPI resources in nsupdate only after taskmgr
				has been destroyed. Thanks to Petr Menšík. [GL !3316]

	5427.	[placeholder]

	5426.	[bug]		Don't abort() when setting SO_INCOMING_CPU on the socket
				fails. [GL #1911]

	5425.	[func]		The default value of "max-stale-ttl" has been changed
				from 1 week to 12 hours. [GL #1877]

	5424.	[bug]		With KASP, when creating a successor key, the "goal"
				state of the current active key (predecessor) was not
				changed and thus never removed from the zone. [GL #1846]

	5423.	[bug]		Fix a bug in keymgr_key_has_successor(): it incorrectly
				returned true if any other key in the keyring had a
				successor. [GL #1845]

	5422.	[bug]		When using dnssec-policy, print correct key timing
				metadata. [GL #1843]

	5421.	[bug]		Fix a race that could cause named to crash when looking
				up the nodename of an RBT node if the tree was modified.
				[GL #1857]

	5420.	[bug]		Add missing isc_{mutex,conditional}_destroy() calls
				that caused a memory leak on FreeBSD. [GL #1893]

	5419.	[func]		Add new dig command line option, "+qid=<num>", which
				allows the query ID to be set to an arbitrary value.
				Add a new ./configure option, --enable-singletrace,
				which allows trace logging of a single query when QID is
				set to 0. [GL #1851]

	5418.	[bug]		delv failed to parse deprecated trusted-keys-style
				trust anchors. [GL #1860]

	5417.	[cleanup]	The code determining the advertised UDP buffer size in
				outgoing EDNS queries has been refactored to improve its
				clarity. [GL #1868]

	5416.	[bug]		Fix a lock order inversion in lib/isc/unix/socket.c.
				[GL #1859]

	5415.	[test]		Address race in dnssec system test that led to
				test failures. [GL #1852]

	5414.	[test]		Adjust time allowed for journal truncation to occur
				in nsupdate system test to avoid test failure.
				[GL #1855]

	5413.	[test]		Address race in autosign system test that led to
				test failures. [GL #1852]

	5412.	[bug]		'provide-ixfr no;' failed to return up-to-date responses
				when the serial was greater than or equal to the
				current serial. [GL #1714]

	5411.	[cleanup]	TCP accept code has been refactored to use a single
				accept() and pass the accepted socket to child threads
				for processing. [GL !3320]

	5410.	[func]		Add the ability to specify per-type record count limits,
				which are enforced when adding records via UPDATE, in an
				"update-policy" statement. [GL #1657]

	5409.	[performance]	When looking up NSEC3 data in a zone database, skip the
				check for empty non-terminal nodes; the NSEC3 tree does
				not have any. [GL #1834]

	5408.	[protocol]	Print Extended DNS Errors if present in OPT record.
				[GL #1835]

	5407.	[func]		Zone timers are now exported via statistics channel.
				Thanks to Paul Frieden, Verizon Media. [GL #1232]

	5406.	[func]		Add a new logging category, "rpz-passthru", which allows
				RPZ passthru actions to be logged in a separate channel.
				[GL #54]

	5405.	[bug]		'named-checkconf -p' could include spurious text in
				server-addresses statements due to an uninitialized DSCP
				value. [GL #1812]

	5404.	[bug]		'named-checkconf -z' could incorrectly indicate
				success if errors were found in one view but not in a
				subsequent one. [GL #1807]

	5403.	[func]		Do not set UDP receive/send buffer sizes - use system
				defaults. [GL #1713]

	5402.	[bug]		On FreeBSD, use SO_REUSEPORT_LB instead of SO_REUSEPORT.
				Enable use of SO_REUSEADDR on all platforms which
				support it. [GL !3365]

	5401.	[bug]		The number of input queues allocated during dnstap
				initialization was too low, which could prevent some
				dnstap data from being logged. [GL #1795]

	5400.	[func]		Add engine support to OpenSSL EdDSA implementation.
				[GL #1763]

	5399.	[func]		Add engine support to OpenSSL ECDSA implementation.
				[GL #1534]

	5398.	[bug]		Named could fail to restart if a zone with a double
				quote (") in its name was added with 'rndc addzone'.
				[GL #1695]

	5397.	[func]		Update PKCS#11 EdDSA implementation to PKCS#11 v3.0.
				Thanks to Aaron Thompson. [GL !3326]

	5396.	[func]		When necessary (i.e. in libuv >= 1.37), use the
				UV_UDP_RECVMMSG flag to enable recvmmsg() support in
				libuv. [GL #1797]

	5395.	[security]	Further limit the number of queries that can be
				triggered from a request.  Root and TLD servers
				are no longer exempt from max-recursion-queries.
				Fetches for missing name server address records
				are limited to 4 for any domain. (CVE-2020-8616)
				[GL #1388]

	5394.	[cleanup]	Named formerly attempted to change the effective UID and
				GID in named_os_openfile(), which could trigger a
				spurious log message if they were already set to the
				desired values. This has been fixed. [GL #1042]
				[GL #1090]

	5393.	[cleanup]	Unused and/or redundant APIs were removed from libirs.
				[GL #1758]

	5392.	[bug]		It was possible for named to crash during shutdown
				or reconfiguration if an RPZ zone was still being
				updated. [GL #1779]

	5391.	[func]		The BIND 9 build system has been changed to use a
				typical autoconf+automake+libtool stack. When building
				from the Git repository, run "autoreconf -fi" first.
				[GL #4]

	5390.	[security]	Replaying a TSIG BADTIME response as a request could
				trigger an assertion failure. (CVE-2020-8617)
				[GL #1703]

	5389.	[bug]		Finish PKCS#11 code cleanup, fix a couple of smaller
				bugs and use PKCS#11 v3.0 EdDSA macros and constants.
				Thanks to Aaron Thompson. [GL !3391]

	5388.	[func]		Reject AXFR streams where the message ID is not
				consistent. [GL #1674]

	5387.	[placeholder]

	5386.	[cleanup]	Address Coverity warnings in lib/dns/keymgr.c.
				[GL #1737]

	5385.	[func]		Make ISC rwlock implementation the default again.
				[GL #1753]

	5384.	[bug]		With "dnssec-policy" in effect, "inline-signing" was
				implicitly set to "yes". Now "inline-signing" is only
				set to "yes" if the zone is not dynamic. [GL #1709]

.. code-block:: none

		--- 9.17.1 released ---

	5383.	[func]		Add a quota attach function with a callback and clean up
				the isc_quota API. [GL !3280]

	5382.	[bug]		Use clock_gettime() instead of gettimeofday() for
				isc_stdtime() function. [GL #1679]

	5381.	[bug]		Fix logging API data race by adding rwlock and caching
				logging levels in stdatomic variables to restore
				performance to original levels. [GL #1675] [GL #1717]

	5380.	[contrib]	Fix building MySQL DLZ modules against MySQL 8
				libraries. [GL #1678]

	5379.	[placeholder]

	5378.	[bug]		Receiving invalid DNS data was triggering an assertion
				failure in nslookup. [GL #1652]

	5377.	[placeholder]

	5376.	[bug]		Fix ineffective DNS rebinding protection when BIND is
				configured as a forwarding DNS server. Thanks to Tobias
				Klein. [GL #1574]

	5375.	[test]		Fix timing issues in the "kasp" system test. [GL #1669]

	5374.	[bug]		Statistics counters tracking recursive clients and
				active connections could underflow. [GL #1087]

	5373.	[bug]		Collecting statistics for DNSSEC signing operations
				(change 5254) caused an array of significant size (over
				100 kB) to be allocated for each configured zone. Each
				of these arrays is tracking all possible key IDs; this
				could trigger an out-of-memory condition on servers with
				a high enough number of zones configured. Fixed by
				tracking up to four keys per zone and rotating counters
				when keys are replaced. This fixes the immediate problem
				of high memory usage, but should be improved in a future
				release by growing or shrinking the number of keys to
				track upon key rollover events. [GL #1179]

	5372.	[bug]		Fix migration from existing DNSSEC key files
				("auto-dnssec maintain") to "dnssec-policy". [GL #1706]

	5371.	[bug]		Improve incremental updates of the RPZ summary
				database to reduce delays that could occur when
				a policy zone update included a large number of
				record deletions. [GL #1447]

	5370.	[bug]		Deactivation of a netmgr handle associated with a
				socket could be skipped in some circumstances.
				Fixed by deactivating the netmgr handle before
				scheduling the asynchronous close routine. [GL #1700]

	5369.	[func]		Add the ability to specify whether to wait for
				nameserver domain names to be looked up, with a new RPZ
				modifying directive 'nsdname-wait-recurse'. [GL #1138]

	5368.	[bug]		Named failed to restart if 'rndc addzone' names
				contained special characters (e.g. '/'). [GL #1655]

	5367.	[placeholder]

.. code-block:: none

		--- 9.17.0 released ---

	5366.	[bug]		Fix a race condition with the keymgr when the same
				zone plus dnssec-policy is configured in multiple
				views. [GL #1653]

	5365.	[bug]		Algorithm rollover was stuck on submitting DS
				because keymgr thought it would move to an invalid
				state.  Fixed by checking the current key against
				the desired state, not the existing state. [GL #1626]

	5364.	[bug]		Algorithm rollover waited too long before introducing
				zone signatures.  It waited to make sure all signatures
				were regenerated, but when introducing a new algorithm,
				all signatures are regenerated immediately.  Only
				add the sign delay if there is a predecessor key.
				[GL #1625]

	5363.	[bug]		When changing a dnssec-policy, existing keys with
				properties that no longer match were not being retired.
				[GL #1624]

	5362.	[func]		Limit the size of IXFR responses so that AXFR will
				be used instead if it would be smaller. This is
				controlled by the "max-ixfr-ratio" option, which
				is a percentage representing the ratio of IXFR size
				to the size of the entire zone. This value cannot
				exceed 100%, which is the default. [GL #1515]

	5361.	[bug]		named might not accept new connections after
				hitting tcp-clients quota. [GL #1643]

	5360.	[bug]		delv could fail to load trust anchors in DNSKEY
				format. [GL #1647]

	5359.	[func]		"rndc nta -d" and "rndc secroots" now include
				"validate-except" entries when listing negative
				trust anchors. These are indicated by the keyword
				"permanent" in place of an expiry date. [GL #1532]

	5358.	[bug]		Inline master zones whose master files were touched
				but otherwise unchanged and were subsequently reloaded
				may have stopped re-signing. [GL !3135]

	5357.	[bug]		Newly added RRSIG records with expiry times before
				the previous earliest expiry times might not be
				re-signed in time.  This was a side effect of 5315.
				[GL !3137]

	5356.	[func]		Update dnssec-policy configuration statements:
				- Rename "zone-max-ttl" dnssec-policy option to
				  "max-zone-ttl" for consistency with the existing
				  zone option.
				- Allow for "lifetime unlimited" as a synonym for
				  "lifetime PT0S".
				- Make "key-directory" optional.
				- Warn if specifying a key length does not make
				  sense; fail if key length is out of range for
				  the algorithm.
				- Allow use of mnemonics when specifying key
				  algorithm (e.g. "rsasha256", "ecdsa384", etc.).
				- Make ISO 8601 durations case-insensitive.
				[GL #1598]

	5355.	[func]		What was set with --with-tuning=large option in
				older BIND9 versions is now a default, and
				a --with-tuning=small option was added for small
				(e.g. OpenWRT) systems. [GL !2989]

	5354.	[bug]		dnssec-policy created new KSK keys for zones in the
				initial stage of signing (with the DS not yet in the
				rumoured or omnipresent states).  Fix by checking the
				key goals rather than the active state when determining
				whether new keys are needed. [GL #1593]

	5353.	[doc]		Document port and dscp parameters in forwarders
				configuration option. [GL #914]

	5352.	[bug]		Correctly handle catalog zone entries containing
				characters that aren't legal in filenames. [GL #1592]

	5351.	[bug]		CDS / CDNSKEY consistency checks failed to handle
				removal records. [GL #1554]

	5350.	[bug]		When a view was configured with class CHAOS, the
				server could crash while processing a query for a
				non-existent record. [GL #1540]

	5349.	[bug]		Fix a race in task_pause/unpause. [GL #1571]

	5348.	[bug]		dnssec-settime -Psync was not being honoured.
				Thanks to Tony Finch. [GL !2893]

.. code-block:: none

		--- 9.15.8 released ---

	5347.	[bug]		Fixed a bug that could cause an intermittent crash
				in validator.c when validating a negative cache
				entry. [GL #1561]

	5346.	[bug]		Make hazard pointer array allocations dynamic, fixing
				a bug that caused named to crash on machines with more
				than 40 cores. [GL #1493]

	5345.	[func]		Key-style trust anchors and DS-style trust anchors
				can now both be used for the same name. [GL #1237]

	5344.	[bug]		Handle accept() errors properly in netmgr. [GL !2880]

	5343.	[func]		Add statistics counters to the netmgr. [GL #1311]

	5342.	[bug]		Disable pktinfo for IPv6 and bind to each interface
				explicitly instead, because libuv doesn't support
				pktinfo control messages. [GL #1558]

	5341.	[func]		Simplify passing the bound TCP socket to child
				threads by using isc_uv_export/import functions.
				[GL !2825]

	5340.	[bug]		Don't deadlock when binding to a TCP socket fails.
				[GL #1499]

	5339.	[bug]		With some libmaxminddb versions, named could erroneously
				match an IP address not belonging to any subnet defined
				in a given GeoIP2 database to one of the existing
				entries in that database. [GL #1552]

	5338.	[bug]		Fix line spacing in `rndc secroots`.
				Thanks to Tony Finch. [GL !2478]

	5337.	[func]		'named -V' now reports maxminddb and protobuf-c
				versions. [GL !2686]

.. code-block:: none

		--- 9.15.7 released ---

	5336.	[bug]		The TCP high-water statistic could report an
				incorrect value on startup. [GL #1392]

	5335.	[func]		Make TCP listening code multithreaded. [GL !2659]

	5334.	[doc]		Update documentation with dnssec-policy clarifications.
				Also change some defaults. [GL !2711]

	5333.	[bug]		Fix duration printing on Solaris when value is not
				an ISO 8601 duration. [GL #1460]

	5332.	[func]		Renamed "dnssec-keys" configuration statement
				to the more descriptive "trust-anchors". [GL !2702]

	5331.	[func]		Use compiler-provided mechanisms for thread local
				storage, and make the requirement for such mechanisms
				explicit in configure. [GL #1444]

	5330.	[bug]		'configure --without-python' was ineffective if
				PYTHON was set in the environment. [GL #1434]

	5329.	[bug]		Reconfiguring named caused memory to be leaked when any
				GeoIP2 database was in use. [GL #1445]

	5328.	[bug]		rbtdb.c:rdataset_{get,set}ownercase failed to obtain
				a node lock. [GL #1417]

	5327.	[func]		Added a statistics counter to track queries
				dropped because the recursive-clients quota was
				exceeded. [GL #1399]

	5326.	[bug]		Add Python dependency on 'distutils.core' to configure.
				'distutils.core' is required for installation.
				[GL #1397]

	5325.	[bug]		Addressed several issues with TCP connections in
				the netmgr: restored support for TCP connection
				timeouts, restored TCP backlog support, actively
				close all open sockets during shutdown. [GL #1312]

	5324.	[bug]		Change the category of some log messages from general
				to the more appropriate catergory of xfer-in. [GL #1394]

	5323.	[bug]		Fix a bug in DNSSEC trust anchor verification.
				[GL !2609]

	5322.	[placeholder]

	5321.	[bug]		Obtain write lock before updating version->records
				and version->bytes. [GL #1341]

	5320.	[cleanup]	Silence TSAN on header->count. [GL #1344]

.. code-block:: none

		--- 9.15.6 released ---

	5319.	[func]		Trust anchors can now be configured using DS
				format to represent a key digest, by using the
				new "initial-ds" or "static-ds" keywords in
				the "dnssec-keys" statement.

				Note: DNSKEY-format and DS-format trust anchors
				cannot both be used for the same domain name.
				[GL #622]

	5318.	[cleanup]	The DNSSEC validation code has been refactored
				for clarity and to reduce code duplication.
				[GL #622]

	5317.	[func]		A new asynchronous network communications system
				based on libuv is now used for listening for
				incoming requests and responding to them. (The
				old isc_socket API remains in use for sending
				iterative queries and processing responses; this
				will be changed too in a later release.)

				This change will make it easier to improve
				performance and implement new protocol layers
				(e.g., DNS over TLS) in the future. [GL #29]

	5316.	[func]		A new "dnssec-policy" option has been added to
				named.conf to implement a key and signing policy
				(KASP) for zones. When this option is in use,
				named can generate new keys as needed and
				automatically roll both ZSK and KSK keys. (Note
				that the syntax for this statement differs from
				the dnssec policy used by dnssec-keymgr.)

				See the ARM for configuration details. [GL #1134]

	5315.	[bug]		Apply the initial RRSIG expiration spread fixed
				to all dynamically created records in the zone
				including NSEC3. Also fix the signature clusters
				when the server has been offline for prolonged
				period of times. [GL #1256]

	5314.	[func]		Added a new statistics variable "tcp-highwater"
				that reports the maximum number of simultaneous TCP
				clients BIND has handled while running. [GL #1206]

	5313.	[bug]		The default GeoIP2 database location did not match
				the ARM.  'named -V' now reports the default
				location. [GL #1301]

	5312.	[bug]		Do not flush the cache for `rndc validation status`.
				Thanks to Tony Finch. [GL !2462]

	5311.	[cleanup]	Include all views in output of `rndc validation status`.
				Thanks to Tony Finch. [GL !2461]

	5310.	[bug]		TCP failures were affecting EDNS statistics. [GL #1059]

	5309.	[placeholder]

	5308.	[bug]		Don't log DNS_R_UNCHANGED from sync_secure_journal()
				at ERROR level in receive_secure_serial(). [GL #1288]

	5307.	[bug]		Fix hang when named-compilezone output is sent to pipe.
				Thanks to Tony Finch. [GL !2481]

	5306.	[security]	Set a limit on number of simultaneous pipelined TCP
				queries. (CVE-2019-6477) [GL #1264]

	5305.	[bug]		NSEC Aggressive Cache ("synth-from-dnssec") has been
				disabled by default because it was found to have
				a significant performance impact on the recursive
				service. [GL #1265]

	5304.	[bug]		"dnskey-sig-validity 0;" was not being accepted.
				[GL #876]

	5303.	[placeholder]

	5302.	[bug]		Fix checking that "dnstap-output" is defined when
				"dnstap" is specified in a view. [GL #1281]

	5301.	[bug]		Detect partial prefixes / incomplete IPv4 address in
				acls. [GL #1143]

	5300.	[bug]		dig/mdig/delv: Add a colon after EDNS option names,
				even when the option is empty, to improve
				readability and allow correct parsing of YAML
				output. [GL #1226]

.. code-block:: none

		--- 9.15.5 released ---

	5299.	[security]	A flaw in DNSSEC verification when transferring
				mirror zones could allow data to be incorrectly
				marked valid. (CVE-2019-6475) [GL #1252]

	5298.	[security]	Named could assert if a forwarder returned a
				referral, rather than resolving the query, when QNAME
				minimization was enabled. (CVE-2019-6476) [GL #1051]

	5297.	[bug]		Check whether a previous QNAME minimization fetch
				is still running before starting a new one; return
				SERVFAIL and log an error if so. [GL #1191]

	5296.	[placeholder]

	5295.	[cleanup]	Split dns_name_copy() calls into dns_name_copy() and
				dns_name_copynf() for those calls that can potentially
				fail and those that should not fail respectively.
				[GL !2265]

	5294.	[func]		Fallback to ACE name on output in locale, which does not
				support converting it to unicode.  [GL #846]

	5293.	[bug]		On Windows, named crashed upon any attempt to fetch XML
				statistics from it. [GL #1245]

	5292.	[bug]		Queue 'rndc nsec3param' requests while signing inline
				zone changes. [GL #1205]

.. code-block:: none

		--- 9.15.4 released ---

	5291.	[placeholder]

	5290.	[placeholder]

	5289.	[bug]		Address NULL pointer dereference in rpz.c:rpz_detach.
				[GL #1210]

	5288.	[bug]		dnssec-must-be-secure was not always honored.
				[GL #1209]

	5287.	[placeholder]

	5286.	[contrib]	Address potential NULL pointer dereferences in
				dlz_mysqldyn_mod.c. [GL #1207]

	5285.	[port]		win32: implement "-T maxudpXXX". [GL #837]

	5284.	[func]		Added +unexpected command line option to dig.
				By default, dig won't accept a reply from a source
				other than the one to which it sent the query.
				Invoking dig with +unexpected argument will allow it
				to process replies from unexpected sources.

	5283.	[bug]		When a response-policy zone expires, ensure that
				its policies are removed from the RPZ summary
				database. [GL #1146]

	5282.	[bug]		Fixed a bug in searching for possible wildcard matches
				for query names in the RPZ summary database. [GL #1146]

	5281.	[cleanup]	Don't escape commas when reporting named's command
				line. [GL #1189]

	5280.	[protocol]	Add support for displaying EDNS option LLQ. [GL #1201]

	5279.	[bug]		When loading, reject zones containing CDS or CDNSKEY
				RRsets at the zone apex if they would cause DNSSEC
				validation failures if published in the parent zone
				as the DS RRset.  [GL #1187]

	5278.	[func]		Add YAML output formats for dig, mdig and delv;
				use the "+yaml" option to enable. [GL #1145]

.. code-block:: none

		--- 9.15.3 released ---

	5277.	[bug]		Cache DB statistics could underflow when serve-stale
				was in use, because of a bug in counter maintenance
				when RRsets become stale.

				Functions for dumping statistics have been updated
				to dump active, stale, and ancient statistic
				counters.  Ancient RRset counters are prefixed
				with '~'; stale RRset counters are still prefixed
				with '#'. [GL #602]

	5276.	[func]		DNSSEC Lookaside Validation (DLV) is now obsolete;
				all code enabling its use has been removed from the
				validator, "delv", and the DNSSEC tools. [GL #7]

	5275.	[bug]		Mark DS records included in referral messages
				with trust level "pending" so that they can be
				validated and cached immediately, with no need to
				re-query. [GL #964]

	5274.	[bug]		Address potential use after free race when shutting
				down rpz. [GL #1175]

	5273.	[bug]		Check that bits [64..71] of a dns64 prefix are zero.
				[GL #1159]

	5272.	[cleanup]	Remove isc-config.sh script as the BIND 9 libraries
				are now purely internal. [GL #1123]

	5271.	[func]		The normal (non-debugging) output of dnssec-signzone
				and dnssec-verify tools now goes to stdout, instead of
				the combination of stderr and stdout.

	5270.	[bug]		'dig +expandaaaa +short' did not work. [GL #1152]

	5269.	[port]		cygwin: can return ETIMEDOUT on connect() with a
				non-blocking socket. [GL #1133]

	5268.	[placeholder]

	5267.	[func]		Allow statistics groups display to be toggle-able.
				[GL #1030]

	5266.	[bug]		named-checkconf failed to report dnstap-output
				missing from named.conf when dnstap was specified.
				[GL #1136]

	5265.	[bug]		DNS64 and RPZ nodata (CNAME *.) rules interacted badly
				[GL #1106]

	5264.	[func]		New DNS Cookie algorithm - siphash24 - has been added
				to BIND 9, and the old HMAC-SHA DNS Cookie algorithms
				have been removed. [GL #605]

.. code-block:: none

		--- 9.15.2 released ---

	5263.	[cleanup]	Use atomics and isc_refcount_t wherever possible.
				[GL #1038]

	5262.	[func]		Removed support for the legacy GeoIP API. [GL #1112]

	5261.	[cleanup]	Remove SO_BSDCOMPAT socket option usage.

	5260.	[bug]		dnstap-read was producing malformed output for large
				packets. [GL #1093]

	5259.	[func]		New option '-i' for 'named-checkconf' to ignore
				warnings about deprecated options. [GL #1101]

	5258.	[func]		Added support for the GeoIP2 API from MaxMind. This
				will be compiled in by default if the "libmaxminddb"
				library is found at compile time, but can be
				suppressed using "configure --disable-geoip".

				Certain geoip ACL settings that were available with
				legacy GeoIP are not available when using GeoIP2.
				[GL #182]

	5257.	[bug]		Some statistics data was not being displayed.
				Add shading to the zone tables. [GL #1030]

	5256.	[bug]		Ensure that glue records are included in root
				priming responses if "minimal-responses" is not
				set to "yes". [GL #1092]

	5255.	[bug]		Errors encountered while reloading inline-signing
				zones could be ignored, causing the zone content to
				be left in an incompletely updated state rather than
				reverted. [GL #1109]

	5254.	[func]		Collect metrics to report to the statistics-channel
				DNSSEC signing operations (dnssec-sign) and refresh
				operations (dnssec-refresh) per zone and per keytag.
				[GL #513]

	5253.	[port]		Support platforms that don't define ULLONG_MAX.
				[GL #1098]

	5252.	[func]		Report if the last 'rndc reload/reconfig' failed in
				rndc status. [GL !2040]

	5251.	[bug]		Statistics were broken in x86 Windows builds.
				[GL #1081]

	5250.	[func]		The default size for RSA keys is now 2048 bits,
				for both ZSKs and KSKs. [GL #1097]

	5249.	[bug]		Fix a possible underflow in recursion clients
				statistics when hitting recursive clients
				soft quota. [GL #1067]

.. code-block:: none

		--- 9.15.1 released ---

	5248.	[func]		To clarify the configuration of DNSSEC keys,
				the "managed-keys" and "trusted-keys" options
				have both been deprecated.  The new "dnssec-keys"
				statement can now be used for all trust anchors,
				with the keywords "iniital-key" or "static-key"
				to indicate whether the configured trust anchor
				should be used for initialization of RFC 5011 key
				management, or as a permanent trust anchor.

				The "static-key" keyword will generate a warning if
				used for the root zone.

				Configurations using "trusted-keys" or "managed-keys"
				will continue to work with no changes, but will
				generate warnings in the log. In a future release,
				these options will be marked obsolete. [GL #6]

	5247.	[cleanup]	The 'cleaning-interval' option has been removed.
				[GL !1731]

	5246.	[func]		Log TSIG if appropriate in 'sending notify to' message.
				[GL #1058]

	5245.	[cleanup]	Reduce logging level for IXFR up-to-date poll
				responses. [GL #1009]

	5244.	[security]	Fixed a race condition in dns_dispatch_getnext()
				that could cause an assertion failure if a
				significant number of incoming packets were
				rejected. (CVE-2019-6471) [GL #942]

	5243.	[bug]		Fix a possible race between dispatcher and socket
				code in a high-load cold-cache resolver scenario.
				[GL #943]

	5242.	[bug]		In relaxed qname minimization mode, fall back to
				normal resolution when encountering a lame
				delegation, and use _.domain/A queries rather
				than domain/NS. [GL #1055]

	5241.	[bug]		Fix Ed448 private and public key ASN.1 prefix blobs.
				[GL #225]

	5240.	[bug]		Remove key id calculation for RSAMD5. [GL #996]

	5239.	[func]		Change the json-c detection to pkg-config. [GL #855]

	5238.	[bug]		Fix a possible deadlock in TCP code. [GL #1046]

	5237.	[bug]		Recurse to find the root server list with 'dig +trace'.
				[GL #1028]

	5236.	[func]		Add SipHash 2-4 implementation in lib/isc/siphash.c
				and switch isc_hash_function() to use SipHash 2-4.
				[GL #605]

	5235.	[cleanup]	Refactor lib/isc/app.c to be thread-safe, unused
				parts of the API has been removed and the
				isc_appctx_t data type has been changed to be
				fully opaque. [GL #1023]

	5234.	[port]		arm: just use the compiler's default support for
				yield. [GL #981]

.. code-block:: none

		--- 9.15.0 released ---

	5233.	[bug]		Negative trust anchors did not work with "forward only;"
				to validating resolvers. [GL #997]

	5232.	[placeholder]

	5231.	[protocol]	Add support for displaying CLIENT-TAG and SERVER-TAG.
				[GL #960]

	5230.	[protocol]	The SHA-1 hash algorithm is no longer used when
				generating DS and CDS records. [GL #1015]

	5229.	[protocol]	Enforce known SSHFP fingerprint lengths. [GL #852]

	5228.	[func]		If trusted-keys and managed-keys were configured
				simultaneously for the same name, the key could
				not be be rolled automatically. This is now
				a fatal configuration error. [GL #868]

	5227.	[placeholder]

	5226.	[placeholder]

	5225.	[func]		Allow dig to print out AAAA record fully expanded.
				with +[no]expandaaaa. [GL #765]

	5224.	[bug]		Only test provide-ixfr on TCP streams. [GL #991]

	5223.	[bug]		Fixed a race in the filter-aaaa plugin accessing
				the hash table. [GL #1005]

	5222.	[bug]		'delv -t ANY' could leak memory. [GL #983]

	5221.	[test]		Enable parallel execution of system tests on
				Windows. [GL !4101]

	5220.	[cleanup]	Refactor the isc_stat structure to take advantage
				of stdatomic. [GL !1493]

	5219.	[bug]		Fixed a race in the filter-aaaa plugin that could
				trigger a crash when returning an instance object
				to the memory pool. [GL #982]

	5218.	[bug]		Conditionally include <dlfcn.h>. [GL #995]

	5217.	[bug]		Restore key id calculation for RSAMD5. [GL #996]

	5216.	[bug]		Fetches-per-zone counter wasn't updated correctly
				when doing qname minimization. [GL #992]

	5215.	[bug]		Change #5124 was incomplete; named could still
				return FORMERR instead of SERVFAIL in some cases.
				[GL #990]

	5214.	[bug]		win32: named now removes its lock file upon shutdown.
				[GL #979]

	5213.	[bug]		win32: Eliminated a race which allowed named.exe running
				as a service to be killed prematurely during shutdown.
				[GL #978]

	5212.	[placeholder]

	5211.	[bug]		Allow out-of-zone additional data to be included
				in authoritative responses if recursion is allowed
				and "minimal-responses" is disabled.  This behavior
				was inadvertently removed in change #4605. [GL #817]

	5210.	[bug]		When dnstap is enabled and recursion is not
				available, incoming queries are now logged
				as "auth". Previously, this depended on whether
				recursion was requested by the client, not on
				whether recursion was available. [GL #963]

	5209.	[bug]		When update-check-ksk is true, add_sigs was not
				considering offline keys, leaving record sets signed
				with the incorrect type key. [GL #763]

	5208.	[test]		Run valid rdata wire encodings through totext+fromtext
				and tofmttext+fromtext methods to check these methods.
				[GL #899]

	5207.	[test]		Check delv and dig TTL values. [GL #965]

	5206.	[bug]		Delv could print out bad TTLs. [GL #965]

	5205.	[bug]		Enforce that a DS hash exists. [GL #899]

	5204.	[test]		Check that dns_rdata_fromtext() produces a record that
				will be accepted by dns_rdata_fromwire(). [GL #852]

	5203.	[bug]		Enforce whether key rdata exists or not in KEY,
				DNSKEY, CDNSKEY and RKEY. [GL #899]

	5202.	[bug]		<dns/ecs.h> was missing ISC_LANG_ENDDECLS. [GL #976]

	5201.	[bug]		Fix a possible deadlock in RPZ update code. [GL #973]

	5200.	[security]	tcp-clients settings could be exceeded in some cases,
				which could lead to exhaustion of file descriptors.
				(CVE-2018-5743) [GL #615]

	5199.	[security]	In certain configurations, named could crash
				if nxdomain-redirect was in use and a redirected
				query resulted in an NXDOMAIN from the cache.
				(CVE-2019-6467) [GL #880]

	5198.	[bug]		If a fetch context was being shut down and, at the same
				time, we returned from qname minimization, an INSIST
				could be hit. [GL #966]

	5197.	[bug]		dig could die in best effort mode on multiple SIG(0)
				records. Similarly on multiple OPT and multiple TSIG
				records. [GL #920]

	5196.	[bug]		make install failed with --with-dlopen=no. [GL #955]

	5195.	[bug]		"allow-update" and "allow-update-forwarding" were
				treated as configuration errors if used at the
				options or view level. [GL #913]

	5194.	[bug]		Enforce non empty ZOMEMD hash. [GL #899]

	5193.	[bug]		EID and NIMLOC failed to do multi-line output
				correctly. [GL #899]

	5192.	[placeholder]

	5191.	[placeholder]

	5190.	[bug]		Ignore trust anchors using disabled algorithms.
				[GL #806]

	5189.	[cleanup]	Remove revoked root DNSKEY from bind.keys. [GL #945]

	5188.	[func]		The "dnssec-enable" option is deprecated and no
				longer has any effect; DNSSEC responses are
				always enabled. [GL #866]

	5187.	[test]		Set time zone before running any tests in dnstap_test.
				[GL #940]

	5186.	[cleanup]	More dnssec-keygen manual tidying. [GL !1678]

	5185.	[placeholder]

	5184.	[bug]		Missing unlocks in sdlz.c. [GL #936]

	5183.	[bug]		Reinitialize ECS data before reusing client
				structures. [GL #881]

	5182.	[bug]		Fix a high-load race/crash in handling of
				isc_socket_close() in resolver. [GL #834]

	5181.	[func]		Add a mechanism for a DLZ module to signal that
				the view's allow-transfer ACL should be used to
				determine whether transfers are allowed. [GL #803]

	5180.	[bug]		delv now honors the operating system's preferred
				ephemeral port range. [GL #925]

	5179.	[cleanup]	Replace some vague type declarations with the more
				specific dns_secalg_t and dns_dsdigest_t.
				Thanks to Tony Finch. [GL !1498]

	5178.	[bug]		Handle EDQUOT (disk quota) and ENOSPC (disk full)
				errors when writing files. [GL #902]

	5177.	[func]		Add the ability to specify in named.conf whether a
				response-policy zone's SOA record should be added
				to the additional section (add-soa yes/no). [GL #865]

	5176.	[tests]		Remove a dependency on libxml in statschannel system
				test. [GL #926]

	5175.	[bug]		Fixed a problem with file input in dnssec-keymgr,
				dnssec-coverage and dnssec-checkds when using
				python3. [GL #882]

	5174.	[doc]		Tidy dnssec-keygen manual. [GL !1557]

	5173.	[bug]		Fixed a race in socket code that could occur when
				accept, send, or recv were called from an event
				loop but the socket had been closed by another
				thread. [RT #874]

	5172.	[bug]		nsupdate now honors the operating system's preferred
				ephemeral port range. [GL #905]

	5171.	[func]		named plugins are now installed into a separate
				directory.  Supplying a filename (a string without path
				separators) in a "plugin" configuration stanza now
				causes named to look for that plugin in that directory.
				[GL #878]

	5170.	[test]		Added --with-dlz-filesystem to feature-test. [GL !1587]

	5169.	[bug]		The presence of certain types in an otherwise
				empty node could cause a crash while processing a
				type ANY query. [GL #901]

	5168.	[bug]		Do not crash on shutdown when RPZ fails to load.  Also,
				keep previous version of the database if RPZ fails to
				load. [GL #813]

	5167.	[bug]		nxdomain-redirect could sometimes lookup the wrong
				redirect name. [GL #892]

	5166.	[placeholder]

	5165.	[contrib]	Removed SDB drivers from contrib; they're obsolete.
				[GL #428]

	5164.	[bug]		Correct errno to result translation in dlz filesystem
				modules. [GL #884]

	5163.	[cleanup]	Out-of-tree builds failed --enable-dnstap. [GL #836]

	5162.	[cleanup]	Improve dnssec-keymgr manual. Thanks to Tony Finch.
				[GL !1518]

	5161.	[bug]		Do not require the SEP bit to be set for mirror zone
				trust anchors. [GL #873]

	5160.	[contrib]	Added DNAME support to the DLZ LDAP schema. Also
				fixed a compilation bug affecting several DLZ
				modules. [GL #872]

	5159.	[bug]		dnssec-coverage was incorrectly ignoring
				names specified on the command line without
				trailing dots. [GL !1478]

	5158.	[protocol]	Add support for AMTRELAY and ZONEMD. [GL #867]

	5157.	[bug]		Nslookup now errors out if there are extra command
				line arguments. [GL #207]

	5156.	[doc]		Extended and refined the section of the ARM describing
				mirror zones. [GL #774]

	5155.	[func]		"named -V" now outputs the default paths to
				named.conf, rndc.conf, bind.keys, and other
				files used or created by named and other tools, so
				that the correct paths to these files can quickly be
				determined regardless of the configure settings
				used when BIND was built. [GL #859]

	5154.	[bug]		dig: process_opt could be called twice on the same
				message leading to a assertion failure. [GL #860]

	5153.	[func]		Zone transfer statistics (size, number of records, and
				number of messages) are now logged for outgoing
				transfers as well as incoming ones. [GL #513]

	5152.	[func]		Improved logging of DNSSEC key events:
				- Zone signing and DNSKEY maintenance events are
				  now logged to the "dnssec" category
				- Messages are now logged when DNSSEC keys are
				  published, activated, inactivated, deleted,
				  or revoked.
				[GL #714]

	5151.	[func]		Options that have been been marked as obsolete in
				named.conf for a very long time are now fatal
				configuration errors. [GL #358]

	5150.	[cleanup]	Remove the ability to compile BIND with assertions
				disabled. [GL #735]

	5149.	[func]		"rndc dumpdb" now prints a line above a stale RRset
				indicating how long the data will be retained in the
				cache for emergency use. [GL #101]

	5148.	[bug]		named did not sign the TKEY response. [GL #821]

	5147.	[bug]		dnssec-keymgr: Add a five-minute margin to better
				handle key events close to 'now'. [GL #848]

	5146.	[placeholder]

	5145.	[func]		Use atomics instead of locked variables for isc_quota
				and isc_counter. [GL !1389]

	5144.	[bug]		dig now returns a non-zero exit code when a TCP
				connection is prematurely closed by a peer more than
				once for the same lookup.  [GL #820]

	5143.	[bug]		dnssec-keymgr and dnssec-coverage failed to find
				key files for zone names ending in ".". [GL #560]

	5142.	[cleanup]	Removed "configure --disable-rpz-nsip" and
				"--disable-rpz-nsdname" options. "nsip-enable"
				and "nsdname-enable" both now default to yes,
				regardless of compile-time settings. [GL #824]

	5141.	[security]	Zone transfer controls for writable DLZ zones were
				not effective as the allowzonexfr method was not being
				called for such zones. (CVE-2019-6465) [GL #790]

	5140.	[bug]		Don't immediately mark existing keys as inactive and
				deleted when running dnssec-keymgr for the first
				time. [GL #117]

	5139.	[bug]		If possible, don't use forwarders when priming.
				This ensures we can get root server IP addresses
				from priming query response glue, which may not
				be present if the forwarding server is returning
				minimal responses. [GL #752]

	5138.	[bug]		Under some circumstances named could hit an assertion
				failure when doing qname minimization when using
				forwarders. [GL #797]

	5137.	[func]		named now logs messages whenever a mirror zone becomes
				usable or unusable for resolution purposes. [GL #818]

	5136.	[cleanup]	Check in named-checkconf that allow-update and
				allow-update-forwarding are not set at the
				view/options level; fix documentation. [GL #512]

	5135.	[port]		sparc: Use smt_pause() instead of pause. [GL #816]

	5134.	[bug]		win32: WSAStartup was not called before getservbyname
				was called. [GL #590]

	5133.	[bug]		'rndc managed-keys' didn't handle class and view
				correctly and failed to add new lines between each
				view. [GL !1327]

	5132.	[bug]		Fix race condition in cleanup part of dns_dt_create().
				[GL !1323]

	5131.	[cleanup]	Address Coverity warnings. [GL #801]

	5130.	[cleanup]	Remove support for l10n message catalogs. [GL #709]

	5129.	[contrib]	sdlz_helper.c:build_querylist was not properly
				splitting the query string. [GL #798]

	5128.	[bug]		Refreshkeytime was not being updated for managed
				keys zones. [GL #784]

	5127.	[bug]		rcode.c:maybe_numeric failed to handle NUL in text
				regions. [GL #807]

	5126.	[bug]		Named incorrectly accepted empty base64 and hex encoded
				fields when reading master files. [GL #807]

	5125.	[bug]		Allow for up to 100 records or 64k of data when caching
				a negative response. [GL #804]

	5124.	[bug]		Named could incorrectly return FORMERR rather than
				SERVFAIL. [GL #804]

	5123.	[bug]		dig could hang indefinitely after encountering an error
				before creating a TCP socket. [GL #692]

	5122.	[bug]		In a "forward first;" configuration, a forwarder
				timeout did not prevent that forwarder from being
				queried again after falling back to full recursive
				resolution. [GL #315]

	5121.	[contrib]	dlz_stub_driver.c fails to return ISC_R_NOTFOUND on none
				matching zone names. [GL !1299]

	5120.	[placeholder]

	5119.	[placeholder]

	5118.	[security]	Named could crash if it is managing a key with
				`managed-keys` and the authoritative zone is rolling
				the key to an unsupported algorithm. (CVE-2018-5745)
				[GL #780]

	5117.	[placeholder]

	5116.	[bug]		Named/named-checkconf triggered a assertion when
				a mirror zone's name is bad. [GL #778]

	5115.	[bug]		Allow unsupported algorithms in zone when not used for
				signing with dnssec-signzone. [GL #783]

	5114.	[func]		Include a 'reconfig/reload in progress' status line
				in rndc status, use it in tests.

	5113.	[port]		Fixed a Windows build error.

	5112.	[bug]		Named/named-checkconf could dump core if there was
				a missing masters clause and a bad notify clause.
				[GL #779]

	5111.	[bug]		Occluded DNSKEY records could make it into the
				delegating NSEC/NSEC3 bitmap. [GL #742]

	5110.	[security]	Named leaked memory if there were multiple Key Tag
				EDNS options present. (CVE-2018-5744) [GL #772]

	5109.	[cleanup]	Remove support for RSAMD5 algorithm. [GL #628]

.. code-block:: none

		--- 9.13.5 released ---

	5108.	[bug]		Named could fail to determine bottom of zone when
				removing out of date keys leading to invalid NSEC
				and NSEC3 records being added to the zone. [GL #771]

	5107.	[bug]		'host -U' did not work. [GL #769]

	5106.	[experimental]	A new "plugin" mechanism has been added to allow
				extension of query processing functionality through
				the use of dynamically loadable libraries. A
				"filter-aaaa.so" plugin has been implemented,
				replacing the filter-aaaa feature that was formerly
				implemented as a native part of BIND.

				The "filter-aaaa", "filter-aaaa-on-v4" and
				"filter-aaaa-on-v6" options can no longer be
				configured using native named.conf syntax. However,
				loading the filter-aaaa.so plugin and setting its
				parameters provides identical functionality.

				Note that the plugin API is a work in progress and
				is likely to evolve as further plugins are
				implemented. [GL #15]

	5105.	[bug]		Fix a race between process_fd and socketclose in
				unix socket code. [GL #744]

	5104.	[cleanup]	Log clearer informational message when a catz zone
				is overridden by a zone in named.conf.
				Thanks to Tony Finch. [GL !1157]

	5103.	[bug]		Add missing design by contract tests to dns_catz*.
				[GL #748]

	5102.	[bug]		dnssec-coverage failed to use the default TTL when
				checking KSK deletion times leading to a exception.
				[GL #585]

	5101.	[bug]		Fix default installation path for Python modules and
				remove the dnspython dependency accidentally introduced
				by change 4970. [GL #730]

	5100.	[func]		Pin resolver tasks to specific task queues. [GL !1117]

	5099.	[func]		Failed mutex and conditional creations are always
				fatal. [GL #674]

.. code-block:: none

		--- 9.13.4 released ---

	5098.	[func]		Failed memory allocations are now fatal. [GL #674]

	5097.	[cleanup]	Remove embedded ATF unit testing framework
				from BIND source distribution.  [GL !875]

	5096.	[func]		Use multiple event loops in socket code, and
				make network threads CPU-affinitive.  This
				significantly improves performance on large
				systems. [GL #666]

	5095.	[test]		Converted all unit tests from ATF to CMocka;
				removed the source code for the ATF libraries.
				Build with "configure --with-cmocka" to enable
				unit testing. [GL #620]

	5094.	[func]		Add 'dig -r' to disable reading of .digrc. [GL !970]

	5093.	[bug]		Log lame qname-minimization servers only if they're
				really lame. [GL #671]

	5092.	[bug]		Address memory leak on SIGTERM in nsupdate when using
				GSS-TSIG. [GL #558]

	5091.	[func]		Two new global and per-view options min-cache-ttl
				and min-ncache-ttl [GL #613]

	5090.	[bug]		dig and mdig failed to properly pre-parse dash value
				pairs when value was a separate argument and started
				with a dash. [GL #584]

	5089.	[bug]		Restore localhost fallback in dig and host which is
				used when no nameserver addresses present in
				/etc/resolv.conf are usable due to the requested
				address family restrictions. [GL #433]

	5088.	[bug]		dig/host/nslookup could crash when interrupted close to
				a query timeout. [GL #599]

	5087.	[test]		Check that result tables are complete. [GL #676]

	5086.	[func]		Log of RPZ now includes the QTYPE and QCLASS. [GL #623]

	5085.	[bug]		win32: Restore looking up nameservers, search list,
				etc. [GL #186]

	5084.	[placeholder]

	5083.	[func]		Add autoconf macro AX_POSIX_SHELL, so we
				can use POSIX-compatible shell features
				in the scripts.

	5082.	[bug]		Fixed a race that could cause a crash in
				dig/host/nslookup. [GL #650]

	5081.	[func]		Use per-worker queues in task manager, make task
				runners CPU-affine. [GL #659]

	5080.	[func]		Improvements to "rndc nta" user interface:
				- catch and report invalid command line options
				- when removing an NTA from all views, do not
				  abort with an error if the NTA was not found
				  in one of the views
				- include the view name in "rndc nta -dump"
				  output, for consistency with the add and remove
				  actions
				Thanks to Tony Finch. [GL !816]

	5079.	[func]		Disable IDN processing in dig and nslookup
				when not on a tty. [GL #653]

	5078.	[cleanup]	Require python components to be explicitly disabled if
				python is not available on unix platforms. [GL #601]

	5077.	[cleanup]	Remove ip6.int support (-i) from dig and mdig.
				[GL !969]

	5076.	[bug]		"require-server-cookie" was not effective if
				"rate-limit" was configured. [GL #617]

	5075.	[bug]		Refresh nameservers from cache when sending final
				query in qname minimization. [GL #16]

	5074.	[cleanup]	Remove vector socket functions - isc_socket_recvv(),
				isc_socket_sendtov(), isc_socket_sendtov2(),
				isc_socket_sendv() - in order to simplify socket code.
				[GL #645]

	5073.	[bug]		Destroy a task first when destroying rpzs and catzs.
				[GL #84]

	5072.	[bug]		Add unit tests for isc_buffer_copyregion() and fix its
				behavior for auto-reallocated buffers. [GL #644]

	5071.	[bug]		Comparison of NXT records was broken. [GL #631]

	5070.	[bug]		Record types which support a empty rdata field were
				not handling the empty rdata field case. [GL #638]

	5069.	[bug]		Fix a hang on in RPZ when named is shutdown during RPZ
				zone update. [GL !907]

	5068.	[bug]		Fix a race in RPZ with min-update-interval set to 0.
				[GL #643]

	5067.	[bug]		Don't minimize qname when sending the query
				to a forwarder. [GL #361]

	5066.	[cleanup]	Allow unquoted strings to be used as a zone names
				in response-policy statements. [GL #641]

	5065.	[bug]		Only set IPV6_USE_MIN_MTU on IPv6. [GL #553]

	5064.	[test]		Initialize TZ environment variable before calling
				dns_test_begin in dnstap_test. [GL #624]

	5063.	[test]		In statschannel test try a few times before failing
				when checking if the compressed output is the same as
				uncompressed. [GL !909]

	5062.	[func]		Use non-crypto-secure PRNG to generate nonces for
				cookies. [GL !887]

	5061.	[protocol]	Add support for EID and NIMLOC. [GL #626]

	5060.	[bug]		GID, UID and UINFO could not be loaded using unknown
				record format. [GL #627]

	5059.	[bug]		Display a per-view list of zones in the web interface.
				[GL #427]

	5058.	[func]		Replace old message digest and hmac APIs with more
				generic isc_md and isc_hmac APIs, and convert their
				respective tests to cmocka. [GL #305]

	5057.	[protocol]	Add support for ATMA. [GL #619]

	5056.	[placeholder]

	5055.	[func]		A default list of primary servers for the root zone is
				now built into named, allowing the "masters" statement
				to be omitted when configuring an IANA root zone
				mirror. [GL #564]

	5054.	[func]		Attempts to use mirror zones with recursion disabled
				are now considered a configuration error. [GL #564]

	5053.	[func]		The only valid zone-level NOTIFY settings for mirror
				zones are now "notify no;" and "notify explicit;".
				[GL #564]

	5052.	[func]		Mirror zones are now configured using "type mirror;"
				rather than "mirror yes;". [GL #564]

	5051.	[doc]		Documentation incorrectly stated that the
				"server-addresses" static-stub zone option accepts
				custom port numbers. [GL #582]

	5050.	[bug]		The libirs version of getaddrinfo() was unable to parse
				scoped IPv6 addresses present in /etc/resolv.conf.
				[GL #187]

	5049.	[cleanup]	QNAME minimization has been deeply refactored. [GL #16]

	5048.	[func]		Add configure option to enable and enforce FIPS mode
				in BIND 9. [GL #506]

	5047.	[bug]		Messages logged for certain query processing failures
				now include a more specific error description if it is
				available. [GL #572]

	5046.	[bug]		named could crash during shutdown if an RPZ
				reload was in progress. [RT #46210]

	5045.	[func]		Remove support for DNSSEC algorithms 3 (DSA)
				and 6 (DSA-NSEC3-SHA1). [GL #22]

	5044.	[cleanup]	If "dnssec-enable" is no, then "dnssec-validation"
				now also defaults to no.  [GL #388]

	5043.	[bug]		Fix creating and validating EdDSA signatures. [GL #579]

	5042.	[test]		Make the chained delegations in reclimit behave
				like they would in a regular name server. [GL #578]

	5041.	[test]		The chain test contains a incomplete delegation.
				[GL #568]

	5040.	[func]		Extended dnstap so that it can log UPDATE requests
				and responses as separate message types. Thanks
				to Greg Rabil. [GL #570]

	5039.	[bug]		Named could fail to preserve owner name case of new
				RRset. [GL #420]

	5038.	[bug]		Chaosnet addresses were compared incorrectly.
				[GL #562]

	5037.	[func]		"allow-recursion-on" and "allow-query-cache-on"
				each now default to the other if only one of them
				is set, in order to be more consistent with the way
				"allow-recursion" and "allow-query-cache" work.
				Also we now ensure that both query-cache ACLs are
				checked when determining cache access. [GL #319]

	5036.	[cleanup]	Fixed a spacing/formatting error in some RPZ-related
				error messages in the log. [GL !805]

	5035.	[test]		Fixed errors that prevented the DNSRPS subtests
				from running in the rpz and rpzrecurse system
				tests. [GL #503]

	5034.	[bug]		A race between threads could prevent zone maintenance
				scheduled immediately after zone load from being
				performed. [GL #542]

	5033.	[bug]		When adding NTAs to multiple views using "rndc nta",
				the text returned via rndc was incorrectly terminated
				after the first line, making it look as if only one
				NTA had been added. Also, it was not possible to
				differentiate between views with the same name but
				different classes; this has been corrected with the
				addition of a "-class" option. [GL #105]

	5032.	[func]		Add krb5-selfsub and ms-selfsub update policy rules.
				[GL #511]

	5031.	[cleanup]	Various defines in platform.h has been either dropped
				if always or never triggered on supported platforms
				or replaced with config.h equivalents if the defines
				didn't have any impact on public headers.  Workarounds
				for LinuxThreads have been removed because NPTL is
				available since Linux kernel 2.6.0.  [GL #525]

	5030.	[bug]		Align CMSG buffers to a 64-bit boundary, fixes crash
				on architectures with strict alignment. [GL #521]

.. code-block:: none

		--- 9.13.3 released ---

	5029.	[func]		Workarounds for servers that misbehave when queried
				with EDNS have been removed, because these broken
				servers and the workarounds for their noncompliance
				cause unnecessary delays, increase code complexity,
				and prevent deployment of new DNS features. See
				https://dnsflagday.net for further details. [GL #150]

	5028.	[bug]		Spread the initial RRSIG expiration times over the
				entire working sig-validity-interval when signing a
				zone in named to even out re-signing and transfer
				loads. [GL #418]

	5027.	[func]		Set SO_SNDBUF size on sockets. [GL #74]

	5026.	[bug]		rndc reconfig should not touch already loaded zones.
				[GL #276]

	5025.	[cleanup]	Remove isc_keyboard family of functions. [GL #178]

	5024.	[func]		Replace custom assembly for atomic operations with
				atomic support from the compiler. The code will now use
				C11 stdatomic, or __atomic, or __sync builtins with GCC
				or Clang compilers, and Interlocked functions with MSVC.
				[GL #10]

	5023.	[cleanup]	Remove wrappers that try to fix broken or incomplete
				implementations of IPv6, pthreads and other core
				functionality required and used by BIND. [GL #192]

	5022.	[doc]		Update ms-self, ms-subdomain, krb5-self, and
				krb5-subdomain documentation. [GL !708]

	5021.	[bug]		dig returned a non-zero exit code when it received a
				reply over TCP after a retry. [GL #487]

	5020.	[func]		RNG uses thread-local storage instead of locks, if
				supported by platform. [GL #496]

	5019.	[cleanup]	A message is now logged when ixfr-from-differences is
				set at zone level for an inline-signed zone. [GL #470]

	5018.	[bug]		Fix incorrect sizeof arguments in lib/isc/pk11.c.
				[GL !588]

	5017.	[bug]		lib/isc/pk11.c failed to unlink the session before
				releasing the lock which is unsafe. [GL !589]

	5016.	[bug]		Named could assert with overlapping filter-aaaa and
				dns64 acls. [GL #445]

	5015.	[bug]		Reloading all zones caused zone maintenance to cease
				for inline-signed zones. [GL #435]

	5014.	[bug]		Signatures loaded from the journal for the signed
				version of an inline-signed zone were not scheduled for
				refresh. [GL #482]

	5013.	[bug]		A referral response with a non-empty ANSWER section was
				inadvertently being treated as an error. [GL #390]

	5012.	[bug]		Fix lock order reversal in pk11_initialize. [GL !590]

	5011.	[func]		Remove support for unthreaded named. [GL #478]

	5010.	[func]		New "validate-except" option specifies a list of
				domains beneath which DNSSEC validation should not
				be performed. [GL #237]

	5009.	[bug]		Upon an OpenSSL failure, the first error in the OpenSSL
				error queue was not logged. [GL #476]

	5008.	[bug]		"rndc signing -nsec3param ..." requests were silently
				ignored for zones which were not yet loaded or
				transferred. [GL #468]

	5007.	[cleanup]	Replace custom ISC boolean and integer data types
				with C99 stdint.h and stdbool.h types. [GL #9]

	5006.	[cleanup]	Code preparing a delegation response was extracted from
				query_delegation() and query_zone_delegation() into a
				separate function in order to decrease code
				duplication. [GL #431]

	5005.	[bug]		dnssec-verify, and dnssec-signzone at the verification
				step, failed on some validly signed zones. [GL #442]

	5004.	[bug]		'rndc reconfig' could cause inline zones to stop
				re-signing. [GL #439]

	5003.	[bug]		dns_acl_isinsecure did not handle geoip elements.
				[GL #406]

	5002.	[bug]		mdig: Handle malformed +ednsopt option, support 100
				+ednsopt options per query rather than 100 total and
				address memory leaks if +ednsopt was specified.
				[GL #410]

	5001.	[bug]		Fix refcount errors on error paths. [GL !563]

	5000.	[bug]		named_server_servestale() could leave the server in
				exclusive mode if an error occurred. [GL #441]

	4999.	[cleanup]	Remove custom printf implementation in lib/isc/print.c.
				[GL #261]

	4998.	[test]		Make resolver and cacheclean tests more civilized.

	4997.	[security]	named could crash during recursive processing
				of DNAME records when "deny-answer-aliases" was
				in use. (CVE-2018-5740) [GL #387]

	4996.	[bug]		dig: Handle malformed +ednsopt option. [GL #403]

	4995.	[test]		Add tests for "tcp-self" update policy. [GL !282]

	4994.	[bug]		Trust anchor telemetry queries were not being sent
				upstream for locally served zones. [GL #392]

	4993.	[cleanup]	Remove support for silently ignoring 'no-change' deltas
				from BIND 8 when processing an IXFR stream. 'no-change'
				deltas will now trigger a fallback to AXFR as the
				recovery mechanism. [GL #369]

	4992.	[bug]		The wrong address was being logged for trust anchor
				telemetry queries. [GL #379]

	4991.	[bug]		"rndc reconfig" was incorrectly handling zones whose
				"mirror" setting was changed. [GL #381]

	4990.	[bug]		Prevent a possible NULL reference in pkcs11-keygen.
				[GL #401]

	4989.	[cleanup]	IDN support in dig has been reworked.  IDNA2003
				fallbacks were removed in the process. [GL #384]

	4988.	[bug]		Don't synthesize NXDOMAIN from NSEC for records under
				a DNAME.

.. code-block:: none

		--- 9.13.2 released ---

	4987.	[cleanup]	dns_rdataslab_tordataset() and its related
				dns_rdatasetmethods_t callbacks were removed as they
				were not being used by anything in BIND. [GL #371]

	4986.	[func]		When built on Linux, BIND now requires the libcap
				library to set process privileges, unless capability
				support is explicitly overridden with "configure
				--disable-linux-caps". [GL #321]

	4985.	[func]		Add a new slave zone option, "mirror", to enable
				serving a non-authoritative copy of a zone that
				is subject to DNSSEC validation before being
				used.  For now, this option is only meant to
				facilitate deployment of an RFC 7706-style local
				copy of the root zone. [GL #33]

	4984.	[bug]		Improve handling of very large incremental
				zone transfers to prevent journal corruption. [GL #339]

	4983.	[func]		Add the ability to not return a DNS COOKIE option
				when one is present in the request (answer-cookie no;).
				[GL #173]

	4982.	[cleanup]	Return FORMERR if the question section is empty
				and no COOKIE option is present; this restores
				older behavior except in the newly specified
				COOKIE case. [GL #260]

	4981.	[bug]		Fix race in cmsg buffer usage in socket code.
				[GL #180]

	4980.	[bug]		Named-checkconf failed to detect bad in-view targets.
				[GL #288]

	4979.	[placeholder]

	4978.	[test]		Fix error handling and resolver configuration in the
				"rpz" system test. [GL #312]

	4977.	[func]		When starting up, log the same details that
				would be reported by 'named -V'. [GL #247]

	4976.	[bug]		Log the label with invalid prefix length correctly
				when loading RPZ zones. [GL #254]

	4975.	[bug]		The server cookie computation for sha1 and sha256 did
				not match the method described in RFC 7873. [GL #356]

	4974.	[bug]		Restore default rrset-order to random. [GL #336]

	4973.	[func]		verifyzone() and the functions it uses were moved to
				libdns and refactored to prevent exit() from being
				called upon failure.  A side effect of that is that
				dnssec-signzone and dnssec-verify now check for memory
				leaks upon shutdown. [GL #266]

	4972.	[func]		Declare the 'rdata' argument for dns_rdata_tostruct()
				to be const. [GL #341]

	4971.	[bug]		dnssec-signzone and dnssec-verify did not treat records
				below a DNAME as out-of-zone data. [GL #298]

	4970.	[func]		Add QNAME minimization option to resolver. [GL #16]

	4969.	[cleanup]	Refactor zone logging functions. [GL #269]

.. code-block:: none

		--- 9.13.1 released ---

	4968.	[bug]		If glue records are signed, attempt to validate them.
				[GL #209]

	4967.	[cleanup]	Add "answer-cookie" to the parser, marked obsolete.

	4966.	[placeholder]

	4965.	[func]		Add support for marking options as deprecated.
				[GL #322]

	4964.	[bug]		Reduce the probability of double signature when deleting
				a DNSKEY by checking if the node is otherwise signed
				by the algorithm of the key to be deleted. [GL #240]

	4963.	[test]		ifconfig.sh now uses "ip" instead of "ifconfig",
				if available, to configure the test interfaces on
				linux.  [GL #302]

	4962.	[cleanup]	Move 'named -T' processing to its own function.
				[GL #316]

	4961.	[protocol]	Remove support for ECC-GOST (GOST R 34.11-94).
				[GL #295]

	4960.	[security]	When recursion is enabled, but the "allow-recursion"
				and "allow-query-cache" ACLs are not specified,
				they should be limited to local networks,
				but were inadvertently set to match the default
				"allow-query", thus allowing remote queries.
				(CVE-2018-5738) [GL #309]

	4959.	[func]		NSID logging (enabled by the "request-nsid" option)
				now has its own "nsid" category, instead of using the
				"resolver" category. [GL !332]

	4958.	[bug]		Remove redundant space from NSEC3 record. [GL #281]

	4957.	[func]		The default setting for "dnssec-validation" is now
				"auto", which activates DNSSEC validation using the
				IANA root key. (The default can be changed back to
				"yes", which activates DNSSEC validation only when keys
				are explicitly configured in named.conf, by building
				BIND with "configure --disable-auto-validation".)
				[GL #30]

	4956.	[func]		Change isc_random() to be just PRNG using xoshiro128**,
				and add isc_nonce_buf() that uses CSPRNG. [GL #289]

	4955.	[cleanup]	Silence cppcheck warnings in lib/dns/master.c.
				[GL #286]

	4954.	[func]		Messages about serving of stale answers are now
				directed to the "serve-stale" logging category.
				Also clarified serve-stale documentation. [GL !323]

	4953.	[bug]		Removed the option to build the red black tree
				database without a hash table; the non-hashing
				version was buggy and is not needed. [GL #184]

	4952.	[func]		Authoritative server support in named for the
				EDNS CLIENT-SUBNET option (which was experimental
				and not practical to deploy) has been removed.

				The ECS option is still supported in dig and mdig
				via the +subnet option, and can be parsed and logged
				when received by named, but it is no longer used
				for ACL processing. The "geoip-use-ecs" option
				is now obsolete; a warning will be logged if it is
				used in named.conf. "ecs" tags in an ACL definition
				are also obsolete and will cause the configuration
				to fail to load.  [GL #32]

	4951.	[protocol]	Add "HOME.ARPA" to list of built in empty zones as
				per RFC 8375. [GL #273]

.. code-block:: none

		--- 9.13.0 released ---

	4950.	[bug]		ISC_SOCKEVENTATTR_TRUNC was not be set. [GL #238]

	4949.	[placeholder]

	4948.	[bug]		When request-nsid is turned on, EDNS NSID options
				should be logged at level info. Since change 3741
				they have been logged at debug(3) by mistake.
				[GL !290]

	4947.	[func]		Replace all random functions with isc_random(),
				isc_random_buf() and isc_random_uniform() API.
				[GL #221]

	4946.	[bug]		Additional glue was not being returned by resolver
				for unsigned zones since change 4596. [GL #209]

	4945.	[func]		BIND can no longer be built without DNSSEC support.
				A cryptography provider (i.e., OpenSSL or a hardware
				service module with PKCS#11 support) must be
				available. [GL #244]

	4944.	[cleanup]	Silence cppcheck portability warnings in
				lib/isc/tests/buffer_test.c. [GL #239]

	4943.	[bug]		Change 4687 consumed too much memory when running
				system tests with --with-tuning=large.  Reduced the
				hash table size to 512 entries for 'named -m record'
				restoring the previous memory footprint. [GL #248]

	4942.	[cleanup]	Consolidate multiple instances of splitting of
				batchline in dig into a single function. [GL #196]

	4941.	[cleanup]	Silence clang static analyzer warnings. [GL #196]

	4940.	[cleanup]	Extract the loop in dns__zone_updatesigs() into
				separate functions to improve code readability.
				[GL #135]

	4939.	[test]		Add basic unit tests for update_sigs(). [GL #135]

	4938.	[placeholder]

	4937.	[func]		Remove support for OpenSSL < 1.0.0 [GL #191]

	4936.	[func]		Always use OpenSSL or PKCS#11 random data providers,
				and remove the --{enable,disable}-crypto-rand configure
				options. [GL #165]

	4935.	[func]		Add support for LibreSSL >= 2.7.0 (some OpenSSL 1.1.0
				call were added). [GL #191]

	4934.	[security]	The serve-stale feature could cause an assertion failure
				in rbtdb.c even when stale-answer-enable was false.
				Simultaneous use of stale cache records and NSEC
				aggressive negative caching could trigger a recursion
				loop. (CVE-2018-5737) [GL #185]

	4933.	[bug]		Not creating signing keys for an inline signed zone
				prevented changes applied to the raw zone from being
				reflected in the secure zone until signing keys were
				made available. [GL #159]

	4932.	[bug]		Bumped signed serial of an inline signed zone was
				logged even when an error occurred while updating
				signatures. [GL #159]

	4931.	[func]		Removed the "rbtdb64" database implementation.
				[GL #217]

	4930.	[bug]		Remove a bogus check in nslookup command line
				argument processing. [GL #206]

	4929.	[func]		Add the ability to set RA and TC in queries made by
				dig (+[no]raflag, +[no]tcflag). [GL #213]

	4928.	[func]		The "dnskey-sig-validity" option allows
				"sig-validity-interval" to be overridden for signatures
				covering DNSKEY RRsets. [GL #145]

	4927.	[placeholder]

	4926.	[func]		Add root key sentinel support.  To disable, add
				'root-key-sentinel no;' to named.conf. [GL #37]

	4925.	[func]		Several configuration options that define intervals
				can now take TTL value suffixes (for example, 2h or 1d)
				in addition to integer parameters. These include
				max-cache-ttl, max-ncache-ttl, max-policy-ttl,
				fstrm-set-reopen-interval, interface-interval, and
				min-update-interval. [GL #203]

	4924.	[cleanup]	Clean up the isc_string_* namespace and leave
				only strlcpy and strlcat. [GL #178]

	4923.	[cleanup]	Refactor socket and socket event options into
				enum types. [GL !135]

	4922.	[bug]		dnstap: Log the destination address of client
				packets rather than the interface address.
				[GL #197]

	4921.	[cleanup]	Add dns_fixedname_initname() and refactor the caller
				code to make usage of the new function, as a part of
				refactoring dns_fixedname_*() macros were turned into
				functions. [GL #183]

	4920.	[cleanup]	Clean up libdns removing most of the backwards
				compatibility wrappers.

	4919.	[cleanup]	Clean up the isc_hash_* namespace and leave only
				the FNV-1a hash implementation. [GL #178]

	4918.	[bug]		Fix double free after keygen error in dnssec-keygen
				when OpenSSL >= 1.1.0 is used and RSA_generate_key_ex
				fails. [GL #109]

	4917.	[func]		Support 64 RPZ policy zones by default. [GL #123]

	4916.	[func]		Remove IDNA2003 support and the bundled idnkit-1.0
				library.

	4915.	[func]		Implement IDNA2008 support in dig by adding support
				for libidn2.  New dig option +idnin has been added,
				which allows to process invalid domain names much
				like dig without IDN support.  libidn2 version 2.0
				or higher is needed for +idnout enabled by default.

	4914.	[security]	A bug in zone database reference counting could lead to
				a crash when multiple versions of a slave zone were
				transferred from a master in close succession.
				(CVE-2018-5736) [GL #134]

	4913.	[test]		Re-implemented older unit tests in bin/tests as ATF,
				removed the lib/tests unit testing library. [GL #115]

	4912.	[test]		Improved the reliability of the 'cds' system test.
				[GL #136]

	4911.	[test]		Improved the reliability of the 'mkeys' system test.
				[GL #128]

	4910.	[func]		Update util/check-changes to work on release branches.
				[GL #113]

	4909.	[bug]		named-checkconf did not detect in-view zone collisions.
				[GL #125]

	4908.	[test]		Eliminated unnecessary waiting in the allow_query
				system test. Also changed its name to allow-query.
				[GL #81]

	4907.	[test]		Improved the reliability of the 'notify' system
				test. [GL #59]

	4906.	[func]		Replace getquad() with inet_pton(), completing
				change #4900. [GL #56]

	4905.	[bug]		irs_resconf_load() ignored resolv.conf syntax errors
				when "domain" or "search" options were present in that
				file. [GL #110]

	4904.	[bug]		Temporarily revert change #4859. [GL #124]

	4903.	[bug]		"check-mx fail;" did not prevent MX records containing
				IP addresses from being added to a zone by a dynamic
				update. [GL #112]

	4902.	[test]		Improved the reliability of the 'ixfr' system
				test. [GL #66]

	4901.	[func]		"dig +nssearch" now lists the name servers
				for a domain that time out, as well as the servers
				that respond. [GL #64]

	4900.	[func]		Remove all uses of inet_aton().  As a result of this
				change, IPv4 addresses are now only accepted in
				dotted-quad format. [GL #13]

	4899.	[test]		Convert most of the remaining system tests to be able
				to run in parallel, continuing the work from change
				#4895. To take advantage of this, use "make -jN check",
				where N is the number of processors to use. [GL #91]

	4898.	[func]		Remove libseccomp based system-call filtering. [GL #93]

	4897.	[test]		Update to rpz system test so that it doesn't recurse.
				[GL #68]

	4896.	[test]		cacheclean system test was not robust. [GL #82]

	4895.	[test]		Allow some system tests to run in parallel.
				[RT #46602]

	4894.	[bug]		named could crash while rolling a dnstap output file.
				[RT #46942]

	4893.	[bug]		Address various issues reported by cppcheck. [GL #51]

	4892.	[bug]		named could leak memory when "rndc reload" was invoked
				before all zone loading actions triggered by a previous
				"rndc reload" command were completed. [RT #47076]

	4891.	[placeholder]

	4890.	[func]		Remove unused ondestroy callback from libisc.
				[isc-projects/bind9!3]

	4889.	[func]		Warn about the use of old root keys without the new
				root key being present.  Warn about dlv.isc.org's
				key being present. Warn about both managed and
				trusted root keys being present. [RT #43670]

	4888.	[test]		Initialize sockets correctly in sample-update so
				that the nsupdate system test will run on Windows.
				[RT #47097]

	4887.	[test]		Enable the rpzrecurse test to run on Windows.
				[RT #47093]

	4886.	[doc]		Document dig -u in manpage. [RT #47150]

	4885.	[security]	update-policy rules that otherwise ignore the name
				field now require that it be set to "." to ensure
				that any type list present is properly interpreted.
				[RT #47126]

	4884.	[bug]		named could crash on shutdown due to a race between
				shutdown_server() and ns__client_request(). [RT #47120]

	4883.	[cleanup]	Improved debugging output from dnssec-cds. [RT #47026]

	4882.	[bug]		Address potential memory leak in
				dns_update_signaturesinc. [RT #47084]

	4881.	[bug]		Only include dst_openssl.h when OpenSSL is required.
				[RT #47068]

	4880.	[bug]		Named wasn't returning the target of a cross-zone
				CNAME between two served zones when recursion was
				desired and available (RD=1, RA=1). (When this is
				not the case, the CNAME target is deliberately
				withheld to prevent accidental cache poisoning.)
				[RT #47078]

	4879.	[bug]		dns_rdata_caa:value_len field was too small.
				[RT #47086]

	4878.	[bug]		List 'ply' as a requirement for the 'isc' python
				package. [RT #47065]

	4877.	[bug]		Address integer overflow when exponentially
				backing off retry intervals. [RT #47041]

	4876.	[bug]		Address deadlock with accessing a keytable. [RT #47000]

	4875.	[bug]		Address compile failures on older systems. [RT #47015]

	4874.	[bug]		Wrong time display when reporting new keywarntime.
				[RT #47042]

	4873.	[doc]		Grammars for named.conf included in the ARM are now
				automatically generated by the configuration parser
				itself.  As a side effect of the work needed to
				separate zone type grammars from each other, this
				also makes checking of zone statements in
				named-checkconf more correct and consistent.
				[RT #36957]

	4872.	[bug]		Don't permit loading meta RR types such as TKEY
				from master files. [RT #47009]

	4871.	[bug]		Fix configure glitch in detecting stdatomic.h
				support on systems with multiple compilers.
				[RT #46959]

	4870.	[test]		Update included ATF library to atf-0.21 preserving
				the ATF tool. [RT #46967]

	4869.	[bug]		Address some cases where NULL with zero length could
				be passed to memmove which is undefined behavior and
				can lead to bad optimization. [RT #46888]

	4868.	[func]		dnssec-keygen can no longer generate HMAC keys.
				Use tsig-keygen instead. [RT #46404]

	4867.	[cleanup]	Normalize rndc on/off commands (validation,
				querylog, serve-stale) so they all accept the
				same synonyms for on/off (yes/no, true/false,
				enable/disable). Thanks to Tony Finch. [RT #47022]

	4866.	[port]		DST library initialization verifies MD5 (when MD5
				was not disabled) and SHA-1 hash and HMAC support.
				[RT #46764]

	4865.	[cleanup]	Simplify handling isc_socket_sendto2() return values.
				[RT #46986]

	4864.	[bug]		named acting as a slave for a catalog zone crashed if
				the latter contained a master definition without an IP
				address. [RT #45999]

	4863.	[bug]		Fix various other bugs reported by Valgrind's
				memcheck tool. [RT #46978]

	4862.	[bug]		The rdata flags for RRSIG were not being properly set
				when constructing a rdataslab. [RT #46978]

	4861.	[bug]		The isc_crc64 unit test was not endian independent.
				[RT #46973]

	4860.	[bug]		isc_int8_t should be signed char.  [RT #46973]

	4859.	[bug]		A loop was possible when attempting to validate
				unsigned CNAME responses from secure zones;
				this caused a delay in returning SERVFAIL and
				also increased the chances of encountering
				CVE-2017-3145. [RT #46839]

	4858.	[security]	Addresses could be referenced after being freed
				in resolver.c, causing an assertion failure.
				(CVE-2017-3145) [RT #46839]

	4857.	[bug]		Maintain attach/detach semantics for event->db,
				event->node, event->rdataset and event->sigrdataset
				in query.c. [RT #46891]

	4856.	[bug]		'rndc zonestatus' reported the wrong underlying type
				for a inline slave zone. [RT #46875]

	4855.	[bug]		isc_time_formatshorttimestamp produced incorrect
				output. [RT #46938]

	4854.	[bug]		query_synthcnamewildcard should stop generating the
				response if query_synthwildcard fails. [RT #46939]

	4853.	[bug]		Add REQUIRE's and INSIST's to isc_time_formatISO8601L
				and isc_time_formatISO8601Lms. [RT #46916]

	4852.	[bug]		Handle strftime() failing in isc_time_formatISO8601ms.
				Add REQUIRE's and INSIST's to isc_time_formattimestamp,
				isc_time_formathttptimestamp, isc_time_formatISO8601,
				isc_time_formatISO8601ms. [RT #46892]

	4851.	[port]		Support using kyua as well as atf-run to run the unit
				tests. [RT #46853]

	4850.	[bug]		Named failed to restart with multiple added zones in
				lmdb database. [RT #46889]

	4849.	[bug]		Duplicate zones could appear in the .nzf file if
				addzone failed. [RT #46435]

	4848.	[func]		Zone types "primary" and "secondary" can now be used
				as synonyms for "master" and "slave" in named.conf.
				[RT #46713]

	4847.	[bug]		dnssec-dnskey-kskonly was not being honored for
				CDS and CDNSKEY. [RT #46755]

	4846.	[test]		Adjust timing values in runtime system test. Address
				named.pid removal races in runtime system test.
				[RT #46800]

	4845.	[bug]		Dig (non iOS) should exit on malformed names.
				[RT #46806]

	4844.	[test]		Address memory leaks in libatf-c. [RT #46798]

	4843.	[bug]		dnssec-signzone free hashlist on exit. [RT #46791]

	4842.	[bug]		Conditionally compile opensslecdsa_link.c to avoid
				warnings about unused function. [RT #46790]

.. code-block:: none

		--- 9.12.0rc1 released ---

	4841.	[bug]		Address -fsanitize=undefined warnings. [RT #46786]

	4840.	[test]		Add tests to cover fallback to using ZSK on inactive
				KSK. [RT #46787]

	4839.	[bug]		zone.c:zone_sign was not properly determining
				if there were active KSK and ZSK keys for
				a algorithm when update-check-ksk is true
				(default) leaving records unsigned with one or
				more DNSKEY algorithms. [RT #46774]

	4838.	[bug]		zone.c:add_sigs was not properly determining
				if there were active KSK and ZSK keys for
				a algorithm when update-check-ksk is true
				(default) leaving records unsigned with one or
				more DNSKEY algorithms. [RT #46754]

	4837.	[bug]		dns_update_signatures{inc} (add_sigs) was not
				properly determining if there were active KSK and
				ZSK keys for a algorithm when update-check-ksk is
				true (default) leaving records unsigned when there
				were multiple DNSKEY algorithms for the zone.
				[RT #46743]

	4836.	[bug]		Zones created using "rndc addzone" could
				temporarily fail to inherit an "allow-transfer"
				ACL that had been configured in the options
				statement. [RT #46603]

	4835.	[cleanup]	Clean up and refactor LMDB-related code. [RT #46718]

	4834.	[port]		Fix LMDB support on OpenBSD. [RT #46718]

	4833.	[bug]		isc_event_free should check that the event is not
				linked when called. [RT #46725]

	4832.	[bug]		Events were not being removed from zone->rss_events.
				[RT #46725]

	4831.	[bug]		Convert the RRSIG expirytime to 64 bits for
				comparisons in diff.c:resign. [RT #46710]

	4830.	[bug]		Failure to configure ATF when requested did not cause
				an error in top-level configure script. [RT #46655]

	4829.	[bug]		isc_heap_delete did not zero the index value when
				the heap was created with a callback to do that.
				[RT #46709]

	4828.	[bug]		Do not use thread-local storage for storing LMDB reader
				locktable slots. [RT #46556]

	4827.	[misc]		Add a precommit check script util/checklibs.sh
				[RT #46215]

	4826.	[cleanup]	Prevent potential build failures in bin/confgen/ and
				bin/named/ when using parallel make. [RT #46648]

	4825.	[bug]		Prevent a bogus "error during managed-keys processing
				(no more)" warning from being logged. [RT #46645]

	4824.	[port]		Add iOS hooks to dig. [RT #42011]

	4823.	[test]		Refactor reclimit system test to improve its
				reliability and speed. [RT #46632]

	4822.	[bug]		Use resign_sooner in dns_db_setsigningtime. [RT #46473]

	4821.	[bug]		When resigning ensure that the SOA's expire time is
				always later that the resigning time of other records.
				[RT #46473]

	4820.	[bug]		dns_db_subtractrdataset should transfer the resigning
				information to the new header. [RT #46473]

	4819.	[bug]		Fully backout the transaction when adding a RRset
				to the resigning / removal heaps fails. [RT #46473]

	4818.	[test]		The logfileconfig system test could intermittently
				report false negatives on some platforms. [RT #46615]

	4817.	[cleanup]	Use DNS_NAME_INITABSOLUTE and DNS_NAME_INITNONABSOLUTE.
				[RT #45433]

	4816.	[bug]		Don't use a common array for storing EDNS options
				in DiG as it could fill up. [RT #45611]

	4815.	[bug]		rbt_test.c:insert_and_delete needed to call
				dns_rbt_addnode instead of dns_rbt_addname. [RT #46553]

	4814.	[cleanup]	Use AS_HELP_STRING for consistent help text. [RT #46521]

	4813.	[bug]		Address potential read after free errors from
				query_synthnodata, query_synthwildcard and
				query_synthnxdomain. [RT #46547]

	4812.	[bug]		Minor improvements to stability and consistency of code
				handling managed keys. [RT #46468]

	4811.	[bug]		Revert api changes to use <isc/buffer.h> inline
				macros.  Provide a alternative mechanism to turn
				on the use of inline macros when building BIND.
				[RT #46520]

	4810.	[test]		The chain system test failed if the IPv6 interfaces
				were not configured. [RT #46508]

.. code-block:: none

		--- 9.12.0b2 released ---

	4809.	[port]		Check at configure time whether -latomic is needed
				for stdatomic.h. [RT #46324]

	4808.	[bug]		Properly test for zlib.h. [RT #46504]

	4807.	[cleanup]	isc_rng_randombytes() returns a specified number of
				bytes from the PRNG; this is now used instead of
				calling isc_rng_random() multiple times. [RT #46230]

	4806.	[func]		Log messages related to loading of zones are now
				directed to the "zoneload" logging category.
				[RT #41640]

	4805.	[bug]		TCP4Active and TCP6Active weren't being updated
				correctly. [RT #46454]

	4804.	[port]		win32: access() does not work on directories as
				required by POSIX.  Supply a alternative in
				isc_file_isdirwritable. [RT #46394]

	4803.	[placeholder]

	4802.	[test]		Refactor mkeys system test to make it quicker and more
				reliable. [RT #45293]

	4801.	[func]		'dnssec-lookaside auto;' and 'dnssec-lookaside .
				trust-anchor dlv.isc.org;' now elicit warnings rather
				than being fatal configuration errors. [RT #46410]

	4800.	[bug]		When processing delzone, write one zone config per
				line to the NZF. [RT #46323]

	4799.	[cleanup]	Improve clarity of keytable unit tests. [RT #46407]

	4798.	[func]		Keys specified in "managed-keys" statements
				are tagged as "initializing" until they have been
				updated by a key refresh query. If initialization
				fails it will be visible from "rndc secroots".
				[RT #46267]

	4797.	[func]		Removed "isc-hmac-fixup", as the versions of BIND that
				had the bug it worked around are long past end of
				life. [RT #46411]

	4796.	[bug]		Increase the maximum configurable TCP keepalive
				timeout to 65535. [RT #44710]

	4795.	[func]		A new statistics counter has been added to track
				priming queries. [RT #46313]

	4794.	[func]		"dnssec-checkds -s" specifies a file from which
				to read a DS set rather than querying the parent.
				[RT #44667]

	4793.	[bug]		nsupdate -[46] could overflow the array of server
				addresses. [RT #46402]

	4792.	[bug]		Fix map file header correctness check. [RT #38418]

	4791.	[doc]		Fixed outdated documentation about export libraries.
				[RT #46341]

	4790.	[bug]		nsupdate could trigger a require when sending a
				update to the second address of the server.
				[RT #45731]

	4789.	[cleanup]	Check writability of new-zones-directory. [RT #46308]

	4788.	[cleanup]	When using "update-policy local", log a warning
				when an update matching the session key is received
				from a remote host. [RT #46213]

	4787.	[cleanup]	Turn nsec3param_salt_totext() into a public function,
				dns_nsec3param_salttotext(), and add unit tests for it.
				[RT #46289]

	4786.	[func]		The "filter-aaaa-on-v4" and "filter-aaaa-on-v6"
				options are no longer conditionally compiled.
				[RT #46340]

	4785.	[func]		The hmac-md5 algorithm is no longer recommended for
				use with RNDC keys.  The default in rndc-confgen
				is now hmac-sha256. [RT #42272]

	4784.	[func]		The use of dnssec-keygen to generate HMAC keys is
				deprecated in favor of tsig-keygen.  dnssec-keygen
				will print a warning when used for this purpose.
				All HMAC algorithms will be removed from
				dnssec-keygen in a future release. [RT #42272]

	4783.	[test]		dnssec: 'check that NOTIFY is sent at the end of
				NSEC3 chain generation failed' required more time
				on some machines for the IXFR to complete. [RT #46388]

	4782.	[test]		dnssec: 'checking positive and negative validation
				with negative trust anchors' required more time to
				complete on some machines. [RT #46386]

	4781.	[maint]		B.ROOT-SERVERS.NET is now 199.9.14.201. [RT #45889]

	4780.	[bug]		When answering ANY queries, don't include the NS
				RRset in the authority section if it was already
				in the answer section. [RT #44543]

	4779.	[bug]		Expire NTA at the start of the second. Don't update
				the expiry value if the record has already expired
				after a successful check. [RT #46368]

	4778.	[test]		Improve synth-from-dnssec testing. [RT #46352]

	4777.	[cleanup]	Removed a redundant call to configure_view_acl().
				[RT #46369]

	4776.	[bug]		Improve portability of ht_test. [RT #46333]

	4775.	[bug]		Address Coverity warnings in ht_test.c and mem_test.c
				[RT #46281]

	4774.	[bug]		<isc/util.h> was incorrectly included in several
				header files. [RT #46311]

	4773.	[doc]		Fixed generating Doxygen documentation for functions
				annotated using certain macros.  Miscellaneous
				Doxygen-related cleanups. [RT #46276]

.. code-block:: none

		--- 9.12.0b1 released ---

	4772.	[test]		Expanded unit testing framework for libns, using
				hooks to interrupt query flow and inspect state
				at specified locations. [RT #46173]

	4771.	[bug]		When sending RFC 5011 refresh queries, disregard
				cached DNSKEY rrsets. [RT #46251]

	4770.	[bug]		Cache additional data from priming queries as glue.
				Previously they were ignored as unsigned
				non-answer data from a secure zone, and never
				actually got added to the cache, causing hints
				to be used frequently for root-server
				addresses, which triggered re-priming. [RT #45241]

	4769.	[func]		The working directory and managed-keys directory has
				to be writeable (and seekable). [RT #46077]

	4768.	[func]		By default, memory is no longer filled with tag values
				when it is allocated or freed; this improves
				performance but makes debugging of certain memory
				issues more difficult. "named -M fill" turns memory
				filling back on. (Building "configure
				--enable-developer", turns memory fill on by
				default again; it can then be disabled with
				"named -M nofill".) [RT #45123]

	4767.	[func]		Add a new function, isc_buffer_printf(), which can be
				used to append a formatted string to the used region of
				a buffer. [RT #46201]

	4766.	[cleanup]	Address Coverity warnings. [RT #46150]

	4765.	[bug]		Address potential INSIST in dnssec-cds. [RT #46150]

	4764.	[bug]		Address portability issues in cds system test.
				[RT #46214]

	4763.	[contrib]	Improve compatibility when building MySQL DLZ
				module by using mysql_config if available.
				[RT #45558]

	4762.	[func]		"update-policy local" is now restricted to updates
				from local addresses. (Previously, other addresses
				were allowed so long as updates were signed by the
				local session key.) [RT #45492]

	4761.	[protocol]	Add support for DOA. [RT #45612]

	4760.	[func]		Add glue cache statistics counters. [RT #46028]

	4759.	[func]		Add logging channel "trust-anchor-telemetry" to
				record trust-anchor-telemetry in incoming requests.
				Both _ta-XXXX.<anchor>/NULL and EDNS KEY-TAG options
				are logged.  [RT #46124]

	4758.	[doc]		Remove documentation of unimplemented "topology".
				[RT #46161]

	4757.	[func]		New "dnssec-cds" command creates a new parent DS
				RRset based on CDS or CDNSKEY RRsets found in
				a child zone, and generates either a dsset file
				or stream of nsupdate commands to update the
				parent. Thanks to Tony Finch. [RT #46090]

	4756.	[bug]		Interrupting dig could lead to an INSIST failure after
				certain errors were encountered while querying a host
				whose name resolved to more than one address.  Change
				4537 increased the odds of triggering this issue by
				causing dig to hang indefinitely when certain error
				paths were evaluated.  dig now also retries TCP queries
				(once) if the server gracefully closes the connection
				before sending a response. [RT #42832, #45159]

	4755.	[cleanup]	Silence unnecessary log message when NZF file doesn't
				exist. [RT #46186]

	4754.	[bug]		dns_zone_setview needs a two stage commit to properly
				handle errors. [RT #45841]

	4753.	[contrib]	Software obtainable from known upstream locations
				(i.e., zkt, nslint, query-loc) has been removed.
				Links to these and other packages can be found at
				https://www.isc.org/community/tools [RT #46182]

	4752.	[test]		Add unit test for isc_net_pton. [RT #46171]

	4751.	[func]		"dnssec-signzone -S" can now automatically add parent
				synchronization records (CDS and CDNSKEY) according
				to key metadata set using the -Psync and -Dsync
				options to dnssec-keygen and dnssec-settime.
				[RT #46149]

	4750.	[func]		"rndc managed-keys destroy" shuts down RFC 5011 key
				maintenance and deletes the managed-keys database.
				If followed by "rndc reconfig" or a server restart,
				key maintenance is reinitialized from scratch.
				This is primarily intended for testing. [RT #32456]

	4749.	[func]		The ISC DLV service has been shut down, and all
				DLV records have been removed from dlv.isc.org.
				- Removed references to ISC DLV in documentation
				- Removed DLV key from bind.keys
				- No longer use ISC DLV by default in delv
				- "dnssec-lookaside auto" and configuration of
				  "dnssec-lookaide" with dlv.isc.org as the trust
				  anchor are both now fatal errors.
				[RT #46155]

	4748.	[cleanup]	Sprintf to snprintf coversions. [RT #46132]

	4747.	[func]		Synthesis of responses from DNSSEC-verified records.
				Stage 3 - synthesize NODATA responses. [RT #40138]

	4746.	[cleanup]	Add configured prefixes to configure summary
				output. [RT #46153]

	4745.	[test]		Add color-coded pass/fail messages to system
				tests when running on terminals that support them.
				[RT #45977]

	4744.	[bug]		Suppress trust-anchor-telemetry queries if
				validation is disabled. [RT #46131]

	4743.	[func]		Exclude trust-anchor-telemetry queries from
				synth-from-dnssec processing. [RT #46123]

	4742.	[func]		Synthesis of responses from DNSSEC-verified records.
				Stage 2 - synthesis of records from wildcard data.
				If the dns64 or filter-aaaa* is configured then the
				involved lookups are currently excluded. [RT #40138]

	4741.	[bug]		Make isc_refcount_current() atomically read the
				counter value. [RT #46074]

	4740.	[cleanup]	Avoid triggering format-truncated warnings. [RT #46107]

	4739.	[cleanup]	Address clang static analysis warnings. [RT #45952]

	4738.	[port]		win32: strftime mishandles %Z. [RT #46039]

	4737.	[cleanup]	Address Coverity warnings. [RT #46012]

	4736.	[cleanup]	(a) Added comments to NSEC3-related functions in
				lib/dns/zone.c.  (b) Refactored NSEC3 salt formatting
				code.  (c) Minor tweaks to lock and result handling.
				[RT #46053]

	4735.	[bug]		Add @ISC_OPENSSL_LIBS@ to isc-config. [RT #46078]

	4734.	[contrib]	Added sample configuration for DNS-over-TLS in
				contrib/dnspriv.

	4733.	[bug]		Change #4706 introduced a bug causing TCP clients
				not be reused correctly, leading to unconstrained
				memory growth. [RT #46029]

	4732.	[func]		Change default minimal-responses setting to
				no-auth-recursive. [RT #46016]

	4731.	[bug]		Fix use after free when closing an LMDB. [RT #46000]

	4730.	[bug]		Fix out of bounds access in DHCID totext() method.
				[RT #46001]

	4729.	[bug]		Don't use memset() to wipe memory, as it may be
				removed by compiler optimizations when the
				memset() occurs on automatic stack allocation
				just before function return. [RT #45947]

	4728.	[func]		Use C11's stdatomic.h instead of isc_atomic
				where available. [RT #40668]

	4727.	[bug]		Retransferring an inline-signed slave using NSEC3
				around the time its NSEC3 salt was changed could result
				in an infinite signing loop. [RT #45080]

	4726.	[port]		Prevent setsockopt() errors related to TCP_FASTOPEN
				from being logged on FreeBSD if the kernel does not
				support it.  Notify the user when the kernel does
				support TCP_FASTOPEN, but it is disabled by sysctl.
				Add a new configure option, --disable-tcp-fastopen, to
				disable use of TCP_FASTOPEN altogether. [RT #44754]

	4725.	[bug]		Nsupdate: "recvsoa" was incorrectly reported for
				failures in sending the update message.  The correct
				location to be reported is "update_completed".
				[RT #46014]

	4724.	[func]		By default, BIND now uses the random number
				functions provided by the crypto library (i.e.,
				OpenSSL or a PKCS#11 provider) as a source of
				randomness rather than /dev/random.  This is
				suitable for virtual machine environments
				which have limited entropy pools and lack
				hardware random number generators.

				This can be overridden by specifying another
				entropy source via the "random-device" option
				in named.conf, or via the -r command line option;
				however, for functions requiring full cryptographic
				strength, such as DNSSEC key generation, this
				cannot be overridden. In particular, the -r
				command line option no longer has any effect on
				dnssec-keygen.

				This can be disabled by building with
				"configure --disable-crypto-rand".
				[RT #31459] [RT #46047]

	4723.	[bug]		Statistics counter DNSTAPdropped was misidentified
				as DNSSECdropped. [RT #46002]

	4722.	[cleanup]	Clean up uses of strcpy() and strcat() in favor of
				strlcpy() and strlcat() for safety. [RT #45981]

	4721.	[func]		'dnssec-signzone -x' and 'dnssec-dnskey-kskonly'
				options now apply to CDNSKEY and DS records as well
				as DNSKEY. Thanks to Tony Finch. [RT #45689]

	4720.	[func]		Added a statistics counter to track prefetch
				queries. [RT #45847]

	4719.	[bug]		Address PVS static analyzer warnings. [RT #45946]

	4718.	[func]		Avoid searching for a owner name compression pointer
				more than once when writing out a RRset. [RT #45802]

	4717.	[bug]		Treat replies with QCOUNT=0 as truncated if TC=1,
				FORMERR if TC=0, and log the error correctly.
				[RT #45836]

	4716.	[placeholder]

.. code-block:: none

		--- 9.12.0a1 released ---

	4715.	[bug]		TreeMemMax was mis-identified as a second HeapMemMax
				in the Json cache statistics. [RT #45980]

	4714.	[port]		openbsd/libressl: add support for building with
				--enable-openssl-hash. [RT #45982]

	4713.	[func]		Added support for the DNS Response Policy Service
				(DNSRPS) API, which allows named to use an external
				response policy daemon when built with
				"configure --enable-dnsrps". Thanks to Farsight
				Security. [RT #43376]

	4712.	[bug]		"dig +domain" and "dig +search" didn't retain the
				search domain when retrying with TCP. [RT #45547]

	4711.	[test]		Some RR types were missing from genzones.sh.
				[RT #45782]

	4710.	[cleanup]	Changed the --enable-openssl-hash default to yes.
				[RT #45019]

	4709.	[cleanup]	Use dns_name_fullhash() to hash names for RRL.
				[RT #45435]

	4708.	[cleanup]	Legacy Windows builds (i.e. for XP and earlier)
				are no longer supported. [RT #45186]

	4707.	[func]		The lightweight resolver daemon and library (lwresd
				and liblwres) have been removed. [RT #45186]

	4706.	[func]		Code implementing name server query processing has
				been moved from bin/named to a new library "libns".
				Functions remaining in bin/named are now prefixed
				with "named_" rather than "ns_".  This will make it
				easier to write unit tests for name server code, or
				link name server functionality into new tools.
				[RT #45186]

	4705.	[placeholder]

	4704.	[cleanup]	Silence Visual Studio compiler warnings. [RT #45898]

	4703.	[bug]		BINDInstall.exe was missing some buffer length checks.
				[RT #45898]

	4702.	[func]		Update function declarations to use
				dns_masterstyle_flags_t for style flags. [RT #45924]

	4701.	[cleanup]	Refactored lib/dns/tsig.c to reduce code
				duplication and simplify the disabling of MD5.
				[RT #45490]

	4700.	[func]		Serving of stale answers is now supported. This
				allows named to provide stale cached answers when
				the authoritative server is under attack.
				See max-stale-ttl, stale-answer-enable,
				stale-answer-ttl. [RT #44790]

	4699.	[func]		Multiple cookie-secret clauses can now be specified.
				The first one specified is used to generate new
				server cookies.  [RT #45672]

	4698.	[port]		Add --with-python-install-dir configure option to allow
				specifying a nonstandard installation directory for
				Python modules. [RT #45407]

	4697.	[bug]		Restore workaround for Microsoft Windows TSIG hash
				computation bug. [RT #45854]

	4696.	[port]		Enable filter-aaaa support by default on Windows
				builds. [RT #45883]

	4695.	[bug]		cookie-secrets were not being properly checked by
				named-checkconf. [RT #45886]

	4694.	[func]		dnssec-keygen no longer uses RSASHA1 by default;
				the signing algorithm must be specified on
				the command line with the "-a" option.  Signing
				scripts that rely on the existing default behavior
				will break; use "dnssec-keygen -a RSASHA1" to
				repair them. (The goal of this change is to make
				it easier to find scripts using RSASHA1 so they
				can be changed in the event of that algorithm
				being deprecated in the future.) [RT #44755]

	4693.	[func]		Synthesis of responses from DNSSEC-verified records.
				Stage 1 covers NXDOMAIN synthesis from NSEC records.
				This is controlled by synth-from-dnssec and is enabled
				by default. [RT #40138]

	4692.	[bug]		Fix build failures with libressl introduced in 4676.
				[RT #45879]

	4691.	[func]		Add -4/-6 command line options to nsupdate and rndc.
				[RT #45632]

	4690.	[bug]		Command line options -4/-6 were handled inconsistently
				between tools. [RT #45632]

	4689.	[cleanup]	Turn on minimal responses for CDNSKEY and CDS in
				addition to DNSKEY and DS. Thanks to Tony Finch.
				[RT #45690]

	4688.	[protocol]	Check and display EDNS KEY TAG options (RFC 8145) in
				messages. [RT #44804]

	4687.	[func]		Refactor tracklines code. [RT #45126]

	4686.	[bug]		dnssec-settime -p could print a bogus warning about
				key deletion scheduled before its inactivation when a
				key had an inactivation date set but no deletion date
				set. [RT #45807]

	4685.	[bug]		dnssec-settime incorrectly calculated publication and
				activation dates for a successor key. [RT #45806]

	4684.	[bug]		delv could send bogus DNS queries when an explicit
				server address was specified on the command line along
				with -4/-6. [RT #45804]

	4683.	[bug]		Prevent nsupdate from immediately exiting on invalid
				user input in interactive mode. [RT #28194]

	4682.	[bug]		Don't report errors on records below a DNAME.
				[RT #44880]

	4681.	[bug]		Log messages from the validator now include the
				associated view unless the view is "_default/IN"
				or "_dnsclient/IN". [RT #45770]

	4680.	[bug]		Fix failing over to another master server address when
				nsupdate is used with GSS-API. [RT #45380]

	4679.	[cleanup]	Suggest using -o when dnssec-verify finds a SOA record
				not at top of zone and -o is not used. [RT #45519]

	4678.	[bug]		geoip-use-ecs has the wrong type when geoip support
				is disabled at configure time. [RT #45763]

	4677.	[cleanup]	Split up the main function in dig to better support
				the iOS app version. [RT #45508]

	4676.	[cleanup]	Allow BIND to be built using OpenSSL 1.0.X with
				deprecated functions removed. [RT #45706]

	4675.	[cleanup]	Don't use C++ keyword class. [RT #45726]

	4674.	[func]		"dig +sigchase", and related options "+topdown" and
				"+trusted-keys", have been removed. Use "delv" for
				queries with DNSSEC validation. [RT #42793]

	4673.	[port]		Silence GCC 7 warnings. [RT #45592]

	4672.	[placeholder]

	4671.	[bug]		Fix a race condition that could cause the
				resolver to crash with assertion failure when
				chasing DS in specific conditions with a very
				short RTT to the upstream nameserver. [RT #45168]

	4670.	[cleanup]	Ensure that a request MAC is never sent back
				in an XFR response unless the signature was
				verified. [RT #45494]

	4669.	[func]		Iterative query logic in resolver.c has been
				refactored into smaller functions and commented,
				for improved readability, maintainability and
				testability. [RT #45362]

	4668.	[bug]		Use localtime_r and gmtime_r for thread safety.
				[RT #45664]

	4667.	[cleanup]	Refactor RDATA unit tests. [RT #45610]

	4666.	[bug]		dnssec-keymgr: Domain names beginning with digits (0-9)
				could cause a parser error when reading the policy
				file. This now works correctly so long as the domain
				name is quoted. [RT #45641]

	4665.	[protocol]	Added support for ED25519 and ED448 DNSSEC signing
				algorithms (RFC 8080). (Note: these algorithms
				depend on code currently in the development branch
				of OpenSSL which has not yet been released.)
				[RT #44696]

	4664.	[func]		Add a "glue-cache" option to enable or disable the
				glue cache. The default is "yes". [RT #45125]

	4663.	[cleanup]	Clarify error message printed by dnssec-dsfromkey.
				[RT #21731]

	4662.	[performance]	Improve cache memory cleanup of zero TTL records
				by putting them at the tail of LRU header lists.
				[RT #45274]

	4661.	[bug]		A race condition could occur if a zone was reloaded
				while resigning, triggering a crash in
				rbtdb.c:closeversion(). [RT #45276]

	4660.	[bug]		Remove spurious "peer" from Windows socket log
				messages. [RT #45617]

	4659.	[bug]		Remove spurious log message about lmdb-mapsize
				not being supported when parsing builtin
				configuration file. [RT #45618]

	4658.	[bug]		Clean up build directory created by "setup.py install"
				immediately.  [RT #45628]

	4657.	[bug]		rrchecker system test result could be improperly
				determined. [RT #45602]

	4656.	[bug]		Apply "port" and "dscp" values specified in catalog
				zone's "default-masters" option to the generated
				configuration of its member zones. [RT #45545]

	4655.	[bug]		Lack of seccomp could be falsely reported. [RT #45599]

	4654.	[cleanup]	Don't use C++ keywords delete, new and namespace.
				[RT #45538]

	4653.	[bug]		Reorder includes to move @DST_OPENSSL_INC@ and
				@ISC_OPENSSL_INC@ after shipped include directories.
				[RT #45581]

	4652.	[bug]		Nsupdate could attempt to use a zeroed address on
				server timeout. [RT #45417]

	4651.	[test]		Silence coverity warnings in tsig_test.c. [RT #45528]

	4650.	[placeholder]

	4649.	[bug]		The wrong zone was logged when a catalog zone is added.
				[RT #45520]

	4648.	[bug]		"rndc reconfig" on a slave no longer causes all member
				zones of configured catalog zones to be removed from
				configuration. [RT #45310]

	4647.	[bug]		Change 4643 broke verification of TSIG signed TCP
				message sequences where not all the messages contain
				TSIG records.  These may be used in AXFR and IXFR
				responses. [RT #45509]

	4646.	[placeholder]

	4645.	[bug]		Fix PKCS#11 RSA parsing when MD5 is disabled.
				[RT #45300]

	4644.	[placeholder]

	4643.	[security]	An error in TSIG handling could permit unauthorized
				zone transfers or zone updates. (CVE-2017-3142)
				(CVE-2017-3143) [RT #45383]

	4642.	[cleanup]	Add more logging of RFC 5011 events affecting the
				status of managed keys: newly observed keys,
				deletion of revoked keys, etc. [RT #45354]

	4641.	[cleanup]	Parallel builds (make -j) could fail with --with-atf /
				--enable-developer. [RT #45373]

	4640.	[bug]		If query_findversion failed in query_getdb due to
				memory failure the error status was incorrectly
				discarded. [RT #45331]

	4639.	[bug]		Fix a regression in --with-tuning reporting introduced
				by change 4488. [RT #45396]

	4638.	[bug]		Reloading or reconfiguring named could fail on
				some platforms when LMDB was in use. [RT #45203]

	4637.	[func]		"nsec3hash -r" option ("rdata order") takes arguments
				in the same order as they appear in NSEC3 or
				NSEC3PARAM records, so that NSEC3 parameters can
				be cut and pasted from an existing record. Thanks
				to Tony Finch for the contribution. [RT #45183]

	4636.	[bug]		Normalize rpz policy zone names when checking for
				existence. [RT #45358]

	4635.	[bug]		Fix RPZ NSDNAME logging that was logging
				failures as NSIP. [RT #45052]

	4634.	[contrib]	check5011.pl needs to handle optional space before
				semi-colon in +multi-line output. [RT #45352]

	4633.	[maint]		Updated AAAA (2001:500:200::b) for B.ROOT-SERVERS.NET.

	4632.	[security]	The BIND installer on Windows used an unquoted
				service path, which can enable privilege escalation.
				(CVE-2017-3141) [RT #45229]

	4631.	[security]	Some RPZ configurations could go into an infinite
				query loop when encountering responses with TTL=0.
				(CVE-2017-3140) [RT #45181]

	4630.	[bug]		"dyndb" is dependent on dlopen existing / being
				enabled. [RT #45291]

	4629.	[bug]		dns_client_startupdate could not be called with a
				running client. [RT #45277]

	4628.	[bug]		Fixed a potential reference leak in query_getdb().
				[RT #45247]

	4627.	[placeholder]

	4626.	[test]		Added more tests for handling of different record
				ordering in CNAME and DNAME responses. [QA #430]

	4625.	[bug]		Running "rndc addzone" and "rndc delzone" at close
				to the same time could trigger a deadlock if using
				LMDB. [RT #45209]

	4624.	[placeholder]

	4623.	[bug]		Use --with-protobuf-c and --with-libfstrm to find
				protoc-c and fstrm_capture. [RT #45187]

	4622.	[bug]		Remove unnecessary escaping of semicolon in CAA and
				URI records. [RT #45216]

	4621.	[port]		Force alignment of oid arrays to silence loader
				warnings. [RT #45131]

	4620.	[port]		Handle EPFNOSUPPORT being returned when probing
				to see if a socket type is supported. [RT #45214]

	4619.	[bug]		Call isc_mem_put instead of isc_mem_free in
				bin/named/server.c:setup_newzones. [RT #45202]

	4618.	[bug]		Check isc_mem_strdup results in dns_view_setnewzones.
				Add logging for lmdb call failures. [RT #45204]

	4617.	[test]		Update rndc system test to be more delay tolerant.
				[RT #45177]

	4616.	[bug]		When using LMDB, zones deleted using "rndc delzone"
				were not correctly removed from the new-zone
				database. [RT #45185]

	4615.	[bug]		AD could be set on truncated answer with no records
				present in the answer and authority sections.
				[RT #45140]

	4614.	[test]		Fixed an error in the sockaddr unit test. [RT #45146]

	4613.	[func]		By default, the maximum size of a zone journal file
				is now twice the size of the zone's contents (there
				is little benefit to a journal larger than this).
				This can be overridden by setting "max-journal-size"
				to "unlimited" or to an explicit value up to 2G.
				Thanks to Tony Finch. [RT #38324]

	4612.	[bug]		Silence 'may be use uninitalised' warning and simplify
				the code in lwres/getaddinfo:process_answer.
				[RT #45158]

	4611.	[bug]		The default LMDB mapsize was too low and caused
				errors after few thousand zones were added using
				rndc addzone. A new config option "lmdb-mapsize"
				has been introduced to configure the LMDB
				mapsize depending on operational needs.
				[RT #44954]

	4610.	[func]		The "new-zones-directory" option specifies the
				location of NZF or NZD files for storing
				configuration of zones added by "rndc addzone".
				Thanks to Petr Menšík. [RT #44853]

	4609.	[cleanup]	Rearrange makefiles to enable parallel execution
				(i.e. "make -j"). [RT #45078]

	4608.	[func]		DiG now warns about .local queries which are reserved
				for Multicast DNS. [RT #44783]

	4607.	[bug]		The memory context's malloced and maxmalloced counters
				were being updated without the appropriate lock being
				held.  [RT #44869]

	4606.	[port]		Stop using experimental "Experimental keys on scalar"
				feature of perl as it has been removed. [RT #45012]

	4605.	[performance]	Improve performance for delegation heavy answers
				and also general query performance. Removes the
				acache feature that didn't significantly improve
				performance. Adds a glue cache. Removes
				additional-from-cache and additional-from-auth
				features. Enables minimal-responses by
				default. Improves performance of compression
				code, owner case restoration, hash function,
				etc. Uses inline buffer implementation by
				default. Many other performance changes and fixes.
				[RT #44029]

	4604.	[bug]		Don't use ERR_load_crypto_strings() when building
				with OpenSSL 1.1.0. [RT #45117]

	4603.	[doc]		Automatically generate named.conf(5) man page
				from doc/misc/options. Thanks to Tony Finch.
				[RT #43525]

	4602.	[func]		Threads are now set to human-readable
				names to assist debugging, when supported by
				the OS. [RT #43234]

	4601.	[bug]		Reject incorrect RSA key lengths during key
				generation and and sign/verify context
				creation. [RT #45043]

	4600.	[bug]		Adjust RPZ trigger counts only when the entry
				being deleted exists. [RT #43386]

	4599.	[bug]		Fix inconsistencies in inline signing time
				comparison that were introduced with the
				introduction of rdatasetheader->resign_lsb.
				[RT #42112]

	4598.	[func]		Update fuzzing code to (1) reply to a DNSKEY
				query from named with appropriate DNSKEY used in
				fuzzing; (2) patch the QTYPE correctly in
				resolver fuzzing; (3) comment things so the rest
				of us are able to understand how fuzzing is
				implemented in named; (4) Coding style changes,
				cleanup, etc. [RT #44787]

	4597.	[bug]		The validator now ignores SHA-1 DS digest type
				when a DS record with SHA-384 digest type is
				present and is a supported digest type.
				[RT #45017]

	4596.	[bug]		Validate glue before adding it to the additional
				section. This also fixes incorrect TTL capping
				when the RRSIG expired earlier than the TTL.
				[RT #45062]

	4595.	[func]		dnssec-keygen will no longer generate RSA keys
				less than 1024 bits in length. dnssec-keymgr
				was similarly updated. [RT #36895]

	4594.	[func]		"dnstap-read -x" prints a hex dump of the wire
				format of each logged DNS message. [RT #44816]

	4593.	[doc]		Update README using markdown, remove outdated FAQ
				file in favor of the knowledge base.

	4592.	[bug]		A race condition on shutdown could trigger an
				assertion failure in dispatch.c. [RT #43822]

	4591.	[port]		Addressed some python 3 compatibility issues.
				Thanks to Ville Skytta. [RT #44955] [RT #44956]

	4590.	[bug]		Support for PTHREAD_MUTEX_ADAPTIVE_NP was not being
				properly detected. [RT #44871]

	4589.	[cleanup]	"configure -q" is now silent. [RT #44829]

	4588.	[bug]		nsupdate could send queries for TKEY to the wrong
				server when using GSSAPI. Thanks to Tomas Hozza.
				[RT #39893]

	4587.	[bug]		named-checkzone failed to handle occulted data below
				DNAMEs correctly. [RT #44877]

	4586.	[func]		dig, host and nslookup now use TCP for ANY queries.
				[RT #44687]

	4585.	[port]		win32: Set CompileAS value. [RT #42474]

	4584.	[bug]		A number of memory usage statistics were not properly
				reported when they exceeded 4G.  [RT #44750]

	4583.	[func]		"host -A" returns most records for a name but
				omits RRSIG, NSEC and NSEC3. (Thanks to Tony Finch.)
				[RT #43032]

	4582.	[security]	'rndc ""' could trigger a assertion failure in named.
				(CVE-2017-3138) [RT #44924]

	4581.	[port]		Linux: Add getpid and getrandom to the list of system
				calls named uses for seccomp. [RT #44883]

	4580.	[bug]		4578 introduced a regression when handling CNAME to
				referral below the current domain. [RT #44850]

	4579.	[func]		Logging channels and dnstap output files can now
				be configured with a "suffix" option, set to
				either "increment" or "timestamp", indicating
				whether to use incrementing numbers or timestamps
				as the file suffix when rolling over a log file.
				[RT #42838]

	4578.	[security]	Some chaining (CNAME or DNAME) responses to upstream
				queries could trigger assertion failures.
				(CVE-2017-3137) [RT #44734]

	4577.	[func]		Make qtype of resolver fuzzing packet configurable
				via command line. [RT #43540]

	4576.	[func]		The RPZ implementation has been substantially
				refactored for improved performance and reliability.
				[RT #43449]

	4575.	[security]	DNS64 with "break-dnssec yes;" can result in an
				assertion failure. (CVE-2017-3136) [RT #44653]

	4574.	[bug]		Dig leaked memory with multiple +subnet options.
				[RT #44683]

	4573.	[func]		Query logic has been substantially refactored (e.g.
				query_find function has been split into smaller
				functions) for improved readability, maintainability
				and testability. [RT #43929]

	4572.	[func]		The "dnstap-output" option can now take "size" and
				"versions" parameters to indicate the maximum size
				a dnstap log file can grow before rolling to a new
				file, and how many old files to retain. [RT #44502]

	4571.	[bug]		Out-of-tree builds of backtrace_test failed.

	4570.	[cleanup]	named did not correctly fall back to the built-in
				initializing keys if the bind.keys file was present
				but empty. [RT #44531]

	4569.	[func]		Store both local and remote addresses in dnstap
				logging, and modify dnstap-read output format to
				print them. [RT #43595]

	4568.	[contrib]	Added a --with-bind option to the dnsperf configure
				script to specify BIND prefix path.

	4567.	[port]		Call getprotobyname and getservbyname prior to calling
				chroot so that shared libraries get loaded. [RT #44537]

	4566.	[func]		Query logging now includes the ECS option if one
				was included in the query. [RT #44476]

	4565.	[cleanup]	The inline macro versions of isc_buffer_put*()
				did not implement automatic buffer reallocation.
				[RT #44216]

	4564.	[maint]		Update the built in managed keys to include the
				upcoming root KSK. [RT #44579]

	4563.	[bug]		Modified zones would occasionally fail to reload.
				[RT #39424]

	4562.	[func]		Add additional memory statistics currently malloced
				and maxmalloced per memory context. [RT #43593]

	4561.	[port]		Silence a warning in strict C99 compilers. [RT #44414]

	4560.	[bug]		mdig: add -m option to enable memory debugging rather
				than having it on all the time. [RT #44509]

	4559.	[bug]		openssl_link.c didn't compile if ISC_MEM_TRACKLINES
				was turned off.  [RT #44509]

	4558.	[bug]		Synthesised CNAME before matching DNAME was still
				being cached when it should not have been.  [RT #44318]

	4557.	[security]	Combining dns64 and rpz can result in dereferencing
				a NULL pointer (read).  (CVE-2017-3135) [RT#44434]

	4556.	[bug]		Sending an EDNS Padding option using "dig
				+ednsopt" could cause a crash in dig. [RT #44462]

	4555.	[func]		dig +ednsopt: EDNS options can now be specified by
				name in addition to numeric value. [RT #44461]

	4554.	[bug]		Remove double unlock in dns_dispatchmgr_setudp.
				[RT #44336]

	4553.	[bug]		Named could deadlock there were multiple changes to
				NSEC/NSEC3 parameters for a zone being processed at
				the same time. [RT #42770]

	4552.	[bug]		Named could trigger a assertion when sending notify
				messages. [RT #44019]

	4551.	[test]		Add system tests for integrity checks of MX and
				SRV records. [RT #43953]

	4550.	[cleanup]	Increased the number of available master file
				output style flags from 32 to 64. [RT #44043]

	4549.	[func]		Added support for the EDNS TCP Keepalive option
				(RFC 7828). [RT #42126]

	4548.	[func]		Added support for the EDNS Padding option (RFC 7830).
				[RT #42094]

	4547.	[port]		Add support for --enable-native-pkcs11 on the AEP
				Keyper HSM. [RT #42463]

	4546.	[func]		Extend the use of const declarations. [RT #43379]

	4545.	[func]		Expand YAML output from dnstap-read to include
				a detailed breakdown of the DNS message contents.
				[RT #43642]

	4544.	[bug]		Add message/payload size to dnstap-read YAML output.
				[RT #43622]

	4543.	[bug]		dns_client_startupdate now delays sending the update
				request until isc_app_ctxrun has been called.
				[RT #43976]

	4542.	[func]		Allow rndc to manipulate redirect zones with using
				-redirect as the zone name (use "-redirect." to
				manipulate a zone named "-redirect"). [RT #43971]

	4541.	[bug]		rndc addzone should properly reject non master/slave
				zones. [RT #43665]

	4540.	[bug]		Correctly handle ecs entries in dns_acl_isinsecure.
				[RT #43601]

	4539.	[bug]		Referencing a nonexistent zone with RPZ could lead
				to a assertion failure when configuring. [RT #43787]

	4538.	[bug]		Call dns_client_startresolve from client->task.
				[RT #43896]

	4537.	[bug]		Handle timeouts better in dig/host/nslookup. [RT #43576]

	4536.	[bug]		ISC_SOCKEVENTATTR_USEMINMTU was not being cleared
				when reusing the event structure. [RT #43885]

	4535.	[bug]		Address race condition in setting / testing of
				DNS_REQUEST_F_SENDING. [RT #43889]

	4534.	[bug]		Only set RD, RA and CD in QUERY responses. [RT #43879]

	4533.	[bug]		dns_client_update should terminate on prerequisite
				failures (NXDOMAIN, YXDOMAIN, NXRRSET, YXRRSET)
				and also on BADZONE.  [RT #43865]

	4532.	[contrib]	Make gen-data-queryperf.py python 3 compatible.
				[RT #43836]

	4531.	[security]	'is_zone' was not being properly updated by redirect2
				and subsequently preserved leading to an assertion
				failure. (CVE-2016-9778) [RT #43837]

	4530.	[bug]		Change 4489 broke the handling of CNAME -> DNAME
				in responses resulting in SERVFAIL being returned.
				[RT #43779]

	4529.	[cleanup]	Silence noisy log warning when DSCP probe fails
				due to firewall rules. [RT #43847]

	4528.	[bug]		Only set the flag bits for the i/o we are waiting
				for on EPOLLERR or EPOLLHUP. [RT #43617]

	4527.	[doc]		Support DocBook XSL Stylesheets v1.79.1. [RT #43831]

	4526.	[doc]		Corrected errors and improved formatting of
				grammar definitions in the ARM. [RT #43739]

	4525.	[doc]		Fixed outdated documentation on managed-keys.
				[RT #43810]

	4524.	[bug]		The net zero test was broken causing IPv4 servers
				with addresses ending in .0 to be rejected. [RT #43776]

	4523.	[doc]		Expand config doc for <querysource4> and
				<querysource6>. [RT #43768]

	4522.	[bug]		Handle big gaps in log file version numbers better.
				[RT #38688]

	4521.	[cleanup]	Log it as an error if an entropy source is not
				found and there is no fallback available. [RT #43659]

	4520.	[cleanup]	Alphabetize more of the grammar when printing it
				out. Fix unbalanced indenting. [RT #43755]

	4519.	[port]		win32: handle ERROR_MORE_DATA. [RT #43534]

	4518.	[func]		The "print-time" option in the logging configuration
				can now take arguments "local", "iso8601" or
				"iso8601-utc" to indicate the format in which the
				date and time should be logged. For backward
				compatibility, "yes" is a synonym for "local".
				[RT #42585]

	4517.	[security]	Named could mishandle authority sections that were
				missing RRSIGs triggering an assertion failure.
				(CVE-2016-9444) [RT # 43632]

	4516.	[bug]		isc_socketmgr_renderjson was missing from the
				windows build. [RT #43602]

	4515.	[port]		FreeBSD: Find readline headers when they are in
				edit/readline/ instead of readline/. [RT #43658]

	4514.	[port]		NetBSD: strip -WL, from ld command line. [RT #43204]

	4513.	[cleanup]	Minimum Python versions are now 2.7 and 3.2.
				[RT #43566]

	4512.	[bug]		win32: @GEOIP_INC@ missing from delv.vcxproj.in.
				[RT #43556]

	4511.	[bug]		win32: mdig.exe-BNFT was missing Configure. [RT #43554]

	4510.	[security]	Named mishandled some responses where covering RRSIG
				records are returned without the requested data
				resulting in a assertion failure. (CVE-2016-9147)
				[RT #43548]

	4509.	[test]		Make the rrl system test more reliable on slower
				machines by using mdig instead of dig. [RT #43280]

	4508.	[security]	Named incorrectly tried to cache TKEY records which
				could trigger a assertion failure when there was
				a class mismatch. (CVE-2016-9131) [RT #43522]

	4507.	[bug]		Named could incorrectly log 'allows updates by IP
				address, which is insecure' [RT #43432]

	4506.	[func]		'named-checkconf -l' will now list the zones found in
				named.conf. [RT #43154]

	4505.	[port]		Use IP_PMTUDISC_OMIT if available. [RT #35494]

	4504.	[security]	Allow the maximum number of records in a zone to
				be specified.  This provides a control for issues
				raised in CVE-2016-6170. [RT #42143]

	4503.	[cleanup]	"make uninstall" now removes files installed by
				BIND. (This currently excludes Python files
				due to lack of support in setup.py.) [RT #42192]

	4502.	[func]		Report multiple and experimental options when printing
				grammar. [RT #43134]

	4501.	[placeholder]

	4500.	[bug]		Support modifier I64 in isc__print_printf. [RT #43526]

	4499.	[port]		MacOSX: silence deprecated function warning
				by using arc4random_stir() when available
				instead of arc4random_addrandom(). [RT #43503]

	4498.	[test]		Simplify prerequisite checks in system tests.
				[RT #43516]

	4497.	[port]		Add support for OpenSSL 1.1.0. [RT #41284]

	4496.	[func]		dig: add +idnout to control whether labels are
				display in punycode or not.  Requires idn support
				to be enabled at compile time. [RT #43398]

	4495.	[bug]		A isc_mutex_init call was not being checked.
				[RT #43391]

	4494.	[bug]		Look for <editline/readline.h>. [RT #43429]

	4493.	[bug]		bin/tests/system/dyndb/driver/Makefile.in should use
				SO_TARGETS. [RT# 43336]

	4492.	[bug]		irs_resconf_load failed to initialize sortlistnxt
				causing bad writes if resolv.conf contained a
				sortlist directive. [RT #43459]

	4491.	[bug]		Improve message emitted when testing whether sendmsg
				works with TOS/TCLASS fails. [RT #43483]

	4490.	[maint]		Added AAAA (2001:500:12::d0d) for G.ROOT-SERVERS.NET.

	4489.	[security]	It was possible to trigger assertions when processing
				a response containing a DNAME answer. (CVE-2016-8864)
				[RT #43465]

	4488.	[port]		Darwin: use -framework for Kerberos. [RT #43418]

	4487.	[test]		Make system tests work on Windows. [RT #42931]

	4486.	[bug]		Look in $prefix/lib/pythonX.Y/site-packages for
				the python modules we install. [RT #43330]

	4485.	[bug]		Failure to find readline when requested should be
				fatal to configure. [RT #43328]

	4484.	[func]		Check prefixes in acls to make sure the address and
				prefix lengths are consistent.  Warn only in
				BIND 9.11 and earlier. [RT #43367]

	4483.	[bug]		Address use before require check and remove extraneous
				dns_message_gettsigkey call in dns_tsig_sign.
				[RT #43374]

	4482.	[cleanup]	Change #4455 was incomplete. [RT #43252]

	4481.	[func]		dig: make +class, +crypto, +multiline, +rrcomments,
				+onesoa, +qr, +ttlid, +ttlunits and -u per lookup
				rather than global. [RT #42450]

	4480.	[placeholder]

	4479.	[placeholder]

	4478.	[func]		Add +continue option to mdig, allow continue on socket
				errors. [RT #43281]

	4477.	[test]		Fix mkeys test timing issues. [RT #41028]

	4476.	[test]		Fix reclimit test on slower machines. [RT #43283]

	4475.	[doc]		Update named-checkconf documentation. [RT #43153]

	4474.	[bug]		win32: call WSAStartup in fromtext_in_wks so that
				getprotobyname and getservbyname work.  [RT #43197]

	4473.	[bug]		Only call fsync / _commit on regular files. [RT #43196]

	4472.	[bug]		Named could fail to find the correct NSEC3 records when
				a zone was updated between looking for the answer and
				looking for the NSEC3 records proving nonexistence
				of the answer. [RT #43247]

.. code-block:: none

		--- 9.11.0 released ---

.. code-block:: none

		--- 9.11.0rc3 released ---

	4471.	[cleanup]	Render client/query logging format consistent for
				ease of log file parsing. (Note that this affects
				"querylog" format: there is now an additional field
				indicating the client object address.) [RT #43238]

	4470.	[bug]		Reset message with intent parse before
				calling dns_dispatch_getnext. [RT #43229]

	4469.	[placeholder]

.. code-block:: none

		--- 9.11.0rc2 released ---

	4468.	[bug]		Address ECS option handling issues. [RT #43191]

	4467.	[security]	It was possible to trigger an assertion when
				rendering a message. (CVE-2016-2776) [RT #43139]

	4466.	[bug]		Interface scanning didn't work on a Windows system
				without a non local IPv6 addresses. [RT #43130]

	4465.	[bug]		Don't use "%z" as Windows doesn't support it.
				[RT #43131]

	4464.	[bug]		Fix windows python support. [RT #43173]

	4463.	[bug]		The dnstap system test failed on some systems.
				[RT #43129]

	4462.	[bug]		Don't describe a returned EDNS COOKIE as "good"
				when there isn't a valid server cookie. [RT #43167]

	4461.	[bug]		win32: not all external data was properly marked
				as external data for windows dll. [RT #43161]

.. code-block:: none

		--- 9.11.0rc1 released ---

	4460.	[test]		Add system test for dnstap using unix domain sockets.
				[RT #42926]

	4459.	[bug]		TCP client objects created to handle pipeline queries
				were not cleaned up correctly, causing uncontrolled
				memory growth. [RT #43106]

	4458.	[cleanup]	Update assertions to be more correct, and also remove
				use of a reserved word. [RT #43090]

	4457.	[maint]		Added AAAA (2001:500:a8::e) for E.ROOT-SERVERS.NET.

	4456.	[doc]		Add DOCTYPE and lang attribute to <html> tags.
				[RT #42587]

	4455.	[cleanup]	Allow dyndb modules to correctly log the filename
				and line number when processing configuration text
				from named.conf. [RT #43050]

	4454.	[bug]		'rndc dnstap -reopen' had a race issue. [RT #43089]

	4453.	[bug]		Prefetching of DS records failed to update their
				RRSIGs. [RT #42865]

	4452.	[bug]		The default key manager policy file is now
				<sysdir>/dnssec-policy.conf (usually
				/etc/dnssec-policy.conf). [RT #43064]

	4451.	[cleanup]	Log more useful information if a PKCS#11 provider
				library cannot be loaded. [RT #43076]

	4450.	[port]		Provide more nuanced HSM support which better matches
				the specific PKCS11 providers capabilities. [RT #42458]

	4449.	[test]		Fix catalog zones test on slower systems. [RT #42997]

	4448.	[bug]		win32: ::1 was not being found when iterating
				interfaces. [RT #42993]

	4447.	[tuning]	Allow the fstrm_iothr_init() options to be set using
				named.conf to control how dnstap manages the data
				flow. [RT #42974]

	4446.	[bug]		The cache_find() and _findrdataset() functions
				could find rdatasets that had been marked stale.
				[RT #42853]

	4445.	[cleanup]	isc_errno_toresult() can now be used to call the
				formerly private function isc__errno2result().
				[RT #43050]

	4444.	[bug]		Fixed some issues related to dyndb: A bug caused
				braces to be omitted when passing configuration text
				from named.conf to a dyndb driver, and there was a
				use-after-free in the sample dyndb driver. [RT #43050]

	4443.	[func]		Set TCP_MAXSEG in addition to IPV6_USE_MIN_MTU on
				TCP sockets. [RT #42864]

	4442.	[bug]		Fix RPZ CIDR tree insertion bug that corrupted
				tree data structure with overlapping networks
				(longest prefix match was ineffective).
				[RT #43035]

	4441.	[cleanup]	Alphabetize host's help output. [RT #43031]

	4440.	[func]		Enable TCP fast open support when available on the
				server side. [RT #42866]

	4439.	[bug]		Address race conditions getting ownernames of nodes.
				[RT #43005]

	4438.	[func]		Use LIFO rather than FIFO when processing startup
				notify and refresh queries. [RT #42825]

	4437.	[func]		Minimal-responses now has two additional modes
				no-auth and no-auth-recursive which suppress
				adding the NS records to the authority section
				as well as the associated address records for the
				nameservers. [RT #42005]

	4436.	[func]		Return TLSA records as additional data for MX and SRV
				lookups. [RT #42894]

	4435.	[tuning]	Only set IPV6_USE_MIN_MTU for UDP when the message
				will not fit into a single IPv4 encapsulated IPv6
				UDP packet when transmitted over a Ethernet link.
				[RT #42871]

	4434.	[protocol]	Return EDNS EXPIRE option for master zones in addition
				to slave zones. [RT #43008]

	4433.	[cleanup]	Report an error when passing an invalid option or
				view name to "rndc dumpdb". [RT #42958]

	4432.	[test]		Hide rndc output on expected failures in logfileconfig
				system test. [RT #27996]

	4431.	[bug]		named-checkconf now checks the rate-limit clause.
				[RT #42970]

	4430.	[bug]		Lwresd died if a search list was not defined.
				Found by 0x710DDDD At Alibaba Security. [RT #42895]

	4429.	[bug]		Address potential use after free on fclose() error.
				[RT #42976]

	4428.	[bug]		The "test dispatch getnext" unit test could fail
				in a threaded build. [RT #42979]

	4427.	[bug]		The "query" and "response" parameters to the
				"dnstap" option had their functions reversed.

.. code-block:: none

		--- 9.11.0b3 released ---

	4426.	[bug]		Addressed Coverity warnings. [RT #42908]

	4425.	[bug]		arpaname, dnstap-read and named-rrchecker were not
				being installed into ${prefix}/bin.  Tidy up
				installation issues with CHANGE 4421. [RT #42910]

	4424.	[experimental]	Named now sends _ta-XXXX.<trust-anchor>/NULL queries
				to provide feedback to the trust-anchor administrators
				about how key rollovers are progressing as per
				draft-ietf-dnsop-edns-key-tag-02.  This can be
				disabled using 'trust-anchor-telemetry no;'.
				[RT #40583]

	4423.	[maint]		Added missing IPv6 address 2001:500:84::b for
				B.ROOT-SERVERS.NET. [RT #42898]

	4422.	[port]		Silence clang warnings in dig.c and dighost.c.
				[RT #42451]

	4421.	[func]		When built with LMDB (Lightning Memory-mapped
				Database), named will now use a database to store
				the configuration for zones added by "rndc addzone"
				instead of using a flat NZF file. This improves
				performance of "rndc delzone" and "rndc modzone"
				significantly. Existing NZF files will
				automatically by converted to NZD databases.
				To view the contents of an NZD or to roll back to
				NZF format, use "named-nzd2nzf". To disable
				this feature, use "configure --without-lmdb".
				[RT #39837]

	4420.	[func]		nslookup now looks for AAAA as well as A by default.
				[RT #40420]

	4419.	[bug]		Don't cause undefined result if the label of an
				entry in catalog zone is changed. [RT #42708]

	4418.	[bug]		Fix a compiler warning in GSSAPI code. [RT #42879]

	4417.	[bug]		dnssec-keymgr could fail to create successor keys
				if the prepublication interval was set to a value
				smaller than the default. [RT #42820]

	4416.	[bug]		dnssec-keymgr: Domain names in policy files could
				fail to match due to trailing dots. [RT #42807]

	4415.	[bug]		dnssec-keymgr: Expired/deleted keys were not always
				excluded. [RT #42884]

	4414.	[bug]		Corrected a bug in the MIPS implementation of
				isc_atomic_xadd(). [RT #41965]

	4413.	[bug]		GSSAPI negotiation could fail if GSS_S_CONTINUE_NEEDED
				was returned. [RT #42733]

.. code-block:: none

		--- 9.11.0b2 released ---

	4412.	[cleanup]	Make fixes for GCC 6. ISC_OFFSET_MAXIMUM macro was
				removed. [RT #42721]

	4411.	[func]		"rndc dnstap -roll" automatically rolls the
				dnstap output file; the previous version is
				saved with ".0" suffix, and earlier versions
				with ".1" and so on. An optional numeric argument
				indicates how many prior files to save. [RT #42830]

	4410.	[bug]		Address use after free and memory leak with dnstap.
				[RT #42746]

	4409.	[bug]		DNS64 should exclude mapped addresses by default when
				an exclude acl is not defined. [RT #42810]

	4408.	[func]		Continue waiting for expected response when we the
				response we get does not match the request. [RT #41026]

	4407.	[performance]	Use GCC builtin for clz in RPZ lookup code.
				[RT #42818]

	4406.	[security]	getrrsetbyname with a non absolute name could
				trigger an infinite recursion bug in lwresd
				and named with lwres configured if when combined
				with a search list entry the resulting name is
				too long. (CVE-2016-2775) [RT #42694]

	4405.	[bug]		Change 4342 introduced a regression where you could
				not remove a delegation in a NSEC3 signed zone using
				OPTOUT via nsupdate. [RT #42702]

	4404.	[misc]		Allow krb5-config to be used when configuring gssapi.
				[RT #42580]

	4403.	[bug]		Rename variables and arguments that shadow: basename,
				clone and gai_error.

	4402.	[bug]		protoc-c is now a hard requirement for --enable-dnstap.

.. code-block:: none

		--- 9.11.0b1 released ---

	4401.	[misc]		Change LICENSE to MPL 2.0.

	4400.	[bug]		ttl policy was not being inherited in policy.py.
				[RT #42718]

	4399.	[bug]		policy.py 'ECCGOST', 'ECDSAP256SHA256', and
				'ECDSAP384SHA384' don't have settable keysize.
				[RT #42718]

	4398.	[bug]		Correct spelling of ECDSAP256SHA256 in policy.py.
				[RT #42718]

	4397.	[bug]		Update Windows python support. [RT #42538]

	4396.	[func]		dnssec-keymgr now takes a '-r randomfile' option.
				[RT #42455]

	4395.	[bug]		Improve out-of-tree installation of python modules.
				[RT #42586]

	4394.	[func]		Add rndc command "dnstap-reopen" to close and
				reopen dnstap output files. [RT #41803]

	4393.	[bug]		Address potential NULL pointer dereferences in
				dnstap code.

	4392.	[func]		Collect statistics for RSSAC02v3 traffic-volume,
				traffic-sizes and rcode-volume reporting. [RT #41475]

	4391.	[contrib]	Fix leaks in contrib DLZ code. [RT #42707]

	4390.	[doc]		Description of masters with TSIG, allow-query and
				allow-transfer options in catalog zones. [RT #42692]

	4389.	[test]		Rewritten test suite for catalog zones. [RT #42676]

	4388.	[func]		Support for master entries with TSIG keys in catalog
				zones. [RT #42577]

	4387.	[bug]		Change 4336 was not complete leading to SERVFAIL
				being return as NS records expired. [RT #42683]

	4386.	[bug]		Remove shadowed overmem function/variable. [RT #42706]

	4385.	[func]		Add support for allow-query and allow-transfer ACLs
				to catalog zones. [RT #42578]

	4384.	[bug]		Change 4256 accidentally disabled logging of the
				rndc command. [RT #42654]

	4383.	[bug]		Correct spelling error in stats channel description of
				"EDNS client subnet option received". [RT #42633]

	4382.	[bug]		rndc {addzone,modzone,delzone,showzone} should all
				compare the zone name using a canonical format.
				[RT #42630]

	4381.	[bug]		Missing "zone-directory" option in catalog zone
				definition caused BIND to crash. [RT #42579]

.. code-block:: none

		--- 9.11.0a3 released ---

	4380.	[experimental]	Added a "zone-directory" option to "catalog-zones"
				syntax, allowing local masterfiles for slaves
				that are provisioned by catalog zones to be stored
				in a directory other than the server's working
				directory. [RT #42527]

	4379.	[bug]		An INSIST could be triggered if a zone contains
				RRSIG records with expiry fields that loop
				using serial number arithmetic. [RT #40571]

	4378.	[contrib]	#include <isc/string.h> for strlcat in zone2ldap.c.
				[RT #42525]

	4377.	[bug]		Don't reuse zero TTL responses beyond the current
				client set (excludes ANY/SIG/RRSIG queries).
				[RT #42142]

	4376.	[experimental]	Added support for Catalog Zones, a new method for
				provisioning secondary servers in which a list of
				zones to be served is stored in a DNS zone and can
				be propagated to slaves via AXFR/IXFR. [RT #41581]

	4375.	[func]		Add support for automatic reallocation of isc_buffer
				to isc_buffer_put* functions. [RT #42394]

	4374.	[bug]		Use SAVE/RESTORE macros in query.c to reduce the
				probability of reference counting errors as seen
				in 4365. [RT #42405]

	4373.	[bug]		Address undefined behavior in getaddrinfo. [RT #42479]

	4372.	[bug]		Address undefined behavior in libt_api. [RT #42480]

	4371.	[func]		New "minimal-any" option reduces the size of UDP
				responses for qtype ANY by returning a single
				arbitrarily selected RRset instead of all RRsets.
				Thanks to Tony Finch. [RT #41615]

	4370.	[bug]		Address python3 compatibility issues with RNDC module.
				[RT #42499] [RT #42506]

.. code-block:: none

		--- 9.11.0a2 released ---

	4369.	[bug]		Fix 'make' and 'make install' out-of-tree python
				support. [RT #42484]

	4368.	[bug]		Fix a crash when calling "rndc stats" on some
				Windows builds because some Visual Studio compilers
				generated crashing code for the "%z" printf()
				format specifier. [RT #42380]

	4367.	[bug]		Remove unnecessary assignment of loadtime in
				zone_touched. [RT #42440]

	4366.	[bug]		Address race condition when updating rbtnode bit
				fields. [RT #42379]

	4365.	[bug]		Address zone reference counting errors involving
				nxdomain-redirect. [RT #42258]

	4364.	[port]		freebsd: add -Wl,-E to loader flags [RT #41690]

	4363.	[port]		win32: Disable explicit triggering UAC when running
				BINDInstall.

	4362.	[func]		Changed rndc reconfig behavior so that newly added
				zones are loaded asynchronously and the loading does
				not block the server. [RT #41934]

	4361.	[cleanup]	Where supported, file modification times returned
				by isc_file_getmodtime() are now accurate to the
				nanosecond. [RT #41968]

	4360.	[bug]		Silence spurious 'bad key type' message when there is
				a existing TSIG key. [RT #42195]

	4359.	[bug]		Inherited 'also-notify' lists were not being checked
				by named-checkconf. [RT #42174]

	4358.	[test]		Added American Fuzzy Lop harness that allows
				feeding fuzzed packets into BIND.
				[RT #41723]

	4357.	[func]		Add the python RNDC module. [RT #42093]

	4356.	[func]		Add the ability to specify whether to wait for
				nameserver addresses to be looked up or not to
				RPZ with a new modifying directive 'nsip-wait-recurse'.
				[RT #35009]

	4355.	[func]		"pkcs11-list" now displays the extractability
				attribute of private or secret keys stored in
				an HSM, as either "true", "false", or "never"
				Thanks to Daniel Stirnimann. [RT #36557]

	4354.	[bug]		Check that the received HMAC length matches the
				expected length prior to check the contents on the
				control channel.  This prevents a OOB read error.
				This was reported by Lian Yihan, <lianyihan@360.cn>.
				[RT #42215]

	4353.	[cleanup]	Update PKCS#11 header files. [RT #42175]

	4352.	[cleanup]	The ISC DNSSEC Lookaside Validation (DLV) service
				is scheduled to be disabled in 2017.  A warning is
				now logged when named is configured to use it,
				either explicitly or via "dnssec-lookaside auto;"
				[RT #42207]

	4351.	[bug]		'dig +noignore' didn't work. [RT #42273]

	4350.	[contrib]	Declare result in  dlz_filesystem_dynamic.c.

	4349.	[contrib]	kasp2policy: A python script to create a DNSSEC
				policy file from an OpenDNSSEC KASP XML file.

	4348.	[func]		dnssec-keymgr: A new python-based DNSSEC key
				management utility, which reads a policy definition
				file and can create or update DNSSEC keys as needed
				to ensure that a zone's keys match policy, roll over
				correctly on schedule, etc.  Thanks to Sebastian
				Castro for assistance in development. [RT #39211]

	4347.	[port]		Corrected a build error on x86_64 Solaris. [RT #42150]

	4346.	[bug]		Fixed a regression introduced in change #4337 which
				caused signed domains with revoked KSKs to fail
				validation. [RT #42147]

	4345.	[contrib]	perftcpdns mishandled the return values from
				clock_nanosleep. [RT #42131]

	4344.	[port]		Address openssl version differences. [RT #42059]

	4343.	[bug]		dns_dnssec_syncupdate mis-declared in <dns/dnssec.h>.
				[RT #42090]

	4342.	[bug]		'rndc flushtree' could fail to clean the tree if there
				wasn't a node at the specified name. [RT #41846]

.. code-block:: none

		--- 9.11.0a1 released ---

	4341.	[bug]		Correct the handling of ECS options with
				address family 0. [RT #41377]

	4340.	[performance]	Implement adaptive read-write locks, reducing the
				overhead of locks that are only held briefly.
				[RT #37329]

	4339.	[test]		Use "mdig" to test pipelined queries. [RT #41929]

	4338.	[bug]		Reimplement change 4324 as it wasn't properly doing
				all the required book keeping. [RT #41941]

	4337.	[bug]		The previous change exposed a latent flaw in
				key refresh queries for managed-keys when
				a cached DNSKEY had TTL 0. [RT #41986]

	4336.	[bug]		Don't emit records with zero ttl unless the records
				were learnt with a zero ttl. [RT #41687]

	4335.	[bug]		zone->view could be detached too early. [RT #41942]

	4334.	[func]		'named -V' now reports zlib version. [RT #41913]

	4333.	[maint]		L.ROOT-SERVERS.NET is now 199.7.83.42 and
				2001:500:9f::42.

	4332.	[placeholder]

	4331.	[func]		When loading managed signed zones detect if the
				RRSIG's inception time is in the future and regenerate
				the RRSIG immediately. [RT #41808]

	4330.	[protocol]	Identify the PAD option as "PAD" when printing out
				a message.

	4329.	[func]		Warn about a common misconfiguration when forwarding
				RFC 1918 zones. [RT #41441]

	4328.	[performance]	Add dns_name_fromwire() benchmark test. [RT #41694]

	4327.	[func]		Log query and depth counters during fetches when
				querytrace (./configure --enable-querytrace) is
				enabled (helps in diagnosing).  [RT #41787]

	4326.	[protocol]	Add support for AVC. [RT #41819]

	4325.	[func]		Add a line to "rndc status" indicating the
				hostname and operating system details. [RT #41610]

	4324.	[bug]		When deleting records from a zone database, interior
				nodes could be left empty but not deleted, damaging
				search performance afterward. [RT #40997]

	4323.	[bug]		Improve HTTP header processing on statschannel.
				[RT #41674]

	4322.	[security]	Duplicate EDNS COOKIE options in a response could
				trigger an assertion failure. (CVE-2016-2088)
				[RT #41809]

	4321.	[bug]		Zones using mapped files containing out-of-zone data
				could return SERVFAIL instead of the expected NODATA
				or NXDOMAIN results. [RT #41596]

	4320.	[bug]		Insufficient memory allocation when handling
				"none" ACL could cause an assertion failure in
				named when parsing ACL configuration. [RT #41745]

	4319.	[security]	Fix resolver assertion failure due to improper
				DNAME handling when parsing fetch reply messages.
				(CVE-2016-1286) [RT #41753]

	4318.	[security]	Malformed control messages can trigger assertions
				in named and rndc. (CVE-2016-1285) [RT #41666]

	4317.	[bug]		Age all unused servers on fetch timeout. [RT #41597]

	4316.	[func]		Add option to tools to print RRs in unknown
				presentation format [RT #41595].

	4315.	[bug]		Check that configured view class isn't a meta class.
				[RT #41572].

	4314.	[contrib]	Added 'dnsperf-2.1.0.0-1', a set of performance
				testing tools provided by Nominum, Inc.

	4313.	[bug]		Handle ns_client_replace failures in test mode.
				[RT #41190]

	4312.	[bug]		dig's unknown DNS and EDNS flags (MBZ value) logging
				was not consistent. [RT #41600]

	4311.	[bug]		Prevent "rndc delzone" from being used on
				response-policy zones. [RT #41593]

	4310.	[performance]	Use __builtin_expect() where available to annotate
				conditions with known behavior. [RT #41411]

	4309.	[cleanup]	Remove the spurious "none" filename from log messages
				when processing built-in configuration. [RT #41594]

	4308.	[func]		Added operating system details to "named -V"
				output. [RT #41452]

	4307.	[bug]		"dig +subnet" and "mdig +subnet" could send
				incorrectly-formatted Client Subnet options
				if the prefix length was not divisible by 8.
				Also fixed a memory leak in "mdig". [RT #45178]

	4306.	[maint]		Added a PKCS#11 openssl patch supporting
				version 1.0.2f [RT #38312]

	4305.	[bug]		dnssec-signzone was not removing unnecessary rrsigs
				from the zone's apex. [RT #41483]

	4304.	[port]		xfer system test failed as 'tail -n +value' is not
				portable. [RT #41315]

	4303.	[bug]		"dig +subnet" was unable to send a prefix length of
				zero, as it was incorrectly changed to 32 for v4
				prefixes or 128 for v6 prefixes. In addition to
				fixing this, "dig +subnet=0" has been added as a
				short form for 0.0.0.0/0. The same changes have
				also been made in "mdig". [RT #41553]

	4302.	[port]		win32: fixed a build error in VS 2015. [RT #41426]

	4301.	[bug]		dnssec-settime -p [DP]sync was not working. [RT #41534]

	4300.	[bug]		A flag could be set in the wrong field when setting
				up non-recursive queries; this could cause the
				SERVFAIL cache to cache responses it shouldn't.
				New querytrace logging has been added which
				identified this error. [RT #41155]

	4299.	[bug]		Check that exactly totallen bytes are read when
				reading a RRset from raw files in both single read
				and incremental modes. [RT #41402]

	4298.	[bug]		dns_rpz_add errors in loadzone were not being
				propagated up the call stack. [RT #41425]

	4297.	[test]		Ensure delegations in RPZ zones fail robustly.
				[RT #41518]

	4296.	[bug]		TCP packet sizes were calculated incorrectly in the
				stats channel; they could be counted in the wrong
				histogram bucket. [RT #40587]

	4295.	[bug]		An unchecked result in dns_message_pseudosectiontotext()
				could allow incorrect text formatting of EDNS EXPIRE
				options. [RT #41437]

	4294.	[bug]		Fixed a regression in which "rndc stop -p" failed
				to print the PID. [RT #41513]

	4293.	[bug]		Address memory leak on priming query creation failure.
				[RT #41512]

	4292.	[placeholder]

	4291.	[cleanup]	Added a required include to dns/forward.h. [RT #41474]

	4290.	[func]		The timers returned by the statistics channel
				(indicating current time, server boot time, and
				most recent reconfiguration time) are now reported
				with millisecond accuracy. [RT #40082]

	4289.	[bug]		The server could crash due to memory being used
				after it was freed if a zone transfer timed out.
				[RT #41297]

	4288.	[bug]		Fixed a regression in resolver.c:possibly_mark()
				which caused known-bogus servers to be queried
				anyway. [RT #41321]

	4287.	[bug]		Silence an overly noisy log message when message
				parsing fails. [RT #41374]

	4286.	[security]	render_ecs errors were mishandled when printing out
				a OPT record resulting in a assertion failure.
				(CVE-2015-8705) [RT #41397]

	4285.	[security]	Specific APL data could trigger a INSIST.
				(CVE-2015-8704) [RT #41396]

	4284.	[bug]		Some GeoIP options were incorrectly documented
				using abbreviated forms which were not accepted by
				named.  The code has been updated to allow both
				long and abbreviated forms. [RT #41381]

	4283.	[bug]		OPENSSL_config is no longer re-callable. [RT #41348]

	4282.	[func]		'dig +[no]mapped' determine whether the use of mapped
				IPv4 addresses over IPv6 is permitted or not.  The
				default is +mapped.  [RT #41307]

	4281.	[bug]		Teach dns_message_totext about BADCOOKIE. [RT #41257]

	4280.	[performance]	Use optimal message sizes to improve compression
				in AXFRs. This reduces network traffic. [RT #40996]

	4279.	[test]		Don't use fixed ports when unit testing. [RT #41194]

	4278.	[bug]		'delv +short +[no]split[=##]' didn't work as expected.
				[RT #41238]

	4277.	[performance]	Improve performance of the RBT, the central zone
				datastructure: The aux hashtable was improved,
				hash function was updated to perform more
				uniform mapping, uppernode was added to
				dns_rbtnode, and other cleanups and performance
				improvements were made. [RT #41165]

	4276.	[protocol]	Add support for SMIMEA. [RT #40513]

	4275.	[performance]	Lazily initialize dns_compress->table only when
				compression is enabled. [RT #41189]

	4274.	[performance]	Speed up typemap processing from text. [RT #41196]

	4273.	[bug]		Only call dns_test_begin() and dns_test_end() once each
				in nsec3_test as it fails with GOST if called multiple
				times.

	4272.	[bug]		dig: the +norrcomments option didn't work with +multi.
				[RT #41234]

	4271.	[test]		Unit tests could deadlock in isc__taskmgr_pause().
				[RT #41235]

	4270.	[security]	Update allowed OpenSSL versions as named is
				potentially vulnerable to CVE-2015-3193.

	4269.	[bug]		Zones using "map" format master files currently
				don't work as policy zones.  This limitation has
				now been documented; attempting to use such zones
				in "response-policy" statements is now a
				configuration error.  [RT #38321]

	4268.	[func]		"rndc status" now reports the path to the
				configuration file. [RT #36470]

	4267.	[test]		Check sdlz error handling. [RT #41142]

	4266.	[placeholder]

	4265.	[bug]		Address unchecked isc_mem_get calls. [RT #41187]

	4264.	[bug]		Check const of strchr/strrchr assignments match
				argument's const status. [RT #41150]

	4263.	[contrib]	Address compiler warnings in mysqldyn module.
				[RT #41130]

	4262.	[bug]		Fixed a bug in epoll socket code that caused
				sockets to not be registered for ready
				notification in some cases, causing named to not
				read from or write to them, resulting in what
				appear to the user as blocked connections.
				[RT #41067]

	4261.	[maint]		H.ROOT-SERVERS.NET is 198.97.190.53 and 2001:500:1::53.
				[RT #40556]

	4260.	[security]	Insufficient testing when parsing a message allowed
				records with an incorrect class to be be accepted,
				triggering a REQUIRE failure when those records
				were subsequently cached. (CVE-2015-8000) [RT #40987]

	4259.	[func]		Add an option for non-destructive control channel
				access using a "read-only" clause. In such
				cases, a restricted set of rndc commands are
				allowed for querying information from named.
				[RT #40498]

	4258.	[bug]		Limit rndc query message sizes to 32 KiB. This should
				not break any legitimate rndc commands, but will
				prevent a rogue rndc query from allocating too
				much memory. [RT #41073]

	4257.	[cleanup]	Python scripts reported incorrect version. [RT #41080]

	4256.	[bug]		Allow rndc command arguments to be quoted so as
				to allow spaces. [RT #36665]

	4255.	[performance]	Add 'message-compression' option to disable DNS
				compression in responses. [RT #40726]

	4254.	[bug]		Address missing lock when getting zone's serial.
				[RT #41072]

	4253.	[security]	Address fetch context reference count handling error
				on socket error. (CVE-2015-8461)  [RT#40945]

	4252.	[func]		Add support for automating the generation CDS and
				CDNSKEY rrsets to named and dnssec-signzone.
				[RT #40424]

	4251.	[bug]		NTAs were deleted when the server was reconfigured
				or reloaded. [RT #41058]

	4250.	[func]		Log the TSIG key in use during inbound zone
				transfers. [RT #41075]

	4249.	[func]		Improve error reporting of TSIG / SIG(0) records in
				the wrong location. [RT #41030]

	4248.	[performance]	Add an isc_atomic_storeq() function, use it in
				stats counters to improve performance.
				[RT #39972] [RT #39979]

	4247.	[port]		Require both HAVE_JSON and JSON_C_VERSION to be
				defined to report json library version. [RT #41045]

	4246.	[test]		Ensure the statschannel system test runs when BIND
				is not built with libjson. [RT #40944]

	4245.	[placeholder]

	4244.	[bug]		The parser was not reporting that use-ixfr is obsolete.
				[RT #41010]

	4243.	[func]		Improved stats reporting from Timothe Litt. [RT #38941]

	4242.	[bug]		Replace the client if not already replaced when
				prefetching. [RT #41001]

	4241.	[doc]		Improved the TSIG, TKEY, and SIG(0) sections in
				the ARM. [RT #40955]

	4240.	[port]		Fix LibreSSL compatibility. [RT #40977]

	4239.	[func]		Changed default servfail-ttl value to 1 second from 10.
				Also, the maximum value is now 30 instead of 300.
				[RT #37556]

	4238.	[bug]		Don't send to servers on net zero (0.0.0.0/8).
				[RT #40947]

	4237.	[doc]		Upgraded documentation toolchain to use DocBook 5
				and dblatex. [RT #40766]

	4236.	[performance]	On machines with 2 or more processors (CPU), the
				default value for the number of UDP listeners
				has been changed to the number of detected
				processors minus one. [RT #40761]

	4235.	[func]		Added support in named for "dnstap", a fast method of
				capturing and logging DNS traffic, and a new command
				"dnstap-read" to read a dnstap log file.  Use
				"configure --enable-dnstap" to enable this
				feature (note that this requires libprotobuf-c
				and libfstrm). See the ARM for configuration details.

				Thanks to Robert Edmonds of Farsight Security.
				[RT #40211]

	4234.	[func]		Add deflate compression in statistics channel HTTP
				server. [RT #40861]

	4233.	[test]		Add tests for CDS and CDNSKEY with delegation-only.
				[RT #40597]

	4232.	[contrib]	Address unchecked memory allocation calls in
				query-loc and zone2ldap. [RT #40789]

	4231.	[contrib]	Address unchecked calloc call in dlz_mysqldyn_mod.c.
				[RT #40840]

	4230.	[contrib]	dlz_wildcard_dynamic.c:dlz_create could return a
				uninitialized result. [RT #40839]

	4229.	[bug]		A variable could be used uninitialized in
				dns_update_signaturesinc. [RT #40784]

	4228.	[bug]		Address race condition in dns_client_destroyrestrans.
				[RT #40605]

	4227.	[bug]		Silence static analysis warnings. [RT #40828]

	4226.	[bug]		Address a theoretical shutdown race in
				zone.c:notify_send_queue(). [RT #38958]

	4225.	[port]		freebsd/openbsd:  Use '${CC} -shared' for building
				shared libraries. [RT #39557]

	4224.	[func]		Added support for "dyndb", a new interface for loading
				zone data from an external database, developed by
				Red Hat for the FreeIPA project.

				DynDB drivers fully implement the BIND database
				API, and are capable of significantly better
				performance and functionality than DLZ drivers,
				while taking advantage of advanced database
				features not available in BIND such as multi-master
				replication.

				Thanks to Adam Tkac and Petr Spacek of Red Hat.
				[RT #35271]

	4223.	[func]		Add support for setting max-cache-size to percentage
				of available physical memory, set default to 90%.
				[RT #38442]

	4222.	[func]		Bias IPv6 servers when selecting the next server to
				query. [RT #40836]

	4221.	[bug]		Resource leak on DNS_R_NXDOMAIN in fctx_create.
				[RT #40583]

	4220.	[doc]		Improve documentation for zone-statistics.
				[RT #36955]

	4219.	[bug]		Set event->result to ISC_R_WOULDBLOCK on EWOULDBLOCK,
				EGAIN when these soft error are not retried for
				isc_socket_send*().

	4218.	[bug]		Potential null pointer dereference on out of memory
				if mmap is not supported. [RT #40777]

	4217.	[protocol]	Add support for CSYNC. [RT #40532]

	4216.	[cleanup]	Silence static analysis warnings. [RT #40649]

	4215.	[bug]		nsupdate: skip to next request on GSSTKEY create
				failure. [RT #40685]

	4214.	[protocol]	Add support for TALINK.  [RT #40544]

	4213.	[bug]		Don't reuse a cache across multiple classes.
				[RT #40205]

	4212.	[func]		Re-query if we get a bad client cookie returned over
				UDP. [RT #40748]

	4211.	[bug]		Ensure that lwresd gets at least one task to work
				with if enabled. [RT #40652]

	4210.	[cleanup]	Silence use after free false positive. [RT #40743]

	4209.	[bug]		Address resource leaks in dlz modules. [RT #40654]

	4208.	[bug]		Address null pointer dereferences on out of memory.
				[RT #40764]

	4207.	[bug]		Handle class mismatches with raw zone files.
				[RT #40746]

	4206.	[bug]		contrib: fixed a possible NULL dereference in
				DLZ wildcard module. [RT #40745]

	4205.	[bug]		'named-checkconf -p' could include unwanted spaces
				when printing tuples with unset optional fields.
				[RT #40731]

	4204.	[bug]		'dig +trace' failed to lookup the correct type if
				the initial root NS query was retried. [RT #40296]

	4203.	[test]		The rrchecker system test now tests conversion
				to and from unknown-type format. [RT #40584]

	4202.	[bug]		isccc_cc_fromwire() could return an incorrect
				result. [RT #40614]

	4201.	[func]		The default preferred-glue is now the address record
				type of the transport the query was received
				over.  [RT #40468]

	4200.	[cleanup]	win32: update BINDinstall to be BIND release
				independent. [RT #38915]

	4199.	[protocol]	Add support for NINFO, RKEY, SINK, TA.
				[RT #40545] [RT #40547] [RT #40561] [RT #40563]

	4198.	[placeholder]

	4197.	[bug]		'named-checkconf -z' didn't handle 'in-view' clauses.
				[RT #40603]

	4196.	[doc]		Improve how "enum + other" types are documented.
				[RT #40608]

	4195.	[bug]		'max-zone-ttl unlimited;' was broken. [RT #40608]

	4194.	[bug]		named-checkconf -p failed to properly print a port
				range.  [RT #40634]

	4193.	[bug]		Handle broken servers that return BADVERS incorrectly.
				[RT #40427]

	4192.	[bug]		The default rrset-order of random was not always being
				applied. [RT #40456]

	4191.	[protocol]	Accept DNS-SD non LDH PTR records in reverse zones
				as per RFC 6763. [RT #37889]

	4190.	[protocol]	Accept Active Directory gc._msdcs.<forest> name as
				valid with check-names.  <forest> still needs to be
				LDH. [RT #40399]

	4189.	[cleanup]	Don't exit on overly long tokens in named.conf.
				[RT #40418]

	4188.	[bug]		Support HTTP/1.0 client properly on the statistics
				channel. [RT #40261]

	4187.	[func]		When any RR type implementation doesn't
				implement totext() for the RDATA's wire
				representation and returns ISC_R_NOTIMPLEMENTED,
				such RDATA is now printed in unknown
				presentation format (RFC 3597). RR types affected
				include LOC(29) and APL(42). [RT #40317].

	4186.	[bug]		Fixed an RPZ bug where a QNAME would be matched
				against a policy RR with wildcard owner name
				(trigger) where the QNAME was the wildcard owner
				name's parent. For example, the bug caused a query
				with QNAME "example.com" to match a policy RR with
				"*.example.com" as trigger. [RT #40357]

	4185.	[bug]		Fixed an RPZ bug where a policy RR with wildcard
				owner name (trigger) would prevent another policy RR
				with its parent owner name from being
				loaded. For example, the bug caused a policy RR
				with trigger "example.com" to not have any
				effect when a previous policy RR with trigger
				"*.example.com" existed in that RPZ zone.
				[RT #40357]

	4184.	[bug]		Fixed a possible memory leak in name compression
				when rendering long messages. (Also, improved
				wire_test for testing such messages.) [RT #40375]

	4183.	[cleanup]	Use timing-safe memory comparisons in cryptographic
				code. Also, the timing-safe comparison functions have
				been renamed to avoid possible confusion with
				memcmp(). Thanks to Loganaden Velvindron of
				AFRINIC. [RT #40148]

	4182.	[cleanup]	Use mnemonics for RR class and type comparisons.
				[RT #40297]

	4181.	[bug]		Queued notify messages could be dequeued from the
				wrong rate limiter queue. [RT #40350]

	4180.	[bug]		Error responses in pipelined queries could
				cause a crash in client.c. [RT #40289]

	4179.	[bug]		Fix double frees in getaddrinfo() in libirs.
				[RT #40209]

	4178.	[bug]		Fix assertion failure in parsing UNSPEC(103) RR from
				text. [RT #40274]

	4177.	[bug]		Fix assertion failure in parsing NSAP records from
				text. [RT #40285]

	4176.	[bug]		Address race issues with lwresd. [RT #40284]

	4175.	[bug]		TKEY with GSS-API keys needed bigger buffers.
				[RT #40333]

	4174.	[bug]		"dnssec-coverage -r" didn't handle time unit
				suffixes correctly. [RT #38444]

	4173.	[bug]		dig +sigchase was not properly matching the trusted
				key. [RT #40188]

	4172.	[bug]		Named / named-checkconf didn't handle a view of CLASS0.
				[RT #40265]

	4171.	[bug]		Fixed incorrect class checks in TSIG RR
				implementation. [RT #40287]

	4170.	[security]	An incorrect boundary check in the OPENPGPKEY
				rdatatype could trigger an assertion failure.
				(CVE-2015-5986) [RT #40286]

	4169.	[test]		Added a 'wire_test -d' option to read input as
				raw binary data, for use as a fuzzing harness.
				[RT #40312]

	4168.	[security]	A buffer accounting error could trigger an
				assertion failure when parsing certain malformed
				DNSSEC keys. (CVE-2015-5722) [RT #40212]

	4167.	[func]		Update rndc's usage output to include recently added
				commands. Thanks to Tony Finch for submitting a
				patch. [RT #40010]

	4166.	[func]		Print informative output from rndc showzone when
				allow-new-zones is not enabled for a view. Thanks to
				Tony Finch for submitting a patch. [RT #40009]

	4165.	[security]	A failure to reset a value to NULL in tkey.c could
				result in an assertion failure. (CVE-2015-5477)
				[RT #40046]

	4164.	[bug]		Don't rename slave files and journals on out of memory.
				[RT #40033]

	4163.	[bug]		Address compiler warnings. [RT #40024]

	4162.	[bug]		httpdmgr->flags was not being initialized. [RT #40017]

	4161.	[test]		Add JSON test for traffic size stats; also test
				for consistency between "rndc stats" and the XML
				and JSON statistics channel contents. [RT #38700]

	4160.	[placeholder]

	4159.	[cleanup]	Alphabetize dig's help output. [RT #39966]

	4158.	[placeholder]

	4157.	[placeholder]

	4156.	[func]		Added statistics counters to track the sizes
				of incoming queries and outgoing responses in
				histogram buckets, as specified in RSSAC002.
				[RT #39049]

	4155.	[func]		Allow RPZ rewrite logging to be configured on a
				per-zone basis using a newly introduced log clause in
				the response-policy option. [RT #39754]

	4154.	[bug]		A OPT record should be included with the FORMERR
				response when there is a malformed EDNS option.
				[RT #39647]

	4153.	[bug]		Dig should zero non significant +subnet bits.  Check
				that non significant ECS bits are zero on receipt.
				[RT #39647]

	4152.	[func]		Implement DNS COOKIE option.  This replaces the
				experimental SIT option of BIND 9.10.  The following
				named.conf directives are available: send-cookie,
				cookie-secret, cookie-algorithm, nocookie-udp-size
				and require-server-cookie.  The following dig options
				are available: +[no]cookie[=value] and +[no]badcookie.
				[RT #39928]

	4151.	[bug]		'rndc flush' could cause a deadlock. [RT #39835]

	4150.	[bug]		win32: listen-on-v6 { any; }; was not working.  Apply
				minimal fix.  [RT #39667]

	4149.	[bug]		Fixed a race condition in the getaddrinfo()
				implementation in libirs, which caused the delv
				utility to crash with an assertion failure when using
				the '@server' syntax with a hostname argument.
				[RT #39899]

	4148.	[bug]		Fix a bug when printing zone names with '/' character
				in XML and JSON statistics output. [RT #39873]

	4147.	[bug]		Filter-aaaa / filter-aaaa-on-v4 / filter-aaaa-on-v6
				was returning referrals rather than nodata responses
				when the AAAA records were filtered.  [RT #39843]

	4146.	[bug]		Address reference leak that could prevent a clean
				shutdown. [RT #37125]

	4145.	[bug]		Not all unassociated adb entries where being printed.
				[RT #37125]

	4144.	[func]		Add statistics counters for nxdomain redirections.
				[RT #39790]

	4143.	[placeholder]

	4142.	[bug]		rndc addzone with view specified saved NZF config
				that could not be read back by named. This has now
				been fixed. [RT #39845]

	4141.	[bug]		A formatting bug caused rndc zonestatus to print
				negative numbers for large serial values. This has
				now been fixed. [RT #39854]

	4140.	[cleanup]	Remove redundant nzf_remove() call during delzone.
				[RT #39844]

	4139.	[doc]		Fix rpz-client-ip documentation. [RT #39783]

	4138.	[security]	An uninitialized value in validator.c could result
				in an assertion failure. (CVE-2015-4620) [RT #39795]

	4137.	[bug]		Make rndc reconfig report configuration errors the
				same way rndc reload does. [RT #39635]

	4136.	[bug]		Stale statistics counters with the leading
				'#' prefix (such as #NXDOMAIN) were not being
				updated correctly. This has been fixed. [RT #39141]

	4135.	[cleanup]	Log expired NTA at startup. [RT #39680]

	4134.	[cleanup]	Include client-ip rules when logging the number
				of RPZ rules of each type. [RT #39670]

	4133.	[port]		Update how various json libraries are handled.
				[RT #39646]

	4132.	[cleanup]	dig: added +rd as a synonym for +recurse,
				added +class as an unabbreviated alternative
				to +cl. [RT #39686]

	4131.	[bug]		Addressed further problems with reloading RPZ
				zones. [RT #39649]

	4130.	[bug]		The compatibility shim for *printf() misprinted some
				large numbers. [RT #39586]

	4129.	[port]		Address API changes in OpenSSL 1.1.0. [RT #39532]

	4128.	[bug]		Address issues raised by Coverity 7.6. [RT #39537]

	4127.	[protocol]	CDS and CDNSKEY need to be signed by the key signing
				key as per RFC 7344, Section 4.1. [RT #37215]

	4126.	[bug]		Addressed a regression introduced in change #4121.
				[RT #39611]

	4125.	[test]		Added tests for dig, renamed delv test to digdelv.
				[RT #39490]

	4124.	[func]		Log errors or warnings encountered when parsing the
				internal default configuration.  Clarify the logging
				of errors and warnings encountered in rndc
				addzone or modzone parameters. [RT #39440]

	4123.	[port]		Added %z (size_t) format options to the portable
				internal printf/sprintf implementation. [RT #39586]

	4122.	[bug]		The server could match a shorter prefix than what was
				available in CLIENT-IP policy triggers, and so, an
				unexpected action could be taken. This has been
				corrected. [RT #39481]

	4121.	[bug]		On servers with one or more policy zones
				configured as slaves, if a policy zone updated
				during regular operation (rather than at
				startup) using a full zone reload, such as via
				AXFR, a bug could allow the RPZ summary data to
				fall out of sync, potentially leading to an
				assertion failure in rpz.c when further
				incremental updates were made to the zone, such
				as via IXFR. [RT #39567]

	4120.	[bug]		A bug in RPZ could cause the server to crash if
				policy zones were updated while recursion was
				pending for RPZ processing of an active query.
				[RT #39415]

	4119.	[test]		Allow dig to set the message opcode. [RT #39550]

	4118.	[bug]		Teach isc-config.sh about irs. [RT #39213]

	4117.	[protocol]	Add EMPTY.AS112.ARPA as per RFC 7534.

	4116.	[bug]		Fix a bug in RPZ that could cause some policy
				zones that did not specifically require
				recursion to be treated as if they did;
				consequently, setting qname-wait-recurse no; was
				sometimes ineffective. [RT #39229]

	4115.	[func]		"rndc -r" now prints the result code (e.g.,
				ISC_R_SUCCESS, ISC_R_TIMEOUT, etc) after
				running the requested command. [RT #38913]

	4114.	[bug]		Fix a regression in radix tree implementation
				introduced by ECS code. This bug was never
				released, but it was reported by a user testing
				master. [RT #38983]

	4113.	[test]		Check for Net::DNS is some system test
				prerequisites. [RT #39369]

	4112.	[bug]		Named failed to load when "root-delegation-only"
				was used without a list of domains to exclude.
				[RT #39380]

	4111.	[doc]		Alphabetize rndc man page. [RT #39360]

	4110.	[bug]		Address memory leaks / null pointer dereferences
				on out of memory. [RT #39310]

	4109.	[port]		linux: support reading the local port range from
				net.ipv4.ip_local_port_range. [RT # 39379]

	4108.	[func]		An additional NXDOMAIN redirect method (option
				"nxdomain-redirect") has been added, allowing
				redirection to a specified DNS namespace instead
				of a single redirect zone. [RT #37989]

	4107.	[bug]		Address potential deadlock when updating zone content.
				[RT #39269]

	4106.	[port]		Improve readline support. [RT #38938]

	4105.	[port]		Misc fixes for Microsoft Visual Studio
				2015 CTP6 in 64 bit mode. [RT #39308]

	4104.	[bug]		Address uninitialized elements. [RT #39252]

	4103.	[port]		Misc fixes for Microsoft Visual Studio
				2015 CTP6. [RT #39267]

	4102.	[bug]		Fix a use after free bug introduced in change
				#4094.  [RT #39281]

	4101.	[bug]		dig: the +split and +rrcomments options didn't
				work with +short. [RT #39291]

	4100.	[bug]		Inherited owernames on the line immediately following
				a $INCLUDE were not working.  [RT #39268]

	4099.	[port]		clang: make unknown commandline options hard errors
				when determining what options are supported.
				[RT #39273]

	4098.	[bug]		Address use-after-free issue when using a
				predecessor key with dnssec-settime. [RT #39272]

	4097.	[func]		Add additional logging about xfrin transfer status.
				[RT #39170]

	4096.	[bug]		Fix a use after free of query->sendevent.
				[RT #39132]

	4095.	[bug]		zone->options2 was not being properly initialized.
				[RT #39228]

	4094.	[bug]		A race during shutdown or reconfiguration could
				cause an assertion in mem.c. [RT #38979]

	4093.	[func]		Dig now learns the SIT value from truncated
				responses when it retries over TCP. [RT #39047]

	4092.	[bug]		'in-view' didn't work for zones beneath a empty zone.
				[RT #39173]

	4091.	[cleanup]	Some cleanups in isc mem code. [RT #38896]

	4090.	[bug]		Fix a crash while parsing malformed CAA RRs in
				presentation format, i.e., from text such as
				from master files. Thanks to John Van de
				Meulebrouck Brendgard for discovering and
				reporting this problem. [RT #39003]

	4089.	[bug]		Send notifies immediately for slave zones during
				startup. [RT #38843]

	4088.	[port]		Fixed errors when building with libressl. [RT #38899]

	4087.	[bug]		Fix a crash due to use-after-free due to sequencing
				of tasks actions. [RT #38495]

	4086.	[bug]		Fix out-of-srcdir build with native pkcs11. [RT #38831]

	4085.	[bug]		ISC_PLATFORM_HAVEXADDQ could be inconsistently set.
				[RT #38828]

	4084.	[bug]		Fix a possible race in updating stats counters.
				[RT #38826]

	4083.	[cleanup]	Print the number of CPUs and UDP listeners
				consistently in the log and in "rndc status"
				output; indicate whether threads are supported
				in "named -V" output. [RT #38811]

	4082.	[bug]		Incrementally sign large inline zone deltas.
				[RT #37927]

	4081.	[cleanup]	Use dns_rdatalist_init consistently. [RT #38759]

	4080.	[func]		Completed change #4022, adding a "lock-file" option
				to named.conf to override the default lock file,
				in addition to the "named -X <filename>" command
				line option.  Setting the lock file to "none"
				using either method disables the check completely.
				[RT #37908]

	4079.	[func]		Preserve the case of the owner name of records to
				the RRset level. [RT #37442]

	4078.	[bug]		Handle the case where CMSG_SPACE(sizeof(int)) !=
				CMSG_SPACE(sizeof(char)). [RT #38621]

	4077.	[test]		Add static-stub regression test for DS NXDOMAIN
				return making the static stub disappear. [RT #38564]

	4076.	[bug]		Named could crash on shutdown with outstanding
				reload / reconfig events. [RT #38622]

	4075.	[placeholder]

	4074.	[cleanup]	Cleaned up more warnings from gcc -Wshadow. [RT #38708]

	4073.	[cleanup]	Add libjson-c version number reporting to
				"named -V"; normalize version number formatting.
				[RT #38056]

	4072.	[func]		Add a --enable-querytrace configure switch for
				very verbose query trace logging. (This option
				has a negative performance impact and should be
				used only for debugging.) [RT #37520]

	4071.	[cleanup]	Initialize pthread mutex attrs just once, instead of
				doing it per mutex creation. [RT #38547]

	4070.	[bug]		Fix a segfault in nslookup in a query such as
				"nslookup isc.org AMS.SNS-PB.ISC.ORG -all".
				[RT #38548]

	4069.	[doc]		Reorganize options in the nsupdate man page.
				[RT #38515]

	4068.	[bug]		Omit unknown serial number from JSON zone statistics.
				[RT #38604]

	4067.	[cleanup]	Reduce noise from RRL when query logging is
				disabled. [RT #38648]

	4066.	[doc]		Reorganize options in the dig man page. [RT #38516]

	4065.	[test]		Additional RFC 5011 tests. [RT #38569]

	4064.	[contrib]	dnssec-keyset.sh: Generates a specified number
				of DNSSEC keys with timing set to implement a
				pre-publication key rollover strategy. Thanks
				to Jeffry A. Spain. [RT #38459]

	4063.	[bug]		Asynchronous zone loads were not handled
				correctly when the zone load was already in
				progress; this could trigger a crash in zt.c.
				[RT #37573]

	4062.	[bug]		Fix an out-of-bounds read in RPZ code. If the
				read succeeded, it doesn't result in a bug
				during operation. If the read failed, named
				could segfault. [RT #38559]

	4061.	[bug]		Handle timeout in legacy system test. [RT #38573]

	4060.	[bug]		dns_rdata_freestruct could be called on a
				uninitialized structure when handling a error.
				[RT #38568]

	4059.	[bug]		Addressed valgrind warnings. [RT #38549]

	4058.	[bug]		UDP dispatches could use the wrong pseudorandom
				number generator context. [RT #38578]

	4057.	[bug]		'dnssec-dsfromkey -T 0' failed to add ttl field.
				[RT #38565]

	4056.	[bug]		Expanded automatic testing of trust anchor
				management and fixed several small bugs including
				a memory leak and a possible loss of key state
				information. [RT #38458]

	4055.	[func]		"rndc managed-keys" can be used to check status
				of trust anchors or to force keys to be refreshed,
				Also, the managed keys data file has easier-to-read
				comments.  [RT #38458]

	4054.	[func]		Added a new tool 'mdig', a lightweight clone of
				dig able to send multiple pipelined queries.
				[RT #38261]

	4053.	[security]	Revoking a managed trust anchor and supplying
				an untrusted replacement could cause named
				to crash with an assertion failure.
				(CVE-2015-1349) [RT #38344]

	4052.	[bug]		Fix a leak of query fetchlock. [RT #38454]

	4051.	[bug]		Fix a leak of pthread_mutexattr_t. [RT #38454]

	4050.	[bug]		RPZ could send spurious SERVFAILs in response
				to duplicate queries. [RT #38510]

	4049.	[bug]		CDS and CDNSKEY had the wrong attributes. [RT #38491]

	4048.	[bug]		adb hash table was not being grown. [RT #38470]

	4047.	[cleanup]	"named -V" now reports the current running versions
				of OpenSSL and the libxml2 libraries, in addition to
				the versions that were in use at build time.

	4046.	[bug]		Accounting of "total use" in memory context
				statistics was not correct. [RT #38370]

	4045.	[bug]		Skip to next master on dns_request_createvia4 failure.
				[RT #25185]

	4044.	[bug]		Change 3955 was not complete, resulting in an assertion
				failure if the timing was just right. [RT #38352]

	4043.	[func]		"rndc modzone" can be used to modify the
				configuration of an existing zone, using similar
				syntax to "rndc addzone". [RT #37895]

	4042.	[bug]		zone.c:iszonesecure was being called too late.
				[RT #38371]

	4041.	[func]		TCP sockets can now be shared while connecting.
				(This will be used to enable client-side support
				of pipelined queries.) [RT #38231]

	4040.	[func]		Added server-side support for pipelined TCP
				queries. Clients may continue sending queries via
				TCP while previous queries are being processed
				in parallel.  (The new "keep-response-order"
				option allows clients to be specified for which
				the old behavior will still be used.) [RT #37821]

	4039.	[cleanup]	Cleaned up warnings from gcc -Wshadow. [RT #37381]

	4038.	[bug]		Add 'rpz' flag to node and use it to determine whether
				to call dns_rpz_delete.  This should prevent unbalanced
				add / delete calls. [RT #36888]

	4037.	[bug]		also-notify was ignoring the tsig key when checking
				for duplicates resulting in some expected notify
				messages not being sent. [RT #38369]

	4036.	[bug]		Make call to open a temporary file name safe during
				NZF creation. [RT #38331]

	4035.	[bug]		Close temporary and NZF FILE pointers before moving
				the former into the latter's place, as required on
				Windows. [RT #38332]

	4034.	[func]		When added, negative trust anchors (NTA) are now
				saved to files (viewname.nta), in order to
				persist across restarts of the named server.
				[RT #37087]

	4033.	[bug]		Missing out of memory check in request.c:req_send.
				[RT #38311]

	4032.	[bug]		Built-in "empty" zones did not correctly inherit the
				"allow-transfer" ACL from the options or view.
				[RT #38310]

	4031.	[bug]		named-checkconf -z failed to report a missing file
				with a hint zone. [RT #38294]

	4030.	[func]		"rndc delzone" is now applicable to zones that were
				configured in named.conf, as well as zones that
				were added via "rndc addzone". (Note, however, that
				if named.conf is not also modified, the deleted zone
				will return when named is reloaded.) [RT #37887]

	4029.	[func]		"rndc showzone" displays the current configuration
				of a specified zone. [RT #37887]

	4028.	[bug]		$GENERATE with a zero step was not being caught as a
				error.  A $GENERATE with a / but no step was not being
				caught as a error. [RT #38262]

	4027.	[port]		Net::DNS 0.81 compatibility. [RT #38165]

	4026.	[bug]		Fix RFC 3658 reference in dig +sigchase. [RT #38173]

	4025.	[port]		bsdi: failed to build. [RT #38047]

	4024.	[bug]		dns_rdata_opt_first, dns_rdata_opt_next,
				dns_rdata_opt_current, dns_rdata_txt_first,
				dns_rdata_txt_next and dns_rdata_txt_current were
				documented but not implemented.  These have now been
				implemented.

				dns_rdata_spf_first, dns_rdata_spf_next and
				dns_rdata_spf_current were documented but not
				implemented.  The prototypes for these
				functions have been removed. [RT #38068]

	4023.	[bug]		win32: socket handling with explicit ports and
				invoking named with -4 was broken for some
				configurations. [RT #38068]

	4022.	[func]		Stop multiple spawns of named by limiting number of
				processes to 1. This is done by using a lockfile and
				checking whether we can listen on any configured
				TCP interfaces. [RT #37908]

	4021.	[bug]		Adjust max-recursion-queries to accommodate
				the need for more queries when the cache is
				empty. [RT #38104]

	4020.	[bug]		Change 3736 broke nsupdate's SOA MNAME discovery
				resulting in updates being sent to the wrong server.
				[RT #37925]

	4019.	[func]		If named is not configured to validate the answer
				then allow fallback to plain DNS on timeout even
				when we know the server supports EDNS. [RT #37978]

	4018.	[placeholder]

	4017.	[test]		Add system test to check lookups to legacy servers
				with broken DNS behavior. [RT #37965]

	4016.	[bug]		Fix a dig segfault due to bad linked list usage.
				[RT #37591]

	4015.	[bug]		Nameservers that are skipped due to them being
				CNAMEs were not being logged. They are now logged
				to category 'cname' as per BIND 8. [RT #37935]

	4014.	[bug]		When including a master file origin_changed was
				not being properly set leading to a potentially
				spurious 'inherited owner' warning. [RT #37919]

	4013.	[func]		Add a new tcp-only option to server (config) /
				peer (struct) to use TCP transport to send
				queries (in place of UDP transport with a
				TCP fallback on truncated (TC set) response).
				[RT #37800]

	4012.	[cleanup]	Check returned status of OpenSSL digest and HMAC
				functions when they return one. Note this applies
				only to FIPS capable OpenSSL libraries put in
				FIPS mode and MD5. [RT #37944]

	4011.	[bug]		master's list port and dscp inheritance was not
				properly implemented. [RT #37792]

	4010.	[cleanup]	Clear the prefetchable state when initiating a
				prefetch. [RT #37399]

	4009.	[func]		delv: added a +tcp option. [RT #37855]

	4008.	[contrib]	Updated zkt to latest version (1.1.3). [RT #37886]

	4007.	[doc]		Remove acl forward reference restriction. [RT #37772]

	4006.	[security]	A flaw in delegation handling could be exploited
				to put named into an infinite loop.  This has
				been addressed by placing limits on the number
				of levels of recursion named will allow (default 7),
				and the number of iterative queries that it will
				send (default 50) before terminating a recursive
				query (CVE-2014-8500).

				The recursion depth limit is configured via the
				"max-recursion-depth" option, and the query limit
				via the "max-recursion-queries" option.  [RT #37580]

	4005.	[func]		The buffer used for returning text from rndc
				commands is now dynamically resizable, allowing
				arbitrarily large amounts of text to be sent back
				to the client. (Prior to this change, it was
				possible for the output of "rndc tsig-list" to be
				truncated.) [RT #37731]

	4004.	[bug]		When delegations had AAAA glue but not A, a
				reference could be leaked causing an assertion
				failure on shutdown. [RT #37796]

	4003.	[security]	When geoip-directory was reconfigured during
				named run-time, the previously loaded GeoIP
				data could remain, potentially causing wrong
				ACLs to be used or wrong results to be served
				based on geolocation (CVE-2014-8680). [RT #37720]

	4002.	[security]	Lookups in GeoIP databases that were not
				loaded could cause an assertion failure
				(CVE-2014-8680). [RT #37679]

	4001.	[security]	The caching of GeoIP lookups did not always
				handle address families correctly, potentially
				resulting in an assertion failure (CVE-2014-8680).
				[RT #37672]

	4000.	[bug]		NXDOMAIN redirection incorrectly handled NXRRSET
				from the redirect zone. [RT #37722]

.. code-block:: none

	3999.	[func]		"mkeys" and "nzf" files are now named after
				their corresponding views, unless the view name
				contains characters that would be incompatible
				with use in a filename (i.e., slash, backslash,
				or capital letters). If a view name does contain
				these characters, the files will still be named
				using a cryptographic hash of the view name.
				Regardless of this, if a file using the old name
				format is found to exist, it will continue to be
				used. [RT #37704]

	3998.	[bug]		isc_radix_search was returning matches that were
				too precise. [RT #37680]

	3997.	[protocol]	Add OPENGPGKEY record. [RT# 37671]

	3996.	[bug]		Address use after free on out of memory error in
				keyring_add. [RT #37639]

	3995.	[bug]		receive_secure_serial holds the zone lock for too
				long. [RT #37626]

	3994.	[func]		Dig now supports setting the last unassigned DNS
				header flag bit (dig +zflag). [RT #37421]

	3993.	[func]		Dig now supports EDNS negotiation by default.
				(dig +[no]ednsnegotiation).

				Note:  This is disabled by default in BIND 9.10
				and enabled by default in BIND 9.11.  [RT #37604]

	3992.	[func]		DiG can now send queries without questions
				(dig +header-only). [RT #37599]

	3991.	[func]		Add the ability to buffer logging output by specifying
				"buffered yes;" when defining a channel. [RT #26561]

	3990.	[test]		Add tests for unknown DNSSEC algorithm handling.
				[RT #37541]

	3989.	[cleanup]	Remove redundant dns_db_resigned calls. [RT #35748]

	3988.	[func]		Allow the zone serial of a dynamically updatable
				zone to be updated via "rndc signing -serial".
				[RT #37404]

	3987.	[port]		Handle future Visual Studio 14 incompatible changes.
				[RT #37380]

	3986.	[doc]		Add the BIND version number to page footers
				in the ARM. [RT #37398]

	3985.	[doc]		Describe how +ndots and +search interact in dig.
				[RT #37529]

	3984.	[func]		Accept 256 byte long PINs in native PKCS#11
				crypto. [RT #37410]

	3983.	[bug]		Change #3940 was incomplete: negative trust anchors
				could be set to last up to a week, but the
				"nta-lifetime" and "nta-recheck" options were
				still limited to one day. [RT #37522]

	3982.	[doc]		Include release notes in product documentation.
				[RT #37272]

	3981.	[bug]		Cache DS/NXDOMAIN independently of other query types.
				[RT #37467]

	3980.	[bug]		Improve --with-tuning=large by self tuning of SO_RCVBUF
				size. [RT #37187]

	3979.	[bug]		Negative trust anchor fetches were not properly
				managed. [RT #37488]

	3978.	[test]		Added a unit test for Diffie-Hellman key
				computation, completing change #3974. [RT #37477]

	3977.	[cleanup]	"rndc secroots" reported a "not found" error when
				there were no negative trust anchors set. [RT #37506]

	3976.	[bug]		When refreshing managed-key trust anchors, clear
				any cached trust so that they will always be
				revalidated with the current set of secure
				roots. [RT #37506]

	3975.	[bug]		Don't populate or use the bad cache for queries that
				don't request or use recursion. [RT #37466]

	3974.	[bug]		Handle DH_compute_key() failure correctly in
				openssldh_link.c. [RT #37477]

	3973.	[test]		Added hooks for Google Performance Tools CPU profiler,
				including real-time/wall-clock profiling. Use
				"configure --with-gperftools-profiler" to enable.
				[RT #37339]

	3972.	[bug]		Fix host's usage statement. [RT #37397]

	3971.	[bug]		Reduce the cascading failures due to a bad $TTL line
				in named-checkconf / named-checkzone. [RT #37138]

	3970.	[contrib]	Fixed a use after free bug in the SDB LDAP driver.
				[RT #37237]

	3969.	[test]		Added 'delv' system test. [RT #36901]

	3968.	[bug]		Silence spurious log messages when using 'named -[46]'.
				[RT #37308]

	3967.	[test]		Add test for inlined signed zone in multiple views
				with different DNSKEY sets. [RT #35759]

	3966.	[bug]		Missing dns_db_closeversion call in receive_secure_db.
				[RT #35746]

	3965.	[func]		Log outgoing packets and improve packet logging to
				support logging the remote address. [RT #36624]

	3964.	[func]		nsupdate now performs check-names processing.
				[RT #36266]

	3963.	[test]		Added NXRRSET test cases to the "dlzexternal"
				system test. [RT #37344]

	3962.	[bug]		'dig +topdown +trace +sigchase' address unhandled error
				conditions. [RT #34663]

	3961.	[bug]		Forwarding of SIG(0) signed UPDATE messages failed with
				BADSIG.  [RT #37216]

	3960.	[bug]		'dig +sigchase' could loop forever. [RT #37220]

	3959.	[bug]		Updates could be lost if they arrived immediately
				after a rndc thaw. [RT #37233]

	3958.	[bug]		Detect when writeable files have multiple references
				in named.conf. [RT #37172]

	3957.	[bug]		"dnssec-keygen -S" failed for ECCGOST, ECDSAP256SHA256
				and ECDSAP384SHA384. [RT #37183]

	3956.	[func]		Notify messages are now rate limited by notify-rate and
				startup-notify-rate instead of serial-query-rate.
				[RT #24454]

	3955.	[bug]		Notify messages due to changes are no longer queued
				behind startup notify messages. [RT #24454]

	3954.	[bug]		Unchecked mutex init in dlz_dlopen_driver.c [RT #37112]

	3953.	[bug]		Don't escape semi-colon in TXT fields. [RT #37159]

	3952.	[bug]		dns_name_fullcompare failed to set *nlabelsp when the
				two name pointers were the same. [RT #37176]

	3951.	[func]		Add the ability to set yet-to-be-defined EDNS flags
				to dig (+ednsflags=#). [RT #37142]

	3950.	[port]		Changed the bin/python Makefile to work around a
				bmake bug in FreeBSD 10 and NetBSD 6. [RT #36993]

	3949.	[experimental]	Experimental support for draft-andrews-edns1 by sending
				EDNS(1) queries (define DRAFT_ANDREWS_EDNS1 when
				building).  Add support for limiting the EDNS version
				advertised to servers: server { edns-version 0; };
				Log the EDNS version received in the query log.
				[RT #35864]

	3948.	[port]		solaris: RCVBUFSIZE was too large on Solaris with
				--with-tuning=large. [RT #37059]

	3947.	[cleanup]	Set the executable bit on libraries when using
				libtool. [RT #36786]

	3946.	[cleanup]	Improved "configure" search for a python interpreter.
				[RT #36992]

	3945.	[bug]		Invalid wildcard expansions could be incorrectly
				accepted by the validator. [RT #37093]

	3944.	[test]		Added a regression test for "server-id". [RT #37057]

	3943.	[func]		SERVFAIL responses can now be cached for a
				limited time (configured by "servfail-ttl",
				default 10 seconds, limit 30). This can reduce
				the frequency of retries when an authoritative
				server is known to be failing, e.g., due to
				ongoing DNSSEC validation problems. [RT #21347]

	3942.	[bug]		Wildcard responses from a optout range should be
				marked as insecure. [RT #37072]

	3941.	[doc]		Include the BIND version number in the ARM. [RT #37067]

	3940.	[func]		"rndc nta" now allows negative trust anchors to be
				set for up to one week. [RT #37069]

	3939.	[func]		Improve UPDATE forwarding performance by allowing TCP
				connections to be shared. [RT #37039]

	3938.	[func]		Added quotas to be used in recursive resolvers
				that are under high query load for names in zones
				whose authoritative servers are nonresponsive or
				are experiencing a denial of service attack.

				- "fetches-per-server" limits the number of
				  simultaneous queries that can be sent to any
				  single authoritative server.  The configured
				  value is a starting point; it is automatically
				  adjusted downward if the server is partially or
				  completely non-responsive. The algorithm used to
				  adjust the quota can be configured via the
				  "fetch-quota-params" option.
				- "fetches-per-zone" limits the number of
				  simultaneous queries that can be sent for names
				  within a single domain.  (Note: Unlike
				  "fetches-per-server", this value is not
				  self-tuning.)
				- New stats counters have been added to count
				  queries spilled due to these quotas.

				See the ARM for details of these options. [RT #37125]

	3937.	[func]		Added some debug logging to better indicate the
				conditions causing SERVFAILs when resolving.
				[RT #35538]

	3936.	[func]		Added authoritative support for the EDNS Client
				Subnet (ECS) option.

				ACLs can now include "ecs" elements which specify
				an address or network prefix; if an ECS option is
				included in a DNS query, then the address encoded
				in the option will be matched against "ecs" ACL
				elements.

				Also, if an ECS address is included in a query,
				then it will be used instead of the client source
				address when matching "geoip" ACL elements.  This
				behavior can be overridden with "geoip-use-ecs no;".
				(Note: to enable "geoip" ACLs, use "configure
				--with-geoip". This requires libGeoIP version
				1.5.0 or higher.)

				When "ecs" or "geoip" ACL elements are used to
				select a view for a query, the response will include
				an ECS option to indicate which client network the
				answer is valid for.

				(Thanks to Vincent Bernat.) [RT #36781]

	3935.	[bug]		"geoip asnum" ACL elements would not match unless
				the full organization name was specified.  They
				can now match against the AS number alone (e.g.,
				AS1234). [RT #36945]

	3934.	[bug]		Catch bad 'sit-secret' in named-checkconf.  Improve
				sit-secret documentation. [RT #36980]

	3933.	[bug]		Corrected the implementation of dns_rdata_casecompare()
				for the HIP rdata type.  [RT #36911]

	3932.	[test]		Improved named-checkconf tests. [RT #36911]

	3931.	[cleanup]	Cleanup how dlz grammar is defined. [RT #36879]

	3930.	[bug]		"rndc nta -r" could cause a server hang if the
				NTA was not found. [RT #36909]

	3929.	[bug]		'host -a' needed to clear idnoptions. [RT #36963]

	3928.	[test]		Improve rndc system test. [RT #36898]

	3927.	[bug]		dig: report PKCS#11 error codes correctly when
				compiled with --enable-native-pkcs11. [RT #36956]

	3926.	[doc]		Added doc for geoip-directory. [RT #36877]

	3925.	[bug]		DS lookup of RFC 1918 empty zones failed. [RT #36917]

	3924.	[bug]		Improve 'rndc addzone' error reporting. [RT #35187]

	3923.	[bug]		Sanity check the xml2-config output. [RT #22246]

	3922.	[bug]		When resigning, dnssec-signzone was removing
				all signatures from delegation nodes. It now
				retains DS and (if applicable) NSEC signatures.
				[RT #36946]

	3921.	[bug]		AD was inappropriately set on RPZ responses. [RT #36833]

	3920.	[doc]		Added doc for masterfile-style. [RT #36823]

	3919.	[bug]		dig: continue to next line if a address lookup fails
				in batch mode. [RT #36755]

	3918.	[doc]		Update check-spf documentation. [RT #36910]

	3917.	[bug]		dig, nslookup and host now continue on names that are
				too long after applying a search list elements.
				[RT #36892]

	3916.	[contrib]	zone2sqlite checked wrong result code.  Address
				compiler warnings. [RT #36931]

	3915.	[bug]		Address a assertion if a route event arrived while
				shutting down. [RT #36887]

	3914.	[bug]		Allow the URI target and CAA value fields to
				be zero length. [RT #36737]

	3913.	[bug]		Address race issue in dispatch. [RT #36731]

	3912.	[bug]		Address some unrecoverable lookup failures. [RT #36330]

	3911.	[func]		Implement EDNS EXPIRE option client side, allowing
				a slave server to set the expiration timer correctly
				when transferring zone data from another slave
				server. [RT #35925]

	3910.	[bug]		Fix races to free event during shutdown. [RT #36720]

	3909.	[bug]		When computing the number of elements required for a
				acl count_acl_elements could have a short count leading
				to a assertion failure.  Also zero out new acl elements
				in dns_acl_merge.  [RT #36675]

	3908.	[bug]		rndc now differentiates between a zone in multiple
				views and a zone that doesn't exist at all. [RT #36691]

	3907.	[cleanup]	Alphabetize rndc help. [RT #36683]

	3906.	[protocol]	Update URI record format to comply with
				draft-faltstrom-uri-08. [RT #36642]

	3905.	[bug]		Address deadlock between view.c and adb.c. [RT #36341]

	3904.	[func]		Add the RPZ SOA to the additional section. [RT36507]

	3903.	[bug]		Improve the accuracy of DiG's reported round trip
				time. [RT 36611]

	3902.	[bug]		liblwres wasn't handling link-local addresses in
				nameserver clauses in resolv.conf. [RT #36039]

	3901.	[protocol]	Added support for CAA record type (RFC 6844).
				[RT #36625]

	3900.	[bug]		Fix a crash in PostgreSQL DLZ driver. [RT #36637]

	3899.	[bug]		"request-ixfr" is only applicable to slave and redirect
				zones. [RT #36608]

	3898.	[bug]		Too small a buffer in tohexstr() calls in test code.
				[RT #36598]

	3897.	[bug]		RPZ summary information was not properly being updated
				after a AXFR resulting in changes sometimes being
				ignored.  [RT #35885]

	3896.	[bug]		Address performance issues with DSCP code on some
				platforms. [RT #36534]

	3895.	[func]		Add the ability to set the DSCP code point to dig.
				[RT #36546]

	3894.	[bug]		Buffers in isc_print_vsnprintf were not properly
				initialized leading to potential overflows when
				printing out quad values. [RT #36505]

	3893.	[bug]		Peer DSCP values could be returned without being set.
				[RT #36538]

	3892.	[bug]		Setting '-t aaaa' in .digrc had unintended side
				effects. [RT #36452]

	3891.	[bug]		Use ${INSTALL_SCRIPT} rather than ${INSTALL_PROGRAM}
				to install python programs.

	3890.	[bug]		RRSIG sets that were not loaded in a single transaction
				at start up where not being correctly added to
				re-signing heaps.  [RT #36302]

	3889.	[port]		hurd: configure fixes as per:
				https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=746540

	3888.	[func]		'rndc status' now reports the number of automatic
				zones. [RT #36015]

	3887.	[cleanup]	Make all static symbols in rbtdb64 end in "64" so
				they are easier to use in a debugger. [RT #36373]

	3886.	[bug]		rbtdb_write_header should use a once to initialize
				FILE_VERSION. [RT #36374]

	3885.	[port]		Use 'open()' rather than 'file()' to open files in
				python.

	3884.	[protocol]	Add CDS and CDNSKEY record types. [RT #36333]

	3883.	[placeholder]

	3882.	[func]		By default, negative trust anchors will be tested
				periodically to see whether data below them can be
				validated, and if so, they will be allowed to
				expire early. The "rndc nta -force" option
				overrides this behavior.  The default NTA lifetime
				and the recheck frequency can be configured by the
				"nta-lifetime" and "nta-recheck" options. [RT #36146]

	3881.	[bug]		Address memory leak with UPDATE error handling.
				[RT #36303]

	3880.	[test]		Update ans.pl to work with new TSIG support in
				Net::DNS; add additional Net::DNS version prerequisite
				checks. [RT #36327]

	3879.	[func]		Add version printing option to various BIND utilities.
				[RT #10686]

	3878.	[bug]		Using the incorrect filename for a DLZ module
				caused a segmentation fault on startup. [RT #36286]

	3877.	[bug]		Inserting and deleting parent and child nodes
				in response policy zones could trigger an assertion
				failure. [RT #36272]

	3876.	[bug]		Improve efficiency of DLZ redirect zones by
				suppressing unnecessary database lookups. [RT #35835]

	3875.	[cleanup]	Clarify log message when unable to read private
				key files. [RT #24702]

	3874.	[test]		Check that only "check-names master" is needed for
				updates to be accepted.

	3873.	[protocol]	Only warn for SPF without TXT spf record. [RT #36210]

	3872.	[bug]		Address issues found by static analysis. [RT #36209]

	3871.	[bug]		Don't publish an activated key automatically before
				its publish time. [RT #35063]

	3870.	[func]		Updated the random number generator used in
				the resolver to use the updated ChaCha based one
				(similar to OpenBSD's changes). Also moved the
				RNG to libisc and added unit tests for it.
				[RT #35942]

	3869.	[doc]		Document that in-view zones cannot be used for
				response policy zones. [RT #35941]

	3868.	[bug]		isc_mem_setwater incorrectly cleared hi_called
				potentially leaving over memory cleaner running.
				[RT #35270]

	3867.	[func]		"rndc nta" can now be used to set a temporary
				negative trust anchor, which disables DNSSEC
				validation below a specified name for a specified
				period of time (not exceeding 24 hours).  This
				can be used when validation for a domain is known
				to be failing due to a configuration error on
				the part of the domain owner rather than a
				spoofing attack. [RT #29358]

	3866.	[bug]		Named could die on disk full in generate_session_key.
				[RT #36119]

	3865.	[test]		Improved testability of the red-black tree
				implementation and added unit tests. [RT #35904]

	3864.	[bug]		RPZ didn't work well when being used as forwarder.
				[RT #36060]

	3863.	[bug]		The "E" flag was missing from the query log as a
				unintended side effect of code rearrangement to
				support EDNS EXPIRE. [RT #36117]

	3862.	[cleanup]	Return immediately if we are not going to log the
				message in ns_client_dumpmessage.

	3861.	[security]	Missing isc_buffer_availablelength check results
				in a REQUIRE assertion when printing out a packet
				(CVE-2014-3859).  [RT #36078]

	3860.	[bug]		ioctl(DP_POLL) array size needs to be determined
				at run time as it is limited to {OPEN_MAX}.
				[RT #35878]

	3859.	[placeholder]

	3858.	[bug]		Disable GCC 4.9 "delete null pointer check".
				[RT #35968]

	3857.	[bug]		Make it harder for a incorrect NOEDNS classification
				to be made. [RT #36020]

	3856.	[bug]		Configuring libjson without also configuring libxml
				resulted in a REQUIRE assertion when retrieving
				statistics using json. [RT #36009]

	3855.	[bug]		Limit smoothed round trip time aging to no more than
				once a second. [RT #32909]

	3854.	[cleanup]	Report unrecognized options, if any, in the final
				configure summary. [RT #36014]

	3853.	[cleanup]	Refactor dns_rdataslab_fromrdataset to separate out
				the handling of a rdataset with no records. [RT #35968]

	3852.	[func]		Increase the default number of clients available
				for servicing lightweight resolver queries, and
				make them configurable via the "lwres-tasks" and
				"lwres-clients" options.  (Thanks to Tomas Hozza.)
				[RT #35857]

	3851.	[func]		Allow libseccomp based system-call filtering
				on Linux; use "configure --enable-seccomp" to
				turn it on.  Thanks to Loganaden Velvindron
				of AFRINIC for the contribution. [RT #35347]

	3850.	[bug]		Disabling forwarding could trigger a REQUIRE assertion.
				[RT #35979]

	3849.	[doc]		Alphabetized dig's +options. [RT #35992]

	3848.	[bug]		Adjust 'statistics-channels specified but not effective'
				error message to account for JSON support. [RT #36008]

	3847.	[bug]		'configure --with-dlz-postgres' failed to fail when
				there is not support available.

	3846.	[bug]		"dig +notcp ixfr=<serial>" should result in a UDP
				ixfr query. [RT #35980]

	3845.	[placeholder]

	3844.	[bug]		Use the x64 version of the Microsoft Visual C++
				Redistributable when built for 64 bit Windows.
				[RT #35973]

	3843.	[protocol]	Check EDNS EXPIRE option in dns_rdata_fromwire.
				[RT #35969]

	3842.	[bug]		Adjust RRL log-only logging category. [RT #35945]

	3841.	[cleanup]	Refactor zone.c:add_opt to use dns_message_buildopt.
				[RT #35924]

	3840.	[port]		Check for arc4random_addrandom() before using it;
				it's been removed from OpenBSD 5.5. [RT #35907]

	3839.	[test]		Use only posix-compatible shell in system tests.
				[RT #35625]

	3838.	[protocol]	EDNS EXPIRE as been assigned a code point of 9.

	3837.	[security]	A NULL pointer is passed to query_prefetch resulting
				a REQUIRE assertion failure when a fetch is actually
				initiated (CVE-2014-3214).  [RT #35899]

	3836.	[bug]		Address C++ keyword usage in header file.

	3835.	[bug]		Geoip ACL elements didn't work correctly when
				referenced via named or nested ACLs. [RT #35879]

	3834.	[bug]		The re-signing heaps were not being updated soon enough
				leading to multiple re-generations of the same RRSIG
				when a zone transfer was in progress. [RT #35273]

	3833.	[bug]		Cross compiling was broken due to calling genrandom at
				build time. [RT #35869]

	3832.	[func]		"named -L <filename>" causes named to send log
				messages to the specified file by default instead
				of to the system log. (Thanks to Tony Finch.)
				[RT #35845]

	3831.	[cleanup]	Reduce logging noise when EDNS state changes occur.
				[RT #35843]

	3830.	[func]		When query logging is enabled, log query errors at
				the same level ('info') as the queries themselves.
				[RT #35844]

	3829.	[func]		"dig +ttlunits" causes dig to print TTL values
				with time-unit suffixes: w, d, h, m, s for
				weeks, days, hours, minutes, and seconds. (Thanks
				to Tony Finch.) [RT #35823]

	3828.	[func]		"dnssec-signzone -N date" updates serial number
				to the current date in YYYYMMDDNN format.
				[RT #35800]

	3827.	[placeholder]

	3826.	[bug]		Corrected bad INSIST logic in isc_radix_remove().
				[RT #35870]

	3825.	[bug]		Address sign extension bug in isc_regex_validate.
				[RT #35758]

	3824.	[bug]		A collision between two flag values could cause
				problems with cache cleaning when SIT was enabled.
				[RT #35858]

	3823.	[func]		Log the rpz cname target when rewriting. [RT #35667]

	3822.	[bug]		Log the correct type of static-stub zones when
				removing them. [RT #35842]

	3821.	[contrib]	Added a new "mysqldyn" DLZ module with dynamic
				update and transaction support. Thanks to Marty
				Lee for the contribution. [RT #35656]

	3820.	[func]		The DLZ API doesn't pass the database version to
				the lookup() function; this can cause DLZ modules
				that allow dynamic updates to mishandle prerequisite
				checks. This has been corrected by adding a
				'dbversion' field to the dns_clientinfo_t
				structure. [RT #35656]

	3819.	[bug]		NSEC3 hashes need to be able to be entered and
				displayed without padding.  This is not a issue for
				currently defined algorithms but may be for future
				hash algorithms. [RT #27925]

	3818.	[bug]		Stop lying to the optimizer that 'void *arg' is a
				constant in isc_event_allocate.

	3817.	[func]		The "delve" command is now spelled "delv" to avoid
				a namespace collision with the Xapian project.
				[RT #35801]

	3816.	[func]		"dig +qr" now reports query size. (Thanks to
				Tony Finch.) [RT #35822]

	3815.	[doc]		Clarify "nsupdate -y" usage in man page. [RT #35808]

	3814.	[func]		The "masterfile-style" zone option controls the
				formatting of dumped zone files. Options are
				"relative" (multiline format) and "full" (one
				record per line). The default is "relative".
				[RT #20798]

	3813.	[func]		"host" now recognizes the "timeout", "attempts" and
				"debug" options when set in /etc/resolv.conf.
				(Thanks to Adam Tkac at RedHat.) [RT #21885]

	3812.	[func]		Dig now supports sending arbitrary EDNS options from
				the command line (+ednsopt=code[:value]). [RT #35584]

	3811.	[func]		"serial-update-method date;" sets serial number
				on dynamic update to today's date in YYYYMMDDNN
				format. (Thanks to Bradley Forschinger.) [RT #24903]

	3810.	[bug]		Work around broken nameservers that fail to ignore
				unknown EDNS options. [RT #35766]

	3809.	[doc]		Fix SIT and NSID documentation.

	3808.	[doc]		Clean up "prefetch" documentation. [RT #35751]

	3807.	[bug]		Fix sign extension bug in dns_name_fromtext when
				lowercase is set. [RT #35743]

	3806.	[test]		Improved system test portability. [RT #35625]

	3805.	[contrib]	Added contrib/perftcpdns, a performance testing tool
				for DNS over TCP. [RT #35710]

.. code-block:: none

		--- 9.10.0rc1 released ---

	3804.	[bug]		Corrected a race condition in dispatch.c in which
				portentry could be reset leading to an assertion
				failure in socket_search(). (Change #3708
				addressed the same issue but was incomplete.)
				[RT #35128]

	3803.	[bug]		"named-checkconf -z" incorrectly rejected zones
				using alternate data sources for not having a "file"
				option. [RT #35685]

	3802.	[bug]		Various header files were not being installed.

	3801.	[port]		Fix probing for gssapi support on FreeBSD. [RT #35615]

	3800.	[bug]		A pending event on the route socket could cause an
				assertion failure when shutting down named. [RT #35674]

	3799.	[bug]		Improve named's command line error reporting.
				[RT #35603]

	3798.	[bug]		'rndc zonestatus' was reporting the wrong re-signing
				time. [RT #35659]

	3797.	[port]		netbsd: geoip support probing was broken. [RT #35642]

	3796.	[bug]		Register dns and pkcs#11 error codes. [RT #35629]

	3795.	[bug]		Make named-checkconf detect raw masterfiles for
				hint zones and reject them. [RT #35268]

	3794.	[maint]		Added AAAA for C.ROOT-SERVERS.NET.

	3793.	[bug]		zone.c:save_nsec3param() could assert when out of
				memory. [RT #35621]

	3792.	[func]		Provide links to the alternate statistics views when
				displaying in a browser.  [RT #35605]

	3791.	[placeholder]

	3790.	[bug]		Handle broken nameservers that send BADVERS in
				response to unknown EDNS options.  Maintain
				statistics on BADVERS responses.

	3789.	[bug]		Null pointer dereference on rbt creation failure.

	3788.	[bug]		dns_peer_getrequestsit was returning request_nsid by
				mistake.

.. code-block:: none

		--- 9.10.0b2 released ---

	3787.	[bug]		The code that checks whether "auto-dnssec" is
				allowed was ignoring "allow-update" ACLs set at
				the options or view level. [RT #29536]

	3786.	[func]		Provide more detailed error codes when using
				native PKCS#11. "pkcs11-tokens" now fails robustly
				rather than asserting when run against an HSM with
				an incomplete PKCS#11 API implementation. [RT #35479]

	3785.	[bug]		Debugging code dumphex didn't accept arbitrarily long
				input (only compiled with -DDEBUG). [RT #35544]

	3784.	[bug]		Using "rrset-order fixed" when it had not been
				enabled at compile time caused inconsistent
				results. It now works as documented, defaulting
				to cyclic mode. [RT #28104]

	3783.	[func]		"tsig-keygen" is now available as an alternate
				command name for "ddns-confgen".  It generates
				a TSIG key in named.conf format without comments.
				[RT #35503]

	3782.	[func]		Specifying "auto" as the salt when using
				"rndc signing -nsec3param" causes named to
				generate a 64-bit salt at random. [RT #35322]

	3781.	[tuning]	Use adaptive mutex locks when available; this
				has been found to improve performance under load
				on many systems. "configure --with-locktype=standard"
				restores conventional mutex locks. [RT #32576]

	3780.	[bug]		$GENERATE handled negative numbers incorrectly.
				[RT #25528]

	3779.	[cleanup]	Clarify the error message when using an option
				that was not enabled at compile time. [RT #35504]

	3778.	[bug]		Log a warning when the wrong address family is
				used in "listen-on" or "listen-on-v6". [RT #17848]

	3777.	[bug]		EDNS EXPIRE code could dump core when processing
				DLZ queries. [RT #35493]

	3776.	[func]		"rndc -q" suppresses output from successful
				rndc commands. Errors are printed on stderr.
				[RT #21393]

	3775.	[bug]		dlz_dlopen driver could return the wrong error
				code on API version mismatch, leading to a segfault.
				[RT #35495]

	3774.	[func]		When using "request-nsid", log the NSID value in
				printable form as well as hex. [RT #20864]

	3773.	[func]		"host", "nslookup" and "nsupdate" now have
				options to print the version number and exit.
				[RT #26057]

	3772.	[contrib]	Added sqlite3 dynamically-loadable DLZ module.
				(Based in part on a contribution from Tim Tessier.)
				[RT #20822]

	3771.	[cleanup]	Adjusted log level for "using built-in key"
				messages. [RT #24383]

	3770.	[bug]		"dig +trace" could fail with an assertion when it
				needed to fall back to TCP due to a truncated
				response. [RT #24660]

	3769.	[doc]		Improved documentation of "rndc signing -list".
				[RT #30652]

	3768.	[bug]		"dnssec-checkds" was missing the SHA-384 digest
				algorithm. [RT #34000]

	3767.	[func]		Log explicitly when using rndc.key to configure
				command channel. [RT #35316]

	3766.	[cleanup]	Fixed problems with building outside the source
				tree when using native PKCS#11. [RT #35459]

	3765.	[bug]		Fixed a bug in "rndc secroots" that could crash
				named when dumping an empty keynode. [RT #35469]

	3764.	[bug]		The dnssec-keygen/settime -S and -i options
				(to set up a successor key and set the prepublication
				interval) were missing from dnssec-keyfromlabel.
				[RT #35394]

	3763.	[bug]		delve: Cache DNSSEC records to avoid the need to
				re-fetch them when restarting validation. [RT #35476]

	3762.	[bug]		Address build problems with --pkcs11-native +
				--with-openssl with ECDSA support. [RT #35467]

	3761.	[bug]		Address dangling reference bug in dns_keytable_add.
				[RT #35471]

	3760.	[bug]		Improve SIT with native PKCS#11 and on Windows.
				[RT #35433]

	3759.	[port]		Enable delve on Windows. [RT #35441]

	3758.	[port]		Enable export library APIs on Windows. [RT #35382]

	3757.	[port]		Enable Python tools (dnssec-coverage,
				dnssec-checkds) to run on Windows. [RT #34355]

	3756.	[bug]		GSSAPI Kerberos realm checking was broken in
				check_config leading to spurious messages being
				logged.  [RT #35443]

.. code-block:: none

		--- 9.10.0b1 released ---

	3755.	[func]		Add stats counters for known EDNS options + others.
				[RT #35447]

	3754.	[cleanup]	win32: Installer now places files in the
				Program Files area rather than system services.
				[RT #35361]

	3753.	[bug]		allow-notify was ignoring keys. [RT #35425]

	3752.	[bug]		Address potential REQUIRE failure if
				DNS_STYLEFLAG_COMMENTDATA is set when printing out
				a rdataset.

	3751.	[tuning]	The default setting for the -U option (setting
				the number of UDP listeners per interface) has
				been adjusted to improve performance. [RT #35417]

	3750.	[experimental]	Partially implement EDNS EXPIRE option as described
				in draft-andrews-dnsext-expire-00.  Retrieval of
				the remaining time until expiry for slave zones
				is supported.

				EXPIRE uses an experimental option code (65002),
				which is subject to change. [RT #35416]

	3749.	[func]		"dig +subnet" sends an EDNS client subnet option
				containing the specified address/prefix when
				querying. (Thanks to Wilmer van der Gaast.)
				[RT #35415]

	3748.	[test]		Use delve to test dns_client interfaces. [RT #35383]

	3747.	[bug]		A race condition could lead to a core dump when
				destroying a resolver fetch object. [RT #35385]

	3746.	[func]		New "max-zone-ttl" option enforces maximum
				TTLs for zones. If loading a zone containing a
				higher TTL, the load fails. DDNS updates with
				higher TTLs are accepted but the TTL is truncated.
				(Note: Currently supported for master zones only;
				inline-signing slaves will be added.) [RT #38405]

	3745.	[func]		"configure --with-tuning=large" adjusts various
				compiled-in constants and default settings to
				values suited to large servers with abundant
				memory. [RT #29538]

	3744.	[experimental]	SIT: send and process Source Identity Tokens
				(similar to DNS Cookies by Donald Eastlake 3rd),
				which are designed to help clients detect off-path
				spoofed responses and for servers to identify
				legitimate clients.

				SIT uses an experimental EDNS option code (65001),
				which will be changed to an IANA-assigned value
				if the experiment is deemed a success.

				SIT can be enabled via "configure --enable-sit" (or
				--enable-developer). It is enabled by default in
				Windows.

				Servers can be configured to send smaller responses
				to clients that have not identified themselves via
				SIT.  RRL processing has also been updated;
				legitimate clients are not subject to rate
				limiting. [RT #35389]

	3743.	[bug]		delegation-only flag wasn't working in forward zone
				declarations despite being documented.  This is
				needed to support turning off forwarding and turning
				on delegation only at the same name.  [RT #35392]

	3742.	[port]		linux: libcap support: declare curval at start of
				block. [RT #35387]

	3741.	[func]		"delve" (domain entity lookup and validation engine):
				A new tool with dig-like semantics for performing DNS
				lookups, with internal DNSSEC validation, using the
				same resolver and validator logic as named. This
				allows easy validation of DNSSEC data in environments
				with untrustworthy resolvers, and assists with
				troubleshooting of DNSSEC problems. [RT #32406]

	3740.	[contrib]	Minor fixes to configure --with-dlz-bdb,
				--with-dlz-postgres and --with-dlz-odbc. [RT #35340]

	3739.	[func]		Added per-zone stats counters to track TCP and
				UDP queries. [RT #35375]

	3738.	[bug]		--enable-openssl-hash failed to build. [RT #35343]

	3737.	[bug]		'rndc retransfer' could trigger a assertion failure
				with inline zones. [RT #35353]

	3736.	[bug]		nsupdate: When specifying a server by name,
				fall back to alternate addresses if the first
				address for that name is not reachable. [RT #25784]

	3735.	[cleanup]	Merged the libiscpk11 library into libisc
				to simplify dependencies. [RT #35205]

	3734.	[bug]		Improve building with libtool. [RT #35314]

	3733.	[func]		Improve interface scanning support.  Interface
				information will be automatically updated if the
				OS supports routing sockets (MacOS, *BSD, Linux).
				Use "automatic-interface-scan no;" to disable.

				Add "rndc scan" to trigger a scan. [RT #23027]

	3732.	[contrib]	Fixed a type mismatch causing the ODBC DLZ
				driver to dump core on 64-bit systems. [RT #35324]

	3731.	[func]		Added a "no-case-compress" ACL, which causes
				named to use case-insensitive compression
				(disabling change #3645) for specified
				clients. (This is useful when dealing
				with broken client implementations that
				use case-sensitive name comparisons,
				rejecting responses that fail to match the
				capitalization of the query that was sent.)
				[RT #35300]

	3730.	[cleanup]	Added "never" as a synonym for "none" when
				configuring key event dates in the dnssec tools.
				[RT #35277]

	3729.	[bug]		dnssec-keygen could set the publication date
				incorrectly when only the activation date was
				specified on the command line. [RT #35278]

	3728.	[doc]		Expanded native-PKCS#11 documentation,
				specifically pkcs11: URI labels. [RT #35287]

	3727.	[func]		The isc_bitstring API is no longer used and
				has been removed from libisc. [RT #35284]

	3726.	[cleanup]	Clarified the error message when attempting
				to configure more than 32 response-policy zones.
				[RT #35283]

	3725.	[contrib]	Updated zkt and nslint to newest versions,
				cleaned up and rearranged the contrib
				directory, and added a README.

.. code-block:: none

		--- 9.10.0a2 released ---

	3724.	[bug]		win32: Fixed a bug that prevented dig and
				host from exiting properly after completing
				a UDP query. [RT #35288]

	3723.	[cleanup]	Imported keys are now handled the same way
				regardless of DNSSEC algorithm. [RT #35215]

	3722.	[bug]		Using geoip ACLs in a blackhole statement
				could cause a segfault. [RT #35272]

	3721.	[doc]		Improved documentation of the EDNS processing
				enhancements introduced in change #3593. [RT #35275]

	3720.	[bug]		Address compiler warnings. [RT #35261]

	3719.	[bug]		Address memory leak in in peer.c. [RT #35255]

	3718.	[bug]		A missing ISC_LINK_INIT in log.c. [RT #35260]

	3717.	[port]		hpux: Treat EOPNOTSUPP as a expected error code when
				probing to see if it is possible to set dscp values
				on a per packet basis. [RT #35252]

	3716.	[bug]		The dns_request code was setting dcsp values when not
				requested.  [RT #35252]

	3715.	[bug]		The region and city databases could fail to
				initialize when using some versions of libGeoIP,
				causing assertion failures when named was
				configured to use them. [RT #35427]

	3714.	[test]		System tests that need to test for cryptography
				support before running can now use a common
				"testcrypto.sh" script to do so. [RT #35213]

	3713.	[bug]		Save memory by not storing "also-notify" addresses
				in zone objects that are configured not to send
				notify requests. [RT #35195]

	3712.	[placeholder]

	3711.	[placeholder]

	3710.	[bug]		Address double dns_zone_detach when switching to
				using automatic empty zones from regular zones.
				[RT #35177]

	3709.	[port]		Use built-in versions of strptime() and timegm()
				on all platforms to avoid portability issues.
				[RT #35183]

	3708.	[bug]		Address a portentry locking issue in dispatch.c.
				[RT #35128]

	3707.	[bug]		irs_resconf_load now returns ISC_R_FILENOTFOUND
				on a missing resolv.conf file and initializes the
				structure as if it had been configured with:

					nameserver ::1
					nameserver 127.0.0.1

				Note: Callers will need to be updated to treat
				ISC_R_FILENOTFOUND as a qualified success or else
				they will leak memory. The following code fragment
				will work with both old and new versions without
				changing the behaviour of the existing code.

				resconf = NULL;
				result = irs_resconf_load(mctx, "/etc/resolv.conf",
							  &resconf);
				if (result != ISC_SUCCESS) {
					if (resconf != NULL)
						irs_resconf_destroy(&resconf);
					....
				}

				[RT #35194]

	3706.	[contrib]	queryperf: Fixed a possible integer overflow when
				printing results. [RT #35182]

	3705.	[func]		"configure --enable-native-pkcs11" enables BIND
				to use the PKCS#11 API for all cryptographic
				functions, so that it can drive a hardware service
				module directly without the need to use a modified
				OpenSSL as intermediary (so long as the HSM's vendor
				provides a complete-enough implementation of the
				PKCS#11 interface). This has been tested successfully
				with the Thales nShield HSM and with SoftHSMv2 from
				the OpenDNSSEC project. [RT #29031]

	3704.	[protocol]	Accept integer timestamps in RRSIG records. [RT #35185]

	3703.	[func]		To improve recursive resolver performance, cache
				records which are still being requested by clients
				can now be automatically refreshed from the
				authoritative server before they expire, reducing
				or eliminating the time window in which no answer
				is available in the cache. See the "prefetch" option
				for more details. [RT #35041]

	3702.	[func]		'dnssec-coverage -l' option specifies a length
				of time to check for coverage; events further into
				the future are ignored.  'dnssec-coverage -z'
				checks only ZSK events, and 'dnssec-coverage -k'
				checks only KSK events.  (Thanks to Peter Palfrader.)
				[RT #35168]

	3701.	[func]		named-checkconf can now obscure shared secrets
				when printing by specifying '-x'. [RT #34465]

	3700.	[func]		Allow access to subgroups of XML statistics via
				special URLs http://<server>:<port>/xml/v3/server,
				/zones, /net, /tasks, /mem, and /status.  [RT #35115]

	3699.	[bug]		Improvements to statistics channel XSL stylesheet:
				the stylesheet can now be cached by the browser;
				section headers are omitted from the stats display
				when there is no data in those sections to be
				displayed; counters are now right-justified for
				easier readability. [RT #35117]

	3698.	[cleanup]	Replaced all uses of memcpy() with memmove().
				[RT #35120]

	3697.	[bug]		Handle "." as a search list element when IDN support
				is enabled. [RT #35133]

	3696.	[bug]		dig failed to handle AXFR style IXFR responses which
				span multiple messages. [RT #35137]

	3695.	[bug]		Address a possible race in dispatch.c. [RT #35107]

	3694.	[bug]		Warn when a key-directory is configured for a zone,
				but does not exist or is not a directory. [RT #35108]

	3693.	[security]	memcpy was incorrectly called with overlapping
				ranges resulting in malformed names being generated
				on some platforms.  This could cause INSIST failures
				when serving NSEC3 signed zones (CVE-2014-0591).
				[RT #35120]

	3692.	[bug]		Two calls to dns_db_getoriginnode were fatal if there
				was no data at the node. [RT #35080]

	3691.	[contrib]	Address null pointer dereference in LDAP and
				MySQL DLZ modules.

	3690.	[bug]		Iterative responses could be missed when the source
				port for an upstream query was the same as the
				listener port (53). [RT #34925]

	3689.	[bug]		Fixed a bug causing an insecure delegation from one
				static-stub zone to another to fail with a broken
				trust chain. [RT #35081]

	3688.	[bug]		loadnode could return a freed node on out of memory.
				[RT #35106]

	3687.	[bug]		Address null pointer dereference in zone_xfrdone.
				[RT #35042]

	3686.	[func]		"dnssec-signzone -Q" drops signatures from keys
				that are still published but no longer active.
				[RT #34990]

	3685.	[bug]		"rndc refresh" didn't work correctly with slave
				zones using inline-signing. [RT #35105]

	3684.	[bug]		The list of included files would grow on reload.
				[RT 35090]

	3683.	[cleanup]	Add a more detailed "not found" message to rndc
				commands which specify a zone name. [RT #35059]

	3682.	[bug]		Correct the behavior of rndc retransfer to allow
				inline-signing slave zones to retain NSEC3 parameters
				instead of reverting to NSEC. [RT #34745]

	3681.	[port]		Update the Windows build system to support feature
				selection and WIN64 builds.  This is a work in
				progress. [RT #34160]

	3680.	[bug]		Ensure buffer space is available in "rndc zonestatus".
				[RT #35084]

	3679.	[bug]		dig could fail to clean up TCP sockets still
				waiting on connect(). [RT #35074]

	3678.	[port]		Update config.guess and config.sub. [RT #35060]

	3677.	[bug]		'nsupdate' leaked memory if 'realm' was used multiple
				times.  [RT #35073]

	3676.	[bug]		"named-checkconf -z" now checks zones of type
				hint and redirect as well as master. [RT #35046]

	3675.	[misc]		Provide a place for third parties to add version
				information for their extensions in the version
				file by setting the EXTENSIONS variable.

.. code-block:: none

		--- 9.10.0a1 released ---

	3674.	[bug]		RPZ zeroed ttls if the query type was '*'. [RT #35026]

	3673.	[func]		New "in-view" zone option allows direct sharing
				of zones between views. [RT #32968]

	3672.	[func]		Local address can now be specified when using
				dns_client API. [RT #34811]

	3671.	[bug]		Don't allow dnssec-importkey overwrite a existing
				non-imported private key.

	3670.	[bug]		Address read after free in server side of
				lwres_getrrsetbyname. [RT #29075]

	3669.	[port]		freebsd: --with-gssapi needs -lhx509. [RT #35001]

	3668.	[bug]		Fix cast in lex.c which could see 0xff treated as eof.
				[RT #34993]

	3667.	[test]		dig: add support to keep the TCP socket open between
				successive queries (+[no]keepopen).  [RT #34918]

	3666.	[func]		Add a tool, named-rrchecker, for checking the syntax
				of individual resource records.  This tool is intended
				to be called by provisioning systems so that the front
				end does not need to be upgraded to support new DNS
				record types. [RT #34778]

	3665.	[bug]		Failure to release lock on error in receive_secure_db.
				[RT #34944]

	3664.	[bug]		Updated OpenSSL PKCS#11 patches to fix active list
				locking and other bugs. [RT #34855]

	3663.	[bug]		Address bugs in dns_rdata_fromstruct and
				dns_rdata_tostruct for WKS and ISDN types. [RT #34910]

	3662.	[bug]		'host' could die if a UDP query timed out. [RT #34870]

	3661.	[bug]		Address lock order reversal deadlock with inline zones.
				[RT #34856]

	3660.	[cleanup]	Changed the name of "isc-config.sh" to "bind9-config".
				[RT #23825]

	3659.	[port]		solaris: don't add explicit dependencies/rules for
				python programs as make won't use the implicit rules.
				[RT #34835]

	3658.	[port]		linux: Address platform specific compilation issue
				when libcap-devel is installed. [RT #34838]

	3657.	[port]		Some readline clones don't accept NULL pointers when
				calling add_history. [RT #34842]

	3656.	[security]	Treat an all zero netmask as invalid when generating
				the localnets acl. (The prior behavior could
				allow unexpected matches when using some versions
				of Winsock: CVE-2013-6320.) [RT #34687]

	3655.	[cleanup]	Simplify TCP message processing when requesting a
				zone transfer.  [RT #34825]

	3654.	[bug]		Address race condition with manual notify requests.
				[RT #34806]

	3653.	[func]		Create delegations for all "children" of empty zones
				except "forward first". [RT #34826]

	3652.	[bug]		Address bug with rpz-drop policy. [RT #34816]

	3651.	[tuning]	Adjust when a master server is deemed unreachable.
				[RT #27075]

	3650.	[tuning]	Use separate rate limiting queues for refresh and
				notify requests. [RT #30589]

	3649.	[cleanup]	Include a comment in .nzf files, giving the name of
				the associated view. [RT #34765]

	3648.	[test]		Updated the ATF test framework to version 0.17.
				[RT #25627]

	3647.	[bug]		Address a race condition when shutting down a zone.
				[RT #34750]

	3646.	[bug]		Journal filename string could be set incorrectly,
				causing garbage in log messages. [RT #34738]

	3645.	[protocol]	Use case sensitive compression when responding to
				queries. [RT #34737]

	3644.	[protocol]	Check that EDNS subnet client options are well formed.
				[RT #34718]

	3643.	[doc]		Clarify RRL "slip" documentation.

	3642.	[func]		Allow externally generated DNSKEY to be imported
				into the DNSKEY management framework.  A new tool
				dnssec-importkey is used to do this. [RT #34698]

	3641.	[bug]		Handle changes to sig-validity-interval settings
				better. [RT #34625]

	3640.	[bug]		ndots was not being checked when searching.  Only
				continue searching on NXDOMAIN responses.  Add the
				ability to specify ndots to nslookup. [RT #34711]

	3639.	[bug]		Treat type 65533 (KEYDATA) as opaque except when used
				in a key zone. [RT #34238]

	3638.	[cleanup]	Add the ability to handle ENOPROTOOPT in case it is
				encountered. [RT #34668]

	3637.	[bug]		'allow-query-on' was checking the source address
				rather than the destination address. [RT #34590]

	3636.	[bug]		Automatic empty zones now behave better with
				forward only "zones" beneath them. [RT #34583]

	3635.	[bug]		Signatures were not being removed from a zone with
				only KSK keys for a algorithm. [RT #34439]

	3634.	[func]		Report build-id in rndc status. Report build-id
				when building from a git repository. [RT #20422]

	3633.	[cleanup]	Refactor OPT processing in named to make it easier
				to support new EDNS options. [RT #34414]

	3632.	[bug]		Signature from newly inactive keys were not being
				removed. [RT #32178]

	3631.	[bug]		Remove spurious warning about missing signatures when
				qtype is SIG. [RT #34600]

	3630.	[bug]		Ensure correct ID computation for MD5 keys. [RT #33033]

	3629.	[func]		Allow the printing of cryptographic fields in DNSSEC
				records by dig to be suppressed (dig +nocrypto).
				[RT #34534]

	3628.	[func]		Report DNSKEY key id's when dumping the cache.
				[RT #34533]

	3627.	[bug]		RPZ changes were not effective on slaves. [RT #34450]

	3626.	[func]		dig: NSID output now easier to read. [RT #21160]

	3625.	[bug]		Don't send notify messages to machines outside of the
				test setup.

	3624.	[bug]		Look for 'json_object_new_int64' when looking for a
				the json library. [RT #34449]

	3623.	[placeholder]

	3622.	[tuning]	Eliminate an unnecessary lock when incrementing
				cache statistics. [RT #34339]

	3621.	[security]	Incorrect bounds checking on private type 'keydata'
				can lead to a remotely triggerable REQUIRE failure
				(CVE-2013-4854). [RT #34238]

	3620.	[func]		Added "rpz-client-ip" policy triggers, enabling
				RPZ responses to be configured on the basis of
				the client IP address; this can be used, for
				example, to blacklist misbehaving recursive
				or stub resolvers. [RT #33605]

	3619.	[bug]		Fixed a bug in RPZ with "recursive-only no;"
				[RT #33776]

	3618.	[func]		"rndc reload" now checks modification times of
				include files as well as master files to determine
				whether to skip reloading a zone. [RT #33936]

	3617.	[bug]		Named was failing to answer queries during
				"rndc reload" [RT #34098]

	3616.	[bug]		Change #3613 was incomplete. [RT #34177]

	3615.	[cleanup]	"configure" now finishes by printing a summary
				of optional BIND features and whether they are
				active or inactive. ("configure --enable-full-report"
				increases the verbosity of the summary.) [RT #31777]

	3614.	[port]		Check for <linux/types.h>. [RT #34162]

	3613.	[bug]		named could crash when deleting inline-signing
				zones with "rndc delzone". [RT #34066]

	3612.	[port]		Check whether to use -ljson or -ljson-c. [RT #34115]

	3611.	[bug]		Improved resistance to a theoretical authentication
				attack based on differential timing.  [RT #33939]

	3610.	[cleanup]	win32: Some executables had been omitted from the
				installer. [RT #34116]

	3609.	[bug]		Corrected a possible deadlock in applications using
				the export version of the isc_app API. [RT #33967]

	3608.	[port]		win32: added todos.pl script to ensure all text files
				the win32 build depends on are converted to DOS
				newline format. [RT #22067]

	3607.	[bug]		dnssec-keygen had broken 'Invalid keyfile' error
				message. [RT #34045]

	3606.	[func]		"rndc flushtree" now flushes matching
				records in the address database and bad cache
				as well as the DNS cache. (Previously only the
				DNS cache was flushed.) [RT #33970]

	3605.	[port]		win32: Addressed several compatibility issues
				with newer versions of Visual Studio. [RT #33916]

	3604.	[bug]		Fixed a compile-time error when building with
				JSON but not XML. [RT #33959]

	3603.	[bug]		Install <isc/stat.h>. [RT #33956]

	3602.	[contrib]	Added DLZ Perl module, allowing Perl scripts to
				integrate with named and serve DNS data.
				(Contributed by John Eaglesham of Yahoo.)

	3601.	[bug]		Added to PKCS#11 openssl patches a value len
				attribute in DH derive key. [RT #33928]

	3600.	[cleanup]	dig: Fixed a typo in the warning output when receiving
				an oversized response. [RT #33910]

	3599.	[tuning]	Check for pointer equivalence in name comparisons.
				[RT #18125]

	3598.	[cleanup]	Improved portability of map file code. [RT #33820]

	3597.	[bug]		Ensure automatic-resigning heaps are reconstructed
				when loading zones in map format. [RT #33381]

	3596.	[port]		Updated win32 build documentation, added
				dnssec-verify. [RT #22067]

	3595.	[port]		win32: Fix build problems introduced by change #3550.
				[RT #33807]

	3594.	[maint]		Update config.guess and config.sub. [RT #33816]

	3593.	[func]		Update EDNS processing to better track remote server
				capabilities. [RT #30655]

	3592.	[doc]		Moved documentation of rndc command options to the
				rndc man page. [RT #33506]

	3591.	[func]		Use CRC-64 to detect map file corruption at load
				time. [RT #33746]

	3590.	[bug]		When using RRL on recursive servers, defer
				rate-limiting until after recursion is complete;
				also, use correct rcode for slipped NXDOMAIN
				responses.  [RT #33604]

	3589.	[func]		Report serial numbers in when starting zone transfers.
				Report accepted NOTIFY requests including serial.
				[RT #33037]

	3588.	[bug]		dig: addressed a memory leak in the sigchase code
				that could cause a shutdown crash.  [RT #33733]

	3587.	[func]		'named -g' now checks the logging configuration but
				does not use it. [RT #33473]

	3586.	[bug]		Handle errors in xmlDocDumpFormatMemoryEnc. [RT #33706]

	3585.	[func]		"rndc delzone -clean" option removes zone files
				when deleting a zone. [RT #33570]

	3584.	[security]	Caching data from an incompletely signed zone could
				trigger an assertion failure in resolver.c
				(CVE-2013-3919). [RT #33690]

	3583.	[bug]		Address memory leak in GSS-API processing [RT #33574]

	3582.	[bug]		Silence false positive warning regarding missing file
				directive for inline slave zones.  [RT #33662]

	3581.	[bug]		Changed the tcp-listen-queue default to 10. [RT #33029]

	3580.	[bug]		Addressed a possible race in acache.c [RT #33602]

	3579.	[maint]		Updates to PKCS#11 openssl patches, supporting
				versions 0.9.8y, 1.0.0k, 1.0.1e [RT #33463]

	3578.	[bug]		'rndc -c file' now fails if 'file' does not exist.
				[RT #33571]

	3577.	[bug]		Handle zero TTL values better. [RT #33411]

	3576.	[bug]		Address a shutdown race when validating. [RT #33573]

	3575.	[func]		Changed the logging category for RRL events from
				'queries' to 'query-errors'. [RT #33540]

	3574.	[doc]		The 'hostname' keyword was missing from server-id
				description in the named.conf man page. [RT #33476]

	3573.	[bug]		"rndc addzone" and "rndc delzone" incorrectly handled
				zone names containing punctuation marks and other
				nonstandard characters. [RT #33419]

	3572.	[func]		Threads are now enabled by default on most
				operating systems. [RT #25483]

	3571.	[bug]		Address race condition in dns_client_startresolve().
				[RT #33234]

	3570.	[bug]		Check internal pointers are valid when loading map
				files. [RT #33403]

	3569.	[contrib]	Ported mysql DLZ driver to dynamically-loadable
				module, and added multithread support. [RT #33394]

	3568.	[cleanup]	Add a product description line to the version file,
				to be reported by named -v/-V. [RT #33366]

	3567.	[bug]		Silence clang static analyzer warnings. [RT #33365]

	3566.	[func]		Log when forwarding updates to master. [RT #33240]

	3565.	[placeholder]

	3564.	[bug]		Improved handling of corrupted map files. [RT #33380]

	3563.	[contrib]	zone2sqlite failed with some table names. [RT #33375]

	3562.	[func]		Update map file header format to include a SHA-1 hash
				of the database content, so that corrupted map files
				can be rejected at load time. [RT #32459]

	3561.	[bug]		dig: issue a warning if an EDNS query returns FORMERR
				or NOTIMP.  Adjust usage message. [RT #33363]

	3560.	[bug]		isc-config.sh did not honor includedir and libdir
				when set via configure. [RT #33345]

	3559.	[func]		Check that both forms of Sender Policy Framework
				records exist or do not exist. [RT #33355]

	3558.	[bug]		IXFR of a DLZ stored zone was broken. [RT #33331]

	3557.	[bug]		Reloading redirect zones was broken. [RT #33292]

	3556.	[maint]		Added AAAA for D.ROOT-SERVERS.NET.

	3555.	[bug]		Address theoretical race conditions in acache.c
				(change #3553 was incomplete). [RT #33252]

	3554.	[bug]		RRL failed to correctly rate-limit upward
				referrals and failed to count dropped error
				responses in the statistics. [RT #33225]

	3553.	[bug]		Address suspected double free in acache. [RT #33252]

	3552.	[bug]		Wrong getopt option string for 'nsupdate -r'.
				[RT #33280]

	3551.	[bug]		resolver.querydscp[46] were uninitialized.  [RT #32686]

	3550.	[func]		Unified the internal and export versions of the
				BIND libraries, allowing external clients to use
				the same libraries as BIND. [RT #33131]

	3549.	[doc]		Documentation for "request-nsid" was missing.
				[RT #33153]

	3548.	[bug]		The NSID request code in resolver.c was broken
				resulting in invalid EDNS options being sent.
				[RT #33153]

	3547.	[bug]		Some malformed unknown rdata records were not properly
				detected and rejected. [RT #33129]

	3546.	[func]		Add EUI48 and EUI64 types. [RT #33082]

	3545.	[bug]		RRL slip behavior was incorrect when set to 1.
				[RT #33111]

	3544.	[contrib]	check5011.pl: Script to report the status of
				managed keys as recorded in managed-keys.bind.
				Contributed by Tony Finch <dot@dotat.at>

	3543.	[bug]		Update socket structure before attaching to socket
				manager after accept. [RT #33084]

	3542.	[placeholder]

	3541.	[bug]		Parts of libdns were not properly initialized when
				built in libexport mode. [RT #33028]

	3540.	[test]		libt_api: t_info and t_assert were not thread safe.

	3539.	[port]		win32: timestamp format didn't match other platforms.

	3538.	[test]		Running "make test" now requires loopback interfaces
				to be set up. [RT #32452]

	3537.	[tuning]	Slave zones, when updated, now send NOTIFY messages
				to peers before being dumped to disk rather than
				after. [RT #27242]

	3536.	[func]		Add support for setting Differentiated Services Code
				Point (DSCP) values in named.  Most configuration
				options which take a "port" option (e.g.,
				listen-on, forwarders, also-notify, masters,
				notify-source, etc) can now also take a "dscp"
				option specifying a code point for use with
				outgoing traffic, if supported by the underlying
				OS. [RT #27596]

	3535.	[bug]		Minor win32 cleanups. [RT #32962]

	3534.	[bug]		Extra text after an embedded NULL was ignored when
				parsing zone files. [RT #32699]

	3533.	[contrib]	query-loc-0.4.0: memory leaks. [RT #32960]

	3532.	[contrib]	zkt: fixed buffer overrun, resource leaks. [RT #32960]

	3531.	[bug]		win32: A uninitialized value could be returned on out
				of memory. [RT #32960]

	3530.	[contrib]	Better RTT tracking in queryperf. [RT #30128]

	3529.	[func]		Named now listens on both IPv4 and IPv6 interfaces
				by default.  Named previously only listened on IPv4
				interfaces by default unless named was running in
				IPv6 only mode.  [RT #32945]

	3528.	[func]		New "dnssec-coverage" command scans the timing
				metadata for a set of DNSSEC keys and reports if a
				lapse in signing coverage has been scheduled
				inadvertently. (Note: This tool depends on python;
				it will not be built or installed on systems that
				do not have a python interpreter.) [RT #28098]

	3527.	[compat]	Add a URI to allow applications to explicitly
				request a particular XML schema from the statistics
				channel, returning 404 if not supported. [RT #32481]

	3526.	[cleanup]	Set up dependencies for unit tests correctly during
				build. [RT #32803]

	3525.	[func]		Support for additional signing algorithms in rndc:
				hmac-sha1, -sha224, -sha256, -sha384, and -sha512.
				The -A option to rndc-confgen can be used to
				select the algorithm for the generated key.
				(The default is still hmac-md5; this may
				change in a future release.) [RT #20363]

	3524.	[func]		Added an alternate statistics channel in JSON format,
				when the server is built with the json-c library:
				http://[address]:[port]/json. [RT #32630]

	3523.	[contrib]	Ported filesystem and ldap DLZ drivers to
				dynamically-loadable modules, and added the
				"wildcard" module based on a contribution from
				Vadim Goncharov <vgoncharov@nic.ru>. [RT #23569]

	3522.	[bug]		DLZ lookups could fail to return SERVFAIL when
				they ought to. [RT #32685]

	3521.	[bug]		Address memory leak in opensslecdsa_link.c. [RT #32249]

	3520.	[bug]		'mctx' was not being referenced counted in some places
				where it should have been.  [RT #32794]

	3519.	[func]		Full replay protection via four-way handshake is
				now mandatory for rndc clients. Very old versions
				of rndc will no longer work. [RT #32798]

	3518.	[bug]		Increase the size of dns_rrl_key.s.rtype by one bit
				so that all dns_rrl_rtype_t enum values fit regardless
				of whether it is treated as signed or unsigned by
				the compiler. [RT #32792]

	3517.	[bug]		Reorder destruction to avoid shutdown race. [RT #32777]

	3516.	[placeholder]

	3515.	[port]		'%T' is not portable in strftime(). [RT #32763]

	3514.	[bug]		The ranges for valid key sizes in ddns-confgen and
				rndc-confgen were too constrained. Keys up to 512
				bits are now allowed for most algorithms, and up
				to 1024 bits for hmac-sha384 and hmac-sha512.
				[RT #32753]

	3513.	[func]		"dig -u" prints times in microseconds rather than
				milliseconds. [RT #32704]

	3512.	[func]		"rndc validation check" reports the current status
				of DNSSEC validation. [RT #21397]

	3511.	[doc]		Improve documentation of redirect zones. [RT #32756]

	3510.	[func]		"rndc status" and XML statistics channel now report
				server start and reconfiguration times. [RT #21048]

	3509.	[cleanup]	Added a product line to version file to allow for
				easy naming of different products (BIND
				vs BIND ESV, for example). [RT #32755]

	3508.	[contrib]	queryperf was incorrectly rejecting the -T option.
				[RT #32338]

	3507.	[bug]		Statistics channel XSL had a glitch when attempting
				to chart query data before any queries had been
				received. [RT #32620]

	3506.	[func]		When setting "max-cache-size" and "max-acache-size",
				the keyword "unlimited" is no longer defined as equal
				to 4 gigabytes (except on 32-bit platforms); it
				means literally unlimited. [RT #32358]

	3505.	[bug]		When setting "max-cache-size" and "max-acache-size",
				larger values than 4 gigabytes could not be set
				explicitly, though larger sizes were available
				when setting cache size to 0. This has been
				corrected; the full range is now available.
				[RT #32358]

	3504.	[func]		Add support for ACLs based on geographic location,
				using MaxMind GeoIP databases. Based on code
				contributed by Ken Brownfield <kb@slide.com>.
				[RT #30681]

	3503.	[doc]		Clarify size_spec syntax. [RT #32449]

	3502.	[func]		zone-statistics: "no" is now a synonym for "none",
				instead of "terse". [RT #29165]

	3501.	[func]		zone-statistics now takes three options: full,
				terse, and none. "yes" and "no" are retained as
				synonyms for full and terse, respectively. [RT #29165]

	3500.	[security]	Support NAPTR regular expression validation on
				all platforms without using libregex, which
				can be vulnerable to memory exhaustion attack
				(CVE-2013-2266). [RT #32688]

.. code-block:: none

	3499.	[doc]		Corrected ARM documentation of built-in zones.
				[RT #32694]

	3498.	[bug]		zone statistics for zones which matched a potential
				empty zone could have their zone-statistics setting
				overridden.

	3497.	[func]		When deleting a slave/stub zone using 'rndc delzone'
				report the files that were being used so they can
				be cleaned up if desired. [RT #27899]

	3496.	[placeholder]

	3495.	[func]		Support multiple response-policy zones (up to 32),
				while improving RPZ performance.  "response-policy"
				syntax now includes a "min-ns-dots" clause, with
				default 1, to exclude top-level domains from
				NSIP and NSDNAME checking. --enable-rpz-nsip and
				--enable-rpz-nsdname are now the default. [RT #32251]

	3494.	[func]		DNS RRL: Blunt the impact of DNS reflection and
				amplification attacks by rate-limiting substantially-
				identical responses. [RT #28130]

	3493.	[contrib]	Added BDBHPT dynamically-loadable DLZ module,
				contributed by Mark Goldfinch. [RT #32549]

	3492.	[bug]		Fixed a regression in zone loading performance
				due to lock contention. [RT #30399]

	3491.	[bug]		Slave zones using inline-signing must specify a
				file name. [RT #31946]

	3490.	[bug]		When logging RDATA during update, truncate if it's
				too long. [RT #32365]

	3489.	[bug]		--enable-developer now turns on ISC_LIST_CHECKINIT.
				dns_dlzcreate() failed to properly initialize
				dlzdb.link.  When cloning a rdataset do not copy
				the link contents.  [RT #32651]

	3488.	[bug]		Use after free error with DH generated keys. [RT #32649]

	3487.	[bug]		Change 3444 was not complete.  There was a additional
				place where the NOQNAME proof needed to be saved.
				[RT #32629]

	3486.	[bug]		named could crash when using TKEY-negotiated keys
				that had been deleted and then recreated. [RT #32506]

	3485.	[cleanup]	Only compile openssl_gostlink.c if we support GOST.

	3484.	[bug]		Some statistics were incorrectly rendered in XML.
				[RT #32587]

	3483.	[placeholder]

	3482.	[func]		dig +nssearch now prints name servers that don't
				have address records (missing AAAA or A, or the name
				doesn't exist). [RT #29348]

	3481.	[cleanup]	Removed use of const const in atf.

	3480.	[bug]		Silence logging noise when setting up zone
				statistics. [RT #32525]

	3479.	[bug]		Address potential memory leaks in gssapi support
				code. [RT #32405]

	3478.	[port]		Fix a build failure in strict C99 environments
				[RT #32475]

	3477.	[func]		Expand logging when adding records via DDNS update
				[RT #32365]

	3476.	[bug]		"rndc zonestatus" could report a spurious "not
				found" error on inline-signing zones. [RT #29226]

	3475.	[cleanup]	Changed name of 'map' zone file format (previously
				'fast'). [RT #32458]

	3474.	[bug]		nsupdate could assert when the local and remote
				address families didn't match. [RT #22897]

	3473.	[bug]		dnssec-signzone/verify could incorrectly report
				an error condition due to an empty node above an
				opt-out delegation lacking an NSEC3. [RT #32072]

	3472.	[bug]		The active-connections counter in the socket
				statistics could underflow. [RT #31747]

	3471.	[bug]		The number of UDP dispatches now defaults to
				the number of CPUs even if -n has been set to
				a higher value. [RT #30964]

	3470.	[bug]		Slave zones could fail to dump when successfully
				refreshing after an initial failure. [RT #31276]

	3469.	[bug]		Handle DLZ lookup failures more gracefully. Improve
				backward compatibility between versions of DLZ dlopen
				API. [RT #32275]

	3468.	[security]	RPZ rules to generate A records (but not AAAA records)
				could trigger an assertion failure when used in
				conjunction with DNS64 (CVE-2012-5689). [RT #32141]

	3467.	[bug]		Added checks in dnssec-keygen and dnssec-settime
				to check for delete date < inactive date. [RT #31719]

	3466.	[contrib]	Corrected the DNS_CLIENTINFOMETHODS_VERSION check
				in DLZ example driver. [RT #32275]

	3465.	[bug]		Handle isolated reserved ports. [RT #31778]

	3464.	[maint]		Updates to PKCS#11 openssl patches, supporting
				versions 0.9.8x, 1.0.0j, 1.0.1c [RT #29749]

	3463.	[doc]		Clarify managed-keys syntax in ARM. [RT #32232]

	3462.	[doc]		Clarify server selection behavior of dig when using
				-4 or -6 options. [RT #32181]

	3461.	[bug]		Negative responses could incorrectly have AD=1
				set. [RT #32237]

	3460.	[bug]		Only link against readline where needed. [RT #29810]

	3459.	[func]		Added -J option to named-checkzone/named-compilezone
				to specify the path to the journal file. [RT #30958]

	3458.	[bug]		Return FORMERR when presented with a overly long
				domain named in a request. [RT #29682]

	3457.	[protocol]	Add ILNP records (NID, LP, L32, L64). [RT #31836]

	3456.	[port]		g++47: ATF failed to compile. [RT #32012]

	3455.	[contrib]	queryperf: fix getopt option list. [RT #32338]

	3454.	[port]		sparc64: improve atomic support. [RT #25182]

	3453.	[bug]		'rndc addzone' of a zone with 'inline-signing yes;'
				failed. [RT #31960]

	3452.	[bug]		Accept duplicate singleton records. [RT #32329]

	3451.	[port]		Increase per thread stack size from 64K to 1M.
				[RT #32230]

	3450.	[bug]		Stop logfileconfig system test spam system logs.
				[RT #32315]

	3449.	[bug]		gen.c: use the pre-processor to construct format
				strings so that compiler can perform sanity checks;
				check the snprintf results. [RT #17576]

	3448.	[bug]		The allow-query-on ACL was not processed correctly.
				[RT #29486]

	3447.	[port]		Add support for libxml2-2.9.x [RT #32231]

	3446.	[port]		win32: Add source ID (see change #3400) to build.
				[RT #31683]

	3445.	[bug]		Warn about zone files with blank owner names
				immediately after $ORIGIN directives. [RT #31848]

	3444.	[bug]		The NOQNAME proof was not being returned from cached
				insecure responses. [RT #21409]

	3443.	[bug]		ddns-confgen: Some TSIG algorithms were incorrectly
				rejected when generating keys. [RT #31927]

	3442.	[port]		Net::DNS 0.69 introduced a non backwards compatible
				change. [RT #32216]

	3441.	[maint]		D.ROOT-SERVERS.NET is now 199.7.91.13.

	3440.	[bug]		Reorder get_key_struct to not trigger a assertion when
				cleaning up due to out of memory error. [RT #32131]

	3439.	[placeholder]

	3438.	[bug]		Don't accept unknown data escape in quotes. [RT #32031]

	3437.	[bug]		isc_buffer_init -> isc_buffer_constinit to initialize
				buffers with constant data. [RT #32064]

	3436.	[bug]		Check malloc/calloc return values. [RT #32088]

	3435.	[bug]		Cross compilation support in configure was broken.
				[RT #32078]

	3434.	[bug]		Pass client info to the DLZ findzone() entry
				point in addition to lookup().  This makes it
				possible for a database to answer differently
				whether it's authoritative for a name depending
				on the address of the client.  [RT #31775]

	3433.	[bug]		dlz_findzone() did not correctly handle
				ISC_R_NOMORE. [RT #31172]

	3432.	[func]		Multiple DLZ databases can now be configured.
				DLZ databases are searched in the order configured,
				unless set to "search no", in which case a
				zone can be configured to be retrieved from a
				particular DLZ database by using a "dlz <name>"
				option in the zone statement.  DLZ databases can
				support type "master" and "redirect" zones.
				[RT #27597]

	3431.	[bug]		ddns-confgen: Some valid key algorithms were
				not accepted. [RT #31927]

	3430.	[bug]		win32: isc_time_formatISO8601 was missing the
				'T' between the date and time. [RT #32044]

	3429.	[bug]		dns_zone_getserial2 could a return success without
				returning a valid serial. [RT #32007]

	3428.	[cleanup]	dig: Add timezone to date output. [RT #2269]

	3427.	[bug]		dig +trace incorrectly displayed name server
				addresses instead of names. [RT #31641]

	3426.	[bug]		dnssec-checkds: Clearer output when records are not
				found. [RT #31968]

	3425.	[bug]		"acacheentry" reference counting was broken resulting
				in use after free. [RT #31908]

	3424.	[func]		dnssec-dsfromkey now emits the hash without spaces.
				[RT #31951]

	3423.	[bug]		"rndc signing -nsec3param" didn't accept the full
				range of possible values.  Address portability issues.
				[RT #31938]

	3422.	[bug]		Added a clear error message for when the SOA does not
				match the referral. [RT #31281]

	3421.	[bug]		Named loops when re-signing if all keys are offline.
				[RT #31916]

	3420.	[bug]		Address VPATH compilation issues. [RT #31879]

	3419.	[bug]		Memory leak on validation cancel. [RT #31869]

	3418.	[func]		New XML schema (version 3.0) for the statistics channel
				adds query type statistics at the zone level, and
				flattens the XML tree and uses compressed format to
				optimize parsing. Includes new XSL that permits
				charting via the Google Charts API on browsers that
				support javascript in XSL.  The old XML schema has been
				deprecated. [RT #30023]

	3417.	[placeholder]

	3416.	[bug]		Named could die on shutdown if running with 128 UDP
				dispatches per interface. [RT #31743]

	3415.	[bug]		named could die with a REQUIRE failure if a validation
				was canceled. [RT #31804]

	3414.	[bug]		Address locking issues found by Coverity. [RT #31626]

	3413.	[func]		Record the number of DNS64 AAAA RRsets that have been
				synthesized. [RT #27636]

	3412.	[bug]		Copy timeval structure from control message data.
				[RT #31548]

	3411.	[tuning]	Use IPV6_USE_MIN_MTU or equivalent with TCP in addition
				to UDP. [RT #31690]

	3410.	[bug]		Addressed Coverity warnings. [RT #31626]

	3409.	[contrib]	contrib/dane/mkdane.sh: Tool to generate TLSA RR's
				from X.509 certificates, for use with DANE
				(DNS-based Authentication of Named Entities).
				[RT #30513]

	3408.	[bug]		Some DNSSEC-related options (update-check-ksk,
				dnssec-loadkeys-interval, dnssec-dnskey-kskonly)
				are now legal in slave zones as long as
				inline-signing is in use. [RT #31078]

	3407.	[placeholder]

	3406.	[bug]		mem.c: Fix compilation errors when building with
				ISC_MEM_TRACKLINES or ISC_MEMPOOL_NAMES disabled.
				Also, ISC_MEM_DEBUG is no longer optional. [RT #31559]

	3405.	[bug]		Handle time going backwards in acache. [RT #31253]

	3404.	[bug]		dnssec-signzone: When re-signing a zone, remove
				RRSIG and NSEC records from nodes that used to be
				in-zone but are now below a zone cut. [RT #31556]

	3403.	[bug]		Silence noisy OpenSSL logging. [RT #31497]

	3402.	[test]		The IPv6 interface numbers used for system
				tests were incorrect on some platforms. [RT #25085]

	3401.	[bug]		Addressed Coverity warnings. [RT #31484]

	3400.	[cleanup]	"named -V" can now report a source ID string, defined
				in the "srcid" file in the build tree and normally set
				to the most recent git hash.  [RT #31494]

	3399.	[port]		netbsd: rename 'bool' parameter to avoid namespace
				clash.  [RT #31515]

	3398.	[bug]		SOA parameters were not being updated with inline
				signed zones if the zone was modified while the
				server was offline. [RT #29272]

	3397.	[bug]		dig crashed when using +nssearch with +tcp. [RT #25298]

	3396.	[bug]		OPT records were incorrectly removed from signed,
				truncated responses. [RT #31439]

	3395.	[protocol]	Add RFC 6598 reverse zones to built in empty zones
				list, 64.100.IN-ADDR.ARPA ... 127.100.IN-ADDR.ARPA.
				[RT #31336]

	3394.	[bug]		Adjust 'successfully validated after lower casing
				signer' log level and category. [RT #31414]

	3393.	[bug]		'host -C' could core dump if REFUSED was received.
				[RT #31381]

	3392.	[func]		Keep statistics on REFUSED responses. [RT #31412]

	3391.	[bug]		A DNSKEY lookup that encountered a CNAME failed.
				[RT #31262]

	3390.	[bug]		Silence clang compiler warnings. [RT #30417]

	3389.	[bug]		Always return NOERROR (not 0) in TSIG. [RT #31275]

	3388.	[bug]		Fixed several Coverity warnings.
				Note: This change includes a fix for a bug that
				was subsequently determined to be an exploitable
				security vulnerability, CVE-2012-5688: named could
				die on specific queries with dns64 enabled.
				[RT #30996]

	3387.	[func]		DS digest can be disabled at runtime with
				disable-ds-digests. [RT #21581]

	3386.	[bug]		Address locking violation when generating new NSEC /
				NSEC3 chains. [RT #31224]

	3385.	[bug]		named-checkconf didn't detect missing master lists
				in also-notify clauses. [RT #30810]

	3384.	[bug]		Improved logging of crypto errors. [RT #30963]

	3383.	[security]	A certain combination of records in the RBT could
				cause named to hang while populating the additional
				section of a response. [RT #31090]

	3382.	[bug]		SOA query from slave used use-v6-udp-ports range,
				if set, regardless of the address family in use.
				[RT #24173]

	3381.	[contrib]	Update queryperf to support more RR types.
				[RT #30762]

	3380.	[bug]		named could die if a nonexistent master list was
				referenced in a also-notify. [RT #31004]

	3379.	[bug]		isc_interval_zero and isc_time_epoch should be
				"const (type)* const". [RT #31069]

	3378.	[bug]		Handle missing 'managed-keys-directory' better.
				[RT #30625]

	3377.	[bug]		Removed spurious newline from NSEC3 multiline
				output. [RT #31044]

	3376.	[bug]		Lack of EDNS support was being recorded without a
				successful response. [RT #30811]

	3375.	[bug]		'rndc dumpdb' failed on empty caches. [RT #30808]

	3374.	[bug]		isc_parse_uint32 failed to return a range error on
				systems with 64 bit longs. [RT #30232]

	3373.	[bug]		win32: open raw files in binary mode. [RT #30944]

	3372.	[bug]		Silence spurious "deleted from unreachable cache"
				messages.  [RT #30501]

	3371.	[bug]		AD=1 should behave like DO=1 when deciding whether to
				add NS RRsets to the additional section or not.
				[RT #30479]

	3370.	[bug]		Address use after free while shutting down. [RT #30241]

	3369.	[bug]		nsupdate terminated unexpectedly in interactive mode
				if built with readline support. [RT #29550]

	3368.	[bug]		<dns/iptable.h>, <dns/private.h> and <dns/zone.h>
				were not C++ safe.

	3367.	[bug]		dns_dnsseckey_create() result was not being checked.
				[RT #30685]

	3366.	[bug]		Fixed Read-After-Write dependency violation for IA64
				atomic operations. [RT #25181]

	3365.	[bug]		Removed spurious newlines from log messages in
				zone.c [RT #30675]

	3364.	[security]	Named could die on specially crafted record.
				[RT #30416]

	3363.	[bug]		Need to allow "forward" and "fowarders" options
				in static-stub zones; this had been overlooked.
				[RT #30482]

	3362.	[bug]		Setting some option values to 0 in named.conf
				could trigger an assertion failure on startup.
				[RT #27730]

	3361.	[bug]		"rndc signing -nsec3param" didn't work correctly
				when salt was set to '-' (no salt). [RT #30099]

	3360.	[bug]		'host -w' could die.  [RT #18723]

	3359.	[bug]		An improperly-formed TSIG secret could cause a
				memory leak. [RT #30607]

	3358.	[placeholder]

	3357.	[port]		Add support for libxml2-2.8.x [RT #30440]

	3356.	[bug]		Cap the TTL of signed RRsets when RRSIGs are
				approaching their expiry, so they don't remain
				in caches after expiry. [RT #26429]

	3355.	[port]		Use more portable awk in verify system test.

	3354.	[func]		Improve OpenSSL error logging. [RT #29932]

	3353.	[bug]		Use a single task for task exclusive operations.
				[RT #29872]

	3352.	[bug]		Ensure that learned server attributes timeout of the
				adb cache. [RT #29856]

	3351.	[bug]		isc_mem_put and isc_mem_putanddetach didn't report
				caller if either ISC_MEM_DEBUGSIZE or ISC_MEM_DEBUGCTX
				memory debugging flags are set. [RT #30243]

	3350.	[bug]		Memory read overrun in isc___mem_reallocate if
				ISC_MEM_DEBUGCTX memory debugging flag is set.
				[RT #30240]

	3349.	[bug]		Change #3345 was incomplete. [RT #30233]

	3348.	[bug]		Prevent RRSIG data from being cached if a negative
				record matching the covering type exists at a higher
				trust level. Such data already can't be retrieved from
				the cache since change 3218 -- this prevents it
				being inserted into the cache as well. [RT #26809]

	3347.	[bug]		dnssec-settime: Issue a warning when writing a new
				private key file would cause a change in the
				permissions of the existing file. [RT #27724]

	3346.	[security]	Bad-cache data could be used before it was
				initialized, causing an assert. [RT #30025]

	3345.	[bug]		Addressed race condition when removing the last item
				or inserting the first item in an ISC_QUEUE.
				[RT #29539]

	3344.	[func]		New "dnssec-checkds" command checks a zone to
				determine which DS records should be published
				in the parent zone, or which DLV records should be
				published in a DLV zone, and queries the DNS to
				ensure that it exists. (Note: This tool depends
				on python; it will not be built or installed on
				systems that do not have a python interpreter.)
				[RT #28099]

	3343.	[placeholder]

	3342.	[bug]		Change #3314 broke saving of stub zones to disk
				resulting in excessive cpu usage in some cases.
				[RT #29952]

	3341.	[func]		New "dnssec-verify" command checks a signed zone
				to ensure correctness of signatures and of NSEC/NSEC3
				chains. [RT #23673]

	3340.	[func]		Added new 'map' zone file format, which is an image
				of a zone database that can be loaded directly into
				memory via mmap(), allowing much faster zone loading.
				(Note: Because of pointer sizes and other
				considerations, this file format is platform-dependent;
				'map' zone files cannot always be transferred from one
				server to another.) [RT #25419]

	3339.	[func]		Allow the maximum supported rsa exponent size to be
				specified: "max-rsa-exponent-size <value>;" [RT #29228]

	3338.	[bug]		Address race condition in units tests: asyncload_zone
				and asyncload_zt. [RT #26100]

	3337.	[bug]		Change #3294 broke support for the multiple keys
				in controls. [RT #29694]

	3336.	[func]		Maintain statistics for RRsets tagged as "stale".
				[RT #29514]

	3335.	[func]		nslookup: return a nonzero exit code when unable
				to get an answer. [RT #29492]

	3334.	[bug]		Hold a zone table reference while performing a
				asynchronous load of a zone. [RT #28326]

	3333.	[bug]		Setting resolver-query-timeout too low can cause
				named to not recover if it loses connectivity.
				[RT #29623]

	3332.	[bug]		Re-use cached DS rrsets if possible. [RT #29446]

	3331.	[security]	dns_rdataslab_fromrdataset could produce bad
				rdataslabs. [RT #29644]

	3330.	[func]		Fix missing signatures on NOERROR results despite
				RPZ rewriting.  Also
				 - add optional "recursive-only yes|no" to the
				   response-policy statement
				 - add optional "max-policy-ttl" to the response-policy
				    statement to limit the false data that
				    "recursive-only no" can introduce into
				    resolvers' caches
				 - add a RPZ performance test to bin/tests/system/rpz
				     when queryperf is available.
				 - the encoding of PASSTHRU action to "rpz-passthru".
				     (The old encoding is still accepted.)
				[RT #26172]


	3329.	[bug]		Handle RRSIG signer-name case consistently: We
				generate RRSIG records with the signer-name in
				lower case.  We accept them with any case, but if
				they fail to validate, we try again in lower case.
				[RT #27451]

	3328.	[bug]		Fixed inconsistent data checking in dst_parse.c.
				[RT #29401]

	3327.	[func]		Added 'filter-aaaa-on-v6' option; this is similar
				to 'filter-aaaa-on-v4' but applies to IPv6
				connections.  (Use "configure --enable-filter-aaaa"
				to enable this option.)  [RT #27308]

	3326.	[func]		Added task list statistics: task model, worker
				threads, quantum, tasks running, tasks ready.
				[RT #27678]

	3325.	[func]		Report cache statistics: memory use, number of
				nodes, number of hash buckets, hit and miss counts.
				[RT #27056]

	3324.	[test]		Add better tests for ADB stats [RT #27057]

	3323.	[func]		Report the number of buckets the resolver is using.
				[RT #27020]

	3322.	[func]		Monitor the number of active TCP and UDP dispatches.
				[RT #27055]

	3321.	[func]		Monitor the number of recursive fetches and the
				number of open sockets, and report these values in
				the statistics channel. [RT #27054]

	3320.	[func]		Added support for monitoring of recursing client
				count. [RT #27009]

	3319.	[func]		Added support for monitoring of ADB entry count and
				hash size. [RT #27057]

	3318.	[tuning]	Reduce the amount of work performed while holding a
				bucket lock when finished with a fetch context.
				[RT #29239]

	3317.	[func]		Add ECDSA support (RFC 6605). [RT #21918]

	3316.	[tuning]	Improved locking performance when recursing.
				[RT #28836]

	3315.	[tuning]	Use multiple dispatch objects for sending upstream
				queries; this can improve performance on busy
				multiprocessor systems by reducing lock contention.
				[RT #28605]

	3314.	[bug]		The masters list could be updated while stub_callback
				or refresh_callback were using it. [RT #26732]

	3313.	[protocol]	Add TLSA record type. [RT #28989]

	3312.	[bug]		named-checkconf didn't detect a bad dns64 clients acl.
				[RT #27631]

	3311.	[bug]		Abort the zone dump if zone->db is NULL in
				zone.c:zone_gotwritehandle. [RT #29028]

	3310.	[test]		Increase table size for mutex profiling. [RT #28809]

	3309.	[bug]		resolver.c:fctx_finddone() was not thread safe.
				[RT #27995]

	3308.	[placeholder]

	3307.	[bug]		Add missing ISC_LANG_BEGINDECLS and ISC_LANG_ENDDECLS.
				[RT #28956]

	3306.	[bug]		Improve DNS64 reverse zone performance. [RT #28563]

	3305.	[func]		Add wire format lookup method to sdb. [RT #28563]

	3304.	[bug]		Use hmctx, not mctx when freeing rbtdb->heaps.
				[RT #28571]

	3303.	[bug]		named could die when reloading. [RT #28606]

	3302.	[bug]		dns_dnssec_findmatchingkeys could fail to find
				keys if the zone name contained character that
				required special mappings. [RT #28600]

	3301.	[contrib]	Update queryperf to build on darwin.  Add -R flag
				for non-recursive queries. [RT #28565]

	3300.	[bug]		Named could die if gssapi was enabled in named.conf
				but was not compiled in. [RT #28338]

	3299.	[bug]		Make SDB handle errors from database drivers better.
				[RT #28534]

	3298.	[bug]		Named could dereference a NULL pointer in
				zmgr_start_xfrin_ifquota if the zone was being removed.
				[RT #28419]

	3297.	[bug]		Named could die on a malformed master file. [RT #28467]

	3296.	[bug]		Named could die with a INSIST failure in
				client.c:exit_check. [RT #28346]

	3295.	[bug]		Adjust isc_time_secondsastimet range check to be more
				portable. [RT # 26542]

	3294.	[bug]		isccc/cc.c:table_fromwire failed to free alist on
				error. [RT #28265]

	3293.	[func]		nsupdate: list supported type. [RT #28261]

	3292.	[func]		Log messages in the axfr stream at debug 10.
				[RT #28040]

	3291.	[port]		Fixed a build error on systems without ENOTSUP.
				[RT #28200]

	3290.	[bug]		<isc/hmacsha.h> was not being installed. [RT #28169]

	3289.	[bug]		'rndc retransfer' failed for inline zones. [RT #28036]

	3288.	[bug]		dlz_destroy() function wasn't correctly registered
				by the DLZ dlopen driver. [RT #28056]

	3287.	[port]		Update ans.pl to work with Net::DNS 0.68. [RT #28028]

	3286.	[bug]		Managed key maintenance timer could fail to start
				after 'rndc reconfig'. [RT #26786]

	3285.	[bug]		val-frdataset was incorrectly disassociated in
				proveunsecure after calling startfinddlvsep.
				[RT #27928]

	3284.	[bug]		Address race conditions with the handling of
				rbtnode.deadlink. [RT #27738]

	3283.	[bug]		Raw zones with with more than 512 records in a RRset
				failed to load. [RT #27863]

	3282.	[bug]		Restrict the TTL of NS RRset to no more than that
				of the old NS RRset when replacing it.
				[RT #27792] [RT #27884]

	3281.	[bug]		SOA refresh queries could be treated as cancelled
				despite succeeding over the loopback interface.
				[RT #27782]

	3280.	[bug]		Potential double free of a rdataset on out of memory
				with DNS64. [RT #27762]

	3279.	[bug]		Hold a internal reference to the zone while performing
				a asynchronous load.  Address potential memory leak
				if the asynchronous is cancelled. [RT #27750]

	3278.	[bug]		Make sure automatic key maintenance is started
				when "auto-dnssec maintain" is turned on during
				"rndc reconfig". [RT #26805]

	3277.	[bug]		win32: isc_socket_dup is not implemented. [RT #27696]

	3276.	[bug]		win32: ns_os_openfile failed to return NULL on
				safe_open failure. [RT #27696]

	3275.	[bug]		Corrected rndc -h output; the 'rndc sync -clean'
				option had been misspelled as '-clear'.  (To avoid
				future confusion, both options now work.) [RT #27173]

	3274.	[placeholder]

	3273.	[bug]		AAAA responses could be returned in the additional
				section even when filter-aaaa-on-v4 was in use.
				[RT #27292]

	3272.	[func]		New "rndc zonestatus" command prints information
				about the specified zone. [RT #21671]

	3271.	[port]		darwin: mksymtbl is not always stable, loop several
				times before giving up.  mksymtbl was using non
				portable perl to covert 64 bit hex strings. [RT #27653]

.. code-block:: none

		--- 9.9.0rc2 released ---

	3270.	[bug]		"rndc reload" didn't reuse existing zones correctly
				when inline-signing was in use. [RT #27650]

	3269.	[port]		darwin 11 and later now built threaded by default.

	3268.	[bug]		Convert RRSIG expiry times to 64 timestamps to work
				out the earliest expiry time. [RT #23311]

	3267.	[bug]		Memory allocation failures could be mis-reported as
				unexpected error.  New ISC_R_UNSET result code.
				[RT #27336]

	3266.	[bug]		The maximum number of NSEC3 iterations for a
				DNSKEY RRset was not being properly computed.
				[RT #26543]

	3265.	[bug]		Corrected a problem with lock ordering in the
				inline-signing code. [RT #27557]

	3264.	[bug]		Automatic regeneration of signatures in an
				inline-signing zone could stall when the server
				was restarted. [RT #27344]

	3263.	[bug]		"rndc sync" did not affect the unsigned side of an
				inline-signing zone. [RT #27337]

	3262.	[bug]		Signed responses were handled incorrectly by RPZ.
				[RT #27316]

	3261.	[func]		RRset ordering now defaults to random. [RT #27174]

	3260.	[bug]		"rrset-order cyclic" could appear not to rotate
				for some query patterns.  [RT #27170/27185]

.. code-block:: none

		--- 9.9.0rc1 released ---

	3259.	[bug]		named-compilezone: Suppress "dump zone to <file>"
				message when writing to stdout. [RT #27109]

	3258.	[test]		Add "forcing full sign with unreadable keys" test.
				[RT #27153]

	3257.	[bug]		Do not generate a error message when calling fsync()
				in a pipe or socket. [RT #27109]

	3256.	[bug]		Disable empty zones for lwresd -C. [RT #27139]

	3255.	[func]		No longer require that a empty zones be explicitly
				enabled or that a empty zone is disabled for
				RFC 1918 empty zones to be configured. [RT #27139]

	3254.	[bug]		Set isc_socket_ipv6only() on the IPv6 control channels.
				[RT #22249]

	3253.	[bug]		Return DNS_R_SYNTAX when the input to a text field is
				too long. [RT #26956]

	3252.	[bug]		When master zones using inline-signing were
				updated while the server was offline, the source
				zone could fall out of sync with the signed
				copy. They can now resynchronize. [RT #26676]

	3251.	[bug]		Enforce a upper bound (65535 bytes) on the amount of
				memory dns_sdlz_putrr() can allocate per record to
				prevent run away memory consumption on ISC_R_NOSPACE.
				[RT #26956]

	3250.	[func]		'configure --enable-developer'; turn on various
				configure options, normally off by default, that
				we want developers to build and test with. [RT #27103]

	3249.	[bug]		Update log message when saving slave zones files for
				analysis after load failures. [RT #27087]

	3248.	[bug]		Configure options --enable-fixed-rrset and
				--enable-exportlib were incompatible with each
				other. [RT #27087]

	3247.	[bug]		'raw' format zones failed to preserve load order
				breaking 'fixed' sort order. [RT #27087]

	3246.	[bug]		Named failed to start with a empty also-notify list.
				[RT #27087]

	3245.	[bug]		Don't report a error unchanged serials unless there
				were other changes when thawing a zone with
				ixfr-fromdifferences. [RT #26845]

	3244.	[func]		Added readline support to nslookup and nsupdate.
				Also simplified nsupdate syntax to make "update"
				and "prereq" optional. [RT #24659]

	3243.	[port]		freebsd,netbsd,bsdi: the thread defaults were not
				being properly set.

	3242.	[func]		Extended the header of raw-format master files to
				include the serial number of the zone from which
				they were generated, if different (as in the case
				of inline-signing zones).  This is to be used in
				inline-signing zones, to track changes between the
				unsigned and signed versions of the zone, which may
				have different serial numbers.

				(Note: raw zonefiles generated by this version of
				BIND are no longer compatible with prior versions.
				To generate a backward-compatible raw zonefile
				using dnssec-signzone or named-compilezone, specify
				output format "raw=0" instead of simply "raw".)
				[RT #26587]

	3241.	[bug]		Address race conditions in the resolver code.
				[RT #26889]

	3240.	[bug]		DNSKEY state change events could be missed. [RT #26874]

	3239.	[bug]		dns_dnssec_findmatchingkeys needs to use a consistent
				timestamp. [RT #26883]

	3238.	[bug]		keyrdata was not being reinitialized in
				lib/dns/rbtdb.c:iszonesecure. [RT #26913]

	3237.	[bug]		dig -6 didn't work with +trace. [RT #26906]

	3236.	[bug]		Backed out changes #3182 and #3202, related to
				EDNS(0) fallback behavior. [RT #26416]

	3235.	[func]		dns_db_diffx, a extended dns_db_diff which returns
				the generated diff and optionally writes it to a
				journal. [RT #26386]

	3234.	[bug]		'make depend' produced invalid makefiles. [RT #26830]

	3233.	[bug]		'rndc freeze/thaw' didn't work for inline zones.
				[RT #26632]

	3232.	[bug]		Zero zone->curmaster before return in
				dns_zone_setmasterswithkeys(). [RT #26732]

	3231.	[bug]		named could fail to send a incompressible zone.
				[RT #26796]

	3230.	[bug]		'dig axfr' failed to properly handle a multi-message
				axfr with a serial of 0. [RT #26796]

	3229.	[bug]		Fix local variable to struct var assignment
				found by CLANG warning.

	3228.	[tuning]	Dynamically grow symbol table to improve zone
				loading performance. [RT #26523]

	3227.	[bug]		Interim fix to make WKS's use of getprotobyname()
				and getservbyname() self thread safe. [RT #26232]

	3226.	[bug]		Address minor resource leakages. [RT #26624]

	3225.	[bug]		Silence spurious "setsockopt(517, IPV6_V6ONLY) failed"
				messages. [RT #26507]

	3224.	[bug]		'rndc signing' argument parsing was broken. [RT #26684]

	3223.	[bug]		'task_test privilege_drop' generated false positives.
				[RT #26766]

	3222.	[cleanup]	Replace dns_journal_{get,set}_bitws with
				dns_journal_{get,set}_sourceserial. [RT #26634]

	3221.	[bug]		Fixed a potential core dump on shutdown due to
				referencing fetch context after it's been freed.
				[RT #26720]

.. code-block:: none

		--- 9.9.0b2 released ---

	3220.	[bug]		Change #3186 was incomplete; dns_db_rpz_findips()
				could fail to set the database version correctly,
				causing an assertion failure. [RT #26180]

	3219.	[bug]		Disable NOEDNS caching following a timeout.

	3218.	[security]	Cache lookup could return RRSIG data associated with
				nonexistent records, leading to an assertion
				failure. [RT #26590]

	3217.	[cleanup]	Fix build problem with --disable-static. [RT #26476]

	3216.	[bug]		resolver.c:validated() was not thread-safe. [RT #26478]

	3215.	[bug]		'rndc recursing' could cause a core dump. [RT #26495]

	3214.	[func]		Add 'named -U' option to set the number of UDP
				listener threads per interface. [RT #26485]

	3213.	[doc]		Clarify ixfr-from-differences behavior. [RT #25188]

	3212.	[bug]		rbtdb.c: failed to remove a node from the deadnodes
				list prior to adding a reference to it leading a
				possible assertion failure. [RT #23219]

	3211.	[func]		dnssec-signzone: "-f -" prints to stdout; "-O full"
				option prints in single-line-per-record format.
				[RT #20287]

	3210.	[bug]		Canceling the oldest query due to recursive-client
				overload could trigger an assertion failure. [RT #26463]

	3209.	[func]		Add "dnssec-lookaside 'no'".  [RT #24858]

	3208.	[bug]		'dig -y' handle unknown tsig algorithm better.
				[RT #25522]

	3207.	[contrib]	Fixed build error in Berkeley DB DLZ module. [RT #26444]

	3206.	[cleanup]	Add ISC information to log at start time. [RT #25484]

	3205.	[func]		Upgrade dig's defaults to better reflect modern
				nameserver behavior.  Enable "dig +adflag" and
				"dig +edns=0" by default.  Enable "+dnssec" when
				running "dig +trace". [RT #23497]

	3204.	[bug]		When a master server that has been marked as
				unreachable sends a NOTIFY, mark it reachable
				again. [RT #25960]

	3203.	[bug]		Increase log level to 'info' for validation failures
				from expired or not-yet-valid RRSIGs. [RT #21796]

	3202.	[bug]		NOEDNS caching on timeout was too aggressive.
				[RT #26416]

	3201.	[func]		'rndc querylog' can now be given an on/off parameter
				instead of only being used as a toggle. [RT #18351]

	3200.	[doc]		Some rndc functions were undocumented or were
				missing from 'rndc -h' output. [RT #25555]

	3199.	[func]		When logging client information, include the name
				being queried. [RT #25944]

	3198.	[doc]		Clarified that dnssec-settime can alter keyfile
				permissions. [RT #24866]

	3197.	[bug]		Don't try to log the filename and line number when
				the config parser can't open a file. [RT #22263]

	3196.	[bug]		nsupdate: return nonzero exit code when target zone
				doesn't exist. [RT #25783]

	3195.	[cleanup]	Silence "file not found" warnings when loading
				managed-keys zone. [RT #26340]

	3194.	[doc]		Updated RFC references in the 'empty-zones-enable'
				documentation. [RT #25203]

	3193.	[cleanup]	Changed MAXZONEKEYS to DNS_MAXZONEKEYS, moved to
				dnssec.h. [RT #26415]

	3192.	[bug]		A query structure could be used after being freed.
				[RT #22208]

	3191.	[bug]		Print NULL records using "unknown" format. [RT #26392]

	3190.	[bug]		Underflow in error handling in isc_mutexblock_init.
				[RT #26397]

	3189.	[test]		Added a summary report after system tests. [RT #25517]

	3188.	[bug]		zone.c:zone_refreshkeys() could fail to detach
				references correctly when errors occurred, causing
				a hang on shutdown. [RT #26372]

	3187.	[port]		win32: support for Visual Studio 2008.  [RT #26356]

.. code-block:: none

		--- 9.9.0b1 released ---

	3186.	[bug]		Version/db mismatch in rpz code. [RT #26180]

	3185.	[func]		New 'rndc signing' option for auto-dnssec zones:
				 - 'rndc signing -list' displays the current
				   state of signing operations
				 - 'rndc signing -clear' clears the signing state
				   records for keys that have fully signed the zone
				 - 'rndc signing -nsec3param' sets the NSEC3
				   parameters for the zone
				The 'rndc keydone' syntax is removed. [RT #23729]

	3184.	[bug]		named had excessive cpu usage when a redirect zone was
				configured. [RT #26013]

	3183.	[bug]		Added RTLD_GLOBAL flag to dlopen call. [RT #26301]

	3182.	[bug]		Auth servers behind firewalls which block packets
				greater than 512 bytes may cause other servers to
				perform poorly. Now, adb retains edns information
				and caches noedns servers. [RT #23392/24964]

	3181.	[func]		Inline-signing is now supported for master zones.
				[RT #26224]

	3180.	[func]		Local copies of slave zones are now saved in raw
				format by default, to improve startup performance.
				'masterfile-format text;' can be used to override
				the default, if desired. [RT #25867]

	3179.	[port]		kfreebsd: build issues. [RT #26273]

	3178.	[bug]		A race condition introduced by change #3163 could
				cause an assertion failure on shutdown. [RT #26271]

	3177.	[func]		'rndc keydone', remove the indicator record that
				named has finished signing the zone with the
				corresponding key.  [RT #26206]

	3176.	[doc]		Corrected example code and added a README to the
				sample external DLZ module in contrib/dlz/example.
				[RT #26215]

	3175.	[bug]		Fix how DNSSEC positive wildcard responses from a
				NSEC3 signed zone are validated.  Stop sending a
				unnecessary NSEC3 record when generating such
				responses. [RT #26200]

	3174.	[bug]		Always compute to revoked key tag from scratch.
				[RT #26186]

	3173.	[port]		Correctly validate root DS responses. [RT #25726]

	3172.	[port]		darwin 10.* and freebsd [89] are now built threaded by
				default.

	3171.	[bug]		Exclusively lock the task when adding a zone using
				'rndc addzone'.  [RT #25600]

.. code-block:: none

		--- 9.9.0a3 released ---

	3170.	[func]		RPZ update:
				- fix precedence among competing rules
				- improve ARM text including documenting rule precedence
				- try to rewrite CNAME chains until first hit
				- new "rpz" logging channel
				- RDATA for CNAME rules can include wildcards
				- replace "NO-OP" named.conf policy override with
				  "PASSTHRU" and add "DISABLED" override ("NO-OP"
				  is still recognized)
				[RT #25172]

	3169.	[func]		Catch db/version mis-matches when calling dns_db_*().
				[RT #26017]

	3168.	[bug]		Nxdomain redirection could trigger an assert with
				a ANY query. [RT #26017]

	3167.	[bug]		Negative answers from forwarders were not being
				correctly tagged making them appear to not be cached.
				[RT #25380]

	3166.	[bug]		Upgrading a zone to support inline-signing failed.
				[RT #26014]

	3165.	[bug]		dnssec-signzone could generate new signatures when
				resigning, even when valid signatures were already
				present. [RT #26025]

	3164.	[func]		Enable DLZ modules to retrieve client information,
				so that responses can be changed depending on the
				source address of the query. [RT #25768]

	3163.	[bug]		Use finer-grained locking in client.c to address
				concurrency problems with large numbers of threads.
				[RT #26044]

	3162.	[test]		start.pl: modified to allow for "named.args" in
				ns*/ subdirectory to override stock arguments to
				named. Largely from RT #26044, but no separate ticket.

	3161.	[bug]		zone.c:del_sigs failed to always reset rdata leading
				assertion failures. [RT #25880]

	3160.	[bug]		When printing out a NSEC3 record in multiline form
				the newline was not being printed causing type codes
				to be run together. [RT #25873]

	3159.	[bug]		On some platforms, named could assert on startup
				when running in a chrooted environment without
				/proc. [RT #25863]

	3158.	[bug]		Recursive servers would prefer a particular UDP
				socket instead of using all available sockets.
				[RT #26038]

	3157.	[tuning]	Reduce the time spent in "rndc reconfig" by parsing
				the config file before pausing the server. [RT #21373]

	3156.	[placeholder]

.. code-block:: none

		--- 9.9.0a2 released ---

	3155.	[bug]		Fixed a build failure when using contrib DLZ
				drivers (e.g., mysql, postgresql, etc). [RT #25710]

	3154.	[bug]		Attempting to print an empty rdataset could trigger
				an assert. [RT #25452]

	3153.	[func]		Extend request-ixfr to zone level and remove the
				side effect of forcing an AXFR. [RT #25156]

	3152.	[cleanup]	Some versions of gcc and clang failed due to
				incorrect use of __builtin_expect. [RT #25183]

	3151.	[bug]		Queries for type RRSIG or SIG could be handled
				incorrectly.  [RT #21050]

	3150.	[func]		Improved startup and reconfiguration time by
				enabling zones to load in multiple threads. [RT #25333]

	3149.	[placeholder]

	3148.	[bug]		Processing of normal queries could be stalled when
				forwarding a UPDATE message. [RT #24711]

	3147.	[func]		Initial inline signing support.  [RT #23657]

.. code-block:: none

		--- 9.9.0a1 released ---

	3146.	[test]		Fixed gcc4.6.0 errors in ATF. [RT #25598]

	3145.	[test]		Capture output of ATF unit tests in "./atf.out" if
				there were any errors while running them. [RT #25527]

	3144.	[bug]		dns_dbiterator_seek() could trigger an assert when
				used with a nonexistent database node. [RT #25358]

	3143.	[bug]		Silence clang compiler warnings. [RT #25174]

	3142.	[bug]		NAPTR is class agnostic. [RT #25429]

	3141.	[bug]		Silence spurious "zone serial (0) unchanged" messages
				associated with empty zones. [RT #25079]

	3140.	[func]		New command "rndc flushtree <name>" clears the
				specified name from the server cache along with
				all names under it. [RT #19970]

	3139.	[test]		Added tests from RFC 6234, RFC 2202, and RFC 1321
				for the hashing algorithms (md5, sha1 - sha512, and
				their hmac counterparts).  [RT #25067]

	3138.	[bug]		Address memory leaks and out-of-order operations when
				shutting named down. [RT #25210]

	3137.	[func]		Improve hardware scalability by allowing multiple
				worker threads to process incoming UDP packets.
				This can significantly increase query throughput
				on some systems.  [RT #22992]

	3136.	[func]		Add RFC 1918 reverse zones to the list of built-in
				empty zones switched on by the 'empty-zones-enable'
				option. [RT #24990]

	3135.	[port]		FreeBSD: workaround broken IPV6_USE_MIN_MTU processing.
				See http://www.freebsd.org/cgi/query-pr.cgi?pr=158307
				[RT #24950]

	3134.	[bug]		Improve the accuracy of dnssec-signzone's signing
				statistics. [RT #16030]

	3133.	[bug]		Change #3114 was incomplete. [RT #24577]

	3132.	[placeholder]

	3131.	[tuning]	Improve scalability by allocating one zone task
				per 100 zones at startup time, rather than using a
				fixed-size task table. [RT #24406]

	3130.	[func]		Support alternate methods for managing a dynamic
				zone's serial number.  Two methods are currently
				defined using serial-update-method, "increment"
				(default) and "unixtime".  [RT #23849]

	3129.	[bug]		Named could crash on 'rndc reconfig' when
				allow-new-zones was set to yes and named ACLs
				were used. [RT #22739]

	3128.	[func]		Inserting an NSEC3PARAM via dynamic update in an
				auto-dnssec zone that has not been signed yet
				will cause it to be signed with the specified NSEC3
				parameters when keys are activated.  The
				NSEC3PARAM record will not appear in the zone until
				it is signed, but the parameters will be stored.
				[RT #23684]

	3127.	[bug]		'rndc thaw' will now remove a zone's journal file
				if the zone serial number has been changed and
				ixfr-from-differences is not in use.  [RT #24687]

	3126.	[security]	Using DNAME record to generate replacements caused
				RPZ to exit with a assertion failure. [RT #24766]

	3125.	[security]	Using wildcard CNAME records as a replacement with
				RPZ caused named to exit with a assertion failure.
				[RT #24715]

	3124.	[bug]		Use an rdataset attribute flag to indicate
				negative-cache records rather than using rrtype 0;
				this will prevent problems when that rrtype is
				used in actual DNS packets. [RT #24777]

	3123.	[security]	Change #2912 exposed a latent flaw in
				dns_rdataset_totext() that could cause named to
				crash with an assertion failure. [RT #24777]

	3122.	[cleanup]	dnssec-settime: corrected usage message. [RT #24664]

	3121.	[security]	An authoritative name server sending a negative
				response containing a very large RRset could
				trigger an off-by-one error in the ncache code
				and crash named. [RT #24650]

	3120.	[bug]		Named could fail to validate zones listed in a DLV
				that validated insecure without using DLV and had
				DS records in the parent zone. [RT #24631]

	3119.	[bug]		When rolling to a new DNSSEC key, a private-type
				record could be created and never marked complete.
				[RT #23253]

	3118.	[bug]		nsupdate could dump core on shutdown when using
				SIG(0) keys. [RT #24604]

	3117.	[cleanup]	Remove doc and parser references to the
				never-implemented 'auto-dnssec create' option.
				[RT #24533]

	3116.	[func]		New 'dnssec-update-mode' option controls updates
				of DNSSEC records in signed dynamic zones.  Set to
				'no-resign' to disable automatic RRSIG regeneration
				while retaining the ability to sign new or changed
				data. [RT #24533]

	3115.	[bug]		Named could fail to return requested data when
				following a CNAME that points into the same zone.
				[RT #24455]

	3114.	[bug]		Retain expired RRSIGs in dynamic zones if key is
				inactive and there is no replacement key. [RT #23136]

	3113.	[doc]		Document the relationship between serial-query-rate
				and NOTIFY messages.

	3112.	[doc]		Add missing descriptions of the update policy name
				types "ms-self", "ms-subdomain", "krb5-self" and
				"krb5-subdomain", which allow machines to update
				their own records, to the BIND 9 ARM.

	3111.	[bug]		Improved consistency checks for dnssec-enable and
				dnssec-validation, added test cases to the
				checkconf system test. [RT #24398]

	3110.	[bug]		dnssec-signzone: Wrong error message could appear
				when attempting to sign with no KSK. [RT #24369]

	3109.	[func]		The also-notify option now uses the same syntax
				as a zone's masters clause.  This means it is
				now possible to specify a TSIG key to use when
				sending notifies to a given server, or to include
				an explicit named masters list in an also-notify
				statement.  [RT #23508]

	3108.	[cleanup]	dnssec-signzone: Clarified some error and
				warning messages; removed #ifdef ALLOW_KSKLESS_ZONES
				code (use -P instead). [RT #20852]

	3107.	[bug]		dnssec-signzone: Report the correct number of ZSKs
				when using -x. [RT #20852]

	3106.	[func]		When logging client requests, include the name of
				the TSIG key if any. [RT #23619]

	3105.	[bug]		GOST support can be suppressed by "configure
				--without-gost" [RT #24367]

	3104.	[bug]		Better support for cross-compiling. [RT #24367]

	3103.	[bug]		Configuring 'dnssec-validation auto' in a view
				instead of in the options statement could trigger
				an assertion failure in named-checkconf. [RT #24382]

	3102.	[func]		New 'dnssec-loadkeys-interval' option configures
				how often, in minutes, to check the key repository
				for updates when using automatic key maintenance.
				Default is every 60 minutes (formerly hard-coded
				to 12 hours). [RT #23744]

	3101.	[bug]		Zones using automatic key maintenance could fail
				to check the key repository for updates. [RT #23744]

	3100.	[security]	Certain response policy zone configurations could
				trigger an INSIST when receiving a query of type
				RRSIG. [RT #24280]

	3099.	[test]		"dlz" system test now runs but gives R:SKIPPED if
				not compiled with --with-dlz-filesystem.  [RT #24146]

	3098.	[bug]		DLZ zones were answering without setting the AA bit.
				[RT #24146]

	3097.	[test]		Add a tool to test handling of malformed packets.
				[RT #24096]

	3096.	[bug]		Set KRB5_KTNAME before calling log_cred() in
				dst_gssapi_acceptctx(). [RT #24004]

	3095.	[bug]		Handle isolated reserved ports in the port range.
				[RT #23957]

	3094.	[doc]		Expand dns64 documentation.

	3093.	[bug]		Fix gssapi/kerberos dependencies [RT #23836]

	3092.	[bug]		Signatures for records at the zone apex could go
				stale due to an incorrect timer setting. [RT #23769]

	3091.	[bug]		Fixed a bug in which zone keys that were published
				and then subsequently activated could fail to trigger
				automatic signing. [RT #22911]

	3090.	[func]		Make --with-gssapi default [RT #23738]

	3089.	[func]		dnssec-dsfromkey now supports reading keys from
				standard input "dnssec-dsfromkey -f -". [RT #20662]

	3088.	[bug]		Remove bin/tests/system/logfileconfig/ns1/named.conf
				and add setup.sh in order to resolve changing
				named.conf issue.  [RT #23687]

	3087.	[bug]		DDNS updates using SIG(0) with update-policy match
				type "external" could cause a crash. [RT #23735]

	3086.	[bug]		Running dnssec-settime -f on an old-style key will
				now force an update to the new key format even if no
				other change has been specified, using "-P now -A now"
				as default values.  [RT #22474]

	3085.	[func]		New '-R' option in dnssec-signzone forces removal
				of signatures which have not yet expired but
				were generated by a key that no longer exists.
				[RT #22471]

	3084.	[func]		A new command "rndc sync" dumps pending changes in
				a dynamic zone to disk; "rndc sync -clean" also
				removes the journal file after syncing.  Also,
				"rndc freeze" no longer removes journal files.
				[RT #22473]

	3083.	[bug]		NOTIFY messages were not being sent when generating
				a NSEC3 chain incrementally. [RT #23702]

	3082.	[port]		strtok_r is threads only. [RT #23747]

	3081.	[bug]		Failure of DNAME substitution did not return
				YXDOMAIN. [RT #23591]

	3080.	[cleanup]	Replaced compile time constant by STDTIME_ON_32BITS.
				[RT #23587]

	3079.	[bug]		Handle isc_event_allocate failures in t_tasks.
				[RT #23572]

	3078.	[func]		Added a new include file with function typedefs
				for the DLZ "dlopen" driver. [RT #23629]

	3077.	[bug]		zone.c:zone_refreshkeys() incorrectly called
				dns_zone_attach(), use zone->irefs instead. [RT #23303]

	3076.	[func]		New '-L' option in dnssec-keygen, dnsset-settime, and
				dnssec-keyfromlabel sets the default TTL of the
				key.  When possible, automatic signing will use that
				TTL when the key is published.  [RT #23304]

	3075.	[bug]		dns_dnssec_findzonekeys{2} used a inconsistent
				timestamp when determining which keys are active.
				[RT #23642]

	3074.	[bug]		Make the adb cache read through for zone data and
				glue learn for zone named is authoritative for.
				[RT #22842]

	3073.	[bug]		managed-keys changes were not properly being recorded.
				[RT #20256]

	3072.	[bug]		dns_dns64_aaaaok() potential NULL pointer dereference.
				[RT #20256]

	3071.	[bug]		has_nsec could be used uninitialized in
				update.c:next_active. [RT #20256]

	3070.	[bug]		dnssec-signzone potential NULL pointer dereference.
				[RT #20256]

	3069.	[cleanup]	Silence warnings messages from clang static analysis.
				[RT #20256]

	3068.	[bug]		Named failed to build with a OpenSSL without engine
				support. [RT #23473]

	3067.	[bug]		ixfr-from-differences {master|slave}; failed to
				select the master/slave zones.  [RT #23580]

	3066.	[func]		The DLZ "dlopen" driver is now built by default,
				no longer requiring a configure option.  To
				disable it, use "configure --without-dlopen".
				Driver also supported on win32.  [RT #23467]

	3065.	[bug]		RRSIG could have time stamps too far in the future.
				[RT #23356]

	3064.	[bug]		powerpc: add sync instructions to the end of atomic
				operations. [RT #23469]

	3063.	[contrib]	More verbose error reporting from DLZ LDAP. [RT #23402]

	3062.	[func]		Made several changes to enhance human readability
				of DNSSEC data in dig output and in generated
				zone files:
				 - DNSKEY record comments are more verbose, no
				   longer used in multiline mode only
				 - multiline RRSIG records reformatted
				 - multiline output mode for NSEC3PARAM records
				 - "dig +norrcomments" suppresses DNSKEY comments
				 - "dig +split=X" breaks hex/base64 records into
				   fields of width X; "dig +nosplit" disables this.
				[RT #22820]

	3061.	[func]		New option "dnssec-signzone -D", only write out
				generated DNSSEC records. [RT #22896]

	3060.	[func]		New option "dnssec-signzone -X <date>" allows
				specification of a separate expiration date
				for DNSKEY RRSIGs and other RRSIGs. [RT #22141]

	3059.	[test]		Added a regression test for change #3023.

	3058.	[bug]		Cause named to terminate at startup or rndc reconfig/
				reload to fail, if a log file specified in the conf
				file isn't a plain file. [RT #22771]

	3057.	[bug]		"rndc secroots" would abort after the first error
				and so could miss some views. [RT #23488]

	3056.	[func]		Added support for URI resource record. [RT #23386]

	3055.	[placeholder]

	3054.	[bug]		Added elliptic curve support check in
				GOST OpenSSL engine detection. [RT #23485]

	3053.	[bug]		Under a sustained high query load with a finite
				max-cache-size, it was possible for cache memory
				to be exhausted and not recovered. [RT #23371]

	3052.	[test]		Fixed last autosign test report. [RT #23256]

	3051.	[bug]		NS records obscure DNAME records at the bottom of the
				zone if both are present. [RT #23035]

	3050.	[bug]		The autosign system test was timing dependent.
				Wait for the initial autosigning to complete
				before running the rest of the test. [RT #23035]

	3049.	[bug]		Save and restore the gid when creating creating
				named.pid at startup. [RT #23290]

	3048.	[bug]		Fully separate view key management. [RT #23419]

	3047.	[bug]		DNSKEY NODATA responses not cached fixed in
				validator.c. Tests added to dnssec system test.
				[RT #22908]

	3046.	[bug]		Use RRSIG original TTL to compute validated RRset
				and RRSIG TTL. [RT #23332]

	3045.	[removed]	Replaced by change #3050.

	3044.	[bug]		Hold the socket manager lock while freeing the socket.
				[RT #23333]

	3043.	[test]		Merged in the NetBSD ATF test framework (currently
				version 0.12) for development of future unit tests.
				Use configure --with-atf to build ATF internally
				or configure --with-atf=prefix to use an external
				copy.  [RT #23209]

	3042.	[bug]		dig +trace could fail attempting to use IPv6
				addresses on systems with only IPv4 connectivity.
				[RT #23297]

	3041.	[bug]		dnssec-signzone failed to generate new signatures on
				ttl changes. [RT #23330]

	3040.	[bug]		Named failed to validate insecure zones where a node
				with a CNAME existed between the trust anchor and the
				top of the zone. [RT #23338]

	3039.	[func]		Redirect on NXDOMAIN support. [RT #23146]

	3038.	[bug]		Install <dns/rpz.h>.  [RT #23342]

	3037.	[doc]		Update COPYRIGHT to contain all the individual
				copyright notices that cover various parts.

	3036.	[bug]		Check built-in zone arguments to see if the zone
				is re-usable or not. [RT #21914]

	3035.	[cleanup]	Simplify by using strlcpy. [RT #22521]

	3034.	[cleanup]	nslookup: use strlcpy instead of safecopy. [RT #22521]

	3033.	[cleanup]	Add two INSIST(bucket != DNS_ADB_INVALIDBUCKET).
				[RT #22521]

	3032.	[bug]		rdatalist.c: add missing REQUIREs. [RT #22521]

	3031.	[bug]		dns_rdataclass_format() handle a zero sized buffer.
				[RT #22521]

	3030.	[bug]		dns_rdatatype_format() handle a zero sized buffer.
				[RT #22521]

	3029.	[bug]		isc_netaddr_format() handle a zero sized buffer.
				[RT #22521]

	3028.	[bug]		isc_sockaddr_format() handle a zero sized buffer.
				[RT #22521]

	3027.	[bug]		Add documented REQUIREs to cfg_obj_asnetprefix() to
				catch NULL pointer dereferences before they happen.
				[RT #22521]

	3026.	[bug]		lib/isc/httpd.c: check that we have enough space
				after calling grow_headerspace() and if not
				re-call grow_headerspace() until we do. [RT #22521]

	3025.	[bug]		Fixed a possible deadlock due to zone resigning.
				[RT #22964]

	3024.	[func]		RTT Banding removed due to minor security increase
				but major impact on resolver latency. [RT #23310]

	3023.	[bug]		Named could be left in an inconsistent state when
				receiving multiple AXFR response messages that were
				not all TSIG-signed. [RT #23254]

	3022.	[bug]		Fixed rpz SERVFAILs after failed zone transfers
				[RT #23246]

	3021.	[bug]		Change #3010 was incomplete. [RT #22296]

	3020.	[bug]		auto-dnssec failed to correctly update the zone when
				changing the DNSKEY RRset. [RT #23232]

	3019.	[test]		Test: check apex NSEC3 records after adding DNSKEY
				record via UPDATE. [RT #23229]

	3018.	[bug]		Named failed to check for the "none;" acl when deciding
				if a zone may need to be re-signed. [RT #23120]

	3017.	[doc]		dnssec-keyfromlabel -I was not properly documented.
				[RT #22887]

	3016.	[bug]		rndc usage missing '-b'. [RT #22937]

	3015.	[port]		win32: fix IN6_IS_ADDR_LINKLOCAL and
				IN6_IS_ADDR_SITELOCAL macros. [RT #22724]

	3014.	[placeholder]

	3013.	[bug]		The DNS64 ttl was not always being set as expected.
				[RT #23034]

	3012.	[bug]		Remove DNSKEY TTL change pairs before generating
				signing records for any remaining DNSKEY changes.
				[RT #22590]

	3011.	[func]		Change the default query timeout from 30 seconds
				to 10.  Allow setting this in named.conf using the new
				'resolver-query-timeout' option, which specifies a max
				time in seconds.  0 means 'default' and anything longer
				than 30 will be silently set to 30. [RT #22852]

	3010.	[bug]		Fixed a bug where "rndc reconfig" stopped the timer
				for refreshing managed-keys. [RT #22296]

	3009.	[bug]		clients-per-query code didn't work as expected with
				particular query patterns. [RT #22972]

.. code-block:: none

		--- 9.8.0b1 released ---

	3008.	[func]		Response policy zones (RPZ) support. [RT #21726]

	3007.	[bug]		Named failed to preserve the case of domain names in
				rdata which is not compressible when writing master
				files.  [RT #22863]

	3006.	[func]		Allow dynamically generated TSIG keys to be preserved
				across restarts of named.  Initially this is for
				TSIG keys generated using GSSAPI. [RT #22639]

	3005.	[port]		Solaris: Work around the lack of
				gsskrb5_register_acceptor_identity() by setting
				the KRB5_KTNAME environment variable to the
				contents of tkey-gssapi-keytab.  Also fixed
				test errors on MacOSX.  [RT #22853]

	3004.	[func]		DNS64 reverse support. [RT #22769]

	3003.	[experimental]	Added update-policy match type "external",
				enabling named to defer the decision of whether to
				allow a dynamic update to an external daemon.
				(Contributed by Andrew Tridgell.) [RT #22758]

	3002.	[bug]		isc_mutex_init_errcheck() failed to destroy attr.
				[RT #22766]

	3001.	[func]		Added a default trust anchor for the root zone, which
				can be switched on by setting "dnssec-validation auto;"
				in the named.conf options. [RT #21727]

	3000.	[bug]		More TKEY/GSS fixes:
				 - nsupdate can now get the default realm from
				   the user's Kerberos principal
				 - corrected gsstest compilation flags
				 - improved documentation
				 - fixed some NULL dereferences
				[RT #22795]

	2999.	[func]		Add GOST support (RFC 5933). [RT #20639]

	2998.	[func]		Add isc_task_beginexclusive and isc_task_endexclusive
				to the task api. [RT #22776]

	2997.	[func]		named -V now reports the OpenSSL and libxml2 versions
				it was compiled against. [RT #22687]

	2996.	[security]	Temporarily disable SO_ACCEPTFILTER support.
				[RT #22589]

	2995.	[bug]		The Kerberos realm was not being correctly extracted
				from the signer's identity. [RT #22770]

	2994.	[port]		NetBSD: use pthreads by default on NetBSD >= 5.0, and
				do not use threads on earlier versions.  Also kill
				the unproven-pthreads, mit-pthreads, and ptl2 support.

	2993.	[func]		Dynamically grow adb hash tables. [RT #21186]

	2992.	[contrib]	contrib/check-secure-delegation.pl:  A simple tool
				for looking at a secure delegation. [RT #22059]

	2991.	[contrib]	contrib/zone-edit.sh: A simple zone editing tool for
				dynamic zones. [RT #22365]

	2990.	[bug]		'dnssec-settime -S' no longer tests prepublication
				interval validity when the interval is set to 0.
				[RT #22761]

	2989.	[func]		Added support for writable DLZ zones. (Contributed
				by Andrew Tridgell of the Samba project.) [RT #22629]

	2988.	[experimental]	Added a "dlopen" DLZ driver, allowing the creation
				of external DLZ drivers that can be loaded as
				shared objects at runtime rather than linked with
				named.  Currently this is switched on via a
				compile-time option, "configure --with-dlz-dlopen".
				Note: the syntax for configuring DLZ zones
				is likely to be refined in future releases.
				(Contributed by Andrew Tridgell of the Samba
				project.) [RT #22629]

	2987.	[func]		Improve ease of configuring TKEY/GSS updates by
				adding a "tkey-gssapi-keytab" option.  If set,
				updates will be allowed with any key matching
				a principal in the specified keytab file.
				"tkey-gssapi-credential" is no longer required
				and is expected to be deprecated.  (Contributed
				by Andrew Tridgell of the Samba project.)
				[RT #22629]

	2986.	[func]		Add new zone type "static-stub".  It's like a stub
				zone, but the nameserver names and/or their IP
				addresses are statically configured. [RT #21474]

	2985.	[bug]		Add a regression test for change #2896. [RT #21324]

	2984.	[bug]		Don't run MX checks when the target of the MX record
				is ".".  [RT #22645]

	2983.	[bug]		Include "loadkeys" in rndc help output. [RT #22493]

.. code-block:: none

		--- 9.8.0a1 released ---

	2982.	[bug]		Reference count dst keys.  dst_key_attach() can be used
				increment the reference count.

				Note: dns_tsigkey_createfromkey() callers should now
				always call dst_key_free() rather than setting it
				to NULL on success. [RT #22672]

	2981.	[func]		Partial DNS64 support (AAAA synthesis). [RT #21991]

	2980.	[bug]		named didn't properly handle UPDATES that changed the
				TTL of the NSEC3PARAM RRset. [RT #22363]

	2979.	[bug]		named could deadlock during shutdown if two
				"rndc stop" commands were issued at the same
				time. [RT #22108]

	2978.	[port]		hpux: look for <devpoll.h> [RT #21919]

	2977.	[bug]		'nsupdate -l' report if the session key is missing.
				[RT #21670]

	2976.	[bug]		named could die on exit after negotiating a GSS-TSIG
				key. [RT #22573]

	2975.	[bug]		rbtdb.c:cleanup_dead_nodes_callback() acquired the
				wrong lock which could lead to server deadlock.
				[RT #22614]

	2974.	[bug]		Some valid UPDATE requests could fail due to a
				consistency check examining the existing version
				of the zone rather than the new version resulting
				from the UPDATE. [RT #22413]

	2973.	[bug]		bind.keys.h was being removed by the "make clean"
				at the end of configure resulting in build failures
				where there is very old version of perl installed.
				Move it to "make maintainer-clean". [RT #22230]

	2972.	[bug]		win32: address windows socket errors. [RT #21906]

	2971.	[bug]		Fixed a bug that caused journal files not to be
				compacted on Windows systems as a result of
				non-POSIX-compliant rename() semantics. [RT #22434]

	2970.	[security]	Adding a NO DATA negative cache entry failed to clear
				any matching RRSIG records.  A subsequent lookup of
				of NO DATA cache entry could trigger a INSIST when the
				unexpected RRSIG was also returned with the NO DATA
				cache entry.

				CVE-2010-3613, VU#706148. [RT #22288]

	2969.	[security]	Fix acl type processing so that allow-query works
				in options and view statements.  Also add a new
				set of tests to verify proper functioning.

				CVE-2010-3615, VU#510208. [RT #22418]

	2968.	[security]	Named could fail to prove a data set was insecure
				before marking it as insecure.  One set of conditions
				that can trigger this occurs naturally when rolling
				DNSKEY algorithms.

				CVE-2010-3614, VU#837744. [RT #22309]

	2967.	[bug]		'host -D' now turns on debugging messages earlier.
				[RT #22361]

	2966.	[bug]		isc_print_vsnprintf() failed to check if there was
				space available in the buffer when adding a left
				justified character with a non zero width,
				(e.g. "%-1c"). [RT #22270]

	2965.	[func]		Test HMAC functions using test data from RFC 2104 and
				RFC 4634. [RT #21702]

	2964.	[placeholder]

	2963.	[security]	The allow-query acl was being applied instead of the
				allow-query-cache acl to cache lookups. [RT #22114]

	2962.	[port]		win32: add more dependencies to BINDBuild.dsw.
				[RT #22062]

	2961.	[bug]		Be still more selective about the non-authoritative
				answers we apply change 2748 to. [RT #22074]

	2960.	[func]		Check that named accepts non-authoritative answers.
				[RT #21594]

	2959.	[func]		Check that named starts with a missing masterfile.
				[RT #22076]

	2958.	[bug]		named failed to start with a missing master file.
				[RT #22076]

	2957.	[bug]		entropy_get() and entropy_getpseudo() failed to match
				the API for RAND_bytes() and RAND_pseudo_bytes()
				respectively. [RT #21962]

	2956.	[port]		Enable atomic operations on the PowerPC64. [RT #21899]

	2955.	[func]		Provide more detail in the recursing log. [RT #22043]

	2954.	[bug]		contrib: dlz_mysql_driver.c bad error handling on
				build_sqldbinstance failure. [RT #21623]

	2953.	[bug]		Silence spurious "expected covering NSEC3, got an
				exact match" message when returning a wildcard
				no data response. [RT #21744]

	2952.	[port]		win32: named-checkzone and named-checkconf failed
				to initialize winsock. [RT #21932]

	2951.	[bug]		named failed to generate a correct signed response
				in a optout, delegation only zone with no secure
				delegations. [RT #22007]

	2950.	[bug]		named failed to perform a SOA up to date check when
				falling back to TCP on UDP timeouts when
				ixfr-from-differences was set. [RT #21595]

	2949.	[bug]		dns_view_setnewzones() contained a memory leak if
				it was called multiple times. [RT #21942]

	2948.	[port]		MacOS: provide a mechanism to configure the test
				interfaces at reboot. See bin/tests/system/README
				for details.

	2947.	[placeholder]

	2946.	[doc]		Document the default values for the minimum and maximum
				zone refresh and retry values in the ARM. [RT #21886]

	2945.	[doc]		Update empty-zones list in ARM. [RT #21772]

	2944.	[maint]		Remove ORCHID prefix from built in empty zones.
				[RT #21772]

	2943.	[func]		Add support to load new keys into managed zones
				without signing immediately with "rndc loadkeys".
				Add support to link keys with "dnssec-keygen -S"
				and "dnssec-settime -S".  [RT #21351]

	2942.	[contrib]	zone2sqlite failed to setup the entropy sources.
				[RT #21610]

	2941.	[bug]		sdb and sdlz (dlz's zone database) failed to support
				DNAME at the zone apex.  [RT #21610]

	2940.	[port]		Remove connection aborted error message on
				Windows. [RT #21549]

	2939.	[func]		Check that named successfully skips NSEC3 records
				that fail to match the NSEC3PARAM record currently
				in use. [RT #21868]

	2938.	[bug]		When generating signed responses, from a signed zone
				that uses NSEC3, named would use a uninitialized
				pointer if it needed to skip a NSEC3 record because
				it didn't match the selected NSEC3PARAM record for
				zone. [RT #21868]

	2937.	[bug]		Worked around an apparent race condition in over
				memory conditions.  Without this fix a DNS cache DB or
				ADB could incorrectly stay in an over memory state,
				effectively refusing further caching, which
				subsequently made a BIND 9 caching server unworkable.
				This fix prevents this problem from happening by
				polling the state of the memory context, rather than
				making a copy of the state, which appeared to cause
				a race.  This is a "workaround" in that it doesn't
				solve the possible race per se, but several experiments
				proved this change solves the symptom.  Also, the
				polling overhead hasn't been reported to be an issue.
				This bug should only affect a caching server that
				specifies a finite max-cache-size.  It's also quite
				likely that the bug happens only when enabling threads,
				but it's not confirmed yet. [RT #21818]

	2936.	[func]		Improved configuration syntax and multiple-view
				support for addzone/delzone feature (see change
				#2930).  Removed "new-zone-file" option, replaced
				with "allow-new-zones (yes|no)".  The new-zone-file
				for each view is now created automatically, with
				a filename generated from a hash of the view name.
				It is no longer necessary to "include" the
				new-zone-file in named.conf; this happens
				automatically.  Zones that were not added via
				"rndc addzone" can no longer be removed with
				"rndc delzone". [RT #19447]

	2935.	[bug]		nsupdate: improve 'file not found' error message.
				[RT #21871]

	2934.	[bug]		Use ANSI C compliant shift range in lib/isc/entropy.c.
				[RT #21871]

	2933.	[bug]		'dig +nsid' used stack memory after it went out of
				scope.  This could potentially result in a unknown,
				potentially malformed, EDNS option being sent instead
				of the desired NSID option. [RT #21781]

	2932.	[cleanup]	Corrected a numbering error in the "dnssec" test.
				[RT #21597]

	2931.	[bug]		Temporarily and partially disable change 2864
				because it would cause infinite attempts of RRSIG
				queries.  This is an urgent care fix; we'll
				revisit the issue and complete the fix later.
				[RT #21710]

	2930.	[experimental]	New "rndc addzone" and "rndc delzone" commands
				allow dynamic addition and deletion of zones.
				To enable this feature, specify a "new-zone-file"
				option at the view or options level in named.conf.
				Zone configuration information for the new zones
				will be written into that file.  To make the new
				zones persist after a restart, "include" the file
				into named.conf in the appropriate view.  (Note:
				This feature is not yet documented, and its syntax
				is expected to change.) [RT #19447]

	2929.	[bug]		Improved handling of GSS security contexts:
				 - added LRU expiration for generated TSIGs
				 - added the ability to use a non-default realm
				 - added new "realm" keyword in nsupdate
				 - limited lifetime of generated keys to 1 hour
				   or the lifetime of the context (whichever is
				   smaller)
				[RT #19737]

	2928.	[bug]		Be more selective about the non-authoritative
				answer we apply change 2748 to. [RT #21594]

	2927.	[placeholder]

	2926.	[placeholder]

	2925.	[bug]		Named failed to accept uncachable negative responses
				from insecure zones. [RT #21555]

	2924.	[func]		'rndc  secroots'  dump a combined summary of the
				current managed keys combined with trusted keys.
				[RT #20904]

	2923.	[bug]		'dig +trace' could drop core after "connection
				timeout". [RT #21514]

	2922.	[contrib]	Update zkt to version 1.0.

	2921.	[bug]		The resolver could attempt to destroy a fetch context
				too soon.  [RT #19878]

	2920.	[func]		Allow 'filter-aaaa-on-v4' to be applied selectively
				to IPv4 clients.  New acl 'filter-aaaa' (default any).

	2919.	[func]		Add autosign-ksk and autosign-zsk virtual time tests.
				[RT #20840]

	2918.	[maint]		Add AAAA address for I.ROOT-SERVERS.NET.

	2917.	[func]		Virtual time test framework. [RT #20801]

	2916.	[func]		Add framework to use IPv6 in tests.
				fd92:7065:b8e:ffff::1 ... fd92:7065:b8e:ffff::7

	2915.	[cleanup]	Be smarter about which objects we attempt to compile
				based on configure options. [RT #21444]

	2914.	[bug]		Make the "autosign" system test more portable.
				[RT #20997]

	2913.	[func]		Add pkcs#11 system tests. [RT #20784]

	2912.	[func]		Windows clients don't like UPDATE responses that clear
				the zone section. [RT #20986]

	2911.	[bug]		dnssec-signzone didn't handle out of zone records well.
				[RT #21367]

	2910.	[func]		Sanity check Kerberos credentials. [RT #20986]

	2909.	[bug]		named-checkconf -p could die if "update-policy local;"
				was specified in named.conf. [RT #21416]

	2908.	[bug]		It was possible for re-signing to stop after removing
				a DNSKEY. [RT #21384]

	2907.	[bug]		The export version of libdns had undefined references.
				[RT #21444]

	2906.	[bug]		Address RFC 5011 implementation issues. [RT #20903]

	2905.	[port]		aix: set use_atomic=yes with native compiler.
				[RT #21402]

	2904.	[bug]		When using DLV, sub-zones of the zones in the DLV,
				could be incorrectly marked as insecure instead of
				secure leading to negative proofs failing.  This was
				a unintended outcome from change 2890. [RT #21392]

	2903.	[bug]		managed-keys-directory missing from namedconf.c.
				[RT #21370]

	2902.	[func]		Add regression test for change 2897. [RT #21040]

	2901.	[port]		Use AC_C_FLEXIBLE_ARRAY_MEMBER. [RT #21316]

	2900.	[bug]		The placeholder negative caching element was not
				properly constructed triggering a INSIST in
				dns_ncache_towire(). [RT #21346]

	2899.	[port]		win32: Support linking against OpenSSL 1.0.0.

	2898.	[bug]		nslookup leaked memory when -domain=value was
				specified. [RT #21301]

	2897.	[bug]		NSEC3 chains could be left behind when transitioning
				to insecure. [RT #21040]

	2896.	[bug]		"rndc sign" failed to properly update the zone
				when adding a DNSKEY for publication only. [RT #21045]

	2895.	[func]		genrandom: add support for the generation of multiple
				files.  [RT #20917]

	2894.	[contrib]	DLZ LDAP support now use '$' not '%'. [RT #21294]

	2893.	[bug]		Improve managed keys support.  New named.conf option
				managed-keys-directory. [RT #20924]

	2892.	[bug]		Handle REVOKED keys better. [RT #20961]

	2891.	[maint]		Update empty-zones list to match
				draft-ietf-dnsop-default-local-zones-13. [RT #21099]

	2890.	[bug]		Handle the introduction of new trusted-keys and
				DS, DLV RRsets better. [RT #21097]

	2889.	[bug]		Elements of the grammar where not properly reported.
				[RT #21046]

	2888.	[bug]		Only the first EDNS option was displayed. [RT #21273]

	2887.	[bug]		Report the keytag times in UTC in the .key file,
				local time is presented as a comment within the
				comment.  [RT #21223]

	2886.	[bug]		ctime() is not thread safe. [RT #21223]

	2885.	[bug]		Improve -fno-strict-aliasing support probing in
				configure. [RT #21080]

	2884.	[bug]		Insufficient validation in dns_name_getlabelsequence().
				[RT #21283]

	2883.	[bug]		'dig +short' failed to handle really large datasets.
				[RT #21113]

	2882.	[bug]		Remove memory context from list of active contexts
				before clearing 'magic'. [RT #21274]

	2881.	[bug]		Reduce the amount of time the rbtdb write lock
				is held when closing a version. [RT #21198]

	2880.	[cleanup]	Make the output of dnssec-keygen and dnssec-revoke
				consistent. [RT #21078]

	2879.	[contrib]	DLZ bdbhpt driver fails to close correct cursor.
				[RT #21106]

	2878.	[func]		Incrementally write the master file after performing
				a AXFR.  [RT #21010]

	2877.	[bug]		The validator failed to skip obviously mismatching
				RRSIGs. [RT #21138]

	2876.	[bug]		Named could return SERVFAIL for negative responses
				from unsigned zones. [RT #21131]

	2875.	[bug]		dns_time64_fromtext() could accept non digits.
				[RT #21033]

	2874.	[bug]		Cache lack of EDNS support only after the server
				successfully responds to the query using plain DNS.
				[RT #20930]

	2873.	[bug]		Canceling a dynamic update via the dns/client module
				could trigger an assertion failure. [RT #21133]

	2872.	[bug]		Modify dns/client.c:dns_client_createx() to only
				require one of IPv4 or IPv6 rather than both.
				[RT #21122]

	2871.	[bug]		Type mismatch in mem_api.c between the definition and
				the header file, causing build failure with
				--enable-exportlib. [RT #21138]

	2870.	[maint]		Add AAAA address for L.ROOT-SERVERS.NET.

	2869.	[bug]		Fix arguments to dns_keytable_findnextkeynode() call.
				[RT #20877]

	2868.	[cleanup]	Run "make clean" at the end of configure to ensure
				any changes made by configure are integrated.
				Use --with-make-clean=no to disable.  [RT #20994]

	2867.	[bug]		Don't set GSS_C_SEQUENCE_FLAG as Windows DNS servers
				don't like it.  [RT #20986]

	2866.	[bug]		Windows does not like the TSIG name being compressed.
				[RT #20986]

	2865.	[bug]		memset to zero event.data.  [RT #20986]

	2864.	[bug]		Direct SIG/RRSIG queries were not handled correctly.
				[RT #21050]

	2863.	[port]		linux: disable IPv6 PMTUD and use network minimum MTU.
				[RT #21056]

	2862.	[bug]		nsupdate didn't default to the parent zone when
				updating DS records. [RT #20896]

	2861.	[doc]		dnssec-settime man pages didn't correctly document the
				inactivation time. [RT #21039]

	2860.	[bug]		named-checkconf's usage was out of date. [RT #21039]

	2859.	[bug]		When canceling validation it was possible to leak
				memory. [RT #20800]

	2858.	[bug]		RTT estimates were not being adjusted on ICMP errors.
				[RT #20772]

	2857.	[bug]		named-checkconf did not fail on a bad trusted key.
				[RT #20705]

	2856.	[bug]		The size of a memory allocation was not always properly
				recorded. [RT #20927]

	2855.	[func]		nsupdate will now preserve the entered case of domain
				names in update requests it sends. [RT #20928]

	2854.	[func]		dig: allow the final soa record in a axfr response to
				be suppressed, dig +onesoa. [RT #20929]

	2853.	[bug]		add_sigs() could run out of scratch space. [RT #21015]

	2852.	[bug]		Handle broken DNSSEC trust chains better. [RT #15619]

	2851.	[doc]		nslookup.1, removed <informalexample> from the docbook
				source as it produced bad nroff.  [RT #21007]

	2850.	[bug]		If isc_heap_insert() failed due to memory shortage
				the heap would have corrupted entries. [RT #20951]

	2849.	[bug]		Don't treat errors from the xml2 library as fatal.
				[RT #20945]

	2848.	[doc]		Moved README.dnssec, README.libdns, README.pkcs11 and
				README.rfc5011 into the ARM. [RT #20899]

	2847.	[cleanup]	Corrected usage message in dnssec-settime. [RT #20921]

	2846.	[bug]		EOF on unix domain sockets was not being handled
				correctly. [RT #20731]

	2845.	[bug]		RFC 5011 client could crash on shutdown. [RT #20903]

	2844.	[doc]		notify-delay default in ARM was wrong.  It should have
				been five (5) seconds.

	2843.	[func]		Prevent dnssec-keygen and dnssec-keyfromlabel from
				creating key files if there is a chance that the new
				key ID will collide with an existing one after
				either of the keys has been revoked.  (To override
				this in the case of dnssec-keyfromlabel, use the -y
				option.  dnssec-keygen will simply create a
				different, non-colliding key, so an override is
				not necessary.) [RT #20838]

	2842.	[func]		Added "smartsign" and improved "autosign" and
				"dnssec" regression tests. [RT #20865]

	2841.	[bug]		Change 2836 was not complete. [RT #20883]

	2840.	[bug]		Temporary fixed pkcs11-destroy usage check.
				[RT #20760]

	2839.	[bug]		A KSK revoked by named could not be deleted.
				[RT #20881]

	2838.	[placeholder]

	2837.	[port]		Prevent Linux spurious warnings about fwrite().
				[RT #20812]

	2836.	[bug]		Keys that were scheduled to become active could
				be delayed. [RT #20874]

	2835.	[bug]		Key inactivity dates were inadvertently stored in
				the private key file with the outdated tag
				"Unpublish" rather than "Inactive".  This has been
				fixed; however, any existing keys that had Inactive
				dates set will now need to have them reset, using
				'dnssec-settime -I'. [RT #20868]

	2834.	[bug]		HMAC-SHA* keys that were longer than the algorithm
				digest length were used incorrectly, leading to
				interoperability problems with other DNS
				implementations.  This has been corrected.
				(Note: If an oversize key is in use, and
				compatibility is needed with an older release of
				BIND, the new tool "isc-hmac-fixup" can convert
				the key secret to a form that will work with all
				versions.) [RT #20751]

	2833.	[cleanup]	Fix usage messages in dnssec-keygen and dnssec-settime.
				[RT #20851]

	2832.	[bug]		Modify "struct stat" in lib/export/samples/nsprobe.c
				to avoid redefinition in some OSs [RT 20831]

	2831.	[security]	Do not attempt to validate or cache
				out-of-bailiwick data returned with a secure
				answer; it must be re-fetched from its original
				source and validated in that context. [RT #20819]

	2830.	[bug]		Changing the OPTOUT setting could take multiple
				passes. [RT #20813]

	2829.	[bug]		Fixed potential node inconsistency in rbtdb.c.
				[RT #20808]

	2828.	[security]	Cached CNAME or DNAME RR could be returned to clients
				without DNSSEC validation. [RT #20737]

	2827.	[security]	Bogus NXDOMAIN could be cached as if valid. [RT #20712]

	2826.	[bug]		NSEC3->NSEC transitions could fail due to a lock not
				being released.  [RT #20740]

	2825.	[bug]		Changing the setting of OPTOUT in a NSEC3 chain that
				was in the process of being created was not properly
				recorded in the zone. [RT #20786]

	2824.	[bug]		"rndc sign" was not being run by the correct task.
				[RT #20759]

	2823.	[bug]		rbtdb.c:getsigningtime() was missing locks. [RT #20781]

	2822.	[bug]		rbtdb.c:loadnode() could return the wrong result.
				[RT #20802]

	2821.	[doc]		Add note that named-checkconf doesn't automatically
				read rndc.key and bind.keys [RT #20758]

	2820.	[func]		Handle read access failure of OpenSSL configuration
				file more user friendly (PKCS#11 engine patch).
				[RT #20668]

	2819.	[cleanup]	Removed unnecessary DNS_POINTER_MAXHOPS define.
				[RT #20771]

	2818.	[cleanup]	rndc could return an incorrect error code
				when a zone was not found. [RT #20767]

	2817.	[cleanup]	Removed unnecessary isc_task_endexclusive() calls.
				[RT #20768]

	2816.	[bug]		previous_closest_nsec() could fail to return
				data for NSEC3 nodes [RT #29730]

	2815.	[bug]		Exclusively lock the task when freezing a zone.
				[RT #19838]

	2814.	[func]		Provide a definitive error message when a master
				zone is not loaded. [RT #20757]

	2813.	[bug]		Better handling of unreadable DNSSEC key files.
				[RT #20710]

	2812.	[bug]		Make sure updates can't result in a zone with
				NSEC-only keys and NSEC3 records. [RT #20748]

	2811.	[cleanup]	Add "rndc sign" to list of commands in rndc usage
				output. [RT #20733]

	2810.	[doc]		Clarified the process of transitioning an NSEC3 zone
				to insecure. [RT #20746]

	2809.	[cleanup]	Restored accidentally-deleted text in usage output
				in dnssec-settime and dnssec-revoke [RT #20739]

	2808.	[bug]		Remove the attempt to install atomic.h from lib/isc.
				atomic.h is correctly installed by the architecture
				specific subdirectories.  [RT #20722]

	2807.	[bug]		Fixed a possible ASSERT when reconfiguring zone
				keys. [RT #20720]

.. code-block:: none

		--- 9.7.0rc1 released ---

	2806.	[bug]		"rdnc sign" could delay re-signing the DNSKEY
				when it had changed. [RT #20703]

	2805.	[bug]		Fixed namespace problems encountered when building
				external programs using non-exported BIND9 libraries
				(i.e., built without --enable-exportlib). [RT #20679]

	2804.	[bug]		Send notifies when a zone is signed with "rndc sign"
				or as a result of a scheduled key change. [RT #20700]

	2803.	[port]		win32: Install named-journalprint, nsec3hash, arpaname
				and genrandom under windows. [RT #20670]

	2802.	[cleanup]	Rename journalprint to named-journalprint. [RT #20670]

	2801.	[func]		Detect and report records that are different according
				to DNSSEC but are semantically equal according to plain
				DNS.  Apply plain DNS comparisons rather than DNSSEC
				comparisons when processing UPDATE requests.
				dnssec-signzone now removes such semantically duplicate
				records prior to signing the RRset.

				named-checkzone -r {ignore|warn|fail} (default warn)
				named-compilezone -r {ignore|warn|fail} (default warn)

				named.conf: check-dup-records {ignore|warn|fail};

	2800.	[func]		Reject zones which have NS records which refer to
				CNAMEs, DNAMEs or don't have address record (class IN
				only).  Reject UPDATEs which would cause the zone
				to fail the above checks if committed. [RT #20678]

	2799.	[cleanup]	Changed the "secure-to-insecure" option to
				"dnssec-secure-to-insecure", and "dnskey-ksk-only"
				to "dnssec-dnskey-kskonly", for clarity. [RT #20586]

	2798.	[bug]		Addressed bugs in managed-keys initialization
				and rollover. [RT #20683]

	2797.	[bug]		Don't decrement the dispatch manager's maxbuffers.
				[RT #20613]

	2796.	[bug]		Missing dns_rdataset_disassociate() call in
				dns_nsec3_delnsec3sx(). [RT #20681]

	2795.	[cleanup]	Add text to differentiate "update with no effect"
				log messages. [RT #18889]

	2794.	[bug]		Install <isc/namespace.h>.  [RT #20677]

	2793.	[func]		Add "autosign" and "metadata" tests to the
				automatic tests. [RT #19946]

	2792.	[func]		"filter-aaaa-on-v4" can now be set in view
				options (if compiled in).  [RT #20635]

	2791.	[bug]		The installation of isc-config.sh was broken.
				[RT #20667]

	2790.	[bug]		Handle DS queries to stub zones. [RT #20440]

	2789.	[bug]		Fixed an INSIST in dispatch.c [RT #20576]

	2788.	[bug]		dnssec-signzone could sign with keys that were
				not requested [RT #20625]

	2787.	[bug]		Spurious log message when zone keys were
				dynamically reconfigured. [RT #20659]

	2786.	[bug]		Additional could be promoted to answer. [RT #20663]

.. code-block:: none

		--- 9.7.0b3 released ---

	2785.	[bug]		Revoked keys could fail to self-sign [RT #20652]

	2784.	[bug]		TC was not always being set when required glue was
				dropped. [RT #20655]

	2783.	[func]		Return minimal responses to EDNS/UDP queries with a UDP
				buffer size of 512 or less.  [RT #20654]

	2782.	[port]		win32: use getaddrinfo() for hostname lookups.
				[RT #20650]

	2781.	[bug]		Inactive keys could be used for signing. [RT #20649]

	2780.	[bug]		dnssec-keygen -A none didn't properly unset the
				activation date in all cases. [RT #20648]

	2779.	[bug]		Dynamic key revocation could fail. [RT #20644]

	2778.	[bug]		dnssec-signzone could fail when a key was revoked
				without deleting the unrevoked version. [RT #20638]

	2777.	[contrib]	DLZ MYSQL auto reconnect support discovery was wrong.

	2776.	[bug]		Change #2762 was not correct. [RT #20647]

	2775.	[bug]		Accept RSASHA256 and RSASHA512 as NSEC3 compatible
				in dnssec-keyfromlabel. [RT #20643]

	2774.	[bug]		Existing cache DB wasn't being reused after
				reconfiguration. [RT #20629]

	2773.	[bug]		In autosigned zones, the SOA could be signed
				with the KSK. [RT #20628]

	2772.	[security]	When validating, track whether pending data was from
				the additional section or not and only return it if
				validates as secure. [RT #20438]

	2771.	[bug]		dnssec-signzone: DNSKEY records could be
				corrupted when importing from key files [RT #20624]

	2770.	[cleanup]	Add log messages to resolver.c to indicate events
				causing FORMERR responses. [RT #20526]

	2769.	[cleanup]	Change #2742 was incomplete. [RT #19589]

	2768.	[bug]		dnssec-signzone: -S no longer implies -g [RT #20568]

	2767.	[bug]		named could crash on startup if a zone was
				configured with auto-dnssec and there was no
				key-directory. [RT #20615]

	2766.	[bug]		isc_socket_fdwatchpoke() should only update the
				socketmgr state if the socket is not pending on a
				read or write.  [RT #20603]

	2765.	[bug]		Skip masters for which the TSIG key cannot be found.
				[RT #20595]

	2764.	[bug]		"rndc-confgen -a" could trigger a REQUIRE. [RT #20610]

	2763.	[bug]		"rndc sign" didn't create an NSEC chain. [RT #20591]

	2762.	[bug]		DLV validation failed with a local slave DLV zone.
				[RT #20577]

	2761.	[cleanup]	Enable internal symbol table for backtrace only for
				systems that are known to work.  Currently, BSD
				variants, Linux and Solaris are supported. [RT #20202]

	2760.	[cleanup]	Corrected named-compilezone usage summary. [RT #20533]

	2759.	[doc]		Add information about .jbk/.jnw files to
				the ARM. [RT #20303]

	2758.	[bug]		win32: Added a workaround for a windows 2008 bug
				that could cause the UDP client handler to shut
				down. [RT #19176]

	2757.	[bug]		dig: assertion failure could occur in connect
				timeout. [RT #20599]

	2756.	[bug]		Fixed corrupt logfile message in update.c. [RT #20597]

	2755.	[placeholder]

	2754.	[bug]		Secure-to-insecure transitions failed when zone
				was signed with NSEC3. [RT #20587]

	2753.	[bug]		Removed an unnecessary warning that could appear when
				building an NSEC chain. [RT #20589]

	2752.	[bug]		Locking violation. [RT #20587]

	2751.	[bug]		Fixed a memory leak in dnssec-keyfromlabel. [RT #20588]

	2750.	[bug]		dig: assertion failure could occur when a server
				didn't have an address. [RT #20579]

	2749.	[bug]		ixfr-from-differences generated a non-minimal ixfr
				for NSEC3 signed zones. [RT #20452]

	2748.	[func]		Identify bad answers from GTLD servers and treat them
				as referrals. [RT #18884]

	2747.	[bug]		Journal roll forwards failed to set the re-signing
				time of RRSIGs correctly. [RT #20541]

	2746.	[port]		hpux: address signed/unsigned expansion mismatch of
				dns_rbtnode_t.nsec. [RT #20542]

	2745.	[bug]		configure script didn't probe the return type of
				gai_strerror(3) correctly. [RT #20573]

	2744.	[func]		Log if a query was over TCP. [RT #19961]

	2743.	[bug]		RRSIG could be incorrectly set in the NSEC3 record
				for a insecure delegation.

.. code-block:: none

		--- 9.7.0b2 released ---

	2742.	[cleanup]	Clarify some DNSSEC-related log messages in
				validator.c. [RT #19589]

	2741.	[func]		Allow the dnssec-keygen progress messages to be
				suppressed (dnssec-keygen -q).  Automatically
				suppress the progress messages when stdin is not
				a tty. [RT #20474]

	2740.	[placeholder]

	2739.	[cleanup]	Clean up API for initializing and clearing trust
				anchors for a view. [RT #20211]

	2738.	[func]		Add RSASHA256 and RSASHA512 tests to the dnssec system
				test. [RT #20453]

	2737.	[func]		UPDATE requests can leak existence information.
				[RT #17261]

	2736.	[func]		Improve the performance of NSEC signed zones with
				more than a normal amount of glue below a delegation.
				[RT #20191]

	2735.	[bug]		dnssec-signzone could fail to read keys
				that were specified on the command line with
				full paths, but weren't in the current
				directory. [RT #20421]

	2734.	[port]		cygwin: arpaname did not compile. [RT #20473]

	2733.	[cleanup]	Clean up coding style in pkcs11-* tools. [RT #20355]

	2732.	[func]		Add optional filter-aaaa-on-v4 option, available
				if built with './configure --enable-filter-aaaa'.
				Filters out AAAA answers to clients connecting
				via IPv4.  (This is NOT recommended for general
				use.) [RT #20339]

	2731.	[func]		Additional work on change 2709.  The key parser
				will now ignore unrecognized fields when the
				minor version number of the private key format
				has been increased.  It will reject any key with
				the major version number increased. [RT #20310]

	2730.	[func]		Have dnssec-keygen display a progress indication
				a la 'openssl genrsa' on standard error. Note
				when the first '.' is followed by a long stop
				one has the choice between slow generation vs.
				poor random quality, i.e., '-r /dev/urandom'.
				[RT #20284]

	2729.	[func]		When constructing a CNAME from a DNAME use the DNAME
				TTL. [RT #20451]

	2728.	[bug]		dnssec-keygen, dnssec-keyfromlabel and
				dnssec-signzone now warn immediately if asked to
				write into a nonexistent directory. [RT #20278]

	2727.	[func]		The 'key-directory' option can now specify a relative
				path. [RT #20154]

	2726.	[func]		Added support for SHA-2 DNSSEC algorithms,
				RSASHA256 and RSASHA512. [RT #20023]

	2725.	[doc]		Added information about the file "managed-keys.bind"
				to the ARM. [RT #20235]

	2724.	[bug]		Updates to a existing node in secure zone using NSEC
				were failing. [RT #20448]

	2723.	[bug]		isc_base32_totext(), isc_base32hex_totext(), and
				isc_base64_totext(), didn't always mark regions of
				memory as fully consumed after conversion.  [RT #20445]

	2722.	[bug]		Ensure that the memory associated with the name of
				a node in a rbt tree is not altered during the life
				of the node. [RT #20431]

	2721.	[port]		Have dst__entropy_status() prime the random number
				generator. [RT #20369]

	2720.	[bug]		RFC 5011 trust anchor updates could trigger an
				assert if the DNSKEY record was unsigned. [RT #20406]

	2719.	[func]		Skip trusted/managed keys for unsupported algorithms.
				[RT #20392]

	2718.	[bug]		The space calculations in opensslrsa_todns() were
				incorrect. [RT #20394]

	2717.	[bug]		named failed to update the NSEC/NSEC3 record when
				the last private type record was removed as a result
				of completing the signing the zone with a key.
				[RT #20399]

	2716.	[bug]		nslookup debug mode didn't return the ttl. [RT #20414]

.. code-block:: none

		--- 9.7.0b1 released ---

	2715.	[bug]		Require OpenSSL support to be explicitly disabled.
				[RT #20288]

	2714.	[port]		aix/powerpc: 'asm("ics");' needs non standard assembler
				flags.

	2713.	[bug]		powerpc: atomic operations missing asm("ics") /
				__isync() calls.

	2712.	[func]		New 'auto-dnssec' zone option allows zone signing
				to be fully automated in zones configured for
				dynamic DNS.  'auto-dnssec allow;' permits a zone
				to be signed by creating keys for it in the
				key-directory and using 'rndc sign <zone>'.
				'auto-dnssec maintain;' allows that too, plus it
				also keeps the zone's DNSSEC keys up to date
				according to their timing metadata. [RT #19943]

	2711.	[port]		win32: Add the bin/pkcs11 tools into the full
				build. [RT #20372]

	2710.	[func]		New 'dnssec-signzone -x' flag and 'dnskey-ksk-only'
				zone option cause a zone to be signed with only KSKs
				signing the DNSKEY RRset, not ZSKs.  This reduces
				the size of a DNSKEY answer.  [RT #20340]

	2709.	[func]		Added some data fields, currently unused, to the
				private key file format, to allow implementation
				of explicit key rollover in a future release
				without impairing backward or forward compatibility.
				[RT #20310]

	2708.	[func]		Insecure to secure and NSEC3 parameter changes via
				update are now fully supported and no longer require
				defines to enable.  We now no longer overload the
				NSEC3PARAM flag field, nor the NSEC OPT bit at the
				apex.  Secure to insecure changes are controlled by
				by the named.conf option 'secure-to-insecure'.

				Warning: If you had previously enabled support by
				adding defines at compile time to BIND 9.6 you should
				ensure that all changes that are in progress have
				completed prior to upgrading to BIND 9.7.  BIND 9.7
				is not backwards compatible.

	2707.	[func]		dnssec-keyfromlabel no longer require engine name
				to be specified in the label if there is a default
				engine or the -E option has been used.  Also, it
				now uses default algorithms as dnssec-keygen does
				(i.e., RSASHA1, or NSEC3RSASHA1 if -3 is used).
				[RT #20371]

	2706.	[bug]		Loading a zone with a very large NSEC3 salt could
				trigger an assert. [RT #20368]

	2705.	[placeholder]

	2704.	[bug]		Serial of dynamic and stub zones could be inconsistent
				with their SOA serial.  [RT #19387]

	2703.	[func]		Introduce an OpenSSL "engine" argument with -E
				for all binaries which can take benefit of
				crypto hardware. [RT #20230]

	2702.	[func]		Update PKCS#11 tools (bin/pkcs11) [RT #20225 & all]

	2701.	[doc]		Correction to ARM: hmac-md5 is no longer the only
				supported TSIG key algorithm. [RT #18046]

	2700.	[doc]		The match-mapped-addresses option is discouraged.
				[RT #12252]

	2699.	[bug]		Missing lock in rbtdb.c. [RT #20037]

	2698.	[placeholder]

	2697.	[port]		win32: ensure that S_IFMT, S_IFDIR, S_IFCHR and
				S_IFREG are defined after including <isc/stat.h>.
				[RT #20309]

	2696.	[bug]		named failed to successfully process some valid
				acl constructs. [RT #20308]

	2695.	[func]		DHCP/DDNS - update fdwatch code for use by
				DHCP.  Modify the api to isc_sockfdwatch_t (the
				callback function for isc_socket_fdwatchcreate)
				to include information about the direction (read
				or write) and add isc_socket_fdwatchpoke.
				[RT #20253]

	2694.	[bug]		Reduce default NSEC3 iterations from 100 to 10.
				[RT #19970]

	2693.	[port]		Add some noreturn attributes. [RT #20257]

	2692.	[port]		win32: 32/64 bit cleanups. [RT #20335]

	2691.	[func]		dnssec-signzone: retain the existing NSEC or NSEC3
				chain when re-signing a previously-signed zone.
				Use -u to modify NSEC3 parameters or switch
				between NSEC and NSEC3. [RT #20304]

	2690.	[bug]		win32: fix isc_thread_key_getspecific() prototype.
				[RT #20315]

	2689.	[bug]		Correctly handle snprintf result. [RT #20306]

	2688.	[bug]		Use INTERFACE_F_POINTTOPOINT, not IFF_POINTOPOINT,
				to decide to fetch the destination address. [RT #20305]

	2687.	[bug]		Fixed dnssec-signzone -S handling of revoked keys.
				Also, added warnings when revoking a ZSK, as this is
				not defined by protocol (but is legal).  [RT #19943]

	2686.	[bug]		dnssec-signzone should clean the old NSEC chain when
				signing with NSEC3 and vice versa. [RT #20301]

	2685.	[contrib]	Update contrib/zkt to version 0.99c. [RT #20054]

	2684.	[cleanup]	dig: formalize +ad and +cd as synonyms for
				+adflag and +cdflag.  [RT #19305]

	2683.	[bug]		dnssec-signzone should clean out old NSEC3 chains when
				the NSEC3 parameters used to sign the zone change.
				[RT #20246]

	2682.	[bug]		"configure --enable-symtable=all" failed to
				build. [RT #20282]

	2681.	[bug]		IPSECKEY RR of gateway type 3 was not correctly
				decoded. [RT #20269]

	2680.	[func]		Move contrib/pkcs11-keygen to bin/pkcs11. [RT #20067]

	2679.	[func]		dig -k can now accept TSIG keys in named.conf
				format.  [RT #20031]

	2678.	[func]		Treat DS queries as if "minimal-response yes;"
				was set. [RT #20258]

	2677.	[func]		Changes to key metadata behavior:
				- Keys without "publish" or "active" dates set will
				  no longer be used for smart signing.  However,
				  those dates will be set to "now" by default when
				  a key is created; to generate a key but not use
				  it yet, use dnssec-keygen -G.
				- New "inactive" date (dnssec-keygen/settime -I)
				  sets the time when a key is no longer used for
				  signing but is still published.
				- The "unpublished" date (-U) is deprecated in
				  favor of "deleted" (-D).
				[RT #20247]

	2676.	[bug]		--with-export-installdir should have been
				--with-export-includedir. [RT #20252]

	2675.	[bug]		dnssec-signzone could crash if the key directory
				did not exist. [RT #20232]

.. code-block:: none

		--- 9.7.0a3 released ---

	2674.	[bug]		"dnssec-lookaside auto;" crashed if named was built
				without openssl. [RT #20231]

	2673.	[bug]		The managed-keys.bind zone file could fail to
				load due to a spurious result from sync_keyzone()
				[RT #20045]

	2672.	[bug]		Don't enable searching in 'host' when doing reverse
				lookups. [RT #20218]

	2671.	[bug]		Add support for PKCS#11 providers not returning
				the public exponent in RSA private keys
				(OpenCryptoki for instance) in
				dnssec-keyfromlabel. [RT #19294]

	2670.	[bug]		Unexpected connect failures failed to log enough
				information to be useful. [RT #20205]

	2669.	[func]		Update PKCS#11 support to support Keyper HSM.
				Update PKCS#11 patch to be against openssl-0.9.8i.

	2668.	[func]		Several improvements to dnssec-* tools, including:
				- dnssec-keygen and dnssec-settime can now set key
				  metadata fields 0 (to unset a value, use "none")
				- dnssec-revoke sets the revocation date in
				  addition to the revoke bit
				- dnssec-settime can now print individual metadata
				  fields instead of always printing all of them,
				  and can print them in unix epoch time format for
				  use by scripts
				[RT #19942]

	2667.	[func]		Add support for logging stack backtrace on assertion
				failure (not available for all platforms). [RT #19780]

	2666.	[func]		Added an 'options' argument to dns_name_fromstring()
				(API change from 9.7.0a2). [RT #20196]

	2665.	[func]		Clarify syntax for managed-keys {} statement, add
				ARM documentation about RFC 5011 support. [RT #19874]

	2664.	[bug]		create_keydata() and minimal_update() in zone.c
				didn't properly check return values for some
				functions.  [RT #19956]

	2663.	[func]		win32:  allow named to run as a service using
				"NT AUTHORITY\LocalService" as the account. [RT #19977]

	2662.	[bug]		lwres_getipnodebyname() and lwres_getipnodebyaddr()
				returned a misleading error code when lwresd was
				down. [RT #20028]

	2661.	[bug]		Check whether socket fd exceeds FD_SETSIZE when
				creating lwres context. [RT #20029]

	2660.	[func]		Add a new set of DNS libraries for non-BIND9
				applications.  See README.libdns. [RT #19369]

	2659.	[doc]		Clarify dnssec-keygen doc: key name must match zone
				name for DNSSEC keys. [RT #19938]

	2658.	[bug]		dnssec-settime and dnssec-revoke didn't process
				key file paths correctly. [RT #20078]

	2657.	[cleanup]	Lower "journal file <path> does not exist, creating it"
				log level to debug 1. [RT #20058]

	2656.	[func]		win32: add a "tools only" check box to the installer
				which causes it to only install dig, host, nslookup,
				nsupdate and relevant DLLs.  [RT #19998]

	2655.	[doc]		Document that key-directory does not affect
				bind.keys, rndc.key or session.key.  [RT #20155]

	2654.	[bug]		Improve error reporting on duplicated names for
				deny-answer-xxx. [RT #20164]

	2653.	[bug]		Treat ENGINE_load_private_key() failures as key
				not found rather than out of memory.  [RT #18033]

	2652.	[func]		Provide more detail about what record is being
				deleted. [RT #20061]

	2651.	[bug]		Dates could print incorrectly in K*.key files on
				64-bit systems. [RT #20076]

	2650.	[bug]		Assertion failure in dnssec-signzone when trying
				to read keyset-* files. [RT #20075]

	2649.	[bug]		Set the domain for forward only zones. [RT #19944]

	2648.	[port]		win32: isc_time_seconds() was broken. [RT #19900]

	2647.	[bug]		Remove unnecessary SOA updates when a new KSK is
				added. [RT #19913]

	2646.	[bug]		Incorrect cleanup on error in socket.c. [RT #19987]

	2645.	[port]		"gcc -m32" didn't work on amd64 and x86_64 platforms
				which default to 64 bits. [RT #19927]

.. code-block:: none

		--- 9.7.0a2 released ---

	2644.	[bug]		Change #2628 caused a regression on some systems;
				named was unable to write the PID file and would
				fail on startup. [RT #20001]

	2643.	[bug]		Stub zones interacted badly with NSEC3 support.
				[RT #19777]

	2642.	[bug]		nsupdate could dump core on solaris when reading
				improperly formatted key files.  [RT #20015]

	2641.	[bug]		Fixed an error in parsing update-policy syntax,
				added a regression test to check it. [RT #20007]

	2640.	[security]	A specially crafted update packet will cause named
				to exit. [RT #20000]

	2639.	[bug]		Silence compiler warnings in gssapi code. [RT #19954]

	2638.	[bug]		Install arpaname. [RT #19957]

	2637.	[func]		Rationalize dnssec-signzone's signwithkey() calling.
				[RT #19959]

	2636.	[func]		Simplify zone signing and key maintenance with the
				dnssec-* tools.  Major changes:
				- all dnssec-* tools now take a -K option to
				  specify a directory in which key files will be
				  stored
				- DNSSEC can now store metadata indicating when
				  they are scheduled to be published, activated,
				  revoked or removed; these values can be set by
				  dnssec-keygen or overwritten by the new
				  dnssec-settime command
				- dnssec-signzone -S (for "smart") option reads key
				  metadata and uses it to determine automatically
				  which keys to publish to the zone, use for
				  signing, revoke, or remove from the zone
				[RT #19816]

	2635.	[bug]		isc_inet_ntop() incorrectly handled 0.0/16 addresses.
				[RT #19716]

	2634.	[port]		win32: Add support for libxml2, enable
				statschannel. [RT #19773]

	2633.	[bug]		Handle 15 bit rand() functions. [RT #19783]

	2632.	[func]		util/kit.sh: warn if documentation appears to be out of
				date.  [RT #19922]

	2631.	[bug]		Handle "//", "/./" and "/../" in mkdirpath().
				[RT #19926 ]

	2630.	[func]		Improved syntax for DDNS autoconfiguration:  use
				"update-policy local;" to switch on local DDNS in a
				zone. (The "ddns-autoconf" option has been removed.)
				[RT #19875]

	2629.	[port]		Check for seteuid()/setegid(), use setresuid()/
				setresgid() if not present. [RT #19932]

	2628.	[port]		linux: Allow /var/run/named/named.pid to be opened
				at startup with reduced capabilities in operation.
				[RT #19884]

	2627.	[bug]		Named aborted if the same key was included in
				trusted-keys more than once. [RT #19918]

	2626.	[bug]		Multiple trusted-keys could trigger an assertion
				failure. [RT #19914]

	2625.	[bug]		Missing UNLOCK in rbtdb.c. [RT #19865]

	2624.	[func]		'named-checkconf -p' will print out the parsed
				configuration. [RT #18871]

	2623.	[bug]		Named started searches for DS non-optimally. [RT #19915]

	2622.	[bug]		Printing of named.conf grammar was broken. [RT #19919]

	2621.	[doc]		Made copyright boilerplate consistent.  [RT #19833]

	2620.	[bug]		Delay thawing the zone until the reload of it has
				completed successfully.  [RT #19750]

	2619.	[func]		Add support for RFC 5011, automatic trust anchor
				maintenance.  The new "managed-keys" statement can
				be used in place of "trusted-keys" for zones which
				support this protocol.  (Note: this syntax is
				expected to change prior to 9.7.0 final.) [RT #19248]

	2618.	[bug]		The sdb and sdlz db_interator_seek() methods could
				loop infinitely. [RT #19847]

	2617.	[bug]		ifconfig.sh failed to emit an error message when
				run from the wrong location. [RT #19375]

	2616.	[bug]		'host' used the nameservers from resolv.conf even
				when a explicit nameserver was specified. [RT #19852]

	2615.	[bug]		"__attribute__((unused))" was in the wrong place
				for ia64 gcc builds. [RT #19854]

	2614.	[port]		win32: 'named -v' should automatically be executed
				in the foreground. [RT #19844]

	2613.	[placeholder]

.. code-block:: none

		--- 9.7.0a1 released ---

	2612.	[func]		Add default values for the arguments to
				dnssec-keygen.  Without arguments, it will now
				generate a 1024-bit RSASHA1 zone-signing key,
				or with the -f KSK option, a 2048-bit RSASHA1
				key-signing key. [RT #19300]

	2611.	[func]		Add -l option to dnssec-dsfromkey to generate
				DLV records instead of DS records. [RT #19300]

	2610.	[port]		sunos: Change #2363 was not complete. [RT #19796]

	2609.	[func]		Simplify the configuration of dynamic zones:
				- add ddns-confgen command to generate
				  configuration text for named.conf
				- add zone option "ddns-autoconf yes;", which
				  causes named to generate a TSIG session key
				  and allow updates to the zone using that key
				- add '-l' (localhost) option to nsupdate, which
				  causes nsupdate to connect to a locally-running
				  named process using the session key generated
				  by named
				[RT #19284]

	2608.	[func]		Perform post signing verification checks in
				dnssec-signzone.  These can be disabled with -P.

				The post sign verification test ensures that for each
				algorithm in use there is at least one non revoked
				self signed KSK key.  That all revoked KSK keys are
				self signed.  That all records in the zone are signed
				by the algorithm.  [RT #19653]

	2607.	[bug]		named could incorrectly delete NSEC3 records for
				empty nodes when processing a update request.
				[RT #19749]

	2606.	[bug]		"delegation-only" was not being accepted in
				delegation-only type zones. [RT #19717]

	2605.	[bug]		Accept DS responses from delegation only zones.
				[RT # 19296]

	2604.	[func]		Add support for DNS rebinding attack prevention through
				new options, deny-answer-addresses and
				deny-answer-aliases.  Based on contributed code from
				JD Nurmi, Google. [RT #18192]

	2603.	[port]		win32: handle .exe extension of named-checkzone and
				named-comilezone argv[0] names under windows.
				[RT #19767]

	2602.	[port]		win32: fix debugging command line build of libisccfg.
				[RT #19767]

	2601.	[doc]		Mention file creation mode mask in the
				named manual page.

	2600.	[doc]		ARM: miscellaneous reformatting for different
				page widths. [RT #19574]

	2599.	[bug]		Address rapid memory growth when validation fails.
				[RT #19654]

	2598.	[func]		Reserve the -F flag. [RT #19657]

	2597.	[bug]		Handle a validation failure with a insecure delegation
				from a NSEC3 signed master/slave zone.  [RT #19464]

	2596.	[bug]		Stale tree nodes of cache/dynamic rbtdb could stay
				long, leading to inefficient memory usage or rejecting
				newer cache entries in the worst case. [RT #19563]

	2595.	[bug]		Fix unknown extended rcodes in dig. [RT #19625]

	2594.	[func]		Have rndc warn if using its default configuration
				file when the key file also exists. [RT #19424]

	2593.	[bug]		Improve a corner source of SERVFAILs [RT #19632]

	2592.	[bug]		Treat "any" as a type in nsupdate. [RT #19455]

	2591.	[bug]		named could die when processing a update in
				removed_orphaned_ds(). [RT #19507]

	2590.	[func]		Report zone/class of "update with no effect".
				[RT #19542]

	2589.	[bug]		dns_db_unregister() failed to clear '*dbimp'.
				[RT #19626]

	2588.	[bug]		SO_REUSEADDR could be set unconditionally after failure
				of bind(2) call.  This should be rare and mostly
				harmless, but may cause interference with other
				processes that happen to use the same port. [RT #19642]

	2587.	[func]		Improve logging by reporting serial numbers for
				when zone serial has gone backwards or unchanged.
				[RT #19506]

	2586.	[bug]		Missing cleanup of SIG rdataset in searching a DLZ DB
				or SDB. [RT #19577]

	2585.	[bug]		Uninitialized socket name could be referenced via a
				statistics channel, triggering an assertion failure in
				XML rendering. [RT #19427]

	2584.	[bug]		alpha: gcc optimization could break atomic operations.
				[RT #19227]

	2583.	[port]		netbsd: provide a control to not add the compile
				date to the version string, -DNO_VERSION_DATE.

	2582.	[bug]		Don't emit warning log message when we attempt to
				remove non-existent journal. [RT #19516]

	2581.	[contrib]	dlz/mysql set MYSQL_OPT_RECONNECT option on connection.
				Requires MySQL 5.0.19 or later. [RT #19084]

	2580.	[bug]		UpdateRej statistics counter could be incremented twice
				for one rejection. [RT #19476]

	2579.	[bug]		DNSSEC lookaside validation failed to handle unknown
				algorithms. [RT #19479]

	2578.	[bug]		Changed default sig-signing-type to 65534, because
				65535 turns out to be reserved.  [RT #19477]

	2577.	[doc]		Clarified some statistics counters. [RT #19454]

	2576.	[bug]		NSEC record were not being correctly signed when
				a zone transitions from insecure to secure.
				Handle such incorrectly signed zones. [RT #19114]

	2575.	[func]		New functions dns_name_fromstring() and
				dns_name_tostring(), to simplify conversion
				of a string to a dns_name structure and vice
				versa. [RT #19451]

	2574.	[doc]		Document nsupdate -g and -o. [RT #19351]

	2573.	[bug]		Replacing a non-CNAME record with a CNAME record in a
				single transaction in a signed zone failed. [RT #19397]

	2572.	[func]		Simplify DLV configuration, with a new option
				"dnssec-lookaside auto;"  This is the equivalent
				of "dnssec-lookaside . trust-anchor dlv.isc.org;"
				plus setting a trusted-key for dlv.isc.org.

				Note: The trusted key is hard-coded into named,
				but is also stored in (and can be overridden
				by) $sysconfdir/bind.keys.  As the ISC DLV key
				rolls over it can be kept up to date by replacing
				the bind.keys file with a key downloaded from
				https://www.isc.org/solutions/dlv. [RT #18685]

	2571.	[func]		Add a new tool "arpaname" which translates IP addresses
				to the corresponding IN-ADDR.ARPA or IP6.ARPA name.
				[RT #18976]

	2570.	[func]		Log the destination address the query was sent to.
				[RT #19209]

	2569.	[func]		Move journalprint, nsec3hash, and genrandom
				commands from bin/tests into bin/tools;
				"make install" will put them in $sbindir. [RT #19301]

	2568.	[bug]		Report when the write to indicate a otherwise
				successful start fails. [RT #19360]

	2567.	[bug]		dst__privstruct_writefile() could miss write errors.
				write_public_key() could miss write errors.
				dnssec-dsfromkey could miss write errors.
				[RT #19360]

	2566.	[cleanup]	Clarify logged message when an insecure DNSSEC
				response arrives from a zone thought to be secure:
				"insecurity proof failed" instead of "not
				insecure". [RT #19400]

	2565.	[func]		Add support for HIP record.  Includes new functions
				dns_rdata_hip_first(), dns_rdata_hip_next()
				and dns_rdata_hip_current().  [RT #19384]

	2564.	[bug]		Only take EDNS fallback steps when processing timeouts.
				[RT #19405]

	2563.	[bug]		Dig could leak a socket causing it to wait forever
				to exit. [RT #19359]

	2562.	[doc]		ARM: miscellaneous improvements, reorganization,
				and some new content.

	2561.	[doc]		Add isc-config.sh(1) man page. [RT #16378]

	2560.	[bug]		Add #include <config.h> to iptable.c. [RT #18258]

	2559.	[bug]		dnssec-dsfromkey could compute bad DS records when
				reading from a K* files.  [RT #19357]

	2558.	[func]		Set the ownership of missing directories created
				for pid-file if -u has been specified on the command
				line. [RT #19328]

	2557.	[cleanup]	PCI compliance:
				* new libisc log module file
				* isc_dir_chroot() now also changes the working
				  directory to "/".
				* additional INSISTs
				* additional logging when files can't be removed.

	2556.	[port]		Solaris: mkdir(2) on tmpfs filesystems does not do the
				error checks in the correct order resulting in the
				wrong error code sometimes being returned. [RT #19249]

	2555.	[func]		dig: when emitting a hex dump also display the
				corresponding characters. [RT #19258]

	2554.	[bug]		Validation of uppercase queries from NSEC3 zones could
				fail. [RT #19297]

	2553.	[bug]		Reference leak on DNSSEC validation errors. [RT #19291]

	2552.	[bug]		zero-no-soa-ttl-cache was not being honored.
				[RT #19340]

	2551.	[bug]		Potential Reference leak on return. [RT #19341]

	2550.	[bug]		Check --with-openssl=<path> finds <openssl/opensslv.h>.
				[RT #19343]

	2549.	[port]		linux: define NR_OPEN if not currently defined.
				[RT #19344]

	2548.	[bug]		Install iterated_hash.h. [RT #19335]

	2547.	[bug]		openssl_link.c:mem_realloc() could reference an
				out-of-range area of the source buffer.  New public
				function isc_mem_reallocate() was introduced to address
				this bug. [RT #19313]

	2546.	[func]		Add --enable-openssl-hash configure flag to use
				OpenSSL (in place of internal routine) for hash
				functions (MD5, SHA[12] and HMAC). [RT #18815]

	2545.	[doc]		ARM: Legal hostname checking (check-names) is
				for SRV RDATA too. [RT #19304]

	2544.	[cleanup]	Removed unused structure members in adb.c. [RT #19225]

	2543.	[contrib]	Update contrib/zkt to version 0.98. [RT #19113]

	2542.	[doc]		Update the description of dig +adflag. [RT #19290]

	2541.	[bug]		Conditionally update dispatch manager statistics.
				[RT #19247]

	2540.	[func]		Add a nibble mode to $GENERATE. [RT #18872]

	2539.	[security]	Update the interaction between recursion, allow-query,
				allow-query-cache and allow-recursion.  [RT #19198]

	2538.	[bug]		cache/ADB memory could grow over max-cache-size,
				especially with threads and smaller max-cache-size
				values. [RT #19240]

	2537.	[func]		Added more statistics counters including those on socket
				I/O events and query RTT histograms. [RT #18802]

	2536.	[cleanup]	Silence some warnings when -Werror=format-security is
				specified. [RT #19083]

	2535.	[bug]		dig +showsearch and +trace interacted badly. [RT #19091]

	2534.	[func]		Check NAPTR records regular expressions and
				replacement strings to ensure they are syntactically
				valid and consistent. [RT #18168]

	2533.	[doc]		ARM: document @ (at-sign). [RT #17144]

	2532.	[bug]		dig: check the question section of the response to
				see if it matches the asked question. [RT #18495]

	2531.	[bug]		Change #2207 was incomplete. [RT #19098]

	2530.	[bug]		named failed to reject insecure to secure transitions
				via UPDATE. [RT #19101]

	2529.	[cleanup]	Upgrade libtool to silence complaints from recent
				version of autoconf. [RT #18657]

	2528.	[cleanup]	Silence spurious configure warning about
				--datarootdir [RT #19096]

	2527.	[placeholder]

	2526.	[func]		New named option "attach-cache" that allows multiple
				views to share a single cache to save memory and
				improve lookup efficiency.  Based on contributed code
				from Barclay Osborn, Google. [RT #18905]

	2525.	[func]		New logging category "query-errors" to provide detailed
				internal information about query failures, especially
				about server failures. [RT #19027]

	2524.	[port]		sunos: dnssec-signzone needs strtoul(). [RT #19129]

	2523.	[bug]		Random type rdata freed by dns_nsec_typepresent().
				[RT #19112]

	2522.	[security]	Handle -1 from DSA_do_verify() and EVP_VerifyFinal().

	2521.	[bug]		Improve epoll cross compilation support. [RT #19047]

	2520.	[bug]		Update xml statistics version number to 2.0 as change
				#2388 made the schema incompatible to the previous
				version. [RT #19080]

	2519.	[bug]		dig/host with -4 or -6 didn't work if more than two
				nameserver addresses of the excluded address family
				preceded in resolv.conf. [RT #19081]

	2518.	[func]		Add support for the new CERT types from RFC 4398.
				[RT #19077]

	2517.	[bug]		dig +trace with -4 or -6 failed when it chose a
				nameserver address of the excluded address type.
				[RT #18843]

	2516.	[bug]		glue sort for responses was performed even when not
				needed. [RT #19039]

	2515.	[port]		win32: build dnssec-dsfromkey and dnssec-keyfromlabel.
				[RT #19063]

	2514.	[bug]		dig/host failed with -4 or -6 when resolv.conf contains
				a nameserver of the excluded address family.
				[RT #18848]

	2513.	[bug]		Fix windows cli build. [RT #19062]

	2512.	[func]		Print a summary of the cached records which make up
				the negative response.  [RT #18885]

	2511.	[cleanup]	dns_rdata_tofmttext() add const to linebreak.
				[RT #18885]

	2510.	[bug]		"dig +sigchase" could trigger REQUIRE failures.
				[RT #19033]

	2509.	[bug]		Specifying a fixed query source port was broken.
				[RT #19051]

	2508.	[placeholder]

	2507.	[func]		Log the recursion quota values when killing the
				oldest query or refusing to recurse due to quota.
				[RT #19022]

	2506.	[port]		solaris: Check at configure time if
				hack_shutup_pthreadonceinit is needed. [RT #19037]

	2505.	[port]		Treat amd64 similarly to x86_64 when determining
				atomic operation support. [RT #19031]

	2504.	[bug]		Address race condition in the socket code. [RT #18899]

	2503.	[port]		linux: improve compatibility with Linux Standard
				Base. [RT #18793]

	2502.	[cleanup]	isc_radix: Improve compliance with coding style,
				document function in <isc/radix.h>. [RT #18534]

	2501.	[func]		$GENERATE now supports all rdata types.  Multi-field
				rdata types need to be quoted.  See the ARM for
				details. [RT #18368]

	2500.	[contrib]	contrib/sdb/pgsql/zonetodb.c called non-existent
				function. [RT #18582]

	2499.	[port]		solaris: lib/lwres/getaddrinfo.c namespace clash.
				[RT #18837]

.. code-block:: none

		--- 9.6.0rc1 released ---

	2498.	[bug]		Removed a bogus function argument used with
				ISC_SOCKET_USE_POLLWATCH: it could cause compiler
				warning or crash named with the debug 1 level
				of logging. [RT #18917]

	2497.	[bug]		Don't add RRSIG bit to NSEC3 bit map for insecure
				delegation.

	2496.	[bug]		Add sanity length checks to NSID option. [RT #18813]

	2495.	[bug]		Tighten RRSIG checks. [RT #18795]

	2494.	[bug]		isc/radix.h, dns/sdlz.h and dns/dlz.h were not being
				installed. [RT #18826]

	2493.	[bug]		The linux capabilities code was not correctly cleaning
				up after itself. [RT #18767]

	2492.	[func]		Rndc status now reports the number of cpus discovered
				and the number of worker threads when running
				multi-threaded. [RT #18273]

	2491.	[func]		Attempt to re-use a local port if we are already using
				the port. [RT #18548]

	2490.	[port]		aix: work around a kernel bug where IPV6_RECVPKTINFO
				is cleared when IPV6_V6ONLY is set. [RT #18785]

	2489.	[port]		solaris: Workaround Solaris's kernel bug about
				/dev/poll:
				http://bugs.opensolaris.org/view_bug.do?bug_id=6724237
				Define ISC_SOCKET_USE_POLLWATCH at build time to enable
				this workaround. [RT #18870]

	2488.	[func]		Added a tool, dnssec-dsfromkey, to generate DS records
				from keyset and .key files. [RT #18694]

	2487.	[bug]		Give TCP connections longer to complete. [RT #18675]

	2486.	[func]		The default locations for named.pid and lwresd.pid
				are now /var/run/named/named.pid and
				/var/run/lwresd/lwresd.pid respectively.

				This allows the owner of the containing directory
				to be set, for "named -u" support, and allows there
				to be a permanent symbolic link in the path, for
				"named -t" support.  [RT #18306]

	2485.	[bug]		Change update's the handling of obscured RRSIG
				records.  Not all orphaned DS records were being
				removed. [RT #18828]

	2484.	[bug]		It was possible to trigger a REQUIRE failure when
				adding NSEC3 proofs to the response in
				query_addwildcardproof().  [RT #18828]

	2483.	[port]		win32: chroot() is not supported. [RT #18805]

	2482.	[port]		libxml2: support versions 2.7.* in addition
				to 2.6.*. [RT #18806]

.. code-block:: none

		--- 9.6.0b1 released ---

	2481.	[bug]		rbtdb.c:matchparams() failed to handle NSEC3 chain
				collisions.  [RT #18812]

	2480.	[bug]		named could fail to emit all the required NSEC3
				records.  [RT #18812]

	2479.	[bug]		xfrout:covers was not properly initialized. [RT #18801]

	2478.	[bug]		'addresses' could be used uninitialized in
				configure_forward(). [RT #18800]

	2477.	[bug]		dig: the global option to print the command line is
				+cmd not print_cmd.  Update the output to reflect
				this. [RT #17008]

	2476.	[doc]		ARM: improve documentation for max-journal-size and
				ixfr-from-differences. [RT #15909] [RT #18541]

	2475.	[bug]		LRU cache cleanup under overmem condition could purge
				particular entries more aggressively. [RT #17628]

	2474.	[bug]		ACL structures could be allocated with insufficient
				space, causing an array overrun. [RT #18765]

	2473.	[port]		linux: raise the limit on open files to the possible
				maximum value before spawning threads; 'files'
				specified in named.conf doesn't seem to work with
				threads as expected. [RT #18784]

	2472.	[port]		linux: check the number of available cpu's before
				calling chroot as it depends on "/proc". [RT #16923]

	2471.	[bug]		named-checkzone was not reporting missing mandatory
				glue when sibling checks were disabled. [RT #18768]

	2470.	[bug]		Elements of the isc_radix_node_t could be incorrectly
				overwritten.  [RT #18719]

	2469.	[port]		solaris: Work around Solaris's select() limitations.
				[RT #18769]

	2468.	[bug]		Resolver could try unreachable servers multiple times.
				[RT #18739]

	2467.	[bug]		Failure of fcntl(F_DUPFD) wasn't logged. [RT #18740]

	2466.	[doc]		ARM: explain max-cache-ttl 0 SERVFAIL issue.
				[RT #18302]

	2465.	[bug]		Adb's handling of lame addresses was different
				for IPv4 and IPv6. [RT #18738]

	2464.	[port]		linux: check that a capability is present before
				trying to set it. [RT #18135]

	2463.	[port]		linux: POSIX doesn't include the IPv6 Advanced Socket
				API and glibc hides parts of the IPv6 Advanced Socket
				API as a result.  This is stupid as it breaks how the
				two halves (Basic and Advanced) of the IPv6 Socket API
				were designed to be used but we have to live with it.
				Define _GNU_SOURCE to pull in the IPv6 Advanced Socket
				API. [RT #18388]

	2462.	[doc]		Document -m (enable memory usage debugging)
				option for dig. [RT #18757]

	2461.	[port]		sunos: Change #2363 was not complete. [RT #17513]

.. code-block:: none

		--- 9.6.0a1 released ---

	2460.	[bug]		Don't call dns_db_getnsec3parameters() on the cache.
				[RT #18697]

	2459.	[contrib]	Import dnssec-zkt to contrib/zkt. [RT #18448]

	2458.	[doc]		ARM: update and correction for max-cache-size.
				[RT #18294]

	2457.	[tuning]	max-cache-size is reverted to 0, the previous
				default.  It should be safe because expired cache
				entries are also purged. [RT #18684]

	2456.	[bug]		In ACLs, ::/0 and 0.0.0.0/0 would both match any
				address, regardless of family.  They now correctly
				distinguish IPv4 from IPv6.  [RT #18559]

	2455.	[bug]		Stop metadata being transferred via axfr/ixfr.
				[RT #18639]

	2454.	[func]		nsupdate: you can now set a default ttl. [RT #18317]

	2453.	[bug]		Remove NULL pointer dereference in dns_journal_print().
				[RT #18316]

	2452.	[func]		Improve bin/test/journalprint. [RT #18316]

	2451.	[port]		solaris: handle runtime linking better. [RT #18356]

	2450.	[doc]		Fix lwresd docbook problem for manual page.
				[RT #18672]

	2449.	[placeholder]

	2448.	[func]		Add NSEC3 support. [RT #15452]

	2447.	[cleanup]	libbind has been split out as a separate product.

	2446.	[func]		Add a new log message about build options on startup.
				A new command-line option '-V' for named is also
				provided to show this information. [RT #18645]

	2445.	[doc]		ARM out-of-date on empty reverse zones (list includes
				RFC1918 address, but these are not yet compiled in).
				[RT #18578]

	2444.	[port]		Linux, FreeBSD, AIX: Turn off path mtu discovery
				(clear DF) for UDP responses and requests.

	2443.	[bug]		win32: UDP connect() would not generate an event,
				and so connected UDP sockets would never clean up.
				Fix this by doing an immediate WSAConnect() rather
				than an io completion port type for UDP.

	2442.	[bug]		A lock could be destroyed twice. [RT #18626]

	2441.	[bug]		isc_radix_insert() could copy radix tree nodes
				incompletely. [RT #18573]

	2440.	[bug]		named-checkconf used an incorrect test to determine
				if an ACL was set to none.

	2439.	[bug]		Potential NULL dereference in dns_acl_isanyornone().
				[RT #18559]

	2438.	[bug]		Timeouts could be logged incorrectly under win32.

	2437.	[bug]		Sockets could be closed too early, leading to
				inconsistent states in the socket module. [RT #18298]

	2436.	[security]	win32: UDP client handler can be shutdown. [RT #18576]

	2435.	[bug]		Fixed an ACL memory leak affecting win32.

	2434.	[bug]		Fixed a minor error-reporting bug in
				lib/isc/win32/socket.c.

	2433.	[tuning]	Set initial timeout to 800ms.

	2432.	[bug]		More Windows socket handling improvements.  Stop
				using I/O events and use IO Completion Ports
				throughout.  Rewrite the receive path logic to make
				it easier to support multiple simultaneous
				requesters in the future.  Add stricter consistency
				checking as a compile-time option (define
				ISC_SOCKET_CONSISTENCY_CHECKS; defaults to off).

	2431.	[bug]		Acl processing could leak memory. [RT #18323]

	2430.	[bug]		win32: isc_interval_set() could round down to
				zero if the input was less than NS_INTERVAL
				nanoseconds.  Round up instead. [RT #18549]

	2429.	[doc]		nsupdate should be in section 1 of the man pages.
				[RT #18283]

	2428.	[bug]		dns_iptable_merge() mishandled merges of negative
				tables. [RT #18409]

	2427.	[func]		Treat DNSKEY queries as if "minimal-response yes;"
				was set. [RT #18528]

	2426.	[bug]		libbind: inet_net_pton() can sometimes return the
				wrong value if excessively large net masks are
				supplied. [RT #18512]

	2425.	[bug]		named didn't detect unavailable query source addresses
				at load time. [RT #18536]

	2424.	[port]		configure now probes for a working epoll
				implementation.  Allow the use of kqueue,
				epoll and /dev/poll to be selected at compile
				time. [RT #18277]

	2423.	[security]	Randomize server selection on queries, so as to
				make forgery a little more difficult.  Instead of
				always preferring the server with the lowest RTT,
				pick a server with RTT within the same 128
				millisecond band.  [RT #18441]

	2422.	[bug]		Handle the special return value of a empty node as
				if it was a NXRRSET in the validator. [RT #18447]

	2421.	[func]		Add new command line option '-S' for named to specify
				the max number of sockets. [RT #18493]
				Use caution: this option may not work for some
				operating systems without rebuilding named.

	2420.	[bug]		Windows socket handling cleanup.  Let the io
				completion event send out canceled read/write
				done events, which keeps us from writing to memory
				we no longer have ownership of.  Add debugging
				socket_log() function.  Rework TCP socket handling
				to not leak sockets.

	2419.	[cleanup]	Document that isc_socket_create() and isc_socket_open()
				should not be used for isc_sockettype_fdwatch sockets.
				[RT #18521]

	2418.	[bug]		AXFR request on a DLZ could trigger a REQUIRE failure
				[RT #18430]

	2417.	[bug]		Connecting UDP sockets for outgoing queries could
				unexpectedly fail with an 'address already in use'
				error. [RT #18411]

	2416.	[func]		Log file descriptors that cause exceeding the
				internal maximum. [RT #18460]

	2415.	[bug]		'rndc dumpdb' could trigger various assertion failures
				in rbtdb.c. [RT #18455]

	2414.	[bug]		A masterdump context held the database lock too long,
				causing various troubles such as dead lock and
				recursive lock acquisition. [RT #18311, #18456]

	2413.	[bug]		Fixed an unreachable code path in socket.c. [RT #18442]

	2412.	[bug]		win32: address a resource leak. [RT #18374]

	2411.	[bug]		Allow using a larger number of sockets than FD_SETSIZE
				for select().  To enable this, set ISC_SOCKET_MAXSOCKETS
				at compilation time.  [RT #18433]

				Note: with changes #2469 and #2421 above, there is no
				need to tweak ISC_SOCKET_MAXSOCKETS at compilation time
				any more.

	2410.	[bug]		Correctly delete m_versionInfo. [RT #18432]

	2409.	[bug]		Only log that we disabled EDNS processing if we were
				subsequently successful.  [RT #18029]

	2408.	[bug]		A duplicate TCP dispatch event could be sent, which
				could then trigger an assertion failure in
				resquery_response().  [RT #18275]

	2407.	[port]		hpux: test for sys/dyntune.h. [RT #18421]

	2406.	[placeholder]

	2405.	[cleanup]	The default value for dnssec-validation was changed to
				"yes" in 9.5.0-P1 and all subsequent releases; this
				was inadvertently omitted from CHANGES at the time.

	2404.	[port]		hpux: files unlimited support.

	2403.	[bug]		TSIG context leak. [RT #18341]

	2402.	[port]		Support Solaris 2.11 and over. [RT #18362]

	2401.	[bug]		Expect to get E[MN]FILE errno internal_accept()
				(from accept() or fcntl() system calls). [RT #18358]

	2400.	[bug]		Log if kqueue()/epoll_create()/open(/dev/poll) fails.
				[RT #18297]

	2399.	[placeholder]

	2398.	[bug]		Improve file descriptor management.  New,
				temporary, named.conf option reserved-sockets,
				default 512. [RT #18344]

	2397.	[bug]		gssapi_functions had too many elements. [RT #18355]

	2396.	[bug]		Don't set SO_REUSEADDR for randomized ports.
				[RT #18336]

	2395.	[port]		Avoid warning and no effect from "files unlimited"
				on Linux when running as root. [RT #18335]

	2394.	[bug]		Default configuration options set the limit for
				open files to 'unlimited' as described in the
				documentation. [RT #18331]

	2393.	[bug]		nested acls containing keys could trigger an
				assertion in acl.c. [RT #18166]

	2392.	[bug]		remove 'grep -q' from acl test script, some platforms
				don't support it. [RT #18253]

	2391.	[port]		hpux: cover additional recvmsg() error codes.
				[RT #18301]

	2390.	[bug]		dispatch.c could make a false warning on 'odd socket'.
				[RT #18301].

	2389.	[bug]		Move the "working directory writable" check to after
				the ns_os_changeuser() call. [RT #18326]

	2388.	[bug]		Avoid using tables for layout purposes in
				statistics XSL [RT #18159].

	2387.	[bug]		Silence compiler warnings in lib/isc/radix.c.
				[RT #18147] [RT #18258]

	2386.	[func]		Add warning about too small 'open files' limit.
				[RT #18269]

	2385.	[bug]		A condition variable in socket.c could leak in
				rare error handling [RT #17968].

	2384.	[security]	Fully randomize UDP query ports to improve
				forgery resilience. [RT #17949, #18098]

	2383.	[bug]		named could double queries when they resulted in
				SERVFAIL due to overkilling EDNS0 failure detection.
				[RT #18182]

	2382.	[doc]		Add descriptions of DHCID, IPSECKEY, SPF and SSHFP
				to ARM.

	2381.	[port]		dlz/mysql: support multiple install layouts for
				mysql.  <prefix>/include/{,mysql/}mysql.h and
				<prefix>/lib/{,mysql/}. [RT #18152]

	2380.	[bug]		dns_view_find() was not returning NXDOMAIN/NXRRSET
				proofs which, in turn, caused validation failures
				for insecure zones immediately below a secure zone
				the server was authoritative for. [RT #18112]

	2379.	[contrib]	queryperf/gen-data-queryperf.py: removed redundant
				TLDs and supported RRs with TTLs [RT #17972]

	2378.	[bug]		gssapi_functions{} had a redundant member in BIND 9.5.
				[RT #18169]

	2377.	[bug]		Address race condition in dnssec-signzone. [RT #18142]

	2376.	[bug]		Change #2144 was not complete.

	2375.	[placeholder]

	2374.	[bug]		"blackhole" ACLs could cause named to segfault due
				to some uninitialized memory. [RT #18095]

	2373.	[bug]		Default values of zone ACLs were re-parsed each time a
				new zone was configured, causing an overconsumption
				of memory. [RT #18092]

	2372.	[bug]		Fixed incorrect TAG_HMACSHA256_BITS value [RT #18047]

	2371.	[doc]		Add +nsid option to dig man page. [RT #18039]

	2370.	[bug]		"rndc freeze" could trigger an assertion in named
				when called on a nonexistent zone. [RT #18050]

	2369.	[bug]		libbind: Array bounds overrun on read in bitncmp().
				[RT #18054]

	2368.	[port]		Linux: use libcap for capability management if
				possible. [RT #18026]

	2367.	[bug]		Improve counting of dns_resstatscounter_retry
				[RT #18030]

	2366.	[bug]		Adb shutdown race. [RT #18021]

	2365.	[bug]		Fix a bug that caused dns_acl_isany() to return
				spurious results. [RT #18000]

	2364.	[bug]		named could trigger a assertion when serving a
				malformed signed zone. [RT #17828]

	2363.	[port]		sunos: pre-set "lt_cv_sys_max_cmd_len=4096;".
				[RT #17513]

	2362.	[cleanup]	Make "rrset-order fixed" a compile-time option.
				settable by "./configure --enable-fixed-rrset".
				Disabled by default. [RT #17977]

	2361.	[bug]		"recursion" statistics counter could be counted
				multiple times for a single query.  [RT #17990]

	2360.	[bug]		Fix a condition where we release a database version
				(which may acquire a lock) while holding the lock.

	2359.	[bug]		Fix NSID bug. [RT #17942]

	2358.	[doc]		Update host's default query description. [RT #17934]

	2357.	[port]		Don't use OpenSSL's engine support in versions before
				OpenSSL 0.9.7f. [RT #17922]

	2356.	[bug]		Built in mutex profiler was not scalable enough.
				[RT #17436]

	2355.	[func]		Extend the number statistics counters available.
				[RT #17590]

	2354.	[bug]		Failed to initialize some rdatasetheader_t elements.
				[RT #17927]

	2353.	[func]		Add support for Name Server ID (RFC 5001).
				'dig +nsid' requests NSID from server.
				'request-nsid yes;' causes recursive server to send
				NSID requests to upstream servers.  Server responds
				to NSID requests with the string configured by
				'server-id' option.  [RT #17091]

	2352.	[bug]		Various GSS_API fixups. [RT #17729]

	2351.	[bug]		convertxsl.pl generated very long lines. [RT #17906]

	2350.	[port]		win32: IPv6 support. [RT #17797]

	2349.	[func]		Provide incremental re-signing support for secure
				dynamic zones. [RT #1091]

	2348.	[func]		Use the EVP interface to OpenSSL. Add PKCS#11 support.
				Documentation is in the new README.pkcs11 file.
				New tool, dnssec-keyfromlabel, which takes the
				label of a key pair in a HSM and constructs a DNS
				key pair for use by named and dnssec-signzone.
				[RT #16844]

	2347.	[bug]		Delete now traverses the RB tree in the canonical
				order. [RT #17451]

	2346.	[func]		Memory statistics now cover all active memory contexts
				in increased detail. [RT #17580]

	2345.	[bug]		named-checkconf failed to detect when forwarders
				were set at both the options/view level and in
				a root zone. [RT #17671]

	2344.	[bug]		Improve "logging{ file ...; };" documentation.
				[RT #17888]

	2343.	[bug]		(Seemingly) duplicate IPv6 entries could be
				created in ADB. [RT #17837]

	2342.	[func]		Use getifaddrs() if available under Linux. [RT #17224]

	2341.	[bug]		libbind: add missing -I../include for off source
				tree builds. [RT #17606]

	2340.	[port]		openbsd: interface configuration. [RT #17700]

	2339.	[port]		tru64: support for libbind. [RT #17589]

	2338.	[bug]		check_ds() could be called with a non DS rdataset.
				[RT #17598]

	2337.	[bug]		BUILD_LDFLAGS was not being correctly set.  [RT #17614]

	2336.	[func]		If "named -6" is specified then listen on all IPv6
				interfaces if there are not listen-on-v6 clauses in
				named.conf.  [RT #17581]

	2335.	[port]		sunos:  libbind and *printf() support for long long.
				[RT #17513]

	2334.	[bug]		Bad REQUIRES in fromstruct_in_naptr(),  off by one
				bug in fromstruct_txt(). [RT #17609]

	2333.	[bug]		Fix off by one error in isc_time_nowplusinterval().
				[RT #17608]

	2332.	[contrib]	query-loc-0.4.0. [RT #17602]

	2331.	[bug]		Failure to regenerate any signatures was not being
				reported nor being past back to the UPDATE client.
				[RT #17570]

	2330.	[bug]		Remove potential race condition when handling
				over memory events. [RT #17572]

				WARNING: API CHANGE: over memory callback
				function now needs to call isc_mem_waterack().
				See <isc/mem.h> for details.

	2329.	[bug]		Clearer help text for dig's '-x' and '-i' options.

	2328.	[maint]		Add AAAA addresses for A.ROOT-SERVERS.NET,
				F.ROOT-SERVERS.NET, H.ROOT-SERVERS.NET,
				J.ROOT-SERVERS.NET, K.ROOT-SERVERS.NET and
				M.ROOT-SERVERS.NET.

	2327.	[bug]		It was possible to dereference a NULL pointer in
				rbtdb.c.  Implement dead node processing in zones as
				we do for caches. [RT #17312]

	2326.	[bug]		It was possible to trigger a INSIST in the acache
				processing.

	2325.	[port]		Linux: use capset() function if available. [RT #17557]

	2324.	[bug]		Fix IPv6 matching against "any;". [RT #17533]

	2323.	[port]		tru64: namespace clash. [RT #17547]

	2322.	[port]		MacOS: work around the limitation of setrlimit()
				for RLIMIT_NOFILE. [RT #17526]

	2321.	[placeholder]

	2320.	[func]		Make statistics counters thread-safe for platforms
				that support certain atomic operations. [RT #17466]

	2319.	[bug]		Silence Coverity warnings in
				lib/dns/rdata/in_1/apl_42.c. [RT #17469]

	2318.	[port]		sunos fixes for libbind.  [RT #17514]

	2317.	[bug]		"make distclean" removed bind9.xsl.h. [RT #17518]

	2316.	[port]		Missing #include <isc/print.h> in lib/dns/gssapictx.c.
				[RT #17513]

	2315.	[bug]		Used incorrect address family for mapped IPv4
				addresses in acl.c. [RT #17519]

	2314.	[bug]		Uninitialized memory use on error path in
				bin/named/lwdnoop.c.  [RT #17476]

	2313.	[cleanup]	Silence Coverity warnings. Handle private stacks.
				[RT #17447] [RT #17478]

	2312.	[cleanup]	Silence Coverity warning in lib/isc/unix/socket.c.
				[RT #17458]

	2311.	[bug]		IPv6 addresses could match IPv4 ACL entries and
				vice versa. [RT #17462]

	2310.	[bug]		dig, host, nslookup: flush stdout before emitting
				debug/fatal messages.  [RT #17501]

	2309.	[cleanup]	Fix Coverity warnings in lib/dns/acl.c and iptable.c.
				[RT #17455]

	2308.	[cleanup]	Silence Coverity warning in bin/named/controlconf.c.
				[RT #17495]

	2307.	[bug]		Remove infinite loop from lib/dns/sdb.c. [RT #17496]

	2306.	[bug]		Remove potential race from lib/dns/resolver.c.
				[RT #17470]

	2305.	[security]	inet_network() buffer overflow. CVE-2008-0122.

	2304.	[bug]		Check returns from all dns_rdata_tostruct() calls.
				[RT #17460]

	2303.	[bug]		Remove unnecessary code from bin/named/lwdgnba.c.
				[RT #17471]

	2302.	[bug]		Fix memset() calls in lib/tests/t_api.c. [RT #17472]

	2301.	[bug]		Remove resource leak and fix error messages in
				bin/tests/system/lwresd/lwtest.c. [RT #17474]

	2300.	[bug]		Fixed failure to close open file in
				bin/tests/names/t_names.c. [RT #17473]

	2299.	[bug]		Remove unnecessary NULL check in
				bin/nsupdate/nsupdate.c. [RT #17475]

	2298.	[bug]		isc_mutex_lock() failure not caught in
				bin/tests/timers/t_timers.c. [RT #17468]

	2297.	[bug]		isc_entropy_createfilesource() failure not caught in
				bin/tests/dst/t_dst.c. [RT #17467]

	2296.	[port]		Allow docbook stylesheet location to be specified to
				configure. [RT #17457]

	2295.	[bug]		Silence static overrun error in bin/named/lwaddr.c.
				[RT #17459]

	2294.	[func]		Allow the experimental statistics channels to have
				multiple connections and ACL.
				Note: the stats-server and stats-server-v6 options
				available in the previous beta releases are replaced
				with the generic statistics-channels statement.

	2293.	[func]		Add ACL regression test. [RT #17375]

	2292.	[bug]		Log if the working directory is not writable.
				[RT #17312]

	2291.	[bug]		PR_SET_DUMPABLE may be set too late.  Also report
				failure to set PR_SET_DUMPABLE. [RT #17312]

	2290.	[bug]		Let AD in the query signal that the client wants AD
				set in the response. [RT #17301]

	2289.	[func]		named-checkzone now reports the out-of-zone CNAME
				found. [RT #17309]

	2288.	[port]		win32: mark service as running when we have finished
				loading.  [RT #17441]

	2287.	[bug]		Use 'volatile' if the compiler supports it. [RT #17413]

	2286.	[func]		Allow a TCP connection to be used as a weak
				authentication method for reverse zones.
				New update-policy methods tcp-self and 6to4-self.
				[RT #17378]

	2285.	[func]		Test framework for client memory context management.
				[RT #17377]

	2284.	[bug]		Memory leak in UPDATE prerequisite processing.
				[RT #17377]

	2283.	[bug]		TSIG keys were not attaching to the memory
				context.  TSIG keys should use the rings
				memory context rather than the clients memory
				context. [RT #17377]

	2282.	[bug]		Acl code fixups. [RT #17346] [RT #17374]

	2281.	[bug]		Attempts to use undefined acls were not being logged.
				[RT #17307]

	2280.	[func]		Allow the experimental http server to be reached
				over IPv6 as well as IPv4. [RT #17332]

	2279.	[bug]		Use setsockopt(SO_NOSIGPIPE), when available,
				to protect applications from receiving spurious
				SIGPIPE signals when using the resolver.

	2278.	[bug]		win32: handle the case where Windows returns no
				search list or DNS suffix. [RT #17354]

	2277.	[bug]		Empty zone names were not correctly being caught at
				in the post parse checks. [RT #17357]

	2276.	[bug]		Install <dst/gssapi.h>.  [RT #17359]

	2275.	[func]		Add support to dig to perform IXFR queries over UDP.
				[RT #17235]

	2274.	[func]		Log zone transfer statistics. [RT #17336]

	2273.	[bug]		Adjust log level to WARNING when saving inconsistent
				stub/slave master and journal files. [RT #17279]

	2272.	[bug]		Handle illegal dnssec-lookaside trust-anchor names.
				[RT #17262]

	2271.	[bug]		Fix a memory leak in http server code [RT #17100]

	2270.	[bug]		dns_db_closeversion() version->writer could be reset
				before it is tested. [RT #17290]

	2269.	[contrib]	dbus memory leaks and missing va_end calls. [RT #17232]

	2268.	[bug]		0.IN-ADDR.ARPA was missing from the empty zones
				list.

.. code-block:: none

		--- 9.5.0b1 released ---

	2267.	[bug]		Radix tree node_num value could be set incorrectly,
				causing positive ACL matches to look like negative
				ones.  [RT #17311]

	2266.	[bug]		client.c:get_clientmctx() returned the same mctx
				once the pool of mctx's was filled. [RT #17218]

	2265.	[bug]		Test that the memory context's basic_table is non NULL
				before freeing.  [RT #17265]

	2264.	[bug]		Server prefix length was being ignored. [RT #17308]

	2263.	[bug]		"named-checkconf -z" failed to set default value
				for "check-integrity".  [RT #17306]

	2262.	[bug]		Error status from all but the last view could be
				lost. [RT #17292]

	2261.	[bug]		Fix memory leak with "any" and "none" ACLs [RT #17272]

	2260.	[bug]		Reported wrong clients-per-query when increasing the
				value. [RT #17236]

	2259.	[placeholder]

.. code-block:: none

		--- 9.5.0a7 released ---

	2258.	[bug]		Fallback from IXFR/TSIG to SOA/AXFR/TSIG broken.
				[RT #17241]

	2257.	[bug]		win32: Use the full path to vcredist_x86.exe when
				calling it. [RT #17222]

	2256.	[bug]		win32: Correctly register the installation location of
				bindevt.dll. [RT #17159]

	2255.	[maint]		L.ROOT-SERVERS.NET is now 199.7.83.42.

	2254.	[bug]		timer.c:dispatch() failed to lock timer->lock
				when reading timer->idle allowing it to see
				intermediate values as timer->idle was reset by
				isc_timer_touch(). [RT #17243]

	2253.	[func]		"max-cache-size" defaults to 32M.
				"max-acache-size" defaults to 16M.

	2252.	[bug]		Fixed errors in sortlist code [RT #17216]

	2251.	[placeholder]

	2250.	[func]		New flag 'memstatistics' to state whether the
				memory statistics file should be written or not.
				Additionally named's -m option will cause the
				statistics file to be written. [RT #17113]

	2249.	[bug]		Only set Authentic Data bit if client requested
				DNSSEC, per RFC 3655 [RT #17175]

	2248.	[cleanup]	Fix several errors reported by Coverity. [RT #17160]

	2247.	[doc]		Sort doc/misc/options. [RT #17067]

	2246.	[bug]		Make the startup of test servers (ans.pl) more
				robust. [RT #17147]

	2245.	[bug]		Validating lack of DS records at trust anchors wasn't
				working. [RT #17151]

	2244.	[func]		Allow the check of nameserver names against the
				SOA MNAME field to be disabled by specifying
				'notify-to-soa yes;'.  [RT #17073]

	2243.	[func]		Configuration files without a newline at the end now
				parse without error. [RT #17120]

	2242.	[bug]		nsupdate: GSS-TSIG support using the Heimdal Kerberos
				library could require a source of random data.
				[RT #17127]

	2241.	[func]		nsupdate: add a interactive 'help' command. [RT #17099]

	2240.	[bug]		Cleanup nsupdates GSS-TSIG support.  Convert
				a number of INSIST()s into plain fatal() errors
				which report the triggering result code.
				The 'key' command wasn't disabling GSS-TSIG.
				[RT #17099]

	2239.	[func]		Ship a pre built bin/named/bind9.xsl.h. [RT #17114]

	2238.	[bug]		It was possible to trigger a REQUIRE when a
				validation was canceled. [RT #17106]

	2237.	[bug]		libbind: res_init() was not thread aware. [RT #17123]

	2236.	[bug]		dnssec-signzone failed to preserve the case of
				of wildcard owner names. [RT #17085]

	2235.	[bug]		<isc/atomic.h> was not being installed. [RT #17135]

	2234.	[port]		Correct some compiler warnings on SCO OSr5 [RT #17134]

	2233.	[func]		Add support for O(1) ACL processing, based on
				radix tree code originally written by Kevin
				Brintnall. [RT #16288]

	2232.	[bug]		dns_adb_findaddrinfo() could fail and return
				ISC_R_SUCCESS. [RT #17137]

	2231.	[bug]		Building dlzbdb (contrib/dlz/bin/dlzbdb) was broken.
				[RT #17088]

	2230.	[bug]		We could INSIST reading a corrupted journal.
				[RT #17132]

	2229.	[bug]		Null pointer dereference on query pool creation
				failure. [RT #17133]

	2228.	[contrib]	contrib: Change 2188 was incomplete.

	2227.	[cleanup]	Tidied up the FAQ. [RT #17121]

	2226.	[placeholder]

	2225.	[bug]		More support for systems with no IPv4 addresses.
				[RT #17111]

	2224.	[bug]		Defer journal compaction if a xfrin is in progress.
				[RT #17119]

	2223.	[bug]		Make a new journal when compacting. [RT #17119]

	2222.	[func]		named-checkconf now checks server key references.
				[RT #17097]

	2221.	[bug]		Set the event result code to reflect the actual
				record turned to caller when a cache update is
				rejected due to a more credible answer existing.
				[RT #17017]

	2220.	[bug]		win32: Address a race condition in final shutdown of
				the Windows socket code. [RT #17028]

	2219.	[bug]		Apply zone consistency checks to additions, not
				removals, when updating. [RT #17049]

	2218.	[bug]		Remove unnecessary REQUIRE from dns_validator_create().
				[RT #16976]

	2217.	[func]		Adjust update log levels. [RT #17092]

	2216.	[cleanup]	Fix a number of errors reported by Coverity.
				[RT #17094]

	2215.	[bug]		Bad REQUIRE check isc_hmacsha1_verify(). [RT #17094]

	2214.	[bug]		Deregister OpenSSL lock callback when cleaning
				up.  Reorder OpenSSL cleanup so that RAND_cleanup()
				is called before the locks are destroyed. [RT #17098]

	2213.	[bug]		SIG0 diagnostic failure messages were looking at the
				wrong status code. [RT #17101]

	2212.	[func]		'host -m' now causes memory statistics and active
				memory to be printed at exit. [RT 17028]

	2211.	[func]		Update "dynamic update temporarily disabled" message.
				[RT #17065]

	2210.	[bug]		Deleting class specific records via UPDATE could
				fail.  [RT #17074]

	2209.	[port]		osx: linking against user supplied static OpenSSL
				libraries failed as the system ones were still being
				found. [RT #17078]

	2208.	[port]		win32: make sure both build methods produce the
				same output. [RT #17058]

	2207.	[port]		Some implementations of getaddrinfo() fail to set
				ai_canonname correctly. [RT #17061]

.. code-block:: none

		--- 9.5.0a6 released ---

	2206.	[security]	"allow-query-cache" and "allow-recursion" now
				cross inherit from each other.

				If allow-query-cache is not set in named.conf then
				allow-recursion is used if set, otherwise allow-query
				is used if set, otherwise the default (localnets;
				localhost;) is used.

				If allow-recursion is not set in named.conf then
				allow-query-cache is used if set, otherwise allow-query
				is used if set, otherwise the default (localnets;
				localhost;) is used.

				[RT #16987]

	2205.	[bug]		libbind: change #2119 broke thread support. [RT #16982]

	2204.	[bug]		"rndc flushname name unknown-view" caused named
				to crash. [RT #16984]

	2203.	[security]	Query id generation was cryptographically weak.
				[RT # 16915]

	2202.	[security]	The default acls for allow-query-cache and
				allow-recursion were not being applied. [RT #16960]

	2201.	[bug]		The build failed in a separate object directory.
				[RT #16943]

	2200.	[bug]		The search for cached NSEC records was stopping to
				early leading to excessive DLV queries. [RT #16930]

	2199.	[bug]		win32: don't call WSAStartup() while loading dlls.
				[RT #16911]

	2198.	[bug]		win32: RegCloseKey() could be called when
				RegOpenKeyEx() failed. [RT #16911]

	2197.	[bug]		Add INSIST to catch negative responses which are
				not setting the event result code appropriately.
				[RT #16909]

	2196.	[port]		win32: yield processor while waiting for once to
				to complete. [RT #16958]

	2195.	[func]		dnssec-keygen now defaults to nametype "ZONE"
				when generating DNSKEYs. [RT #16954]

	2194.	[bug]		Close journal before calling 'done' in xfrin.c.

.. code-block:: none

		--- 9.5.0a5 released ---

	2193.	[port]		win32: BINDInstall.exe is now linked statically.
				[RT #16906]

	2192.	[port]		win32: use vcredist_x86.exe to install Visual
				Studio's redistributable dlls if building with
				Visual Stdio 2005 or later.

	2191.	[func]		named-checkzone now allows dumping to stdout (-).
				named-checkconf now has -h for help.
				named-checkzone now has -h for help.
				rndc now has -h for help.
				Better handling of '-?' for usage summaries.
				[RT #16707]

	2190.	[func]		Make fallback to plain DNS from EDNS due to timeouts
				more visible.  New logging category "edns-disabled".
				[RT #16871]

	2189.	[bug]		Handle socket() returning EINTR. [RT #15949]

	2188.	[contrib]	queryperf: autoconf changes to make the search for
				libresolv or libbind more robust. [RT #16299]

	2187.	[bug]		query_addds(), query_addwildcardproof() and
				query_addnxrrsetnsec() should take a version
				argument. [RT #16368]

	2186.	[port]		cygwin: libbind: check for struct sockaddr_storage
				independently of IPv6. [RT #16482]

	2185.	[port]		sunos: libbind: check for ssize_t, memmove() and
				memchr(). [RT #16463]

	2184.	[bug]		bind9.xsl.h didn't build out of the source tree.
				[RT #16830]

	2183.	[bug]		dnssec-signzone didn't handle offline private keys
				well.  [RT #16832]

	2182.	[bug]		dns_dispatch_createtcp() and dispatch_createudp()
				could return ISC_R_SUCCESS when they ran out of
				memory. [RT #16365]

	2181.	[port]		sunos: libbind: add paths.h from BIND 8. [RT #16462]

	2180.	[cleanup]	Remove bit test from 'compress_test' as they
				are no longer needed. [RT #16497]

	2179.	[func]		'rndc command zone' will now find 'zone' if it is
				unique to all the views. [RT #16821]

	2178.	[bug]		'rndc reload' of a slave or stub zone resulted in
				a reference leak. [RT #16867]

	2177.	[bug]		Array bounds overrun on read (rcodetext) at
				debug level 10+. [RT #16798]

	2176.	[contrib]	dbus update to handle race condition during
				initialization (Bugzilla 235809). [RT #16842]

	2175.	[bug]		win32: windows broadcast condition variable support
				was broken. [RT #16592]

	2174.	[bug]		I/O errors should always be fatal when reading
				master files. [RT #16825]

	2173.	[port]		win32: When compiling with MSVS 2005 SP1 we also
				need to ship Microsoft.VC80.MFCLOC.

.. code-block:: none

		--- 9.5.0a4 released ---

	2172.	[bug]		query_addsoa() was being called with a non zone db.
				[RT #16834]

	2171.	[bug]		Handle breaks in DNSSEC trust chains where the parent
				servers are not DS aware (DS queries to the parent
				return a referral to the child).

	2170.	[func]		Add acache processing to test suite. [RT #16711]

	2169.	[bug]		host, nslookup: when reporting NXDOMAIN report the
				given name and not the last name searched for.
				[RT #16763]

	2168.	[bug]		nsupdate: in non-interactive mode treat syntax errors
				as fatal errors. [RT #16785]

	2167.	[bug]		When re-using a automatic zone named failed to
				attach it to the new view. [RT #16786]

.. code-block:: none

		--- 9.5.0a3 released ---

	2166.	[bug]		When running in batch mode, dig could misinterpret
				a server address as a name to be looked up, causing
				unexpected output. [RT #16743]

	2165.	[func]		Allow the destination address of a query to determine
				if we will answer the query or recurse.
				allow-query-on, allow-recursion-on and
				allow-query-cache-on. [RT #16291]

	2164.	[bug]		The code to determine how named-checkzone /
				named-compilezone was called failed under windows.
				[RT #16764]

	2163.	[bug]		If only one of query-source and query-source-v6
				specified a port the query pools code broke (change
				2129).  [RT #16768]

	2162.	[func]		Allow "rrset-order fixed" to be disabled at compile
				time. [RT #16665]

	2161.	[bug]		Fix which log messages are emitted for 'rndc flush'.
				[RT #16698]

	2160.	[bug]		libisc wasn't handling NULL ifa_addr pointers returned
				from getifaddrs(). [RT #16708]

.. code-block:: none

		--- 9.5.0a2 released ---

	2159.	[bug]		Array bounds overrun in acache processing. [RT #16710]

	2158.	[bug]		ns_client_isself() failed to initialize key
				leading to a REQUIRE failure. [RT #16688]

	2157.	[func]		dns_db_transfernode() created. [RT #16685]

	2156.	[bug]		Fix node reference leaks in lookup.c:lookup_find(),
				resolver.c:validated() and resolver.c:cache_name().
				Fix a memory leak in rbtdb.c:free_noqname().
				Make lookup.c:lookup_find() robust against
				event leaks. [RT #16685]

	2155.	[contrib]	SQLite sdb module from jaboydjr@netwalk.com.
				[RT #16694]

	2154.	[func]		Scoped (e.g. IPv6 link-local) addresses may now be
				matched in acls by omitting the scope. [RT #16599]

	2153.	[bug]		nsupdate could leak memory. [RT #16691]

	2152.	[cleanup]	Use sizeof(buf) instead of fixed number in
				dighost.c:get_trusted_key(). [RT #16678]

	2151.	[bug]		Missing newline in usage message for journalprint.
				[RT #16679]

	2150.	[bug]		'rrset-order cyclic' uniformly distribute the
				starting point for the first response for a given
				RRset. [RT #16655]

	2149.	[bug]		isc_mem_checkdestroyed() failed to abort on
				if there were still active memory contexts.
				[RT #16672]

	2148.	[func]		Add positive logging for rndc commands. [RT #14623]

	2147.	[bug]		libbind: remove potential buffer overflow from
				hmac_link.c. [RT #16437]

	2146.	[cleanup]	Silence Linux's spurious "obsolete setsockopt
				SO_BSDCOMPAT" message. [RT #16641]

	2145.	[bug]		Check DS/DLV digest lengths for known digests.
				[RT #16622]

	2144.	[cleanup]	Suppress logging of SERVFAIL from forwarders.
				[RT #16619]

	2143.	[bug]		We failed to restart the IPv6 client when the
				kernel failed to return the destination the
				packet was sent to. [RT #16613]

	2142.	[bug]		Handle master files with a modification time that
				matches the epoch. [RT #16612]

	2141.	[bug]		dig/host should not be setting IDN_ASCCHECK (IDN
				equivalent of LDH checks).  [RT #16609]

	2140.	[bug]		libbind: missing unlock on pthread_key_create()
				failures. [RT #16654]

	2139.	[bug]		dns_view_find() was being called with wrong type
				in adb.c. [RT #16670]

	2138.	[bug]		Lock order reversal in resolver.c. [RT #16653]

	2137.	[port]		Mips little endian and/or mips 64 bit are now
				supported for atomic operations. [RT #16648]

	2136.	[bug]		nslookup/host looped if there was no search list
				and the host didn't exist. [RT #16657]

	2135.	[bug]		Uninitialized rdataset in sdlz.c. [RT #16656]

	2134.	[func]		Additional statistics support. [RT #16666]

	2133.	[port]		powerpc:  Support both IBM and MacOS Power PC
				assembler syntaxes. [RT #16647]

	2132.	[bug]		Missing unlock on out of memory in
				dns_dispatchmgr_setudp().

	2131.	[contrib]	dlz/mysql: AXFR was broken. [RT #16630]

	2130.	[func]		Log if CD or DO were set. [RT #16640]

	2129.	[func]		Provide a pool of UDP sockets for queries to be
				made over. See use-queryport-pool, queryport-pool-ports
				and queryport-pool-updateinterval.  [RT #16415]

	2128.	[doc]		xsltproc --nonet, update DTD versions.  [RT #16635]

	2127.	[port]		Improved OpenSSL 0.9.8 support. [RT #16563]

	2126.	[security]	Serialize validation of type ANY responses. [RT #16555]

	2125.	[bug]		dns_zone_getzeronosoattl() REQUIRE failure if DLZ
				was defined. [RT #16574]

	2124.	[security]	It was possible to dereference a freed fetch
				context. [RT #16584]

.. code-block:: none

		--- 9.5.0a1 released ---

	2123.	[func]		Use Doxygen to generate internal documentation.
				[RT #11398]

	2122.	[func]		Experimental http server and statistics support
				for named via xml.

	2121.	[func]		Add a 10 slot dead masters cache (LRU) with a 600
				second timeout. [RT #16553]

	2120.	[doc]		Fix markup on nsupdate man page. [RT #16556]

	2119.	[compat]	libbind: allow res_init() to succeed enough to
				return the default domain even if it was unable
				to allocate memory.

	2118.	[bug]		Handle response with long chains of domain name
				compression pointers which point to other compression
				pointers. [RT #16427]

	2117.	[bug]		DNSSEC fixes: named could fail to cache NSEC records
				which could lead to validation failures.  named didn't
				handle negative DS responses that were in the process
				of being validated.  Check CNAME bit before accepting
				NODATA proof. To be able to ignore a child NSEC there
				must be SOA (and NS) set in the bitmap. [RT #16399]

	2116.	[bug]		'rndc reload' could cause the cache to continually
				be cleaned. [RT #16401]

	2115.	[bug]		'rndc reconfig' could trigger a INSIST if the
				number of masters for a zone was reduced. [RT #16444]

	2114.	[bug]		dig/host/nslookup: searches for names with multiple
				labels were failing. [RT #16447]

	2113.	[bug]		nsupdate: if a zone is specified it should be used
				for server discover. [RT #16455]

	2112.	[security]	Warn if weak RSA exponent is used. [RT #16460]

	2111.	[bug]		Fix a number of errors reported by Coverity.
				[RT #16507]

	2110.	[bug]		"minimal-responses yes;" interacted badly with BIND 8
				priming queries. [RT #16491]

	2109.	[port]		libbind: silence aix 5.3 compiler warnings. [RT #16502]

	2108.	[func]		DHCID support. [RT #16456]

	2107.	[bug]		dighost.c: more cleanup of buffers. [RT #16499]

	2106.	[func]		'rndc status' now reports named's version. [RT #16426]

	2105.	[func]		GSS-TSIG support (RFC 3645).

	2104.	[port]		Fix Solaris SMF error message.

	2103.	[port]		Add /usr/sfw to list of locations for OpenSSL
				under Solaris.

	2102.	[port]		Silence Solaris 10 warnings.

	2101.	[bug]		OpenSSL version checks were not quite right.
				[RT #16476]

	2100.	[port]		win32: copy libeay32.dll to Build\Debug.
				Copy Debug\named-checkzone to Debug\named-compilezone.

	2099.	[port]		win32: more manifest issues.

	2098.	[bug]		Race in rbtdb.c:no_references(), which occasionally
				triggered an INSIST failure about the node lock
				reference.  [RT #16411]

	2097.	[bug]		named could reference a destroyed memory context
				after being reloaded / reconfigured. [RT #16428]

	2096.	[bug]		libbind: handle applications that fail to detect
				res_init() failures better.

	2095.	[port]		libbind: always prototype inet_cidr_ntop_ipv6() and
				net_cidr_ntop_ipv6(). [RT #16388]

	2094.	[contrib]	Update named-bootconf.  [RT #16404]

	2093.	[bug]		named-checkzone -s was broken.

	2092.	[bug]		win32: dig, host, nslookup.  Use registry config
				if resolv.conf does not exist or no nameservers
				listed. [RT #15877]

	2091.	[port]		dighost.c: race condition on cleanup. [RT #16417]

	2090.	[port]		win32: Visual C++ 2005 command line manifest support.
				[RT #16417]

	2089.	[security]	Raise the minimum safe OpenSSL versions to
				OpenSSL 0.9.7l and OpenSSL 0.9.8d.  Versions
				prior to these have known security flaws which
				are (potentially) exploitable in named. [RT #16391]

	2088.	[security]	Change the default RSA exponent from 3 to 65537.
				[RT #16391]

	2087.	[port]		libisc failed to compile on OS's w/o a vsnprintf.
				[RT #16382]

	2086.	[port]		libbind: FreeBSD now has get*by*_r() functions.
				[RT #16403]

	2085.	[doc]		win32: added index.html and README to zip. [RT #16201]

	2084.	[contrib]	dbus update for 9.3.3rc2.

	2083.	[port]		win32: Visual C++ 2005 support.

	2082.	[doc]		Document 'cache-file' as a test only option.

	2081.	[port]		libbind: minor 64-bit portability fix in memcluster.c.
				[RT #16360]

	2080.	[port]		libbind: res_init.c did not compile on older versions
				of Solaris. [RT #16363]

	2079.	[bug]		The lame cache was not handling multiple types
				correctly. [RT #16361]

	2078.	[bug]		dnssec-checkzone output style "default" was badly
				named.  It is now called "relative". [RT #16326]

	2077.	[bug]		'dnssec-signzone -O raw' wasn't outputting the
				complete signed zone. [RT #16326]

	2076.	[bug]		Several files were missing #include <config.h>
				causing build failures on OSF. [RT #16341]

	2075.	[bug]		The spillat timer event handler could leak memory.
				[RT #16357]

	2074.	[bug]		dns_request_createvia2(), dns_request_createvia3(),
				dns_request_createraw2() and dns_request_createraw3()
				failed to send multiple UDP requests. [RT #16349]

	2073.	[bug]		Incorrect semantics check for update policy "wildcard".
				[RT #16353]

	2072.	[bug]		We were not generating valid HMAC SHA digests.
				[RT #16320]

	2071.	[port]		Test whether gcc accepts -fno-strict-aliasing.
				[RT #16324]

	2070.	[bug]		The remote address was not always displayed when
				reporting dispatch failures. [RT #16315]

	2069.	[bug]		Cross compiling was not working. [RT #16330]

	2068.	[cleanup]	Lower incremental tuning message to debug 1.
				[RT #16319]

	2067.	[bug]		'rndc' could close the socket too early triggering
				a INSIST under Windows. [RT #16317]

	2066.	[security]	Handle SIG queries gracefully. [RT #16300]

	2065.	[bug]		libbind: probe for HPUX prototypes for
				endprotoent_r() and endservent_r().  [RT 16313]

	2064.	[bug]		libbind: silence AIX compiler warnings. [RT #16218]

	2063.	[bug]		Change #1955 introduced a bug which caused the first
				'rndc flush' call to not free memory. [RT #16244]

	2062.	[bug]		'dig +nssearch' was reusing a buffer before it had
				been returned by the socket code. [RT #16307]

	2061.	[bug]		Accept expired wildcard message reversed. [RT #16296]

	2060.	[bug]		Enabling DLZ support could leave views partially
				configured. [RT #16295]

	2059.	[bug]		Search into cache rbtdb could trigger an INSIST
				failure while cleaning up a stale rdataset.
				[RT #16292]

	2058.	[bug]		Adjust how we calculate rtt estimates in the presence
				of authoritative servers that drop EDNS and/or CD
				requests.  Also fallback to EDNS/512 and plain DNS
				faster for zones with less than 3 servers.  [RT #16187]

	2057.	[bug]		Make setting "ra" dependent on both allow-query-cache
				and allow-recursion. [RT #16290]

	2056.	[bug]		dig: ixfr= was not being treated case insensitively
				at all times. [RT #15955]

	2055.	[bug]		Missing goto after dropping multicast query.
				[RT #15944]

	2054.	[port]		freebsd: do not explicitly link against -lpthread.
				[RT #16170]

	2053.	[port]		netbsd:libbind: silence compiler warnings. [RT #16220]

	2052.	[bug]		'rndc' improve connect failed message to report
				the failing address. [RT #15978]

	2051.	[port]		More strtol() fixes. [RT #16249]

	2050.	[bug]		Parsing of NSAP records was not case insensitive.
				[RT #16287]

	2049.	[bug]		Restore SOA before AXFR when falling back from
				a attempted IXFR when transferring in a zone.
				Allow a initial SOA query before attempting
				a AXFR to be requested. [RT #16156]

	2048.	[bug]		It was possible to loop forever when using
				avoid-v4-udp-ports / avoid-v6-udp-ports when
				the OS always returned the same local port.
				[RT #16182]

	2047.	[bug]		Failed to initialize the interface flags to zero.
				[RT #16245]

	2046.	[bug]		rbtdb.c:rdataset_setadditional() could cause duplicate
				cleanup [RT #16247].

	2045.	[func]		Use lock buckets for acache entries to limit memory
				consumption. [RT #16183]

	2044.	[port]		Add support for atomic operations for Itanium.
				[RT #16179]

	2043.	[port]		nsupdate/nslookup: Force the flushing of the prompt
				for interactive sessions. [RT #16148]

	2042.	[bug]		named-checkconf was incorrectly rejecting the
				logging category "config". [RT #16117]

	2041.	[bug]		"configure --with-dlz-bdb=yes" produced a bad
				set of libraries to be linked. [RT #16129]

	2040.	[bug]		rbtdb no_references() could trigger an INSIST
				failure with --enable-atomic.  [RT #16022]

	2039.	[func]		Check that all buffers passed to the socket code
				have been retrieved when the socket event is freed.
				[RT #16122]

	2038.	[bug]		dig/nslookup/host was unlinking from wrong list
				when handling errors. [RT #16122]

	2037.	[func]		When unlinking the first or last element in a list
				check that the list head points to the element to
				be unlinked. [RT #15959]

	2036.	[bug]		'rndc recursing' could cause trigger a REQUIRE.
				[RT #16075]

	2035.	[func]		Make falling back to TCP on UDP refresh failure
				optional. Default "try-tcp-refresh yes;" for BIND 8
				compatibility. [RT #16123]

	2034.	[bug]		gcc: set -fno-strict-aliasing. [RT #16124]

	2033.	[bug]		We weren't creating multiple client memory contexts
				on demand as expected. [RT #16095]

	2032.	[bug]		Remove a INSIST in query_addadditional2(). [RT #16074]

	2031.	[bug]		Emit a error message when "rndc refresh" is called on
				a non slave/stub zone. [RT # 16073]

	2030.	[bug]		We were being overly conservative when disabling
				openssl engine support. [RT #16030]

	2029.	[bug]		host printed out the server multiple times when
				specified on the command line. [RT #15992]

	2028.	[port]		linux: socket.c compatibility for old systems.
				[RT #16015]

	2027.	[port]		libbind: Solaris x86 support. [RT #16020]

	2026.	[bug]		Rate limit the two recursive client exceeded messages.
				[RT #16044]

	2025.	[func]		Update "zone serial unchanged" message. [RT #16026]

	2024.	[bug]		named emitted spurious "zone serial unchanged"
				messages on reload. [RT #16027]

	2023.	[bug]		"make install" should create ${localstatedir}/run and
				${sysconfdir} if they do not exist. [RT #16033]

	2022.	[bug]		If dnssec validation is disabled only assert CD if
				CD was requested. [RT #16037]

	2021.	[bug]		dnssec-enable no; triggered a REQUIRE. [RT #16037]

	2020.	[bug]		rdataset_setadditional() could leak memory. [RT #16034]

	2019.	[tuning]	Reduce the amount of work performed per quantum
				when cleaning the cache. [RT #15986]

	2018.	[bug]		Checking if the HMAC MD5 private file was broken.
				[RT #15960]

	2017.	[bug]		allow-query default was not correct. [RT #15946]

	2016.	[bug]		Return a partial answer if recursion is not
				allowed but requested and we had the answer
				to the original qname. [RT #15945]

	2015.	[cleanup]	use-additional-cache is now acache-enable for
				consistency.  Default acache-enable off in BIND 9.4
				as it requires memory usage to be configured.
				It may be enabled by default in BIND 9.5 once we
				have more experience with it.

	2014.	[func]		Statistics about acache now recorded and sent
				to log. [RT #15976]

	2013.	[bug]		Handle unexpected TSIGs on unsigned AXFR/IXFR
				responses more gracefully. [RT #15941]

	2012.	[func]		Don't insert new acache entries if acache is full.
				[RT #15970]

	2011.	[func]		dnssec-signzone can now update the SOA record of
				the signed zone, either as an increment or as the
				system time(). [RT #15633]

	2010.	[placeholder]	rt15958

	2009.	[bug]		libbind: Coverity fixes. [RT #15808]

	2008.	[func]		It is now possible to enable/disable DNSSEC
				validation from rndc.  This is useful for the
				mobile hosts where the current connection point
				breaks DNSSEC (firewall/proxy).  [RT #15592]

					rndc validation newstate [view]

	2007.	[func]		It is now possible to explicitly enable DNSSEC
				validation.  default dnssec-validation no; to
				be changed to yes in 9.5.0.  [RT #15674]

	2006.	[security]	Allow-query-cache and allow-recursion now default
				to the built in acls "localnets" and "localhost".

				This is being done to make caching servers less
				attractive as reflective amplifying targets for
				spoofed traffic.  This still leave authoritative
				servers exposed.

				The best fix is for full BCP 38 deployment to
				remove spoofed traffic.

	2005.	[bug]		libbind: Retransmission timeouts should be
				based on which attempt it is to the nameserver
				and not the nameserver itself. [RT #13548]

	2004.	[bug]		dns_tsig_sign() could pass a NULL pointer to
				dst_context_destroy() when cleaning up after a
				error. [RT #15835]

	2003.	[bug]		libbind: The DNS name/address lookup functions could
				occasionally follow a random pointer due to
				structures not being completely zeroed. [RT #15806]

	2002.	[bug]		libbind: tighten the constraints on when
				struct addrinfo._ai_pad exists.  [RT #15783]

	2001.	[func]		Check the KSK flag when updating a secure dynamic zone.
				New zone option "update-check-ksk yes;".  [RT #15817]

	2000.	[bug]		memmove()/strtol() fix was incomplete. [RT #15812]

	1999.	[func]		Implement "rrset-order fixed". [RT #13662]

	1998.	[bug]		Restrict handling of fifos as sockets to just SunOS.
				This allows named to connect to entropy gathering
				daemons that use fifos instead of sockets. [RT #15840]

	1997.	[bug]		Named was failing to replace negative cache entries
				when a positive one for the type was learnt.
				[RT #15818]

	1996.	[bug]		nsupdate: if a zone has been specified it should
				appear in the output of 'show'. [RT #15797]

	1995.	[bug]		'host' was reporting multiple "is an alias" messages.
				[RT #15702]

	1994.	[port]		OpenSSL 0.9.8 support. [RT #15694]

	1993.	[bug]		Log messages, via syslog, were missing the space
				after the timestamp if "print-time yes" was specified.
				[RT #15844]

	1992.	[bug]		Not all incoming zone transfer messages included the
				view.  [RT #15825]

	1991.	[cleanup]	The configuration data, once read, should be treated
				as read only.  Expand the use of const to enforce this
				at compile time. [RT #15813]

	1990.	[bug]		libbind:  isc's override of broken gettimeofday()
				implementations was not always effective.
				[RT #15709]

	1989.	[bug]		win32: don't check the service password when
				re-installing. [RT #15882]

	1988.	[bug]		Remove a bus error from the SHA256/SHA512 support.
				[RT #15878]

	1987.	[func]		DS/DLV SHA256 digest algorithm support. [RT #15608]

	1986.	[func]		Report when a zone is removed. [RT #15849]

	1985.	[protocol]	DLV has now been assigned a official type code of
				32769. [RT #15807]

				Note: care should be taken to ensure you upgrade
				both named and dnssec-signzone at the same time for
				zones with DLV records where named is the master
				server for the zone.  Also any zones that contain
				DLV records should be removed when upgrading a slave
				zone.  You do not however have to upgrade all
				servers for a zone with DLV records simultaneously.

	1984.	[func]		dig, nslookup and host now advertise a 4096 byte
				EDNS UDP buffer size by default. [RT #15855]

	1983.	[func]		Two new update policies.  "selfsub" and "selfwild".
				[RT #12895]

	1982.	[bug]		DNSKEY was being accepted on the parent side of
				a delegation.  KEY is still accepted there for
				RFC 3007 validated updates. [RT #15620]

	1981.	[bug]		win32: condition.c:wait() could fail to reattain
				the mutex lock.

	1980.	[func]		dnssec-signzone: output the SOA record as the
				first record in the signed zone. [RT #15758]

	1979.	[port]		linux: allow named to drop core after changing
				user ids. [RT #15753]

	1978.	[port]		Handle systems which have a broken recvmsg().
				[RT #15742]

	1977.	[bug]		Silence noisy log message. [RT #15704]

	1976.	[bug]		Handle systems with no IPv4 addresses. [RT #15695]

	1975.	[bug]		libbind: isc_gethexstring() could misparse multi-line
				hex strings with comments. [RT #15814]

	1974.	[doc]		List each of the zone types and associated zone
				options separately in the ARM.

	1973.	[func]		TSIG HMACSHA1, HMACSHA224, HMACSHA256, HMACSHA384 and
				HMACSHA512 support. [RT #13606]

	1972.	[contrib]	DBUS dynamic forwarders integration from
				Jason Vas Dias <jvdias@redhat.com>.

	1971.	[port]		linux: make detection of missing IF_NAMESIZE more
				robust. [RT #15443]

	1970.	[bug]		nsupdate: adjust UDP timeout when falling back to
				unsigned SOA query. [RT #15775]

	1969.	[bug]		win32: the socket code was freeing the socket
				structure too early. [RT #15776]

	1968.	[bug]		Missing lock in resolver.c:validated(). [RT #15739]

	1967.	[func]		dig/nslookup/host: warn about missing "QR". [RT #15779]

	1966.	[bug]		Don't set CD when we have fallen back to plain DNS.
				[RT #15727]

	1965.	[func]		Suppress spurious "recursion requested but not
				available" warning with 'dig +qr'. [RT #15780].

	1964.	[func]		Separate out MX and SRV to CNAME checks. [RT #15723]

	1963.	[port]		Tru64 4.0E doesn't support send() and recv().
				[RT #15586]

	1962.	[bug]		Named failed to clear old update-policy when it
				was removed. [RT #15491]

	1961.	[bug]		Check the port and address of responses forwarded
				to dispatch. [RT #15474]

	1960.	[bug]		Update code should set NSEC ttls from SOA MINIMUM.
				[RT #15465]

	1959.	[func]		Control the zeroing of the negative response TTL to
				a soa query.  Defaults "zero-no-soa-ttl yes;" and
				"zero-no-soa-ttl-cache no;". [RT #15460]

	1958.	[bug]		Named failed to update the zone's secure state
				until the zone was reloaded. [RT #15412]

	1957.	[bug]		Dig mishandled responses to class ANY queries.
				[RT #15402]

	1956.	[bug]		Improve cross compile support, 'gen' is now built
				by native compiler.  See README for additional
				cross compile support information. [RT #15148]

	1955.	[bug]		Pre-allocate the cache cleaning iterator. [RT #14998]

	1954.	[func]		Named now falls back to advertising EDNS with a
				512 byte receive buffer if the initial EDNS queries
				fail.  [RT #14852]

	1953.	[func]		The maximum EDNS UDP response named will send can
				now be set in named.conf (max-udp-size).  This is
				independent of the advertised receive buffer
				(edns-udp-size). [RT #14852]

	1952.	[port]		hpux: tell the linker to build a runtime link
				path "-Wl,+b:". [RT #14816].

	1951.	[security]	Drop queries from particular well known ports.
				Don't return FORMERR to queries from particular
				well known ports.  [RT #15636]

	1950.	[port]		Solaris 2.5.1 and earlier cannot bind() then connect()
				a TCP socket. This prevents the source address being
				set for TCP connections. [RT #15628]

	1949.	[func]		Addition memory leakage checks. [RT #15544]

	1948.	[bug]		If was possible to trigger a REQUIRE failure in
				xfrin.c:maybe_free() if named ran out of memory.
				[RT #15568]

	1947.	[func]		It is now possible to configure named to accept
				expired RRSIGs.  Default "dnssec-accept-expired no;".
				Setting "dnssec-accept-expired yes;" leaves named
				vulnerable to replay attacks.  [RT #14685]

	1946.	[bug]		resume_dslookup() could trigger a REQUIRE failure
				when using forwarders. [RT #15549]

	1945.	[cleanup]	dnssec-keygen: RSA (RSAMD5) is no longer recommended.
				To generate a RSAMD5 key you must explicitly request
				RSAMD5. [RT #13780]

	1944.	[cleanup]	isc_hash_create() does not need a read/write lock.
				[RT #15522]

	1943.	[bug]		Set the loadtime after rolling forward the journal.
				[RT #15647]

	1942.	[bug]		If the name of a DNSKEY match that of one in
				trusted-keys do not attempt to validate the DNSKEY
				using the parents DS RRset. [RT #15649]

	1941.	[bug]		ncache_adderesult() should set eresult even if no
				rdataset is passed to it. [RT #15642]

	1940.	[bug]		Fixed a number of error conditions reported by
				Coverity.

	1939.	[bug]		The resolver could dereference a null pointer after
				validation if all the queries have timed out.
				[RT #15528]

	1938.	[bug]		The validator was not correctly handling unsecure
				negative responses at or below a SEP. [RT #15528]

	1937.	[bug]		sdlz doesn't handle RRSIG records. [RT #15564]

	1936.	[bug]		The validator could leak memory. [RT #15544]

	1935.	[bug]		'acache' was DO sensitive. [RT #15430]

	1934.	[func]		Validate pending NS RRsets, in the authority section,
				prior to returning them if it can be done without
				requiring DNSKEYs to be fetched.  [RT #15430]

	1933.	[bug]		dump_rdataset_raw() had a incorrect INSIST. [RT #15534]

	1932.	[bug]		hpux: LDFLAGS was getting corrupted. [RT #15530]

	1931.	[bug]		Per-client mctx could require a huge amount of memory,
				particularly for a busy caching server. [RT #15519]

	1930.	[port]		HPUX: ia64 support. [RT #15473]

	1929.	[port]		FreeBSD: extend use of PTHREAD_SCOPE_SYSTEM.

	1928.	[bug]		Race in rbtdb.c:currentversion(). [RT #15517]

	1927.	[bug]		Access to soanode or nsnode in rbtdb violated the
				lock order rule and could cause a dead lock.
				[RT #15518]

	1926.	[bug]		The Windows installer did not check for empty
				passwords.  BINDinstall was being installed in
				the wrong place. [RT #15483]

	1925.	[port]		All outer level AC_TRY_RUNs need cross compiling
				defaults. [RT #15469]

	1924.	[port]		libbind: hpux ia64 support. [RT #15473]

	1923.	[bug]		ns_client_detach() called too early. [RT #15499]

	1922.	[bug]		check-tool.c:setup_logging() missing call to
				dns_log_setcontext().

	1921.	[bug]		Client memory contexts were not using internal
				malloc. [RT #15434]

	1920.	[bug]		The cache rbtdb lock array was too small to
				have the desired performance characteristics.
				[RT #15454]

	1919.	[contrib]	queryperf: a set of new features: collecting/printing
				response delays, printing intermediate results, and
				adjusting query rate for the "target" qps.

	1918.	[bug]		Memory leak when checking acls. [RT #15391]

	1917.	[doc]		funcsynopsisinfo wasn't being treated as verbatim
				when generating man pages. [RT #15385]

	1916.	[func]		Integrate contributed IDN code from JPNIC. [RT #15383]

	1915.	[bug]		dig +ndots was broken. [RT #15215]

	1914.	[protocol]	DS is required to accept mnemonic algorithms
				(RFC 4034).  Still emit numeric algorithms for
				compatibility with RFC 3658. [RT #15354]

	1913.	[func]		Integrate contributed DLZ code into named. [RT #11382]

	1912.	[port]		aix: atomic locking for powerpc. [RT #15020]

	1911.	[bug]		Update windows socket code. [RT #14965]

	1910.	[bug]		dig's +sigchase code overhauled. [RT #14933]

	1909.	[bug]		The DLV code has been re-worked to make no longer
				query order sensitive. [RT #14933]

	1908.	[func]		dig now warns if 'RA' is not set in the answer when
				'RD' was set in the query.  host/nslookup skip servers
				that fail to set 'RA' when 'RD' is set unless a server
				is explicitly set.  [RT #15005]

	1907.	[func]		host/nslookup now continue (default)/fail on SERVFAIL.
				[RT #15006]

	1906.	[func]		dig now has a '-q queryname' and '+showsearch' options.
				[RT #15034]

	1905.	[bug]		Strings returned from cfg_obj_asstring() should be
				treated as read-only.  The prototype for
				cfg_obj_asstring() has been updated to reflect this.
				[RT #15256]

	1904.	[func]		Automatic empty zone creation for D.F.IP6.ARPA and
				friends.  Note: RFC 1918 zones are not yet covered by
				this but are likely to be in a future release.

				New options: empty-server, empty-contact,
				empty-zones-enable and disable-empty-zone.

	1903.	[func]		ISC string copy API.

	1902.	[func]		Attempt to make the amount of work performed in a
				iteration self tuning.  The covers nodes clean from
				the cache per iteration, nodes written to disk when
				rewriting a master file and nodes destroyed per
				iteration when destroying a zone or a cache.
				[RT #14996]

	1901.	[cleanup]	Don't add DNSKEY records to the additional section.

	1900.	[bug]		ixfr-from-differences failed to ensure that the
				serial number increased. [RT #15036]

	1899.	[func]		named-checkconf now validates update-policy entries.
				[RT #14963]

	1898.	[bug]		Extend ISC_SOCKADDR_FORMATSIZE and
				ISC_NETADDR_FORMATSIZE to allow for scope details.

	1897.	[func]		x86 and x86_64 now have separate atomic locking
				implementations.

	1896.	[bug]		Recursive clients soft quota support wasn't working
				as expected. [RT #15103]

	1895.	[bug]		A escaped character is, potentially, converted to
				the output character set too early. [RT #14666]

	1894.	[doc]		Review ARM for BIND 9.4.

	1893.	[port]		Use uintptr_t if available. [RT #14606]

	1892.	[func]		Support for SPF rdata type. [RT #15033]

	1891.	[port]		freebsd: pthread_mutex_init can fail if it runs out
				of memory. [RT #14995]

	1890.	[func]		Raise the UDP receive buffer size to 32k if it is
				less than 32k. [RT #14953]

	1889.	[port]		sunos: non blocking i/o support. [RT #14951]

	1888.	[func]		Support for IPSECKEY rdata type. [RT #14967]

	1887.	[bug]		The cache could delete expired records too fast for
				clients with a virtual time in the past. [RT #14991]

	1886.	[bug]		fctx_create() could return success even though it
				failed. [RT #14993]

	1885.	[func]		dig: report the number of extra bytes still left in
				the packet after processing all the records.

	1884.	[cleanup]	dighost.c: move external declarations into <dig/dig.h>.

	1883.	[bug]		dnssec-signzone, dnssec-keygen: handle negative debug
				levels. [RT #14962]

	1882.	[func]		Limit the number of recursive clients that can be
				waiting for a single query (<qname,qtype,qclass>) to
				resolve.  New options clients-per-query and
				max-clients-per-query.

	1881.	[func]		Add a system test for named-checkconf. [RT #14931]

	1880.	[func]		The lame cache is now done on a <qname,qclass,qtype>
				basis as some servers only appear to be lame for
				certain query types.  [RT #14916]

	1879.	[func]		"USE INTERNAL MALLOC" is now runtime selectable.
				[RT #14892]

	1878.	[func]		Detect duplicates of UDP queries we are recursing on
				and drop them.  New stats category "duplicate".
				[RT #2471]

	1877.	[bug]		Fix unreasonably low quantum on call to
				dns_rbt_destroy2().  Remove unnecessary unhash_node()
				call. [RT #14919]

	1876.	[func]		Additional memory debugging support to track size
				and mctx arguments. [RT #14814]

	1875.	[bug]		process_dhtkey() was using the wrong memory context
				to free some memory. [RT #14890]

	1874.	[port]		sunos: portability fixes. [RT #14814]

	1873.	[port]		win32: isc__errno2result() now reports its caller.
				[RT #13753]

	1872.	[port]		win32: Handle ERROR_NETNAME_DELETED.  [RT #13753]

	1871.	[placeholder]

	1870.	[func]		Added framework for handling multiple EDNS versions.
				[RT #14873]

	1869.	[func]		dig can now specify the EDNS version when making
				a query. [RT #14873]

	1868.	[func]		edns-udp-size can now be overridden on a per
				server basis. [RT #14851]

	1867.	[bug]		It was possible to trigger a INSIST in
				dlv_validatezonekey(). [RT #14846]

	1866.	[bug]		resolv.conf parse errors were being ignored by
				dig/host/nslookup. [RT #14841]

	1865.	[bug]		Silently ignore nameservers in /etc/resolv.conf with
				bad addresses. [RT #14841]

	1864.	[bug]		Don't try the alternative transfer source if you
				got a answer / transfer with the main source
				address. [RT #14802]

	1863.	[bug]		rrset-order "fixed" error messages not complete.

	1862.	[func]		Add additional zone data constancy checks.
				named-checkzone has extended checking of NS, MX and
				SRV record and the hosts they reference.
				named has extended post zone load checks.
				New zone options: check-mx and integrity-check.
				[RT #4940]

	1861.	[bug]		dig could trigger a INSIST on certain malformed
				responses. [RT #14801]

	1860.	[port]		solaris 2.8: hack_shutup_pthreadmutexinit was
				incorrectly set. [RT #14775]

	1859.	[func]		Add support for CH A record. [RT #14695]

	1858.	[bug]		The flush-zones-on-shutdown option wasn't being
				parsed. [RT #14686]

	1857.	[bug]		named could trigger a INSIST() if reconfigured /
				reloaded too fast.  [RT #14673]

	1856.	[doc]		Switch Docbook toolchain from DSSSL to XSL.
				[RT #11398]

	1855.	[bug]		ixfr-from-differences was failing to detect changes
				of ttl due to dns_diff_subtract() was ignoring the ttl
				of records.  [RT #14616]

	1854.	[bug]		lwres also needs to know the print format for
				(long long).  [RT #13754]

	1853.	[bug]		Rework how DLV interacts with proveunsecure().
				[RT #13605]

	1852.	[cleanup]	Remove last vestiges of dnssec-signkey and
				dnssec-makekeyset (removed from Makefile years ago).

	1851.	[doc]		Doxygen comment markup. [RT #11398]

	1850.	[bug]		Memory leak in lwres_getipnodebyaddr(). [RT #14591]

	1849.	[doc]		All forms of the man pages (docbook, man, html) should
				have consistent copyright dates.

	1848.	[bug]		Improve SMF integration. [RT #13238]

	1847.	[bug]		isc_ondestroy_init() is called too late in
				dns_rbtdb_create()/dns_rbtdb64_create().
				[RT #13661]

	1846.	[contrib]	query-loc-0.3.0 from Stephane Bortzmeyer
				<bortzmeyer@nic.fr>.

	1845.	[bug]		Improve error reporting to distinguish between
				accept()/fcntl() and socket()/fcntl() errors.
				[RT #13745]

	1844.	[bug]		inet_pton() accepted more that 4 hexadecimal digits
				for each 16 bit piece of the IPv6 address.  The text
				representation of a IPv6 address has been tightened
				to disallow this (draft-ietf-ipv6-addr-arch-v4-02.txt).
				[RT #5662]

	1843.	[cleanup]	CINCLUDES takes precedence over CFLAGS.  This helps
				when CFLAGS contains "-I /usr/local/include"
				resulting in old header files being used.

	1842.	[port]		cmsg_len() could produce incorrect results on
				some platform. [RT #13744]

	1841.	[bug]		"dig +nssearch" now makes a recursive query to
				find the list of nameservers to query. [RT #13694]

	1840.	[func]		dnssec-signzone can now randomize signature end times
				(dnssec-signzone -j jitter). [RT #13609]

	1839.	[bug]		<isc/hash.h> was not being installed.

	1838.	[cleanup]	Don't allow Linux capabilities to be inherited.
				[RT #13707]

	1837.	[bug]		Compile time option ISC_FACILITY was not effective
				for 'named -u <user>'.  [RT #13714]

	1836.	[cleanup]	Silence compiler warnings in hash_test.c.

	1835.	[bug]		Update dnssec-signzone's usage message. [RT #13657]

	1834.	[bug]		Bad memset in rdata_test.c. [RT #13658]

	1833.	[bug]		Race condition in isc_mutex_lock_profile(). [RT #13660]

	1832.	[bug]		named fails to return BADKEY on unknown TSIG algorithm.
				[RT #13620]

	1831.	[doc]		Update named-checkzone documentation. [RT #13604]

	1830.	[bug]		adb lame cache has sense of test reversed. [RT #13600]

	1829.	[bug]		win32: "pid-file none;" broken. [RT #13563]

	1828.	[bug]		isc_rwlock_init() failed to properly cleanup if it
				encountered a error. [RT #13549]

	1827.	[bug]		host: update usage message for '-a'. [RT #37116]

	1826.	[bug]		Missing DESTROYLOCK() in isc_mem_createx() on out
				of memory error. [RT #13537]

	1825.	[bug]		Missing UNLOCK() on out of memory error from in
				rbtdb.c:subtractrdataset(). [RT #13519]

	1824.	[bug]		Memory leak on dns_zone_setdbtype() failure.
				[RT #13510]

	1823.	[bug]		Wrong macro used to check for point to point interface.
				[RT #13418]

	1822.	[bug]		check-names test for RT was reversed. [RT #13382]

	1821.	[placeholder]

	1820.	[bug]		Gracefully handle acl loops. [RT #13659]

	1819.	[bug]		The validator needed to check both the algorithm and
				digest types of the DS to determine if it could be
				used to introduce a secure zone. [RT #13593]

	1818.	[bug]		'named-checkconf -z' triggered an INSIST. [RT #13599]

	1817.	[func]		Add support for additional zone file formats for
				improving loading performance.  The masterfile-format
				option in named.conf can be used to specify a
				non-default format.  A separate command
				named-compilezone was provided to generate zone files
				in the new format.  Additionally, the -I and -O options
				for dnssec-signzone specify the input and output
				formats.

	1816.	[port]		UnixWare: failed to compile lib/isc/unix/net.c.
				[RT #13597]

	1815.	[bug]		nsupdate triggered a REQUIRE if the server was set
				without also setting the zone and it encountered
				a CNAME and was using TSIG.  [RT #13086]

	1814.	[func]		UNIX domain controls are now supported.

	1813.	[func]		Restructured the data locking framework using
				architecture dependent atomic operations (when
				available), improving response performance on
				multi-processor machines significantly.
				x86, x86_64, alpha, powerpc, and mips are currently
				supported.

	1812.	[port]		win32: IN6_IS_ADDR_UNSPECIFIED macro is incorrect.
				[RT #13453]

	1811.	[func]		Preserve the case of domain names in rdata during
				zone transfers. [RT #13547]

	1810.	[bug]		configure, lib/bind/configure make different default
				decisions about whether to do a threaded build.
				[RT #13212]

	1809.	[bug]		"make distclean" failed for libbind if the platform
				is not supported.

	1808.	[bug]		zone.c:notify_zone() contained a race condition,
				zone->db could change underneath it.  [RT #13511]

	1807.	[bug]		When forwarding (forward only) set the active domain
				from the forward zone name. [RT #13526]

	1806.	[bug]		The resolver returned the wrong result when a CNAME /
				DNAME was encountered when fetching glue from a
				secure namespace. [RT #13501]

	1805.	[bug]		Pending status was not being cleared when DLV was
				active. [RT #13501]

	1804.	[bug]		Ensure that if we are queried for glue that it fits
				in the additional section or TC is set to tell the
				client to retry using TCP. [RT #10114]

	1803.	[bug]		dnssec-signzone sometimes failed to remove old
				RRSIGs. [RT #13483]

	1802.	[bug]		Handle connection resets better. [RT #11280]

	1801.	[func]		Report differences between hints and real NS rrset
				and associated address records.

	1800.	[bug]		Changes #1719 allowed a INSIST to be triggered.
				[RT #13428]

	1799.	[bug]		'rndc flushname' failed to flush negative cache
				entries. [RT #13438]

	1798.	[func]		The server syntax has been extended to support a
				range of servers.  [RT #11132]

	1797.	[func]		named-checkconf now check acls to verify that they
				only refer to existing acls. [RT #13101]

	1796.	[func]		"rndc freeze/thaw" now freezes/thaws all zones.

	1795.	[bug]		"rndc dumpdb" was not fully documented.  Minor
				formatting issues with "rndc dumpdb -all".  [RT #13396]

	1794.	[func]		Named and named-checkzone can now both check for
				non-terminal wildcard records.

	1793.	[func]		Extend adjusting TTL warning messages. [RT #13378]

	1792.	[func]		New zone option "notify-delay".  Specify a minimum
				delay between sets of NOTIFY messages.

	1791.	[bug]		'host -t a' still printed out AAAA and MX records.
				[RT #13230]

	1790.	[cleanup]	Move lib/dns/sec/dst up into lib/dns.  This should
				allow parallel make to succeed.

	1789.	[bug]		Prerequisite test for tkey and dnssec could fail
				with "configure --with-libtool".

	1788.	[bug]		libbind9.la/libbind9.so needs to link against
				libisccfg.la/libisccfg.so.

	1787.	[port]		HPUX: both "cc" and "gcc" need -Wl,+vnocompatwarnings.

	1786.	[port]		AIX: libt_api needs to be taught to look for
				T_testlist in the main executable (--with-libtool).
				[RT #13239]

	1785.	[bug]		libbind9.la/libbind9.so needs to link against
				libisc.la/libisc.so.

	1784.	[cleanup]	"libtool -allow-undefined" is the default.
				Leave hooks in configure to allow it to be set
				if needed in the future.

	1783.	[cleanup]	We only need one copy of libtool.m4, ltmain.sh in the
				source tree.

	1782.	[port]		OSX: --with-libtool + --enable-libbind broke on
				__evOptMonoTime.  [RT #13219]

	1781.	[port]		FreeBSD 5.3: set PTHREAD_SCOPE_SYSTEM. [RT #12810]

	1780.	[bug]		Update libtool to 1.5.10.

	1779.	[port]		OSF 5.1: libtool didn't handle -pthread correctly.

	1778.	[port]		HUX 11.11: fix broken IN6ADDR_ANY_INIT and
				IN6ADDR_LOOPBACK_INIT macros.

	1777.	[port]		OSF 5.1: fix broken IN6ADDR_ANY_INIT and
				IN6ADDR_LOOPBACK_INIT macros.

	1776.	[port]		Solaris 2.9: fix broken IN6ADDR_ANY_INIT and
				IN6ADDR_LOOPBACK_INIT macros.

	1775.	[bug]		Only compile getnetent_r.c when threaded. [RT #13205]

	1774.	[port]		Aix: Silence compiler warnings / build failures.
				[RT #13154]

	1773.	[bug]		Fast retry on host / net unreachable. [RT #13153]

	1772.	[placeholder]

	1771.	[placeholder]

	1770.	[bug]		named-checkconf failed to report missing a missing
				file clause for rbt{64} master/hint zones. [RT #13009]

	1769.	[port]		win32: change compiler flags /MTd ==> /MDd,
				/MT ==> /MD.

	1768.	[bug]		nsecnoexistnodata() could be called with a non-NSEC
				rdataset. [RT #12907]

	1767.	[port]		Builds on IPv6 platforms without IPv6 Advanced API
				support for (struct in6_pktinfo) failed.  [RT #13077]

	1766.	[bug]		Update the master file timestamp on successful refresh
				as well as the journal's timestamp. [RT #13062]

	1765.	[bug]		configure --with-openssl=auto failed. [RT #12937]

	1764.	[bug]		dns_zone_replacedb failed to emit a error message
				if there was no SOA record in the replacement db.
				[RT #13016]

	1763.	[func]		Perform sanity checks on NS records which refer to
				'in zone' names. [RT #13002]

	1762.	[bug]		isc_interfaceiter_create() could return ISC_R_SUCCESS
				even when it failed. [RT #12995]

	1761.	[bug]		'rndc dumpdb' didn't report unassociated entries.
				[RT #12971]

	1760.	[bug]		Host / net unreachable was not penalising rtt
				estimates. [RT #12970]

	1759.	[bug]		Named failed to startup if the OS supported IPv6
				but had no IPv6 interfaces configured. [RT #12942]

	1758.	[func]		Don't send notify messages to self. [RT #12933]

	1757.	[func]		host now can turn on memory debugging flags with '-m'.

	1756.	[func]		named-checkconf now checks the logging configuration.
				[RT #12352]

	1755.	[func]		allow-update is now settable at the options / view
				level. [RT #6636]

	1754.	[bug]		We weren't always attempting to query the parent
				server for the DS records at the zone cut.
				[RT #12774]

	1753.	[bug]		Don't serve a slave zone which has no NS records.
				[RT #12894]

	1752.	[port]		Move isc_app_start() to after ns_os_daemonise()
				as some fork() implementations unblock the signals
				that are blocked by isc_app_start(). [RT #12810]

	1751.	[bug]		--enable-getifaddrs failed under linux. [RT #12867]

	1750.	[port]		lib/bind/make/rules.in:subdirs was not bash friendly.
				[RT #12864]

.. code-block:: none

	1749.	[bug]		'check-names response ignore;' failed to ignore.
				[RT #12866]

	1748.	[func]		dig now returns the byte count for axfr/ixfr.

	1747.	[bug]		BIND 8 compatibility: named/named-checkconf failed
				to parse "host-statistics-max" in named.conf.

	1746.	[func]		Make public the function to read a key file,
				dst_key_read_public(). [RT #12450]

	1745.	[bug]		Dig/host/nslookup accept replies from link locals
				regardless of scope if no scope was specified when
				query was sent. [RT #12745]

	1744.	[bug]		If tuple2msgname() failed to convert a tuple to
				a name a REQUIRE could be triggered. [RT #12796]

	1743.	[bug]		If isc_taskmgr_create() was not able to create the
				requested number of worker threads then destruction
				of the manager would trigger an INSIST() failure.
				[RT #12790]

	1742.	[bug]		Deleting all records at a node then adding a
				previously existing record, in a single UPDATE
				transaction, failed to leave / regenerate the
				associated RRSIG records. [RT #12788]

	1741.	[bug]		Deleting all records at a node in a secure zone
				using a update-policy grant failed. [RT #12787]

	1740.	[bug]		Replace rbt's hash algorithm as it performed badly
				with certain zones. [RT #12729]

				NOTE: a hash context now needs to be established
				via isc_hash_create() if the application was not
				already doing this.

	1739.	[bug]		dns_rbt_deletetree() could incorrectly return
				ISC_R_QUOTA.  [RT #12695]

	1738.	[bug]		Enable overrun checking by default. [RT #12695]

	1737.	[bug]		named failed if more than 16 masters were specified.
				[RT #12627]

	1736.	[bug]		dst_key_fromnamedfile() could fail to read a
				public key. [RT #12687]

	1735.	[bug]		'dig +sigtrace' could die with a REQUIRE failure.
				[RE #12688]

	1734.	[cleanup]	'rndc-confgen -a -t' remove extra '/' in path.
				[RT #12588]

	1733.	[bug]		Return non-zero exit status on initial load failure.
				[RT #12658]

	1732.	[bug]		'rrset-order name "*"' wasn't being applied to ".".
				[RT #12467]

	1731.	[port]		darwin: relax version test in ifconfig.sh.
				[RT #12581]

	1730.	[port]		Determine the length type used by the socket API.
				[RT #12581]

	1729.	[func]		Improve check-names error messages.

	1728.	[doc]		Update check-names documentation.

	1727.	[bug]		named-checkzone: check-names support didn't match
				documentation.

	1726.	[port]		aix5: add support for aix5.

	1725.	[port]		linux: update error message on interaction of threads,
				capabilities and setuid support (named -u). [RT #12541]

	1724.	[bug]		Look for DNSKEY records with "dig +sigtrace".
				[RT #12557]

	1723.	[cleanup]	Silence compiler warnings from t_tasks.c. [RT #12493]

	1722.	[bug]		Don't commit the journal on malformed ixfr streams.
				[RT #12519]

	1721.	[bug]		Error message from the journal processing were not
				always identifying the relevant journal. [RT #12519]

	1720.	[bug]		'dig +chase' did not terminate on a RFC 2308 Type 1
				negative response. [RT #12506]

	1719.	[bug]		named was not correctly caching a RFC 2308 Type 1
				negative response. [RT #12506]

	1718.	[bug]		nsupdate was not handling RFC 2308 Type 3 negative
				responses when looking for the zone / master server.
				[RT #12506]

	1717.	[port]		solaris: ifconfig.sh did not support Solaris 10.
				"ifconfig.sh down" didn't work for Solaris 9.

	1716.	[doc]		named.conf(5) was being installed in the wrong
				location.  [RT #12441]

	1715.	[func]		'dig +trace' now randomly selects the next servers
				to try.  Report if there is a bad delegation.

	1714.	[bug]		dig/host/nslookup were only trying the first
				address when a nameserver was specified by name.
				[RT #12286]

	1713.	[port]		linux: extend capset failure message to say:
				please ensure that the capset kernel module is
				loaded.  see insmod(8)

	1712.	[bug]		Missing FULLCHECK for "trusted-key" in dig.

	1711.	[func]		'rndc unfreeze' has been deprecated by 'rndc thaw'.

	1710.	[func]		'rndc notify zone [class [view]]' resend the NOTIFY
				messages for the specified zone. [RT #9479]

	1709.	[port]		solaris: add SMF support from Sun.

	1708.	[cleanup]	Replaced dns_fullname_hash() with dns_name_fullhash()
				for conformance to the name space convention.  Binary
				backward compatibility to the old function name is
				provided. [RT #12376]

	1707.	[contrib]	sdb/ldap updated to version 1.0-beta.

	1706.	[bug]		'rndc stop' failed to cause zones to be flushed
				sometimes. [RT #12328]

	1705.	[func]		Allow the journal's name to be changed via named.conf.

	1704.	[port]		lwres needed a snprintf() implementation for
				platforms without snprintf().  Add missing
				"#include <isc/print.h>". [RT #12321]

	1703.	[bug]		named would loop sending NOTIFY messages when it
				failed to receive a response. [RT #12322]

	1702.	[bug]		also-notify should not be applied to built in zones.
				[RT #12323]

	1701.	[doc]		A minimal named.conf man page.

	1700.	[func]		nslookup is no longer to be treated as deprecated.
				Remove "deprecated" warning message.  Add man page.

	1699.	[bug]		dnssec-signzone can generate "not exact" errors
				when resigning. [RT #12281]

	1698.	[doc]		Use reserved IPv6 documentation prefix.

	1697.	[bug]		xxx-source{,-v6} was not effective when it
				specified one of listening addresses and a
				different port than the listening port. [RT #12257]

	1696.	[bug]		dnssec-signzone failed to clean out nodes that
				consisted of only NSEC and RRSIG records.
				[RT #12154]

	1695.	[bug]		DS records when forwarding require special handling.
				[RT #12133]

	1694.	[bug]		Report if the builtin views of "_default" / "_bind"
				are defined in named.conf. [RT #12023]

	1693.	[bug]		max-journal-size was not effective for master zones
				with ixfr-from-differences set. [RT #12024]

	1692.	[bug]		Don't set -I, -L and -R flags when libcrypto is in
				/usr/lib. [RT #11971]

	1691.	[bug]		sdb's attachversion was not complete. [RT #11990]

	1690.	[bug]		Delay detaching view from the client until UPDATE
				processing completes when shutting down. [RT #11714]

	1689.	[bug]		DNS_NAME_TOREGION() and DNS_NAME_SPLIT() macros
				contained gratuitous semicolons. [RT #11707]

	1688.	[bug]		LDFLAGS was not supported.

	1687.	[bug]		Race condition in dispatch. [RT #10272]

	1686.	[bug]		Named sent a extraneous NOTIFY when it received a
				redundant UPDATE request. [RT #11943]

	1685.	[bug]		Change #1679 loop tests weren't quite right.

	1684.	[func]		ixfr-from-differences now takes master and slave in
				addition to yes and no at the options and view levels.

	1683.	[bug]		dig +sigchase could leak memory. [RT #11445]

	1682.	[port]		Update configure test for (long long) printf format.
				[RT #5066]

	1681.	[bug]		Only set SO_REUSEADDR when a port is specified in
				isc_socket_bind(). [RT #11742]

	1680.	[func]		rndc: the source address can now be specified.

	1679.	[bug]		When there was a single nameserver with multiple
				addresses for a zone not all addresses were tried.
				[RT #11706]

	1678.	[bug]		RRSIG should use TYPEXXXXX for unknown types.

	1677.	[bug]		dig: +aaonly didn't work, +aaflag undocumented.

	1676.	[func]		New option "allow-query-cache".  This lets
				allow-query be used to specify the default zone
				access level rather than having to have every
				zone override the global value.  allow-query-cache
				can be set at both the options and view levels.
				If allow-query-cache is not set allow-query applies.

	1675.	[bug]		named would sometimes add extra NSEC records to
				the authority section.

	1674.	[port]		linux: increase buffer size used to scan
				/proc/net/if_inet6.

	1673.	[port]		linux: issue a error messages if IPv6 interface
				scans fails.

	1672.	[cleanup]	Tests which only function in a threaded build
				now return R:THREADONLY (rather than R:UNTESTED)
				in a non-threaded build.

	1671.	[contrib]	queryperf: add NAPTR to the list of known types.

	1670.	[func]		Log UPDATE requests to slave zones without an acl as
				"disabled" at debug level 3. [RT #11657]

	1669.	[placeholder]

	1668.	[bug]		DIG_SIGCHASE was making bin/dig/host dump core.

	1667.	[port]		linux: not all versions have IF_NAMESIZE.

	1666.	[bug]		The optional port on hostnames in dual-stack-servers
				was being ignored.

	1665.	[func]		rndc now allows addresses to be set in the
				server clauses.

	1664.	[bug]		nsupdate needed KEY for SIG(0), not DNSKEY.

	1663.	[func]		Look for OpenSSL by default.

	1662.	[bug]		Change #1658 failed to change one use of 'type'
				to 'keytype'.

	1661.	[bug]		Restore dns_name_concatenate() call in
				adb.c:set_target().  [RT #11582]

	1660.	[bug]		win32: connection_reset_fix() was being called
				unconditionally.  [RT #11595]

	1659.	[cleanup]	Cleanup some messages that were referring to KEY vs
				DNSKEY, NXT vs NSEC and SIG vs RRSIG.

	1658.	[func]		Update dnssec-keygen to default to KEY for HMAC-MD5
				and DH.  Tighten which options apply to KEY and
				DNSKEY records.

	1657.	[doc]		ARM: document query log output.

	1656.	[doc]		Update DNSSEC description in ARM to cover DS, NSEC
				DNSKEY and RRSIG.  [RT #11542]

	1655.	[bug]		Logging multiple versions w/o a size was broken.
				[RT #11446]

	1654.	[bug]		isc_result_totext() contained array bounds read
				error.

	1653.	[func]		Add key type checking to dst_key_fromfilename(),
				DST_TYPE_KEY should be used to read TSIG, TKEY and
				SIG(0) keys.

	1652.	[bug]		TKEY still uses KEY.

	1651.	[bug]		dig: process multiple dash options.

	1650.	[bug]		dig, nslookup: flush standard out after each command.

	1649.	[bug]		Silence "unexpected non-minimal diff" message.
				[RT #11206]

	1648.	[func]		Update dnssec-lookaside named.conf syntax to support
				multiple dnssec-lookaside namespaces (not yet
				implemented).

	1647.	[bug]		It was possible trigger a INSIST when chasing a DS
				record that required walking back over a empty node.
				[RT #11445]

	1646.	[bug]		win32: logging file versions didn't work with
				non-UNC filenames.  [RT #11486]

	1645.	[bug]		named could trigger a REQUIRE failure if multiple
				masters with keys are specified.

	1644.	[bug]		Update the journal modification time after a
				successful refresh query. [RT #11436]

	1643.	[bug]		dns_db_closeversion() could leak memory / node
				references. [RT #11163]

	1642.	[port]		Support OpenSSL implementations which don't have
				DSA support. [RT #11360]

	1641.	[bug]		Update the check-names description in ARM. [RT #11389]

	1640.	[bug]		win32: isc_socket_cancel(ISC_SOCKCANCEL_ACCEPT) was
				incorrectly closing the socket.  [RT #11291]

	1639.	[func]		Initial dlv system test.

	1638.	[bug]		"ixfr-from-differences" could generate a REQUIRE
				failure if the journal open failed. [RT #11347]

	1637.	[bug]		Node reference leak on error in addnoqname().

	1636.	[bug]		The dump done callback could get ISC_R_SUCCESS even if
				a error had occurred.  The database version no longer
				matched the version of the database that was dumped.

	1635.	[bug]		Memory leak on error in query_addds().

	1634.	[bug]		named didn't supply a useful error message when it
				detected duplicate views.  [RT #11208]

	1633.	[bug]		named should return NOTIMP to update requests to a
				slaves without a allow-update-forwarding acl specified.
				[RT #11331]

	1632.	[bug]		nsupdate failed to send prerequisite only UPDATE
				messages. [RT #11288]

	1631.	[bug]		dns_journal_compact() could sometimes corrupt the
				journal. [RT #11124]

	1630.	[contrib]	queryperf: add support for IPv6 transport.

	1629.	[func]		dig now supports IPv6 scoped addresses with the
				extended format in the local-server part. [RT #8753]

	1628.	[bug]		Typo in Compaq Trucluster support. [RT #11264]

	1627.	[bug]		win32: sockets were not being closed when the
				last external reference was removed. [RT #11179]

	1626.	[bug]		--enable-getifaddrs was broken. [RT #11259]

	1625.	[bug]		named failed to load/transfer RFC2535 signed zones
				which contained CNAMES. [RT #11237]

	1624.	[bug]		zonemgr_putio() call should be locked. [RT #11163]

	1623.	[bug]		A serial number of zero was being displayed in the
				"sending notifies" log message when also-notify was
				used. [RT #11177]

	1622.	[func]		probe the system to see if IPV6_(RECV)PKTINFO is
				available, and suppress wildcard binding if not.

	1621.	[bug]		match-destinations did not work for IPv6 TCP queries.
				[RT #11156]

	1620.	[func]		When loading a zone report if it is signed. [RT #11149]

	1619.	[bug]		Missing ISC_LIST_UNLINK in end_reserved_dispatches().
				[RT #11118]

	1618.	[bug]		Fencepost errors in dns_name_ishostname() and
				dns_name_ismailbox() could trigger a INSIST().

	1617.	[port]		win32: VC++ 6.0 support.

	1616.	[compat]	Ensure that named's version is visible in the core
				dump. [RT #11127]

	1615.	[port]		Define ISC_SOCKADDR_LEN_T based on _BSD_SOCKLEN_T_ if
				it is defined.

	1614.	[port]		win32: silence resource limit messages. [RT #11101]

	1613.	[bug]		Builds would fail on machines w/o a if_nametoindex().
				Missing #ifdef ISC_PLATFORM_HAVEIFNAMETOINDEX/#endif.
				[RT #11119]

	1612.	[bug]		check-names at the option/view level could trigger
				an INSIST. [RT #11116]

	1611.	[bug]		solaris: IPv6 interface scanning failed to cope with
				no active IPv6 interfaces.

	1610.	[bug]		On dual stack machines "dig -b" failed to set the
				address type to be looked up with "@server".
				[RT #11069]

	1609.	[func]		dig now has support to chase DNSSEC signature chains.
				Requires -DDIG_SIGCHASE=1 to be set in STD_CDEFINES.

				DNSSEC validation code in dig coded by Olivier Courtay
				(olivier.courtay@irisa.fr) for the IDsA project
				(http://idsa.irisa.fr).

	1608.	[func]		dig and host now accept -4/-6 to select IP transport
				to use when making queries.

	1607.	[bug]		dig, host and nslookup were still using random()
				to generate query ids. [RT #11013]

	1606.	[bug]		DLV insecurity proof was failing.

	1605.	[func]		New dns_db_find() option DNS_DBFIND_COVERINGNSEC.

	1604.	[bug]		A xfrout_ctx_create() failure would result in
				xfrout_ctx_destroy() being called with a
				partially initialized structure.

	1603.	[bug]		nsupdate: set interactive based on isatty().
				[RT #10929]

	1602.	[bug]		Logging to a file failed unless a size was specified.
				[RT #10925]

	1601.	[bug]		Silence spurious warning 'both "recursion no;" and
				"allow-recursion" active' warning from view "_bind".
				[RT #10920]

	1600.	[bug]		Duplicate zone pre-load checks were not case
				insensitive.

	1599.	[bug]		Fix memory leak on error path when checking named.conf.

	1598.	[func]		Specify that certain parts of the namespace must
				be secure (dnssec-must-be-secure).

	1597.	[func]		Allow notify-source and query-source to be specified
				on a per server basis similar to transfer-source.
				[RT #6496]

	1596.	[func]		Accept 'notify-source' style syntax for query-source.

	1595.	[func]		New notify type 'master-only'.  Enable notify for
				master zones only.

	1594.	[bug]		'rndc dumpdb' could prevent named from answering
				queries while the dump was in progress.  [RT #10565]

	1593.	[bug]		rndc should return "unknown command" to unknown
				commands. [RT #10642]

	1592.	[bug]		configure_view() could leak a dispatch. [RT #10675]

	1591.	[bug]		libbind: updated to BIND 8.4.5.

	1590.	[port]		netbsd: update thread support.

	1589.	[func]		DNSSEC lookaside validation.

	1588.	[bug]		win32: TCP sockets could become blocked. [RT #10115]

	1587.	[bug]		dns_message_settsigkey() failed to clear existing key.
				[RT #10590]

	1586.	[func]		"check-names" is now implemented.

	1585.	[placeholder]

	1584.	[bug]		"make test" failed with a read only source tree.
				[RT #10461]

	1583.	[bug]		Records add via UPDATE failed to get the correct trust
				level. [RT #10452]

	1582.	[bug]		rrset-order failed to work on RRsets with more
				than 32 elements. [RT #10381]

	1581.	[func]		Disable DNSSEC support by default.  To enable
				DNSSEC specify "dnssec-enable yes;" in named.conf.

	1580.	[bug]		Zone destruction on final detach takes a long time.
				[RT #3746]

	1579.	[bug]		Multiple task managers could not be created.

	1578.	[bug]		Don't use CLASS E IPv4 addresses when resolving.
				[RT #10346]

	1577.	[bug]		Use isc_uint32_t in ultrasparc optimizer bug
				workaround code. [RT #10331]

	1576.	[bug]		Race condition in dns_dispatch_addresponse().
				[RT #10272]

	1575.	[func]		Log TSIG name on TSIG verify failure. [RT #4404]

	1574.	[bug]		Don't attempt to open the controls socket(s) when
				running tests. [RT #9091]

	1573.	[port]		linux: update to libtool 1.5.2 so that
				"make install DESTDIR=/xx" works with
				"configure --with-libtool".  [RT #9941]

	1572.	[bug]		nsupdate: sign the soa query to find the enclosing
				zone if the server is specified. [RT #10148]

	1571.	[bug]		rbt:hash_node() could fail leaving the hash table
				in an inconsistent state.  [RT #10208]

	1570.	[bug]		nsupdate failed to handle classes other than IN.
				New keyword 'class' which sets the default class.
				[RT #10202]

	1569.	[func]		nsupdate new command 'answer' which displays the
				complete answer message to the last update.

	1568.	[bug]		nsupdate now reports that the update failed in
				interactive mode. [RT #10236]

	1567.	[maint]		B.ROOT-SERVERS.NET is now 192.228.79.201.

	1566.	[port]		Support for the cmsg framework on Solaris and HP/UX.
				This also solved the problem that match-destinations
				for IPv6 addresses did not work on these systems.
				[RT #10221]

	1565.	[bug]		CD flag should be copied to outgoing queries unless
				the query is under a secure entry point in which case
				CD should be set.

	1564.	[func]		Attempt to provide a fallback entropy source to be
				used if named is running chrooted and named is unable
				to open entropy source within the chroot area.
				[RT #10133]

	1563.	[bug]		Gracefully fail when unable to obtain neither an IPv4
				nor an IPv6 dispatch. [RT #10230]

	1562.	[bug]		isc_socket_create() and isc_socket_accept() could
				leak memory under error conditions. [RT #10230]

	1561.	[bug]		It was possible to release the same name twice if
				named ran out of memory. [RT #10197]

	1560.	[port]		FreeBSD: work around FreeBSD 5.2 mapping EAI_NODATA
				and EAI_NONAME to the same value.

	1559.	[port]		named should ignore SIGFSZ.

	1558.	[func]		New DNSSEC 'disable-algorithms'.  Support entry into
				child zones for which we don't have a supported
				algorithm.  Such child zones are treated as unsigned.

	1557.	[func]		Implement missing DNSSEC tests for
				* NOQNAME proof with wildcard answers.
				* NOWILDARD proof with NXDOMAIN.
				Cache and return NOQNAME with wildcard answers.

	1556.	[bug]		nsupdate now treats all names as fully qualified.
				[RT #6427]

	1555.	[func]		'rrset-order cyclic' no longer has a random starting
				point per query. [RT #7572]

	1554.	[bug]		dig, host, nslookup failed when no nameservers
				were specified in /etc/resolv.conf. [RT #8232]

	1553.	[bug]		The windows socket code could stop accepting
				connections. [RT #10115]

	1552.	[bug]		Accept NOTIFY requests from mapped masters if
				matched-mapped is set. [RT #10049]

	1551.	[port]		Open "/dev/null" before calling chroot().

	1550.	[port]		Call tzset(), if available, before calling chroot().

	1549.	[func]		named-checkzone can now write out the zone contents
				in a easily parsable format (-D and -o).

	1548.	[bug]		When parsing APL records it was possible to silently
				accept out of range ADDRESSFAMILY values. [RT #9979]

	1547.	[bug]		Named wasted memory recording duplicate lame zone
				entries. [RT #9341]

	1546.	[bug]		We were rejecting valid secure CNAME to negative
				answers.

	1545.	[bug]		It was possible to leak memory if named was unable to
				bind to the specified transfer source and TSIG was
				being used. [RT #10120]

	1544.	[bug]		Named would logged a single entry to a file despite it
				being over the specified size limit.

	1543.	[bug]		Logging using "versions unlimited" did not work.

	1542.	[placeholder]

	1541.	[func]		NSEC now uses new bitmap format.

	1540.	[bug]		"rndc reload <dynamiczone>" was silently accepted.
				[RT #8934]

	1539.	[bug]		Open UDP sockets for notify-source and transfer-source
				that use reserved ports at startup. [RT #9475]

	1538.	[placeholder]	rt9997

	1537.	[func]		New option "querylog".  If set specify whether query
				logging is to be enabled or disabled at startup.

	1536.	[bug]		Windows socket code failed to log a error description
				when returning ISC_R_UNEXPECTED. [RT #9998]

	1535.	[placeholder]

	1534.	[bug]		Race condition when priming cache. [RT #9940]

	1533.	[func]		Warn if both "recursion no;" and "allow-recursion"
				are active. [RT #4389]

	1532.	[port]		netbsd: the configure test for <sys/sysctl.h>
				requires <sys/param.h>.

	1531.	[port]		AIX more libtool fixes.

	1530.	[bug]		It was possible to trigger a INSIST() failure if a
				slave master file was removed at just the correct
				moment. [RT #9462]

	1529.	[bug]		"notify explicit;" failed to log that NOTIFY messages
				were being sent for the zone. [RT #9442]

	1528.	[cleanup]	Simplify some dns_name_ functions based on the
				deprecation of bitstring labels.

	1527.	[cleanup]	Reduce the number of gettimeofday() calls without
				losing necessary timer granularity.

	1526.	[func]		Implemented "additional section caching (or acache)",
				an internal cache framework for additional section
				content to improve response performance.  Several
				configuration options were provided to control the
				behavior.

	1525.	[bug]		dns_cache_create() could trigger a REQUIRE
				failure in isc_mem_put() during error cleanup.
				[RT #9360]

	1524.	[port]		AIX needs to be able to resolve all symbols when
				creating shared libraries (--with-libtool).

	1523.	[bug]		Fix race condition in rbtdb. [RT #9189]

	1522.	[bug]		dns_db_findnode() relax the requirements on 'name'.
				[RT #9286]

	1521.	[bug]		dns_view_createresolver() failed to check the
				result from isc_mem_create(). [RT #9294]

	1520.	[protocol]	Add SSHFP (SSH Finger Print) type.

	1519.	[bug]		dnssec-signzone:nsec_setbit() computed the wrong
				length of the new bitmap.

	1518.	[bug]		dns_nsec_buildrdata(), and hence dns_nsec_build(),
				contained a off-by-one error when working out the
				number of octets in the bitmap.

	1517.	[port]		Support for IPv6 interface scanning on HP/UX and
				TrueUNIX 5.1.

	1516.	[func]		Roll the DNSSEC types to RRSIG, NSEC and DNSKEY.

	1515.	[func]		Allow transfer source to be set in a server statement.
				[RT #6496]

	1514.	[bug]		named: isc_hash_destroy() was being called too early.
				[RT #9160]

	1513.	[doc]		Add "US" to root-delegation-only exclude list.

	1512.	[bug]		Extend the delegation-only logging to return query
				type, class and responding nameserver.

	1511.	[bug]		delegation-only was generating false positives
				on negative answers from sub-zones.

	1510.	[func]		New view option "root-delegation-only".  Apply
				delegation-only check to all TLDs and root.
				Note there are some TLDs that are NOT delegation
				only (e.g. DE, LV, US and MUSEUM) these can be excluded
				from the checks by using exclude.

				root-delegation-only exclude {
					"DE"; "LV"; "US"; "MUSEUM";
				};

	1509.	[bug]		Hint zones should accept delegation-only.  Forward
				zone should not accept delegation-only.

	1508.	[bug]		Don't apply delegation-only checks to answers from
				forwarders.

	1507.	[bug]		Handle BIND 8 style returns to NS queries to parents
				when making delegation-only checks.

	1506.	[bug]		Wrong return type for dns_view_isdelegationonly().

	1505.	[bug]		Uninitialized rdataset in sdb. [RT #8750]

	1504.	[func]		New zone type "delegation-only".

	1503.	[port]		win32: install libeay32.dll outside of system32.

	1502.	[bug]		nsupdate: adjust timeouts for UPDATE requests over TCP.

	1501.	[func]		Allow TCP queue length to be specified via
				named.conf, tcp-listen-queue.

	1500.	[bug]		host failed to lookup MX records.  Also look up
				AAAA records.

.. code-block:: none

	1499.	[bug]		isc_random need to be seeded better if arc4random()
				is not used.

	1498.	[port]		bsdos: 5.x support.

	1497.	[placeholder]

	1496.	[port]		test for pthread_attr_setstacksize().

	1495.	[cleanup]	Replace hash functions with universal hash.

	1494.	[security]	Turn on RSA BLINDING as a precaution.

	1493.	[placeholder]

	1492.	[cleanup]	Preserve rwlock quota context when upgrading /
				downgrading. [RT #5599]

	1491.	[bug]		dns_master_dump*() would produce extraneous $ORIGIN
				lines. [RT #6206]

	1490.	[bug]		Accept reading state as well as working state in
				ns_client_next(). [RT #6813]

	1489.	[compat]	Treat 'allow-update' on slave zones as a warning.
				[RT #3469]

	1488.	[bug]		Don't override trust levels for glue addresses.
				[RT #5764]

	1487.	[bug]		A REQUIRE() failure could be triggered if a zone was
				queued for transfer and the zone was then removed.
				[RT #6189]

	1486.	[bug]		isc_print_snprintf() '%%' consumed one too many format
				characters. [RT #8230]

	1485.	[bug]		gen failed to handle high type values. [RT #6225]

	1484.	[bug]		The number of records reported after a AXFR was wrong.
				[RT #6229]

	1483.	[bug]		dig axfr failed if the message id in the answer failed
				to match that in the request.  Only the id in the first
				message is required to match. [RT #8138]

	1482.	[bug]		named could fail to start if the kernel supports
				IPv6 but no interfaces are configured.  Similarly
				for IPv4. [RT #6229]

	1481.	[bug]		Refresh and stub queries failed to use masters keys
				if specified. [RT #7391]

	1480.	[bug]		Provide replay protection for rndc commands.  Full
				replay protection requires both rndc and named to
				be updated.  Partial replay protection (limited
				exposure after restart) is provided if just named
				is updated.

	1479.	[bug]		cfg_create_tuple() failed to handle out of
				memory cleanup.  parse_list() would leak memory
				on syntax errors.

	1478.	[port]		ifconfig.sh didn't account for other virtual
				interfaces.  It now takes a optional argument
				to specify the first interface number. [RT #3907]

	1477.	[bug]		memory leak using stub zones and TSIG.

	1476.	[placeholder]

	1475.	[port]		Probe for old sprintf().

	1474.	[port]		Provide strtoul() and memmove() for platforms
				without them.

	1473.	[bug]		create_map() and create_string() failed to handle out
				of memory cleanup.  [RT #6813]

	1472.	[contrib]	idnkit-1.0 from JPNIC, replaces mdnkit.

	1471.	[bug]		libbind: updated to BIND 8.4.0.

	1470.	[bug]		Incorrect length passed to snprintf. [RT #5966]

	1469.	[func]		Log end of outgoing zone transfer at same level
				as the start of transfer is logged. [RT #4441]

	1468.	[func]		Internal zones are no longer counted for
				'rndc status'.  [RT #4706]

	1467.	[func]		$GENERATES now supports optional class and ttl.

	1466.	[bug]		lwresd configuration errors resulted in memory
				and lock leaks.  [RT #5228]

	1465.	[bug]		isc_base64_decodestring() and isc_base64_tobuffer()
				failed to check that trailing bits were zero allowing
				some invalid base64 strings to be accepted.  [RT #5397]

	1464.	[bug]		Preserve "out of zone" data for outgoing zone
				transfers. [RT #5192]

	1463.	[bug]		dns_rdata_from{wire,struct}() failed to catch bad
				NXT bit maps. [RT #5577]

	1462.	[bug]		parse_sizeval() failed to check the token type.
				[RT #5586]

	1461.	[bug]		Remove deadlock from rbtdb code. [RT #5599]

	1460.	[bug]		inet_pton() failed to reject certain malformed
				IPv6 literals.

	1459.	[placeholder]

	1458.	[cleanup]	sprintf() -> snprintf().

	1457.	[port]		Provide strlcat() and strlcpy() for platforms without
				them.

	1456.	[contrib]	gen-data-queryperf.py from Stephane Bortzmeyer.

	1455.	[bug]		<netaddr> missing from server grammar in
				doc/misc/options. [RT #5616]

	1454.	[port]		Use getifaddrs() if available for interface scanning.
				--disable-getifaddrs to override.  Glibc currently
				has a getifaddrs() that does not support IPv6.
				Use --enable-getifaddrs=glibc to force the use of
				this version under linux machines.

	1453.	[doc]		ARM: $GENERATE example wasn't accurate. [RT #5298]

	1452.	[placeholder]

	1451.	[bug]		rndc-confgen didn't exit with a error code for all
				failures. [RT #5209]

	1450.	[bug]		Fetching expired glue failed under certain
				circumstances.  [RT #5124]

	1449.	[bug]		query_addbestns() didn't handle running out of memory
				gracefully.

	1448.	[bug]		Handle empty wildcards labels.

	1447.	[bug]		We were casting (unsigned int) to and from (void *).
				rdataset->private4 is now rdataset->privateuint4
				to reflect a type change.

	1446.	[func]		Implemented undocumented alternate transfer sources
				from BIND 8.  See use-alt-transfer-source,
				alt-transfer-source and alt-transfer-source-v6.

				SECURITY: use-alt-transfer-source is ENABLED unless
				you are using views.  This may cause a security risk
				resulting in accidental disclosure of wrong zone
				content if the master supplying different source
				content based on IP address.  If you are not certain
				ISC recommends setting use-alt-transfer-source no;

	1445.	[bug]		DNS_ADBFIND_STARTATROOT broke stub zones.  This has
				been replaced with DNS_ADBFIND_STARTATZONE which
				causes the search to start using the closest zone.

	1444.	[func]		dns_view_findzonecut2() allows you to specify if the
				cache should be searched for zone cuts.

	1443.	[func]		Masters lists can now be specified and referenced
				in zone masters clauses and other masters lists.

	1442.	[func]		New functions for manipulating port lists:
				dns_portlist_create(), dns_portlist_add(),
				dns_portlist_remove(), dns_portlist_match(),
				dns_portlist_attach() and dns_portlist_detach().

	1441.	[func]		It is now possible to tell dig to bind to a specific
				source port.

	1440.	[func]		It is now possible to tell named to avoid using
				certain source ports (avoid-v4-udp-ports,
				avoid-v6-udp-ports).

	1439.	[bug]		Named could return NOERROR with certain NOTIFY
				failures.  Return NOTAUTH if the NOTIFY zone is
				not being served.

	1438.	[func]		Log TSIG (if any) when logging NOTIFY requests.

	1437.	[bug]		Leave space for stdio to work in. [RT #5033]

	1436.	[func]		dns_zonemgr_resumexfrs() can be used to restart
				stalled transfers.

	1435.	[bug]		zmgr_resume_xfrs() was being called read locked
				rather than write locked.  zmgr_resume_xfrs()
				was not being called if the zone was being
				shutdown.

	1434.	[bug]		"rndc reconfig" failed to initiate the initial
				zone transfer of new slave zones.

	1433.	[bug]		named could trigger a REQUIRE failure if it could
				not get a file descriptor when attempting to write
				a master file. [RT #4347]

	1432.	[func]		The advertised EDNS UDP buffer size can now be set
				via named.conf (edns-udp-size).

	1431.	[bug]		isc_print_snprintf() "%s" with precision could walk off
				end of argument. [RT #5191]

	1430.	[port]		linux: IPv6 interface scanning support.

	1429.	[bug]		Prevent the cache getting locked to old servers.

	1428.	[placeholder]

	1427.	[bug]		Race condition in adb with threaded build.

	1426.	[placeholder]

	1425.	[port]		linux/libbind: define __USE_MISC when testing *_r()
				function prototypes in netdb.h.  [RT #4921]

	1424.	[bug]		EDNS version not being correctly printed.

	1423.	[contrib]	queryperf: added A6 and SRV.

	1422.	[func]		Log name/type/class when denying a query.  [RT #4663]

	1421.	[func]		Differentiate updates that don't succeed due to
				prerequisites (unsuccessful) vs other reasons
				(failed).

	1420.	[port]		solaris: work around gcc optimizer bug.

	1419.	[port]		openbsd: use /dev/arandom. [RT #4950]

	1418.	[bug]		'rndc reconfig' did not cause new slaves to load.

	1417.	[func]		ID.SERVER/CHAOS is now a built in zone.
				See "server-id" for how to configure.

	1416.	[bug]		Empty node should return NOERROR NODATA, not NXDOMAIN.
				[RT #4715]

	1415.	[func]		DS TTL now derived from NS ttl.  NXT TTL now derived
				from SOA MINIMUM.

	1414.	[func]		Support for KSK flag.

	1413.	[func]		Explicitly request the (re-)generation of DS records
				from keysets (dnssec-signzone -g).

	1412.	[func]		You can now specify servers to be tried if a nameserver
				has IPv6 address and you only support IPv4 or the
				reverse. See dual-stack-servers.

	1411.	[bug]		empty nodes should stop wildcard matches. [RT #4802]

	1410.	[func]		Handle records that live in the parent zone, e.g. DS.

	1409.	[bug]		DS should have attribute DNS_RDATATYPEATTR_DNSSEC.

	1408.	[bug]		"make distclean" was not complete. [RT #4700]

	1407.	[bug]		lfsr incorrectly implements the shift register.
				[RT #4617]

	1406.	[bug]		dispatch initializes one of the LFSR's with a incorrect
				polynomial.  [RT #4617]

	1405.	[func]		Use arc4random() if available.

	1404.	[bug]		libbind: ns_name_ntol() could overwrite a zero length
				buffer.

	1403.	[func]		dnssec-signzone, dnssec-keygen, dnssec-makekeyset
				dnssec-signkey now report their version in the
				usage message.

	1402.	[cleanup]	A6 has been moved to experimental and is no longer
				fully supported.

	1401.	[bug]		adb wasn't clearing state when the timer expired.

	1400.	[bug]		Block the addition of wildcard NS records by IXFR
				or UPDATE. [RT #3502]

	1399.	[bug]		Use serial number arithmetic when testing SIG
				timestamps. [RT #4268]

	1398.	[doc]		ARM: notify-also should have been also-notify.
				[RT #4345]

	1397.	[maint]		J.ROOT-SERVERS.NET is now 192.58.128.30.

	1396.	[func]		dnssec-signzone: adjust the default signing time by
				1 hour to allow for clock skew.

	1395.	[port]		OpenSSL 0.9.7 defines CRYPTO_LOCK_ENGINE but doesn't
				have a working implementation.  [RT #4079]

	1394.	[func]		It is now possible to check if a particular element is
				in a acl.  Remove duplicate entries from the localnets
				acl.

	1393.	[port]		Bind to individual IPv6 interfaces if IPV6_IPV6ONLY
				is not available in the kernel to prevent accidentally
				listening on IPv4 interfaces.

	1392.	[bug]		named-checkzone: update usage.

	1391.	[func]		Add support for IPv6 scoped addresses in named.

	1390.	[func]		host now supports ixfr.

	1389.	[bug]		named could fail to rotate long log files.  [RT #3666]

	1388.	[port]		irix: check for sys/sysctl.h and NET_RT_IFLIST before
				defining HAVE_IFLIST_SYSCTL. [RT #3770]

	1387.	[bug]		named could crash due to an access to invalid memory
				space (which caused an assertion failure) in
				incremental cleaning.  [RT #3588]

	1386.	[bug]		named-checkzone -z stopped on errors in a zone.
				[RT #3653]

	1385.	[bug]		Setting serial-query-rate to 10 would trigger a
				REQUIRE failure.

	1384.	[bug]		host was incompatible with BIND 8 in its exit code and
				in the output with the -l option.  [RT #3536]

	1383.	[func]		Track the serial number in a IXFR response and log if
				a mismatch occurs.  This is a more specific error than
				"not exact". [RT #3445]

	1382.	[bug]		make install failed with --enable-libbind. [RT #3656]

	1381.	[bug]		named failed to correctly process answers that
				contained DNAME records where the resulting CNAME
				resulted in a negative answer.

	1380.	[func]		'rndc recursing' dump recursing queries to
				'recursing-file = "named.recursing";'.

	1379.	[func]		'rndc status' now reports tcp and recursion quota
				states.

	1378.	[func]		Improved positive feedback for 'rndc {reload|refresh}.

	1377.	[func]		dns_zone_load{new}() now reports if the zone was
				loaded, queued for loading to up to date.

	1376.	[func]		New function dns_zone_logc() to log to specified
				category.

	1375.	[func]		'rndc dumpdb' now dumps the adb cache along with the
				data cache.

	1374.	[func]		dns_adb_dump() now logs the lame zones associated
				with each server.

	1373.	[bug]		Recovery from expired glue failed under certain
				circumstances.

	1372.	[bug]		named crashes with an assertion failure on exit when
				sharing the same port for listening and querying, and
				changing listening addresses several times. [RT #3509]

	1371.	[bug]		notify-source-v6, transfer-source-v6 and
				query-source-v6 with explicit addresses and using the
				same ports as named was listening on could interfere
				with named's ability to answer queries sent to those
				addresses.

	1370.	[bug]		dig '+[no]recurse' was incorrectly documented.

	1369.	[bug]		Adding an NS record as the lexicographically last
				record in a secure zone didn't work.

	1368.	[func]		remove support for bitstring labels.

	1367.	[func]		Use response times to select forwarders.

	1366.	[contrib]	queryperf usage was incomplete.  Add '-h' for help.

	1365.	[func]		"localhost" and "localnets" acls now include IPv6
				addresses / prefixes.

	1364.	[func]		Log file name when unable to open memory statistics
				and dump database files. [RT #3437]

	1363.	[func]		Listen-on-v6 now supports specific addresses.

	1362.	[bug]		remove IFF_RUNNING test when scanning interfaces.

	1361.	[func]		log the reason for rejecting a server when resolving
				queries.

	1360.	[bug]		--enable-libbind would fail when not built in the
				source tree for certain OS's.

	1359.	[security]	Support patches OpenSSL libraries.
				http://www.cert.org/advisories/CA-2002-23.html

	1358.	[bug]		It was possible to trigger a INSIST when debugging
				large dynamic updates. [RT #3390]

	1357.	[bug]		nsupdate was extremely wasteful of memory.

	1356.	[tuning]	Reduce the number of events / quantum for zone tasks.

	1355.	[bug]		Fix DNSSEC wildcard proof for CNAME/DNAME.

	1354.	[doc]		lwres man pages had illegal nroff.

	1353.	[contrib]	sdb/ldap to version 0.9.

	1352.	[bug]		dig, host, nslookup when falling back to TCP use the
				current search entry (if any). [RT #3374]

	1351.	[bug]		lwres_getipnodebyname() returned the wrong name
				when given a IPv4 literal, af=AF_INET6 and AI_MAPPED
				was set.

	1350.	[bug]		dns_name_fromtext() failed to handle too many labels
				gracefully.

	1349.	[security]	Minimum OpenSSL version now 0.9.6e (was 0.9.5a).
				http://www.cert.org/advisories/CA-2002-23.html

	1348.	[port]		win32: Rewrote code to use I/O Completion Ports
				in socket.c and eliminating a host of socket
				errors. Performance is enhanced.

	1347.	[placeholder]

	1346.	[placeholder]

	1345.	[port]		Use a explicit -Wformat with gcc.  Not all versions
				include it in -Wall.

	1344.	[func]		Log if the serial number on the master has gone
				backwards.
				If you have multiple machines specified in the masters
				clause you may want to set 'multi-master yes;' to
				suppress this warning.

	1343.	[func]		Log successful notifies received (info).  Adjust log
				level for failed notifies to notice.

	1342.	[func]		Log remote address with TCP dispatch failures.

	1341.	[func]		Allow a rate limiter to be stalled.

	1340.	[bug]		Delay and spread out the startup refresh load.

	1339.	[func]		dig, host and nslookup now use IP6.ARPA for nibble
				lookups.  Bit string lookups are no longer attempted.

	1338.	[placeholder]

	1337.	[placeholder]

	1336.	[func]		Nibble lookups under IP6.ARPA are now supported by
				dns_byaddr_create().  dns_byaddr_createptrname() is
				deprecated, use dns_byaddr_createptrname2() instead.

	1335.	[bug]		When performing a nonexistence proof, the validator
				should discard parent NXTs from higher in the DNS.

	1334.	[bug]		When signing/verifying rdatasets, duplicate rdatas
				need to be suppressed.

	1333.	[contrib]	queryperf now reports a summary of returned
				rcodes (-c), rcodes are printed in mnemonic form (-v).

	1332.	[func]		Report the current serial with periodic commits when
				rolling forward the journal.

	1331.	[func]		Generate DNSSEC wildcard proofs.

	1330.	[bug]		When processing events (non-threaded) only allow
				the task one chance to use to use its quantum.

	1329.	[func]		named-checkzone will now check if nameservers that
				appear to be IP addresses.  Available modes "fail",
				"warn" (default) and "ignore" the results of the
				check.

	1328.	[bug]		The validator could incorrectly verify an invalid
				negative proof.

	1327.	[bug]		The validator would incorrectly mark data as insecure
				when seeing a bogus signature before a correct
				signature.

	1326.	[bug]		DNAME/CNAME signatures were not being cached when
				validation was not being performed. [RT #3284]

	1325.	[bug]		If the tcpquota was exhausted it was possible to
				to trigger a INSIST() failure.

	1324.	[port]		darwin: ifconfig.sh now supports darwin.

	1323.	[port]		linux: Slackware 4.0 needs <asm/unistd.h>. [RT #3205]

	1322.	[bug]		dnssec-signzone usage message was misleading.

	1321.	[bug]		If the last RRset in a zone is glue, dnssec-signzone
				would incorrectly duplicate its output and sign it.

	1320.	[doc]		query-source-v6 was missing from options section.
				[RT #3218]

	1319.	[func]		libbind: log attempts to exploit #1318.

	1318.	[bug]		libbind: Remote buffer overrun.

	1317.	[port]		libbind: TrueUNIX 5.1 does not like __align as a
				element name.

	1316.	[bug]		libbind: gethostans() could get out of sync parsing
				the response if there was a very long CNAME chain.

	1315.	[bug]		Options should apply to the internal _bind view.

	1314.	[port]		Handle ECONNRESET from sendmsg() [unix].

	1313.	[func]		Query log now says if the query was signed (S) or
				if EDNS was used (E).

	1312.	[func]		Log TSIG key used w/ outgoing zone transfers.

	1311.	[bug]		lwres_getrrsetbyname leaked memory.  [RT #3159]

	1310.	[bug]		'rndc stop' failed to cause zones to be flushed
				sometimes. [RT #3157]

	1309.	[func]		Log that a zone transfer was covered by a TSIG.

	1308.	[func]		DS (delegation signer) support.

	1307.	[bug]		nsupdate: allow white space base64 key data.

	1306.	[bug]		Badly encoded LOC record when the size, horizontal
				precision or vertical precision was 0.1m.

	1305.	[bug]		Document that internal zones are included in the
				rndc status results.

	1304.	[func]		New function: dns_zone_name().

	1303.	[func]		Option 'flush-zones-on-shutdown <boolean>;'.

	1302.	[func]		Extended rndc dumpdb to support dumping of zones and
				view selection: 'dumpdb [-all|-zones|-cache] [view]'.

	1301.	[func]		New category 'update-security'.

	1300.	[port]		Compaq Trucluster support.

	1299.	[bug]		Set AI_ADDRCONFIG when looking up addresses
				via getaddrinfo() (affects dig, host, nslookup, rndc
				and nsupdate).

	1298.	[bug]		The CINCLUDES macro in lib/dns/sec/dst/Makefile
				could be left with a trailing "\" after configure
				has been run.

	1297.	[port]		linux: make handling EINVAL from socket() no longer
				conditional on #ifdef LINUX.

	1296.	[bug]		isc_log_closefilelogs() needed to lock the log
				context.

	1295.	[bug]		isc_log_setdebuglevel() needed to lock the log
				context.

	1294.	[func]		libbind: no longer attempts bit string labels for
				IPv6 reverse resolution.  Try IP6.ARPA then IP6.INT
				for nibble style resolution.

	1293.	[func]		Entropy can now be retrieved from EGDs. [RT #2438]

	1292.	[func]		Enable IPv6 support when using ioctl style interface
				scanning and OS supports SIOCGLIFADDR using struct
				if_laddrreq.

	1291.	[func]		Enable IPv6 support when using sysctl style interface
				scanning.

	1290.	[func]		"dig axfr" now reports the number of messages
				as well as the number of records.

	1289.	[port]		See if -ldl is required for OpenSSL? [RT #2672]

	1288.	[bug]		Adjusted REQUIRE's in lib/dns/name.c to better
				reflect written requirements.

	1287.	[bug]		REQUIRE that DNS_DBADD_MERGE only be set when adding
				a rdataset to a zone db in the rbtdb implementation of
				addrdataset.

	1286.	[bug]		dns_name_downcase() enforce requirement that
				target != NULL or name->buffer != NULL.

	1285.	[func]		lwres: probe the system to see what address families
				are currently in use.

	1284.	[bug]		The RTT estimate on unused servers was not aged.
				[RT #2569]

	1283.	[func]		Use "dataready" accept filter if available.

	1282.	[port]		libbind: hpux 11.11 interface scanning.

	1281.	[func]		Log zone when unable to get private keys to update
				zone.  Log zone when NXT records are missing from
				secure zone.

	1280.	[bug]		libbind: escape '(' and ')' when converting to
				presentation form.

	1279.	[port]		Darwin uses (unsigned long) for size_t. [RT #2590]

	1278.	[func]		dig: now supports +[no]cl +[no]ttlid.

	1277.	[func]		You can now create your own customized printing
				styles: dns_master_stylecreate() and
				dns_master_styledestroy().

	1276.	[bug]		libbind: const pointer conflicts in res_debug.c.

	1275.	[port]		libbind: hpux: treat all hpux systems as BIG_ENDIAN.

	1274.	[bug]		Memory leak in lwres_gnbarequest_parse().

	1273.	[port]		libbind: solaris: 64 bit binary compatibility.

	1272.	[contrib]	Berkeley DB 4.0 sdb implementation from
				Nuno Miguel Rodrigues <nmr@co.sapo.pt>.

	1271.	[bug]		"recursion available: {denied,approved}" was too
				confusing.

	1270.	[bug]		Check that system inet_pton() and inet_ntop() support
				AF_INET6.

	1269.	[port]		Openserver: ifconfig.sh support.

	1268.	[port]		Openserver: the value FD_SETSIZE depends on whether
				<sys/param.h> is included or not.  Be consistent.

	1267.	[func]		isc_file_openunique() now creates file using mode
				0666 rather than 0600.

	1266.	[bug]		ISC_LINK_INIT, ISC_LINK_UNLINK, ISC_LIST_DEQUEUE,
				__ISC_LINK_UNLINKUNSAFE and __ISC_LIST_DEQUEUEUNSAFE
				are not C++ compatible, use *_TYPE versions instead.

	1265.	[bug]		libbind: LINK_INIT and UNLINK were not compatible with
				C++, use LINK_INIT_TYPE and UNLINK_TYPE instead.

	1264.	[placeholder]

	1263.	[bug]		Reference after free error if dns_dispatchmgr_create()
				failed.

	1262.	[bug]		ns_server_destroy() failed to set *serverp to NULL.

	1261.	[func]		libbind: ns_sign2() and ns_sign_tcp() now provide
				support for compressed TSIG owner names.

	1260.	[func]		libbind: res_update can now update IPv6 servers,
				new function res_findzonecut2().

	1259.	[bug]		libbind: get_salen() IPv6 support was broken for OSs
				w/o sa_len.

	1258.	[bug]		libbind: res_nametotype() and res_nametoclass() were
				broken.

	1257.	[bug]		Failure to write pid-file should not be fatal on
				reload. [RT #2861]

	1256.	[contrib]	'queryperf' now has EDNS (-e) + DNSSEC DO (-D) support.

	1255.	[bug]		When verifying that an NXT proves nonexistence, check
				the rcode of the message and only do the matching NXT
				check.  That is, for NXDOMAIN responses, check that
				the name is in the range between the NXT owner and
				next name, and for NOERROR NODATA responses, check
				that the type is not present in the NXT bitmap.

	1254.	[func]		preferred-glue option from BIND 8.3.

	1253.	[bug]		The dnssec system test failed to remove the correct
				files.

	1252.	[bug]		Dig, host and nslookup were not checking the address
				the answer was coming from against the address it was
				sent to. [RT #2692]

	1251.	[port]		win32: a make file contained absolute version specific
				references.

	1250.	[func]		Nsupdate will report the address the update was
				sent to.

.. code-block:: none

	1249.	[bug]		Missing masters clause was not handled gracefully.
				[RT #2703]

	1248.	[bug]		DESTDIR was not being propagated between makes.

	1247.	[bug]		Don't reset the interface index for link/site local
				addresses. [RT #2576]

	1246.	[func]		New functions isc_sockaddr_issitelocal(),
				isc_sockaddr_islinklocal(), isc_netaddr_issitelocal()
				and isc_netaddr_islinklocal().

	1245.	[bug]		Treat ENOBUFS, ENOMEM and ENFILE as soft errors for
				accept().

	1244.	[bug]		Receiving a TCP message from a blackhole address would
				prevent further messages being received over that
				interface.

	1243.	[bug]		It was possible to trigger a REQUIRE() in
				dns_message_findtype(). [RT #2659]

	1242.	[bug]		named-checkzone failed if a journal existed. [RT #2657]

	1241.	[bug]		Drop received UDP messages with a zero source port
				as these are invariably forged. [RT #2621]

	1240.	[bug]		It was possible to leak zone references by
				specifying an incorrect zone to rndc.

	1239.	[bug]		Under certain circumstances named could continue to
				use a name after it had been freed triggering
				INSIST() failures.  [RT #2614]

	1238.	[bug]		It is possible to lockup the server when shutting down
				if notifies were being processed. [RT #2591]

	1237.	[bug]		nslookup: "set q=type" failed.

	1236.	[bug]		dns_rdata{class,type}_fromtext() didn't handle non
				NULL terminated text regions. [RT #2588]

	1235.	[func]		Report 'out of memory' errors from openssl.

	1234.	[bug]		contrib/sdb: 'zonetodb' failed to call
				dns_result_register().  DNS_R_SEENINCLUDE should not
				be fatal.

	1233.	[bug]		The flags field of a KEY record can be expressed in
				hex as well as decimal.

	1232.	[bug]		unix/errno2result() didn't handle EADDRNOTAVAIL.

	1231.	[port]		HPUX 11.11 recvmsg() can return spurious EADDRNOTAVAIL.

	1230.	[bug]		isccc_cc_isreply() and isccc_cc_isack() were broken.

	1229.	[bug]		named would crash if it received a TSIG signed
				query as part of an AXFR response. [RT #2570]

	1228.	[bug]		'make install' did not depend on 'make all'. [RT #2559]

	1227.	[bug]		dns_lex_getmastertoken() now returns ISC_R_BADNUMBER
				if a number was expected and some other token was
				found. [RT #2532]

	1226.	[func]		Use EDNS for zone refresh queries. [RT #2551]

	1225.	[func]		dns_message_setopt() no longer requires that
				dns_message_renderbegin() to have been called.

	1224.	[bug]		'rrset-order' and 'sortlist' should be additive
				not exclusive.

	1223.	[func]		'rrset-order' partially works 'cyclic' and 'random'
				are supported.

	1222.	[bug]		Specifying 'port *' did not always result in a system
				selected (non-reserved) port being used. [RT #2537]

	1221.	[bug]		Zone types 'master', 'slave' and 'stub' were not being
				compared case insensitively. [RT #2542]

	1220.	[func]		Support for APL rdata type.

	1219.	[func]		Named now reports the TSIG extended error code when
				signature verification fails. [RT #1651]

	1218.	[bug]		Named incorrectly returned SERVFAIL rather than
				NOTAUTH when there was a TSIG BADTIME error. [RT #2519]

	1217.	[func]		Report locations of previous key definition when a
				duplicate is detected.

	1216.	[bug]		Multiple server clauses for the same server were not
				reported.  [RT #2514]

	1215.	[port]		solaris: add support to ifconfig.sh for x86 2.5.1

	1214.	[bug]		Win32: isc_file_renameunique() could leave zero length
				files behind.

	1213.	[func]		Report view associated with client if it is not a
				standard view (_default or _bind).

	1212.	[port]		libbind: 64k answer buffers were causing stack space
				to be exceeded for certain OS.  Use heap space instead.

	1211.	[bug]		dns_name_fromtext() incorrectly handled certain
				valid octal bitlabels. [RT #2483]

	1210.	[bug]		libbind: getnameinfo() failed to lookup IPv4 mapped /
				compatible addresses. [RT #2461]

	1209.	[bug]		Dig, host, nslookup were not checking the message ids
				on the responses. [RT #2454]

	1208.	[bug]		dns_master_load*() failed to log a error message if
				an error was detected when parsing the owner name of
				a record.  [RT #2448]

	1207.	[bug]		libbind: getaddrinfo() could call freeaddrinfo() with
				an invalid pointer.

	1206.	[bug]		SERVFAIL and NOTIMP responses to an EDNS query should
				trigger a non-EDNS retry.

	1205.	[bug]		OPT, TSIG and TKEY cannot be used to set the "class"
				of the message. [RT #2449]

	1204.	[bug]		libbind: res_nupdate() failed to update the name
				server addresses before sending the update.

	1203.	[func]		Report locations of previous acl and zone definitions
				when a duplicate is detected.

	1202.	[func]		New functions: cfg_obj_line() and cfg_obj_file().

	1201.	[bug]		Require that if 'callbacks' is passed to
				dns_rdata_fromtext(), callbacks->error and
				callbacks->warn are initialized.

	1200.	[bug]		Log 'errno' that we are unable to convert to
				isc_result_t. [RT #2404]

	1199.	[doc]		ARM reference to RFC 2157 should have been RFC 1918.
				[RT #2436]

	1198.	[bug]		OPT printing style was not consistent with the way the
				header fields are printed.  The DO bit was not reported
				if set.  Report if any of the MBZ bits are set.

	1197.	[bug]		Attempts to define the same acl multiple times were not
				detected.

	1196.	[contrib]	update mdnkit to 2.2.3.

	1195.	[bug]		Attempts to redefine builtin acls should be caught.
				[RT #2403]

	1194.	[bug]		Not all duplicate zone definitions were being detected
				at the named.conf checking stage. [RT #2431]

	1193.	[bug]		dig +besteffort parsing didn't handle packet
				truncation.  dns_message_parse() has new flag
				DNS_MESSAGE_IGNORETRUNCATION.

	1192.	[bug]		The seconds fields in LOC records were restricted
				to three decimal places.  More decimal places should
				be allowed but warned about.

	1191.	[bug]		A dynamic update removing the last non-apex name in
				a secure zone would fail. [RT #2399]

	1190.	[func]		Add the "rndc freeze" and "rndc unfreeze" commands.
				[RT #2394]

	1189.	[bug]		On some systems, malloc(0) returns NULL, which
				could cause the caller to report an out of memory
				error. [RT #2398]

	1188.	[bug]		Dynamic updates of a signed zone would fail if
				some of the zone private keys were unavailable.

	1187.	[bug]		named was incorrectly returning DNSSEC records
				in negative responses when the DO bit was not set.

	1186.	[bug]		isc_hex_tobuffer(,,length = 0) failed to unget the
				EOL token when reading to end of line.

	1185.	[bug]		libbind: don't assume statp->_u._ext.ext is valid
				unless RES_INIT is set when calling res_*init().

	1184.	[bug]		libbind: call res_ndestroy() if RES_INIT is set
				when res_*init() is called.

	1183.	[bug]		Handle ENOSR error when writing to the internal
				control pipe. [RT #2395]

	1182.	[bug]		The server could throw an assertion failure when
				constructing a negative response packet.

	1181.	[func]		Add the "key-directory" configuration statement,
				which allows the server to look for online signing
				keys in alternate directories.

	1180.	[func]		dnssec-keygen should always generate keys with
				protocol 3 (DNSSEC), since it's less confusing
				that way.

	1179.	[func]		Add SIG(0) support to nsupdate.

	1178.	[bug]		Follow and cache (if appropriate) A6 and other
				data chains to completion in the additional section.

	1177.	[func]		Report view when loading zones if it is not a
				standard view (_default or _bind). [RT #2270]

	1176.	[doc]		Document that allow-v6-synthesis is only performed
				for clients that are supplied recursive service.
				[RT #2260]

	1175.	[bug]		named-checkzone and named-checkconf failed to call
				dns_result_register() at startup which could
				result in runtime exceptions when printing
				"out of memory" errors. [RT #2335]

	1174.	[bug]		Win32: add WSAECONNRESET to the expected errors
				from connect(). [RT #2308]

	1173.	[bug]		Potential memory leaks in isc_log_create() and
				isc_log_settag(). [RT #2336]

	1172.	[doc]		Add CERT, GPOS, KX, NAPTR, NSAP, PX and TXT to
				table of RR types in ARM.

	1171.	[func]		Added function isc_region_compare(), updated files in
				lib/dns to use this function instead of local one.

	1170.	[bug]		Don't attempt to print the token when a I/O error
				occurs when parsing named.conf. [RT #2275]

	1169.	[func]		Identify recursive queries in the query log.

	1168.	[bug]		Empty also-notify clauses were not handled. [RT #2309]

	1167.	[contrib]	nslint-2.1a3 (from author).

	1166.	[bug]		"Not Implemented" should be reported as NOTIMP,
				not NOTIMPL. [RT #2281]

	1165.	[bug]		We were rejecting notify-source{-v6} in zone clauses.

	1164.	[bug]		Empty masters clauses in slave / stub zones were not
				handled gracefully. [RT #2262]

	1163.	[func]		isc_time_formattimestamp() now includes the year.

	1162.	[bug]		The allow-notify option was not accepted in slave
				zone statements.

	1161.	[bug]		named-checkzone looped on unbalanced brackets.
				[RT #2248]

	1160.	[bug]		Generating Diffie-Hellman keys longer than 1024
				bits could fail. [RT #2241]

	1159.	[bug]		MD and MF are not permitted to be loaded by RFC1123.

	1158.	[func]		Report the client's address when logging notify
				messages.

	1157.	[func]		match-clients and match-destinations now accept
				keys. [RT #2045]

	1156.	[port]		The configure test for strsep() incorrectly
				succeeded on certain patched versions of
				AIX 4.3.3. [RT #2190]

	1155.	[func]		Recover from master files being removed from under
				us.

	1154.	[bug]		Don't attempt to obtain the netmask of a interface
				if there is no address configured. [RT #2176]

	1153.	[func]		'rndc {stop|halt} -p' now reports the process id
				of the instance of named being shutdown.

	1152.	[bug]		libbind: read buffer overflows.

	1151.	[bug]		nslookup failed to check that the arguments to
				the port, timeout, and retry options were
				valid integers and in range. [RT #2099]

	1150.	[bug]		named incorrectly accepted TTL values
				containing plus or minus signs, such as
				1d+1h-1s.

	1149.	[func]		New function isc_parse_uint32().

	1148.	[func]		'rndc-confgen -a' now provides positive feedback.

	1147.	[func]		Set IPV6_V6ONLY on IPv6 sockets if supported by
				the OS.  listen-on-v6 { any; }; should no longer
				result in IPv4 queries be accepted.  Similarly
				control { inet :: ... }; should no longer result
				in IPv4 connections being accepted.  This can be
				overridden at compile time by defining
				ISC_ALLOW_MAPPED=1.

	1146.	[func]		Allow IPV6_IPV6ONLY to be set/cleared on a socket if
				supported by the OS by a new function
				isc_socket_ipv6only().

	1145.	[func]		"host" no longer reports a NOERROR/NODATA response
				by printing nothing. [RT #2065]

	1144.	[bug]		rndc-confgen would crash if both the -a and -t
				options were specified. [RT #2159]

	1143.	[bug]		When a trusted-keys statement was present and named
				was built without crypto support, it would leak memory.

	1142.	[bug]		dnssec-signzone would fail to delete temporary files
				in some failure cases. [RT #2144]

	1141.	[bug]		When named rejected a control message, it would
				leak a file descriptor and memory.  It would also
				fail to respond, causing rndc to hang.
				[RT #2139, #2164]

	1140.	[bug]		rndc-confgen did not accept IPv6 addresses as arguments
				to the -s option. [RT #2138]

	1139.	[func]		It is now possible to flush a given name from the
				cache(s) via 'rndc flushname name [view]'. [RT #2051]

	1138.	[func]		It is now possible to flush a given name from the
				cache by calling the new function
				dns_cache_flushname().

	1137.	[func]		It is now possible to flush a given name from the
				ADB by calling the new function dns_adb_flushname().

	1136.	[bug]		CNAME records synthesized from DNAMEs did not
				have a TTL of zero as required by RFC2672.
				[RT #2129]

	1135.	[func]		You can now override the default syslog() facility for
				named/lwresd at compile time. [RT #1982]

	1134.	[bug]		Multi-threaded servers could deadlock in ferror()
				when reloading zone files. [RT #1951, #1998]

	1133.	[bug]		IN6_IS_ADDR_LOOPBACK was not portably defined on
				platforms without IN6_IS_ADDR_LOOPBACK. [RT #2106]

	1132.	[func]		Improve UPDATE prerequisite failure diagnostic messages.

	1131.	[bug]		The match-destinations view option did not work with
				IPv6 destinations. [RT #2073, #2074]

	1130.	[bug]		Log messages reporting an out-of-range serial number
				did not include the out-of-range number but the
				following token. [RT #2076]

	1129.	[bug]		Multi-threaded servers could crash under heavy
				resolution load due to a race condition. [RT #2018]

	1128.	[func]		sdb drivers can now provide RR data in either text
				or wire format, the latter using the new functions
				dns_sdb_putrdata() and dns_sdb_putnamedrdata().

	1127.	[func]		rndc: If the server to contact has multiple addresses,
				try all of them.

	1126.	[bug]		The server could access a freed event if shut
				down while a client start event was pending
				delivery. [RT #2061]

	1125.	[bug]		rndc: -k option was missing from usage message.
				[RT #2057]

	1124.	[doc]		dig: +[no]dnssec, +[no]besteffort and +[no]fail
				are now documented. [RT #2052]

	1123.	[bug]		dig +[no]fail did not match description. [RT #2052]

	1122.	[tuning]	Resolution timeout reduced from 90 to 30 seconds.
				[RT #2046]

	1121.	[bug]		The server could attempt to access a NULL zone
				table if shut down while resolving.
				[RT #1587, #2054]

	1120.	[bug]		Errors in options were not fatal. [RT #2002]

	1119.	[func]		Added support in Win32 for NTFS file/directory ACL's
				for access control.

	1118.	[bug]		On multi-threaded servers, a race condition
				could cause an assertion failure in resolver.c
				during resolver shutdown. [RT #2029]

	1117.	[port]		The configure check for in6addr_loopback incorrectly
				succeeded on AIX 4.3 when compiling with -O2
				because the test code was optimized away.
				[RT #2016]

	1116.	[bug]		Setting transfers in a server clause, transfers-in,
				or transfers-per-ns to a value greater than
				2147483647 disabled transfers. [RT #2002]

	1115.	[func]		Set maximum values for cleaning-interval,
				heartbeat-interval, interface-interval,
				max-transfer-idle-in, max-transfer-idle-out,
				max-transfer-time-in, max-transfer-time-out,
				statistics-interval of 28 days and
				sig-validity-interval of 3660 days. [RT #2002]

	1114.	[port]		Ignore more accept() errors. [RT #2021]

	1113.	[bug]		The allow-update-forwarding option was ignored
				when specified in a view. [RT #2014]

	1112.	[placeholder]

	1111.	[bug]		Multi-threaded servers could deadlock processing
				recursive queries due to a locking hierarchy
				violation in adb.c. [RT #2017]

	1110.	[bug]		dig should only accept valid abbreviations of +options.
				[RT #2003]

	1109.	[bug]		nsupdate accepted illegal ttl values.

	1108.	[bug]		On Win32, rndc was hanging when named was not running
				due to failure to select for exceptional conditions
				in select(). [RT #1870]

	1107.	[bug]		nsupdate could catch an assertion failure if an
				invalid domain name was given as the argument to
				the "zone" command.

	1106.	[bug]		After seeing an out of range TTL, nsupdate would
				treat all TTLs as out of range. [RT #2001]

	1105.	[port]		OpenUNIX 8 enable threads by default. [RT #1970]

	1104.	[bug]		Invalid arguments to the transfer-format option
				could cause an assertion failure. [RT #1995]

	1103.	[port]		OpenUNIX 8 support (ifconfig.sh). [RT #1970]

	1102.	[doc]		Note that query logging is enabled by directing the
				queries category to a channel.

	1101.	[bug]		Array bounds read error in lwres_gai_strerror.

	1100.	[bug]		libbind: DNSSEC key ids were computed incorrectly.

	1099.	[cleanup]	libbind: defining REPORT_ERRORS in lib/bind/dst caused
				compile time errors.

	1098.	[bug]		libbind: HMAC-MD5 key files are now mode 0600.

	1097.	[func]		libbind: RES_PRF_TRUNC for dig.

	1096.	[func]		libbind: "DNSSEC OK" (DO) support.

	1095.	[func]		libbind: resolver option: no-tld-query.  disables
				trying unqualified as a tld.  no_tld_query is also
				supported for FreeBSD compatibility.

	1094.	[func]		libbind: add support gcc's format string checking.

	1093.	[doc]		libbind: miscellaneous nroff fixes.

	1092.	[bug]		libbind: get*by*() failed to check if res_init() had
				been called.

	1091.	[bug]		libbind: misplaced va_end().

	1090.	[bug]		libbind: dns_ho.c:add_hostent() was not returning
				the amount of memory consumed resulting in garbage
				address being returned.  Alignment calculations were
				wasting space.  We weren't suppressing duplicate
				addresses.

	1089.	[func]		libbind: inet_{cidr,net}_{pton,ntop}() now have IPv6
				support.

	1088.	[port]		libbind: MPE/iX C.70 (incomplete)

	1087.	[bug]		libbind: struct __res_state too large on 64 bit arch.

	1086.	[port]		libbind: sunos: old sprintf.

	1085.	[port]		libbind: solaris: sys_nerr and sys_errlist do not
				exist when compiling in 64 bit mode.

	1084.	[cleanup]	libbind: gai_strerror() rewritten.

	1083.	[bug]		The default control channel listened on the
				wildcard address, not the loopback as documented.
				[RT #1975]

	1082.	[bug]		The -g option to named incorrectly caused logging
				to be sent to syslog in addition to stderr.
				[RT #1974]

	1081.	[bug]		Multicast queries were incorrectly identified
				based on the source address, not the destination
				address.

	1080.	[bug]		BIND 8 compatibility: accept bare IP prefixes
				as the second element of a two-element top level
				sort list statement. [RT #1964]

	1079.	[bug]		BIND 8 compatibility: accept bare elements at top
				level of sort list treating them as if they were
				a single element list. [RT #1963]

	1078.	[bug]		We failed to correct bad tv_usec values in one case.
				[RT #1966]

	1077.	[func]		Do not accept further recursive clients when
				the total number of recursive lookups being
				processed exceeds max-recursive-clients, even
				if some of the lookups are internally generated.
				[RT #1915, #1938]

	1076.	[bug]		A badly defined global key could trigger an assertion
				on load/reload if views were used. [RT #1947]

	1075.	[bug]		Out-of-range network prefix lengths were not
				reported. [RT #1954]

	1074.	[bug]		Running out of memory in dump_rdataset() could
				cause an assertion failure. [RT #1946]

	1073.	[bug]		The ADB cache cleaning should also be space driven.
				[RT #1915, #1938]

	1072.	[bug]		The TCP client quota could be exceeded when
				recursion occurred. [RT #1937]

	1071.	[bug]		Sockets listening for TCP DNS connections
				specified an excessive listen backlog. [RT #1937]

	1070.	[bug]		Copy DNSSEC OK (DO) to response as specified by
				draft-ietf-dnsext-dnssec-okbit-03.txt.

	1069.	[placeholder]

	1068.	[bug]		errno could be overwritten by catgets(). [RT #1921]

	1067.	[func]		Allow quotas to be soft, isc_quota_soft().

	1066.	[bug]		Provide a thread safe wrapper for strerror().
				[RT #1689]

	1065.	[func]		Runtime support to select new / old style interface
				scanning using ioctls.

	1064.	[bug]		Do not shut down active network interfaces if we
				are unable to scan the interface list. [RT #1921]

	1063.	[bug]		libbind: "make install" was failing on IRIX.
				[RT #1919]

	1062.	[bug]		If the control channel listener socket was shut
				down before server exit, the listener object could
				be freed twice. [RT #1916]

	1061.	[bug]		If periodic cache cleaning happened to start
				while cleaning due to reaching the configured
				maximum cache size was in progress, the server
				could catch an assertion failure. [RT #1912]

	1060.	[func]		Move refresh, stub and notify UDP retry processing
				into dns_request.

	1059.	[func]		dns_request now support will now retry UDP queries,
				dns_request_createvia2() and dns_request_createraw2().

	1058.	[func]		Limited lifetime ticker timers are now available,
				isc_timertype_limited.

	1057.	[bug]		Reloading the server after adding a "file" clause
				to a zone statement could cause the server to
				crash due to a typo in change 1016.

	1056.	[bug]		Rndc could catch an assertion failure on SIGINT due
				to an uninitialized variable. [RT #1908]

	1055.	[func]		Version and hostname queries can now be disabled
				using "version none;" and "hostname none;",
				respectively.

	1054.	[bug]		On Win32, cfg_categories and cfg_modules need to be
				exported from the libisccfg DLL.

	1053.	[bug]		Dig did not increase its timeout when receiving
				AXFRs unless the +time option was used. [RT #1904]

	1052.	[bug]		Journals were not being created in binary mode
				resulting in "journal format not recognized" error
				under Win32. [RT #1889]

	1051.	[bug]		Do not ignore a network interface completely just
				because it has a noncontiguous netmask.  Instead,
				omit it from the localnets ACL and issue a warning.
				[RT #1891]

	1050.	[bug]		Log messages reporting malformed IP addresses in
				address lists such as that of the forwarders option
				failed to include the correct error code, file
				name, and line number. [RT #1890]

	1049.	[func]		"pid-file none;" will disable writing a pid file.
				[RT #1848]

	1048.	[bug]		Servers built with -DISC_MEM_USE_INTERNAL_MALLOC=1
				didn't work.

	1047.	[bug]		named was incorrectly refusing all requests signed
				with a TSIG key derived from an unsigned TKEY
				negotiation with a NOERROR response. [RT #1886]

	1046.	[bug]		The help message for the --with-openssl configure
				option was inaccurate. [RT #1880]

	1045.	[bug]		It was possible to skip saving glue for a nameserver
				for a stub zone.

	1044.	[bug]		Specifying allow-transfer, notify-source, or
				notify-source-v6 in a stub zone was not treated
				as an error.

	1043.	[bug]		Specifying a transfer-source or transfer-source-v6
				option in the zone statement for a master zone was
				not treated as an error. [RT #1876]

	1042.	[bug]		The "config" logging category did not work properly.
				[RT #1873]

	1041.	[bug]		Dig/host/nslookup could catch an assertion failure
				on SIGINT due to an uninitialized variable. [RT #1867]

	1040.	[bug]		Multiple listen-on-v6 options with different ports
				were not accepted. [RT #1875]

	1039.	[bug]		Negative responses with CNAMEs in the answer section
				were cached incorrectly. [RT #1862]

	1038.	[bug]		In servers configured with a tkey-domain option,
				TKEY queries with an owner name other than the root
				could cause an assertion failure. [RT #1866, #1869]

	1037.	[bug]		Negative responses whose authority section contain
				SOA or NS records whose owner names are not equal
				equal to or parents of the query name should be
				rejected. [RT #1862]

	1036.	[func]		Silently drop requests received via multicast as
				long as there is no final multicast DNS standard.

	1035.	[bug]		If we respond to multicast queries (which we
				currently do not), respond from a unicast address
				as specified in RFC 1123. [RT #137]

	1034.	[bug]		Ignore the RD bit on multicast queries as specified
				in RFC 1123. [RT #137]

	1033.	[bug]		Always respond to requests with an unsupported opcode
				with NOTIMP, even if we don't have a matching view
				or cannot determine the class.

	1032.	[func]		hostname.bind/txt/chaos now returns the name of
				the machine hosting the nameserver.  This is useful
				in diagnosing problems with anycast servers.

	1031.	[bug]		libbind.a: isc__gettimeofday() infinite recursion.
				[RT #1858]

	1030.	[bug]		On systems with no resolv.conf file, nsupdate
				exited with an error rather than defaulting
				to using the loopback address. [RT #1836]

	1029.	[bug]		Some named.conf errors did not cause the loading
				of the configuration file to return a failure
				status even though they were logged. [RT #1847]

	1028.	[bug]		On Win32, dig/host/nslookup looked for resolv.conf
				in the wrong directory. [RT #1833]

	1027.	[bug]		RRs having the reserved type 0 should be rejected.
				[RT #1471]

	1026.	[placeholder]

	1025.	[bug]		Don't use multicast addresses to resolve iterative
				queries. [RT #101]

	1024.	[port]		Compilation failed on HP-UX 11.11 due to
				incompatible use of the SIOCGLIFCONF macro
				name. [RT #1831]

	1023.	[func]		Accept hints without TTLs.

	1022.	[bug]		Don't report empty root hints as "extra data".
				[RT #1802]

	1021.	[bug]		On Win32, log message timestamps were one month
				later than they should have been, and the server
				would exhibit unspecified behavior in December.

	1020.	[bug]		IXFR log messages did not distinguish between
				true IXFRs, AXFR-style IXFRs, and mere version
				polls. [RT #1811]

	1019.	[bug]		The value of the lame-ttl option was limited to 18000
				seconds, not 1800 seconds as documented. [RT #1803]

	1018.	[bug]		The default log channel was not always initialized
				correctly. [RT #1813]

	1017.	[bug]		When specifying TSIG keys to dig and nsupdate using
				the -k option, they must be HMAC-MD5 keys. [RT #1810]

	1016.	[bug]		Slave zones with no backup file were re-transferred
				on every server reload.

	1015.	[bug]		Log channels that had a "versions" option but no
				"size" option failed to create numbered log
				files. [RT #1783]

	1014.	[bug]		Some queries would cause statistics counters to
				increment more than once or not at all. [RT #1321]

	1013.	[bug]		It was possible to cancel a query twice when marking
				a server as bogus or by having a blackhole acl.
				[RT #1776]

	1012.	[bug]		The -p option to named did not behave as documented.

	1011.	[cleanup]	Removed isc_dir_current().

	1010.	[bug]		The server could attempt to execute a command channel
				command after initiating server shutdown, causing
				an assertion failure. [RT #1766]

	1009.	[port]		OpenUNIX 8 support. [RT #1728]

	1008.	[port]		libtool.m4, ltmain.sh from libtool-1.4.2.

	1007.	[port]		config.guess, config.sub from autoconf-2.52.

	1006.	[bug]		If a KEY RR was found missing during DNSSEC validation,
				an assertion failure could subsequently be triggered
				in the resolver. [RT #1763]

	1005.	[bug]		Don't copy nonzero RCODEs from request to response.
				[RT #1765]

	1004.	[port]		Deal with recvfrom() returning EHOSTDOWN. [RT #1770]

	1003.	[func]		Add the +retry option to dig.

	1002.	[bug]		When reporting an unknown class name in named.conf,
				including the file name and line number. [RT #1759]

	1001.	[bug]		win32 socket code doio_recv was not catching a
				WSACONNRESET error when a client was timing out
				the request and closing its socket. [RT #1745]

	1000.	[bug]		BIND 8 compatibility: accept "HESIOD" as an alias
				for class "HS". [RT #1759]

	 999.	[func]		"rndc retransfer zone [class [view]]" added.
				[RT #1752]

	 998.	[func]		named-checkzone now has arguments to specify the
				chroot directory (-t) and working directory (-w).
				[RT #1755]

	 997.	[func]		Add support for RSA-SHA1 keys (RFC3110).

	 996.	[func]		Issue warning if the configuration filename contains
				the chroot path.

	 995.	[bug]		dig, host, nslookup: using a raw IPv6 address as a
				target address should be fatal on a IPv4 only system.

	 994.	[func]		Treat non-authoritative responses to queries for type
				NS as referrals even if the NS records are in the
				answer section, because BIND 8 servers incorrectly
				send them that way.  This is necessary for DNSSEC
				validation of the NS records of a secure zone to
				succeed when the parent is a BIND 8 server. [RT #1706]

	 993.	[func]		dig: -v now reports the version.

	 992.	[doc]		dig: ~/.digrc is now documented.

	 991.	[func]		Lower UDP refresh timeout messages to level
				debug 1.

	 990.	[bug]		The rndc-confgen man page was not installed.

	 989.	[bug]		Report filename if $INCLUDE fails for file related
				errors. [RT #1736]

	 988.	[bug]		'additional-from-auth no;' did not work reliably
				in the case of queries answered from the cache.
				[RT #1436]

	 987.	[bug]		"dig -help" didn't show "+[no]stats".

	 986.	[bug]		"dig +noall" failed to clear stats and command
				printing.

	 985.	[func]		Consider network interfaces to be up iff they have
				a nonzero IP address rather than based on the
				IFF_UP flag. [RT #1160]

	 984.	[bug]		Multi-threading should be enabled by default on
				Solaris 2.7 and newer, but it wasn't.

	 983.	[func]		The server now supports generating IXFR difference
				sequences for non-dynamic zones by comparing zone
				versions, when enabled using the new config
				option "ixfr-from-differences". [RT #1727]

	 982.	[func]		If "memstatistics-file" is set in options the memory
				statistics will be written to it.

	 981.	[func]		The dnssec tools can now take multiple '-r randomfile'
				arguments.

	 980.	[bug]		Incoming zone transfers restarting after an error
				could trigger an assertion failure. [RT #1692]

	 979.	[func]		Incremental master file dumping.  dns_master_dumpinc(),
				dns_master_dumptostreaminc(), dns_dumpctx_attach(),
				dns_dumpctx_detach(), dns_dumpctx_cancel(),
				dns_dumpctx_db() and dns_dumpctx_version().

	 978.	[bug]		dns_db_attachversion() had an invalid REQUIRE()
				condition.

	 977.	[bug]		Improve "not at top of zone" error message.

	 976.	[func]		named-checkconf can now test load master zones
				(named-checkconf -z). [RT #1468]

	 975.	[bug]		"max-cache-size default;" as a view option
				caused an assertion failure.

	 974.	[bug]		"max-cache-size unlimited;" as a global option
				was not accepted.

	 973.	[bug]		Failed to log the question name when logging:
				"bad zone transfer request: non-authoritative zone
				(NOTAUTH)".

	 972.	[bug]		The file modification time code in zone.c was using the
				wrong epoch. [RT #1667]

	 971.	[placeholder]

	 970.	[func]		'max-journal-size' can now be used to set a target
				size for a journal.

	 969.	[func]		dig now supports the undocumented dig 8 feature
				of allowing arbitrary labels, not just dotted
				decimal quads, with the -x option.  This can be
				used to conveniently look up RFC2317 names as in
				"dig -x 10.0.0.0-127". [RT #827, #1576, #1598]

	 968.	[bug]		On win32, the isc_time_now() function was unnecessarily
				calling strtime(). [RT #1671]

	 967.	[bug]		On win32, the link for bindevt was not including the
				required resource file to enable the event viewer
				to interpret the error messages in the event log,
				[RT #1668]

	 966.	[placeholder]

	 965.	[bug]		Including data other than root server NS and A
				records in the root hint file could cause a rbtdb
				node reference leak. [RT #1581, #1618]

	 964.	[func]		Warn if data other than root server NS and A records
				are found in the root hint file. [RT #1581, #1618]

	 963.	[bug]		Bad ISC_LANG_ENDDECLS. [RT #1645]

	 962.	[bug]		libbind: bad "#undef", don't attempt to install
				non-existent nlist.h. [RT #1640]

	 961.	[bug]		Tried to use a IPV6 feature when ISC_PLATFORM_HAVEIPV6
				was not defined. [RT #1482]

	 960.	[port]		liblwres failed to build on systems with support for
				getrrsetbyname() in the OS. [RT #1592]

	 959.	[port]		On FreeBSD, determine the number of CPUs by calling
				sysctlbyname(). [RT #1584]

	 958.	[port]		ssize_t is not available on all platforms. [RT #1607]

	 957.	[bug]		sys/select.h inclusion was broken on older platforms.
				[RT #1607]

	 956.	[bug]		ns_g_autorndcfile changed to ns_g_keyfile
				in named/win32/os.c due to code changes in
				change #953. win32 .make file for rndc-confgen
				updated to add include path for os.h header.

.. code-block:: none

		--- 9.2.0rc1 released ---

	 955.	[bug]		When using views, the zone's class was not being
				inherited from the view's class. [RT #1583]

	 954.	[bug]		When requesting AXFRs or IXFRs using dig, host, or
				nslookup, the RD bit should not be set as zone
				transfers are inherently non-recursive. [RT #1575]

	 953.	[func]		The /var/run/named.key file from change #843
				has been replaced by /etc/rndc.key.  Both
				named and rndc will look for this file and use
				it to configure a default control channel key
				if not already configured using a different
				method (rndc.conf / controls).  Unlike
				named.key, rndc.key is not created automatically;
				it must be created by manually running
				"rndc-confgen -a".

	 952.	[bug]		The server required manual intervention to serve the
				affected zones if it died between creating a journal
				and committing the first change to it.

	 951.	[bug]		CFLAGS was not passed to the linker when
				linking some of the test programs under
				bin/tests. [RT #1555].

	 950.	[bug]		Explicit TTLs did not properly override $TTL
				due to a bug in change 834. [RT #1558]

	 949.	[bug]		host was unable to print records larger than 512
				bytes. [RT #1557]

.. code-block:: none

		--- 9.2.0b2 released ---

	 948.	[port]		Integrated support for building on Windows NT /
				Windows 2000.

	 947.	[bug]		dns_rdata_soa_t had a badly named element "mname" which
				was really the RNAME field from RFC1035.  To avoid
				confusion and silent errors that would occur it the
				"origin" and "mname" elements were given their correct
				names "mname" and "rname" respectively, the "mname"
				element is renamed to "contact".

	 946.	[cleanup]	doc/misc/options is now machine-generated from the
				configuration parser syntax tables, and therefore
				more likely to be correct.

	 945.	[func]		Add the new view-specific options
				"match-destinations" and "match-recursive-only".

	 944.	[func]		Check for expired signatures on load.

	 943.	[bug]		The server could crash when receiving a command
				via rndc if the configuration file listed only
				nonexistent keys in the controls statement. [RT #1530]

	 942.	[port]		libbind: GETNETBYADDR_ADDR_T was not correctly
				defined on some platforms.

	 941.	[bug]		The configuration checker crashed if a slave
				zone didn't contain a masters statement. [RT #1514]

	 940.	[bug]		Double zone locking failure on error path. [RT #1510]

.. code-block:: none

		--- 9.2.0b1 released ---

	 939.	[port]		Add the --disable-linux-caps option to configure for
				systems that manage capabilities outside of named.
				[RT #1503]

	 938.	[placeholder]

	 937.	[bug]		A race when shutting down a zone could trigger a
				INSIST() failure. [RT #1034]

	 936.	[func]		Warn about IPv4 addresses that are not complete
				dotted quads. [RT #1084]

	 935.	[bug]		inet_pton failed to reject leading zeros.

	 934.	[port]		Deal with systems where accept() spuriously returns
				ECONNRESET.

	 933.	[bug]		configure failed doing libbind on platforms not
				supported by BIND 8. [RT #1496]

.. code-block:: none

		--- 9.2.0a3 released ---

	 932.	[bug]		Use INSTALL_SCRIPT, not INSTALL_PROGRAM,
				when installing isc-config.sh.
				[RT #198, #1466]

	 931.	[bug]		The controls statement only attempted to verify
				messages using the first key in the key list.
				(9.2.0a1/a2 only).

	 930.	[func]		Query performance testing tool added as
				contrib/queryperf.

	 929.	[placeholder]

	 928.	[bug]		nsupdate would send empty update packets if the
				send (or empty line) command was run after
				another send but before any new updates or
				prerequisites were specified.  It should simply
				ignore this command.

	 927.	[bug]		Don't hold the zone lock for the entire dump to disk.
				[RT #1423]

	 926.	[bug]		The resolver could deadlock with the ADB when
				shutting down (multi-threaded builds only).
				[RT #1324]

	 925.	[cleanup]	Remove openssl from the distribution; require that
				--with-openssl be specified if DNSSEC is needed.

	 924.	[port]		Extend support for pre-RFC2133 IPv6 implementation.
				[RT #987]

	 923.	[bug]		Multiline TSIG secrets (and other multiline strings)
				were not accepted in named.conf. [RT #1469]

	 922.	[func]		Added two new lwres_getrrsetbyname() result codes,
				ERR_NONAME and ERR_NODATA.

	 921.	[bug]		lwres returned an incorrect error code if it received
				a truncated message.

	 920.	[func]		Increase the lwres receive buffer size to 16K.
				[RT #1451]

	 919.	[placeholder]

	 918.	[func]		In nsupdate, TSIG errors are no longer treated as
				fatal errors.

	 917.	[func]		New nsupdate command 'key', allowing TSIG keys to
				be specified in the nsupdate command stream rather
				than the command line.

	 916.	[bug]		Specifying type ixfr to dig without specifying
				a serial number failed in unexpected ways.

	 915.	[func]		The named-checkconf and named-checkzone programs
				now have a '-v' option for printing their version.
				[RT #1151]

	 914.	[bug]		Global 'server' statements were rejected when
				using views, even though they were accepted
				in 9.1. [RT #1368]

	 913.	[bug]		Cache cleaning was not sufficiently aggressive.
				[RT #1441, #1444]

	 912.	[bug]		Attempts to set the 'additional-from-cache' or
				'additional-from-auth' option to 'no' in a
				server with recursion enabled will now
				be ignored and cause a warning message.
				[RT #1145]

	 911.	[placeholder]

	 910.	[port]		Some pre-RFC2133 IPv6 implementations do not define
				IN6ADDR_ANY_INIT. [RT #1416]

	 909.	[placeholder]

	 908.	[func]		New program, rndc-confgen, to simplify setting up rndc.

	 907.	[func]		The ability to get entropy from either the
				random device, a user-provided file or from
				the keyboard was migrated from the DNSSEC tools
				to libisc as isc_entropy_usebestsource().

	 906.	[port]		Separated the system independent portion of
				lib/isc/unix/entropy.c into lib/isc/entropy.c
				and added lib/isc/win32/entropy.c.

	 905.	[bug]		Configuring a forward "zone" for the root domain
				did not work. [RT #1418]

	 904.	[bug]		The server would leak memory if attempting to use
				an expired TSIG key. [RT #1406]

	 903.	[bug]		dig should not crash when receiving a TCP packet
				of length 0.

	 902.	[bug]		The -d option was ignored if both -t and -g were also
				specified.

	 901.	[placeholder]

	 900.	[bug]		A config.guess update changed the system identification
				string of FreeBSD systems; configure and
				bin/tests/system/ifconfig.sh now recognize the new
				string.

.. code-block:: none

		--- 9.2.0a2 released ---

	 899.	[bug]		lib/dns/soa.c failed to compile on many platforms
				due to inappropriate use of a void value.
				[RT #1372, #1373, #1386, #1387, #1395]

	 898.	[bug]		"dig" failed to set a nonzero exit status
				on UDP query timeout. [RT #1323]

	 897.	[bug]		A config.guess update changed the system identification
				string of UnixWare systems; configure now recognizes
				the new string.

	 896.	[bug]		If a configuration file is set on named's command line
				and it has a relative pathname, the current directory
				(after any possible jailing resulting from named -t)
				will be prepended to it so that reloading works
				properly even when a directory option is present.

	 895.	[func]		New function, isc_dir_current(), akin to POSIX's
				getcwd().

	 894.	[bug]		When using the DNSSEC tools, a message intended to warn
				when the keyboard was being used because of the lack
				of a suitable random device was not being printed.

	 893.	[func]		Removed isc_file_test() and added isc_file_exists()
				for the basic functionality that was being added
				with isc_file_test().

	 892.	[placeholder]

	 891.	[bug]		Return an error when a SIG(0) signed response to
				an unsigned query is seen.  This should actually
				do the verification, but it's not currently
				possible. [RT #1391]

	 890.	[cleanup]	The man pages no longer require the mandoc macros
				and should now format cleanly using most versions of
				nroff, and HTML versions of the man pages have been
				added.  Both are generated from DocBook source.

	 889.	[port]		Eliminated blank lines before .TH in nroff man
				pages since they cause problems with some versions
				of nroff. [RT #1390]

	 888.	[bug]		Don't die when using TKEY to delete a nonexistent
				TSIG key. [RT #1392]

	 887.	[port]		Detect broken compilers that can't call static
				functions from inline functions. [RT #1212]

	 886.	[placeholder]

	 885.	[placeholder]

	 884.	[placeholder]

	 883.	[placeholder]

	 882.	[placeholder]

	 881.	[placeholder]

	 880.	[placeholder]

	 879.	[placeholder]

	 878.	[placeholder]

	 877.	[placeholder]

	 876.	[placeholder]

	 875.	[placeholder]

	 874.	[placeholder]

	 873.	[placeholder]

	 872.	[placeholder]

	 871.	[placeholder]

	 870.	[placeholder]

	 869.	[placeholder]

	 868.	[placeholder]

	 867.	[placeholder]

	 866.	[func]		Close debug only file channels when debug is set to
				zero. [RT #1246]

	 865.	[bug]		The new configuration parser did not allow
				the optional debug level in a "severity debug"
				clause of a logging channel to be omitted.
				This is now allowed and treated as "severity
				debug 1;" like it does in BIND 8.2.4, not as
				"severity debug 0;" like it did in BIND 9.1.
				[RT #1367]

	 864.	[cleanup]	Multi-threading is now enabled by default on
				OSF1, Solaris 2.7 and newer, AIX, IRIX, and HP-UX.

	 863.	[bug]		If an error occurred while an outgoing zone transfer
				was starting up, the server could access a domain
				name that had already been freed when logging a
				message saying that the transfer was starting.
				[RT #1383]

	 862.	[bug]		Use after realloc(), non portable pointer arithmetic in
				grmerge().

	 861.	[port]		Add support for Mac OS X, by making it equivalent
				to Darwin.  This was derived from the config.guess
				file shipped with Mac OS X. [RT #1355]

	 860.	[func]		Drop cross class glue in zone transfers.

	 859.	[bug]		Cache cleaning now won't swamp the CPU if there
				is a persistent over limit condition.

	 858.	[func]		isc_mem_setwater() no longer requires that when the
				callback function is non-NULL then its hi_water
				argument must be greater than its lo_water argument
				(they can now be equal) or that they be non-zero.

	 857.	[cleanup]	Use ISC_MAGIC() to define all magic numbers for
				structs, for our friends in EBCDIC-land.

	 856.	[func]		Allow partial rdatasets to be returned in answer and
				authority sections to help non-TCP capable clients
				recover from truncation. [RT #1301]

	 855.	[bug]		Stop spurious "using RFC 1035 TTL semantics" warnings.

	 854.	[bug]		The config parser didn't properly handle config
				options that were specified in units of time other
				than seconds. [RT #1372]

	 853.	[bug]		configure_view_acl() failed to detach existing acls.
				[RT #1374]

	 852.	[bug]		Handle responses from servers which do not know
				about IXFR.

	 851.	[cleanup]	The obsolete support-ixfr option was not properly
				ignored.

.. code-block:: none

		--- 9.2.0a1 released ---

	 850.	[bug]		dns_rbt_findnode() would not find nodes that were
				split on a bitstring label somewhere other than in
				the last label of the node. [RT #1351]

	 849.	[func]		<isc/net.h> will ensure INADDR_LOOPBACK is defined.

	 848.	[func]		A minimum max-cache-size of two megabytes is enforced
				by the cache cleaner.

	 847.	[func]		Added isc_file_test(), which currently only has
				some very basic functionality to test for the
				existence of a file, whether a pathname is absolute,
				or whether a pathname is the fundamental representation
				of the current directory.  It is intended that this
				function can be expanded to test other things a
				programmer might want to know about a file.

	 846.	[func]		A non-zero 'param' to dst_key_generate() when making an
				hmac-md5 key means that good entropy is not required.

	 845.	[bug]		The access rights on the public file of a symmetric
				key are now restricted as soon as the file is opened,
				rather than after it has been written and closed.

	 844.	[func]		<isc/net.h> will ensure INADDR_LOOPBACK is defined,
				just as <lwres/net.h> does.

	 843.	[func]		If no controls statement is present in named.conf,
				or if any inet phrase of a controls statement is
				lacking a keys clause, then a key will be automatically
				generated by named and an rndc.conf-style file
				named named.key will be written that uses it.  rndc
				will use this file only if its normal configuration
				file, or one provided on the command line, does not
				exist.

	 842.	[func]		'rndc flush' now takes an optional view.

	 841.	[bug]		When sdb modules were not declared threadsafe, their
				create and destroy functions were not serialized.

	 840.	[bug]		The config file parser could print the wrong file
				name if an error was detected after an included file
				was parsed. [RT #1353]

	 839.	[func]		Dump packets for which there was no view or that the
				class could not be determined to category "unmatched".

	 838.	[port]		UnixWare 7.x.x is now supported by
				bin/tests/system/ifconfig.sh.

	 837.	[cleanup]	Multi-threading is now enabled by default only on
				OSF1, Solaris 2.7 and newer, and AIX.

	 836.	[func]		Upgraded libtool to 1.4.

	 835.	[bug]		The dispatcher could enter a busy loop if
				it got an I/O error receiving on a UDP socket.
				[RT #1293]

	 834.	[func]		Accept (but warn about) master files beginning with
				an SOA record without an explicit TTL field and
				lacking a $TTL directive, by using the SOA MINTTL
				as a default TTL.  This is for backwards compatibility
				with old versions of BIND 8, which accepted such
				files without warning although they are illegal
				according to RFC1035.

	 833.	[cleanup]	Moved dns_soa_*() from <dns/journal.h> to
				<dns/soa.h>, and extended them to support
				all the integer-valued fields of the SOA RR.

	 832.	[bug]		The default location for named.conf in named-checkconf
				should depend on --sysconfdir like it does in named.
				[RT #1258]

	 831.	[placeholder]

	 830.	[func]		Implement 'rndc status'.

	 829.	[bug]		The DNS_R_ZONECUT result code should only be returned
				when an ANY query is made with DNS_DBFIND_GLUEOK set.
				In all other ANY query cases, returning the delegation
				is better.

	 828.	[bug]		The errno value from recvfrom() could be overwritten
				by logging code. [RT #1293]

	 827.	[bug]		When an IXFR protocol error occurs, the slave
				should retry with AXFR.

	 826.	[bug]		Some IXFR protocol errors were not detected.

	 825.	[bug]		zone.c:ns_query() detached from the wrong zone
				reference. [RT #1264]

	 824.	[bug]		Correct line numbers reported by dns_master_load().
				[RT #1263]

	 823.	[func]		The output of "dig -h" now goes to stdout so that it
				can easily be piped through "more". [RT #1254]

	 822.	[bug]		Sending nxrrset prerequisites would crash nsupdate.
				[RT #1248]

	 821.	[bug]		The program name used when logging to syslog should
				be stripped of leading path components.
				[RT #1178, #1232]

	 820.	[bug]		Name server address lookups failed to follow
				A6 chains into the glue of local authoritative
				zones.

	 819.	[bug]		In certain cases, the resolver's attempts to
				restart an address lookup at the root could cause
				the fetch to deadlock (with itself) instead of
				restarting. [RT #1225]

	 818.	[bug]		Certain pathological responses to ANY queries could
				cause an assertion failure. [RT #1218]

	 817.	[func]		Adjust timeouts for dialup zone queries.

	 816.	[bug]		Report potential problems with log file accessibility
				at configuration time, since such problems can't
				reliably be reported at the time they actually occur.

	 815.	[bug]		If a log file was specified with a path separator
				character (i.e. "/") in its name and the directory
				did not exist, the log file's name was treated as
				though it were the directory name. [RT #1189]

	 814.	[bug]		Socket objects left over from accept() failures
				were incorrectly destroyed, causing corruption
				of socket manager data structures.

	 813.	[bug]		File descriptors exceeding FD_SETSIZE were handled
				badly. [RT #1192]

	 812.	[bug]		dig sometimes printed incomplete IXFR responses
				due to an uninitialized variable. [RT #1188]

	 811.	[bug]		Parentheses were not quoted in zone dumps. [RT #1194]

	 810.	[bug]		The signer name in SIG records was not properly
				down-cased when signing/verifying records. [RT #1186]

	 809.	[bug]		Configuring a non-local address as a transfer-source
				could cause an assertion failure during load.

	 808.	[func]		Add 'rndc flush' to flush the server's cache.

	 807.	[bug]		When setting up TCP connections for incoming zone
				transfers, the transfer-source port was not
				ignored like it should be.

	 806.	[bug]		DNS_R_SEENINCLUDE was failing to propagate back up
				the calling stack to the zone maintenance level,
				causing zones to not reload when an included file was
				touched but the top-level zone file was not.

	 805.	[bug]		When using "forward only", missing root hints should
				not cause queries to fail. [RT #1143]

	 804.	[bug]		Attempting to obtain entropy could fail in some
				situations.  This would be most common on systems
				with user-space threads. [RT #1131]

	 803.	[bug]		Treat all SIG queries as if they have the CD bit set,
				otherwise no data will be returned [RT #749]

	 802.	[bug]		DNSSEC key tags were computed incorrectly in almost
				all cases. [RT #1146]

	 801.	[bug]		nsupdate should treat lines beginning with ';' as
				comments. [RT #1139]

	 800.	[bug]		dnssec-signzone produced incorrect statistics for
				large zones. [RT #1133]

	 799.	[bug]		The ADB didn't find AAAA glue in a zone unless A6
				glue was also present.

	 798.	[bug]		nsupdate should be able to reject bad input lines
				and continue. [RT #1130]

	 797.	[func]		Issue a warning if the 'directory' option contains
				a relative path. [RT #269]

	 796.	[func]		When a size limit is associated with a log file,
				only roll it when the size is reached, not every
				time the log file is opened. [RT #1096]

	 795.	[func]		Add the +multiline option to dig. [RT #1095]

	 794.	[func]		Implement the "port" and "default-port" statements
				in rndc.conf.

	 793.	[cleanup]	The DNSSEC tools could create filenames that were
				illegal or contained shell meta-characters.  They
				now use a different text encoding of names that
				doesn't have these problems. [RT #1101]

	 792.	[cleanup]	Replace the OMAPI command channel protocol with a
				simpler one.

	 791.	[bug]		The command channel now works over IPv6.

	 790.	[bug]		Wildcards created using dynamic update or IXFR
				could fail to match. [RT #1111]

	 789.	[bug]		The "localhost" and "localnets" ACLs did not match
				when used as the second element of a two-element
				sortlist item.

	 788.	[func]		Add the "match-mapped-addresses" option, which
				causes IPv6 v4mapped addresses to be treated as
				IPv4 addresses for the purpose of acl matching.

	 787.	[bug]		The DNSSEC tools failed to downcase domain
				names when mapping them into file names.

	 786.	[bug]		When DNSSEC signing/verifying data, owner names were
				not properly down-cased.

	 785.	[bug]		A race condition in the resolver could cause
				an assertion failure. [RT #673, #872, #1048]

	 784.	[bug]		nsupdate and other programs would not quit properly
				if some signals were blocked by the caller. [RT #1081]

	 783.	[bug]		Following CNAMEs could cause an assertion failure
				when either using an sdb database or under very
				rare conditions.

	 782.	[func]		Implement the "serial-query-rate" option.

	 781.	[func]		Avoid error packet loops by dropping duplicate FORMERR
				responses. [RT #1006]

	 780.	[bug]		Error handling code dealing with out of memory or
				other rare errors could lead to assertion failures
				by calling functions on uninitialized names. [RT #1065]

	 779.	[func]		Added the "minimal-responses" option.

	 778.	[bug]		When starting cache cleaning, cleaning_timer_action()
				returned without first pausing the iterator, which
				could cause deadlock. [RT #998]

	 777.	[bug]		An empty forwarders list in a zone failed to override
				global forwarders. [RT #995]

	 776.	[func]		Improved error reporting in denied messages. [RT #252]

	 775.	[placeholder]

	 774.	[func]		max-cache-size is implemented.

	 773.	[func]		Added isc_rwlock_trylock() to attempt to lock without
				blocking.

	 772.	[bug]		Owner names could be incorrectly omitted from cache
				dumps in the presence of negative caching entries.
				[RT #991]

	 771.	[cleanup]	TSIG errors related to unsynchronized clocks
				are logged better. [RT #919]

	 770.	[func]		Add the "edns yes_or_no" statement to the server
				clause. [RT #524]

	 769.	[func]		Improved error reporting when parsing rdata. [RT #740]

	 768.	[bug]		The server did not emit an SOA when a CNAME
				or DNAME chain ended in NXDOMAIN in an
				authoritative zone.

	 767.	[placeholder]

	 766.	[bug]		A few cases in query_find() could leak fname.
				This would trigger the mpctx->allocated == 0
				assertion when the server exited.
				[RT #739, #776, #798, #812, #818, #821, #845,
				#892, #935, #966]

	 765.	[func]		ACL names are once again case insensitive, like
				in BIND 8. [RT #252]

	 764.	[func]		Configuration files now allow "include" directives
				in more places, such as inside the "view" statement.
				[RT #377, #728, #860]

	 763.	[func]		Configuration files no longer have reserved words.
				[RT #731, #753]

	 762.	[cleanup]	The named.conf and rndc.conf file parsers have
				been completely rewritten.

	 761.	[bug]		_REENTRANT was still defined when building with
				--disable-threads.

	 760.	[contrib]	Significant enhancements to the pgsql sdb driver.

	 759.	[bug]		The resolver didn't turn off "avoid fetches" mode
				when restarting, possibly causing resolution
				to fail when it should not.  This bug only affected
				platforms which support both IPv4 and IPv6. [RT #927]

	 758.	[bug]		The "avoid fetches" code did not treat negative
				cache entries correctly, causing fetches that would
				be useful to be avoided.  This bug only affected
				platforms which support both IPv4 and IPv6. [RT #927]

	 757.	[func]		Log zone transfers.

	 756.	[bug]		dns_zone_load() could "return" success when no master
				file was configured.

	 755.	[bug]		Fix incorrectly formatted log messages in zone.c.

	 754.	[bug]		Certain failure conditions sending UDP packets
				could cause the server to retry the transmission
				indefinitely. [RT #902]

	 753.	[bug]		dig, host, and nslookup would fail to contact a
				remote server if getaddrinfo() returned an IPv6
				address on a system that doesn't support IPv6.
				[RT #917]

	 752.	[func]		Correct bad tv_usec elements returned by
				gettimeofday().

	 751.	[func]		Log successful zone loads / transfers.  [RT #898]

	 750.	[bug]		A query should not match a DNAME whose trust level
				is pending. [RT #916]

	 749.	[bug]		When a query matched a DNAME in a secure zone, the
				server did not return the signature of the DNAME.
				[RT #915]

	 748.	[doc]		List supported RFCs in doc/misc/rfc-compliance.
				[RT #781]

	 747.	[bug]		The code to determine whether an IXFR was possible
				did not properly check for a database that could
				not have a journal. [RT #865, #908]

	 746.	[bug]		The sdb didn't clone rdatasets properly, causing
				a crash when the server followed delegations. [RT #905]

	 745.	[func]		Report the owner name of records that fail
				semantic checks while loading.

	 744.	[bug]		When returning DNS_R_CNAME or DNS_R_DNAME as the
				result of an ANY or SIG query, the resolver failed
				to setup the return event's rdatasets, causing an
				assertion failure in the query code. [RT #881]

	 743.	[bug]		Receiving a large number of certain malformed
				answers could cause named to stop responding.
				[RT #861]

	 742.	[placeholder]

	 741.	[port]		Support openssl-engine. [RT #709]

	 740.	[port]		Handle openssl library mismatches slightly better.

	 739.	[port]		Look for /dev/random in configure, rather than
				assuming it will be there for only a predefined
				set of OSes.

	 738.	[bug]		If a non-threadsafe sdb driver supported AXFR and
				received an AXFR request, it would deadlock or die
				with an assertion failure. [RT #852]

	 737.	[port]		stdtime.c failed to compile on certain platforms.

	 736.	[func]		New functions isc_task_{begin,end}exclusive().

	 735.	[doc]		Add BIND 4 migration notes.

	 734.	[bug]		An attempt to re-lock the zone lock could occur if
				the server was shutdown during a zone transfer.
				[RT #830]

	 733.	[bug]		Reference counts of dns_acl_t objects need to be
				locked but were not. [RT #801, #821]

	 732.	[bug]		Glue with 0 TTL could also cause SERVFAIL. [RT #828]

	 731.	[bug]		Certain zone errors could cause named-checkzone to
				fail ungracefully. [RT #819]

	 730.	[bug]		lwres_getaddrinfo() returns the correct result when
				it fails to contact a server. [RT #768]

	 729.	[port]		pthread_setconcurrency() needs to be called on Solaris.

	 728.	[bug]		Fix comment processing on master file directives.
				[RT #757]

	 727.	[port]		Work around OS bug where accept() succeeds but
				fails to fill in the peer address of the accepted
				connection, by treating it as an error rather than
				an assertion failure. [RT #809]

	 726.	[func]		Implement the "trace" and "notrace" commands in rndc.

	 725.	[bug]		Installing man pages could fail.

	 724.	[func]		New libisc functions isc_netaddr_any(),
				isc_netaddr_any6().

	 723.	[bug]		Referrals whose NS RRs had a 0 TTL caused the resolver
				to return DNS_R_SERVFAIL. [RT #783]

	 722.	[func]		Allow incremental loads to be canceled.

	 721.	[cleanup]	Load manager and dns_master_loadfilequota() are no
				more.

	 720.	[bug]		Server could enter infinite loop in
				dispatch.c:do_cancel(). [RT #733]

	 719.	[bug]		Rapid reloads could trigger an assertion failure.
				[RT #743, #763]

	 718.	[cleanup]	"internal" is no longer a reserved word in named.conf.
				[RT #753, #731]

	 717.	[bug]		Certain TKEY processing failure modes could
				reference an uninitialized variable, causing the
				server to crash. [RT #750]

	 716.	[bug]		The first line of a $INCLUDE master file was lost if
				an origin was specified. [RT #744]

	 715.	[bug]		Resolving some A6 chains could cause an assertion
				failure in adb.c. [RT #738]

	 714.	[bug]		Preserve interval timers across reloads unless changed.
				[RT #729]

	 713.	[func]		named-checkconf takes '-t directory' similar to named.
				[RT #726]

	 712.	[bug]		Sending a large signed update message caused an
				assertion failure. [RT #718]

	 711.	[bug]		The libisc and liblwres implementations of
				inet_ntop contained an off by one error.

	 710.	[func]		The forwarders statement now takes an optional
				port. [RT #418]

	 709.	[bug]		ANY or SIG queries for data with a TTL of 0
				would return SERVFAIL. [RT #620]

	 708.	[bug]		When building with --with-openssl, the openssl headers
				included with BIND 9 should not be used. [RT #702]

	 707.	[func]		The "filename" argument to named-checkzone is no
				longer optional, to reduce confusion. [RT #612]

	 706.	[bug]		Zones with an explicit "allow-update { none; };"
				were considered dynamic and therefore not reloaded
				on SIGHUP or "rndc reload".

	 705.	[port]		Work out resource limit type for use where rlim_t is
				not available. [RT #695]

	 704.	[port]		RLIMIT_NOFILE is not available on all platforms.
				[RT #695]

	 703.	[port]		sys/select.h is needed on older platforms. [RT #695]

	 702.	[func]		If the address 0.0.0.0 is seen in resolv.conf,
				use 127.0.0.1 instead. [RT #693]

	 701.	[func]		Root hints are now fully optional.  Class IN
				views use compiled-in hints by default, as
				before.  Non-IN views with no root hints now
				provide authoritative service but not recursion.
				A warning is logged if a view has neither root
				hints nor authoritative data for the root. [RT #696]

	 700.	[bug]		$GENERATE range check was wrong. [RT #688]

	 699.	[bug]		The lexer mishandled empty quoted strings. [RT #694]

	 698.	[bug]		Aborting nsupdate with ^C would lead to several
				race conditions.

	 697.	[bug]		nsupdate was not compatible with the undocumented
				BIND 8 behavior of ignoring TTLs in "update delete"
				commands. [RT #693]

	 696.	[bug]		lwresd would die with an assertion failure when passed
				a zero-length name. [RT #692]

	 695.	[bug]		If the resolver attempted to query a blackholed or
				bogus server, the resolution would fail immediately.

	 694.	[bug]		$GENERATE did not produce the last entry.
				[RT #682, #683]

	 693.	[bug]		An empty lwres statement in named.conf caused
				the server to crash while loading.

	 692.	[bug]		Deal with systems that have getaddrinfo() but not
				gai_strerror(). [RT #679]

	 691.	[bug]		Configuring per-view forwarders caused an assertion
				failure. [RT #675, #734]

	 690.	[func]		$GENERATE now supports DNAME. [RT #654]

	 689.	[doc]		man pages are now installed. [RT #210]

	 688.	[func]		"make tags" now works on systems with the
				"Exuberant Ctags" etags.

	 687.	[bug]		Only say we have IPv6, with sufficient functionality,
				if it has actually been tested. [RT #586]

	 686.	[bug]		dig and nslookup can now be properly aborted during
				blocking operations. [RT #568]

	 685.	[bug]		nslookup should use the search list/domain options
				from resolv.conf by default. [RT #405, #630]

	 684.	[bug]		Memory leak with view forwarders. [RT #656]

	 683.	[bug]		File descriptor leak in isc_lex_openfile().

	 682.	[bug]		nslookup displayed SOA records incorrectly. [RT #665]

	 681.	[bug]		$GENERATE specifying output format was broken. [RT #653]

	 680.	[bug]		dns_rdata_fromstruct() mishandled options bigger
				than 255 octets.

	 679.	[bug]		$INCLUDE could leak memory and file descriptors on
				reload. [RT #639]

	 678.	[bug]		"transfer-format one-answer;" could trigger an assertion
				failure. [RT #646]

	 677.	[bug]		dnssec-signzone would occasionally use the wrong ttl
				for database operations and fail. [RT #643]

	 676.	[bug]		Log messages about lame servers to category
				'lame-servers' rather than 'resolver', so as not
				to be gratuitously incompatible with BIND 8.

	 675.	[bug]		TKEY queries could cause the server to leak
				memory.

	 674.	[func]		Allow messages to be TSIG signed / verified using
				a offset from the current time.

	 673.	[func]		The server can now convert RFC1886-style recursive
				lookup requests into RFC2874-style lookups, when
				enabled using the new option "allow-v6-synthesis".

	 672.	[bug]		The wrong time was in the "time signed" field when
				replying with BADTIME error.

	 671.	[bug]		The message code was failing to parse a message with
				no question section and a TSIG record. [RT #628]

	 670.	[bug]		The lwres replacements for getaddrinfo and
				getipnodebyname didn't properly check for the
				existence of the sockaddr sa_len field.

	 669.	[bug]		dnssec-keygen now makes the public key file
				non-world-readable for symmetric keys. [RT #403]

	 668.	[func]		named-checkzone now reports multiple errors in master
				files.

	 667.	[bug]		On Linux, running named with the -u option and a
				non-world-readable configuration file didn't work.
				[RT #626]

	 666.	[bug]		If a request sent by dig is longer than 512 bytes,
				use TCP.

	 665.	[bug]		Signed responses were not sent when the size of the
				TSIG + question exceeded the maximum message size.
				[RT #628]

	 664.	[bug]		The t_tasks and t_timers module tests are now skipped
				when building without threads, since they require
				threads.

	 663.	[func]		Accept a size_spec, not just an integer, in the
				(unimplemented and ignored) max-ixfr-log-size option
				for compatibility with recent versions of BIND 8.
				[RT #613]

	 662.	[bug]		dns_rdata_fromtext() failed to log certain errors.

	 661.	[bug]		Certain UDP IXFR requests caused an assertion failure
				(mpctx->allocated == 0). [RT #355, #394, #623]

	 660.	[port]		Detect multiple CPUs on HP-UX and IRIX.

	 659.	[performance]	Rewrite the name compression code to be much faster.

	 658.	[cleanup]	Remove all vestiges of 16 bit global compression.

	 657.	[bug]		When a listen-on statement in an lwres block does not
				specify a port, use 921, not 53.  Also update the
				listen-on documentation. [RT #616]

	 656.	[func]		Treat an unescaped newline in a quoted string as
				an error.  This means that TXT records with missing
				close quotes should have meaningful errors printed.

	 655.	[bug]		Improve error reporting on unexpected eof when loading
				zones. [RT #611]

	 654.	[bug]		Origin was being forgotten in TCP retries in dig.
				[RT #574]

	 653.	[bug]		+defname option in dig was reversed in sense.
				[RT #549]

	 652.	[bug]		zone_saveunique() did not report the new name.

	 651.	[func]		The AD bit in responses now has the meaning
				specified in <draft-ietf-dnsext-ad-is-secure>.

	 650.	[bug]		SIG(0) records were being generated and verified
				incorrectly. [RT #606]

	 649.	[bug]		It was possible to join to an already running fctx
				after it had "cloned" its events, but before it sent
				them.  In this case, the event of the newly joined
				fetch would not contain the answer, and would
				trigger the INSIST() in fctx_sendevents().  In
				BIND 9.0, this bug did not trigger an INSIST(), but
				caused the fetch to fail with a SERVFAIL result.
				[RT #588, #597, #605, #607]

	 648.	[port]		Add support for pre-RFC2133 IPv6 implementations.

	 647.	[bug]		Resolver queries sent after following multiple
				referrals had excessively long retransmission
				timeouts due to incorrectly counting the referrals
				as "restarts".

	 646.	[bug]		The UnixWare ISC_PLATFORM_FIXIN6INADDR fix in isc/net.h
				didn't _cleanly_ fix the problem it was trying to fix.

	 645.	[port]		BSD/OS 3.0 needs pthread_init(). [RT #603]

	 644.	[bug]		#622 needed more work. [RT #562]

	 643.	[bug]		xfrin error messages made more verbose, added class
				of the zone. [RT #599]

	 642.	[bug]		Break the exit_check() race in the zone module.
				[RT #598]

.. code-block:: none

		--- 9.1.0b2 released ---

	 641.	[bug]		$GENERATE caused a uninitialized link to be used.
				[RT #595]

	 640.	[bug]		Memory leak in error path could cause
				"mpctx->allocated == 0" failure. [RT #584]

	 639.	[bug]		Reading entropy from the keyboard would sometimes fail.
				[RT #591]

	 638.	[port]		lib/isc/random.c needed to explicitly include time.h
				to get a prototype for time() when pthreads was not
				being used. [RT #592]

	 637.	[port]		Use isc_u?int64_t instead of (unsigned) long long in
				lib/isc/print.c.  Also allow lib/isc/print.c to
				be compiled even if the platform does not need it.
				[RT #592]

	 636.	[port]		Shut up MSVC++ about a possible loss of precision
				in the ISC__BUFFER_PUTUINT*() macros. [RT #592]

	 635.	[bug]		Reloading a server with a configured blackhole list
				would cause an assertion. [RT #590]

	 634.	[bug]		A log file will completely stop being written when
				it reaches the maximum size in all cases, not just
				when versioning is also enabled. [RT #570]

	 633.	[port]		Cope with rlim_t missing on BSD/OS systems. [RT #575]

	 632.	[bug]		The index array of the journal file was
				corrupted as it was written to disk.

	 631.	[port]		Build without thread support on systems without
				pthreads.

	 630.	[bug]		Locking failure in zone code. [RT #582]

	 629.	[bug]		9.1.0b1 dereferenced a null pointer and crashed
				when responding to a UDP IXFR request.

	 628.	[bug]		If the root hints contained only AAAA addresses,
				named would be unable to perform resolution.

	 627.	[bug]		The EDNS0 blackhole detection code of change 324
				waited for three retransmissions to each server,
				which takes much too long when a domain has many
				name servers and all of them drop EDNS0 queries.
				Now we retry without EDNS0 after three consecutive
				timeouts, even if they are all from different
				servers. [RT #143]

	 626.	[bug]		The lightweight resolver daemon no longer crashes
				when asked for a SIG rrset. [RT #558]

	 625.	[func]		Zones now inherit their class from the enclosing view.

	 624.	[bug]		The zone object could get timer events after it had
				been destroyed, causing a server crash. [RT #571]

	 623.	[func]		Added "named-checkconf" and "named-checkzone" program
				for syntax checking named.conf files and zone files,
				respectively.

	 622.	[bug]		A canceled request could be destroyed before
				dns_request_destroy() was called. [RT #562]

	 621.	[port]		Disable IPv6 at runtime if IPv6 sockets are unusable.
				This mostly affects Red Hat Linux 7.0, which has
				conflicts between libc and the kernel.

	 620.	[bug]		dns_master_load*inc() now require 'task' and 'load'
				to be non-null.  Also 'done' will not be called if
				dns_master_load*inc() fails immediately. [RT #565]

	 619.	[placeholder]

	 618.	[bug]		Queries to a signed zone could sometimes cause
				an assertion failure.

	 617.	[bug]		When using dynamic update to add a new RR to an
				existing RRset with a different TTL, the journal
				entries generated from the update did not include
				explicit deletions and re-additions of the existing
				RRs to update their TTL to the new value.

	 616.	[func]		dnssec-signzone -t output now includes performance
				statistics.

	 615.	[bug]		dnssec-signzone did not like child keysets signed
				by multiple keys.

	 614.	[bug]		Checks for uninitialized link fields were prone
				to false positives, causing assertion failures.
				The checks are now disabled by default and may
				be re-enabled by defining ISC_LIST_CHECKINIT.

	 613.	[bug]		"rndc reload zone" now reloads primary zones.
				It previously only updated slave and stub zones,
				if an SOA query indicated an out of date serial.

	 612.	[cleanup]	Shutup a ridiculously noisy HP-UX compiler that
				complains relentlessly about how its treatment
				of 'const' has changed as well as how casting
				sometimes tightens alignment constraints.

	 611.	[func]		allow-notify can be used to permit processing of
				notify messages from hosts other than a slave's
				masters.

	 610.	[func]		rndc dumpdb is now supported.

	 609.	[bug]		getrrsetbyname() would crash lwresd if the server
				found more SIGs than answers. [RT #554]

	 608.	[func]		dnssec-signzone now adds a comment to the zone
				with the time the file was signed.

	 607.	[bug]		nsupdate would fail if it encountered a CNAME or
				DNAME in a response to an SOA query. [RT #515]

	 606.	[bug]		Compiling with --disable-threads failed due
				to isc_thread_self() being incorrectly defined
				as an integer rather than a function.

	 605.	[func]		New function isc_lex_getlasttokentext().

	 604.	[bug]		The named.conf parser could print incorrect line
				numbers when long comments were present.

	 603.	[bug]		Make dig handle multiple types or classes on the same
				query more correctly.

	 602.	[func]		Cope automatically with UnixWare's broken
				IN6_IS_ADDR_* macros. [RT #539]

	 601.	[func]		Return a non-zero exit code if an update fails
				in nsupdate.

	 600.	[bug]		Reverse lookups sometimes failed in dig, etc...

	 599.	[func]		Added four new functions to the libisc log API to
				support i18n messages.  isc_log_iwrite(),
				isc_log_ivwrite(), isc_log_iwrite1() and
				isc_log_ivwrite1() were added.

	 598.	[bug]		An update-policy statement would cause the server
				to assert while loading. [RT #536]

	 597.	[func]		dnssec-signzone is now multi-threaded.

	 596.	[bug]		DNS_RDATASLAB_FORCE and DNS_RDATASLAB_EXACT are
				not mutually exclusive.

	 595.	[port]		On Linux 2.2, socket() returns EINVAL when it
				should return EAFNOSUPPORT.  Work around this.
				[RT #531]

	 594.	[func]		sdb drivers are now assumed to not be thread-safe
				unless the DNS_SDBFLAG_THREADSAFE flag is supplied.

	 593.	[bug]		If a secure zone was missing all its NXTs and
				a dynamic update was attempted, the server entered
				an infinite loop.

	 592.	[bug]		The sig-validity-interval option now specifies a
				number of days, not seconds.  This matches the
				documentation. [RT #529]

.. code-block:: none

		--- 9.1.0b1 released ---

	 591.	[bug]		Work around non-reentrancy in openssl by disabling
				pre-computation in keys.

	 590.	[doc]		There are now man pages for the lwres library in
				doc/man/lwres.

	 589.	[bug]		The server could deadlock if a zone was updated
				while being transferred out.

	 588.	[bug]		ctx->in_use was not being correctly initialized when
				when pushing a file for $INCLUDE. [RT #523]

	 587.	[func]		A warning is now printed if the "allow-update"
				option allows updates based on the source IP
				address, to alert users to the fact that this
				is insecure and becoming increasingly so as
				servers capable of update forwarding are being
				deployed.

	 586.	[bug]		multiple views with the same name were fatal. [RT #516]

	 585.	[func]		dns_db_addrdataset() and dns_rdataslab_merge()
				now support 'exact' additions in a similar manner to
				dns_db_subtractrdataset() and dns_rdataslab_subtract().

	 584.	[func]		You can now say 'notify explicit'; to suppress
				notification of the servers listed in NS records
				and notify only those servers listed in the
				'also-notify' option.

	 583.	[func]		"rndc querylog" will now toggle logging of
				queries, like "ndc querylog" in BIND 8.

	 582.	[bug]		dns_zone_idetach() failed to lock the zone.
				[RT #199, #463]

	 581.	[bug]		log severity was not being correctly processed.
				[RT #485]

	 580.	[func]		Ignore trailing garbage on incoming DNS packets,
				for interoperability with broken server
				implementations. [RT #491]

	 579.	[bug]		nsupdate did not take a filename to read update from.
				[RT #492]

	 578.	[func]		New config option "notify-source", to specify the
				source address for notify messages.

	 577.	[func]		Log illegal RDATA combinations. e.g. multiple
				singleton types, cname and other data.

	 576.	[doc]		isc_log_create() description did not match reality.

	 575.	[bug]		isc_log_create() was not setting internal state
				correctly to reflect the default channels created.

	 574.	[bug]		TSIG signed queries sent by the resolver would fail to
				have their responses validated and would leak memory.

	 573.	[bug]		The journal files of IXFRed slave zones were
				inadvertently discarded on server reload, causing
				"journal out of sync with zone" errors on subsequent
				reloads. [RT #482]

	 572.	[bug]		Quoted strings were not accepted as key names in
				address match lists.

	 571.	[bug]		It was possible to create an rdataset of singleton
				type which had more than one rdata. [RT #154]
				[RT #279]

	 570.	[bug]		rbtdb.c allowed zones containing nodes which had
				both a CNAME and "other data". [RT #154]

	 569.	[func]		The DNSSEC AD bit will not be set on queries which
				have not requested a DNSSEC response.

	 568.	[func]		Add sample simple database drivers in contrib/sdb.

	 567.	[bug]		Setting the zone transfer timeout to zero caused an
				assertion failure. [RT #302]

	 566.	[func]		New public function dns_timer_setidle().

	 565.	[func]		Log queries more like BIND 8: query logging is now
				done to category "queries", level "info". [RT #169]

	 564.	[func]		Add sortlist support to lwresd.

	 563.	[func]		New public functions dns_rdatatype_format() and
				dns_rdataclass_format(), for convenient formatting
				of rdata type/class mnemonics in log messages.

	 562.	[cleanup]	Moved lib/dns/*conf.c to bin/named where they belong.

	 561.	[func]		The 'datasize', 'stacksize', 'coresize' and 'files'
				clauses of the options{} statement are now implemented.

	 560.	[bug]		dns_name_split did not properly the resulting prefix
				when a maximal length bitstring label was split which
				was preceded by another bitstring label. [RT #429]

	 559.	[bug]		dns_name_split did not properly create the suffix
				when splitting within a maximal length bitstring label.

	 558.	[func]		New functions, isc_resource_getlimit and
				isc_resource_setlimit.

	 557.	[func]		Symbolic constants for libisc integral types.

	 556.	[func]		The DNSSEC OK bit in the EDNS extended flags
				is now implemented.  Responses to queries without
				this bit set will not contain any DNSSEC records.

	 555.	[bug]		A slave server attempting a zone transfer could
				crash with an assertion failure on certain
				malformed responses from the master. [RT #457]

	 554.	[bug]		In some cases, not all of the dnssec tools were
				properly installed.

	 553.	[bug]		Incoming zone transfers deferred due to quota
				were not started when quota was increased but
				only when a transfer in progress finished. [RT #456]

	 552.	[bug]		We were not correctly detecting the end of all c-style
				comments. [RT #455]

	 551.	[func]		Implemented the 'sortlist' option.

	 550.	[func]		Support unknown rdata types and classes.

	 549.	[bug]		"make" did not immediately abort the build when a
				subdirectory make failed [RT #450].

	 548.	[func]		The lexer now ungets tokens more correctly.

	 547.	[placeholder]

	 546.	[func]		Option 'lame-ttl' is now implemented.

	 545.	[func]		Name limit and counting options removed from dig;
				they didn't work properly, and cannot be correctly
				implemented without significant changes.

	 544.	[func]		Add statistics option, enable statistics-file option,
				add RNDC option "dump-statistics" to write out a
				query statistics file.

	 543.	[doc]		The 'port' option is now documented.

	 542.	[func]		Add support for update forwarding as required for
				full compliance with RFC2136.  It is turned off
				by default and can be enabled using the
				'allow-update-forwarding' option.

	 541.	[func]		Add bogus server support.

	 540.	[func]		Add dialup support.

	 539.	[func]		Support the blackhole option.

	 538.	[bug]		fix buffer overruns by 1 in lwres_getnameinfo().

	 537.	[placeholder]

	 536.	[func]		Use transfer-source{-v6} when sending refresh queries.
				Transfer-source{-v6} now take a optional port
				parameter for setting the UDP source port.  The port
				parameter is ignored for TCP.

	 535.	[func]		Use transfer-source{-v6} when forwarding update
				requests.

	 534.	[func]		Ancestors have been removed from RBT chains.  Ancestor
				information can be discerned via node parent pointers.

	 533.	[func]		Incorporated name hashing into the RBT database to
				improve search speed.

	 532.	[func]		Implement DNS UPDATE pseudo records using
				DNS_RDATA_UPDATE flag.

	 531.	[func]		Rdata really should be initialized before being assigned
				to (dns_rdata_fromwire(), dns_rdata_fromtext(),
				dns_rdata_clone(), dns_rdata_fromregion()),
				check that it is.

	 530.	[func]		New function dns_rdata_invalidate().

	 529.	[bug]		521 contained a bug which caused zones to always
				reload.  [RT #410]

	 528.	[func]		The ISC_LIST_XXXX macros now perform sanity checks
				on their arguments.  ISC_LIST_XXXXUNSAFE can be use
				to skip the checks however use with caution.

	 527.	[func]		New function dns_rdata_clone().

	 526.	[bug]		nsupdate incorrectly refused to add RRs with a TTL
				of 0.

	 525.	[func]		New arguments 'options' for dns_db_subtractrdataset(),
				and 'flags' for dns_rdataslab_subtract() allowing you
				to request that the RR's must exist prior to deletion.
				DNS_R_NOTEXACT is returned if the condition is not met.

	 524.	[func]		The 'forward' and 'forwarders' statement in
				non-forward zones should work now.

	 523.	[doc]		The source to the Administrator Reference Manual is
				now an XML file using the DocBook DTD, and is included
				in the distribution.  The plain text version of the
				ARM is temporarily unavailable while we figure out
				how to generate readable plain text from the XML.

	 522.	[func]		The lightweight resolver daemon can now use
				a real configuration file, and its functionality
				can be provided by a name server.  Also, the -p and -P
				options to lwresd have been reversed.

	 521.	[bug]		Detect master files which contain $INCLUDE and always
				reload. [RT #196]

	 520.	[bug]		Upgraded libtool to 1.3.5, which makes shared
				library builds almost work on AIX (and possibly
				others).

	 519.	[bug]		dns_name_split() would improperly split some bitstring
				labels, zeroing a few of the least significant bits in
				the prefix part.  When such an improperly created
				prefix was returned to the RBT database, the bogus
				label was dutifully stored, corrupting the tree.
				[RT #369]

	 518.	[bug]		The resolver did not realize that a DNAME which was
				"the answer" to the client's query was "the answer",
				and such queries would fail. [RT #399]

	 517.	[bug]		The resolver's DNAME code would trigger an assertion
				if there was more than one DNAME in the chain.
				[RT #399]

	 516.	[bug]		Cache lookups which had a NULL node pointer, e.g.
				those by dns_view_find(), and which would match a
				DNAME, would trigger an INSIST(!search.need_cleanup)
				assertion. [RT #399]

	 515.	[bug]		The ssu table was not being attached / detached
				by dns_zone_[sg]etssutable. [RT #397]

	 514.	[func]		Retry refresh and notify queries if they timeout.
				[RT #388]

	 513.	[func]		New functionality added to rdnc and server to allow
				individual zones to be refreshed or reloaded.

	 512.	[bug]		The zone transfer code could throw an exception with
				an invalid IXFR stream.

	 511.	[bug]		The message code could throw an assertion on an
				out of memory failure. [RT #392]

	 510.	[bug]		Remove spurious view notify warning. [RT #376]

	 509.	[func]		Add support for write of zone files on shutdown.

	 508.	[func]		dns_message_parse() can now do a best-effort
				attempt, which should allow dig to print more invalid
				messages.

	 507.	[func]		New functions dns_zone_flush(), dns_zt_flushanddetach()
				and dns_view_flushanddetach().

	 506.	[func]		Do not fail to start on errors in zone files.

	 505.	[bug]		nsupdate was printing "unknown result code". [RT #373]

	 504.	[bug]		The zone was not being marked as dirty when updated via
				IXFR.

	 503.	[bug]		dumptime was not being set along with
				DNS_ZONEFLG_NEEDDUMP.

	 502.	[func]		On a SERVFAIL reply, DiG will now try the next server
				in the list, unless the +fail option is specified.

	 501.	[bug]		Incorrect port numbers were being displayed by
				nslookup. [RT #352]

	 500.	[func]		Nearly useless +details option removed from DiG.

	 499.	[func]		In DiG, specifying a class with -c or type with -t
				changes command-line parsing so that classes and
				types are only recognized if following -c or -t.
				This allows hosts with the same name as a class or
				type to be looked up.

	 498.	[doc]		There is now a man page for "dig"
				in doc/man/bin/dig.1.

	 497.	[bug]		The error messages printed when an IP match list
				contained a network address with a nonzero host
				part where not sufficiently detailed. [RT #365]

	 496.	[bug]		named didn't sanity check numeric parameters. [RT #361]

	 495.	[bug]		nsupdate was unable to handle large records. [RT #368]

	 494.	[func]		Do not cache NXDOMAIN responses for SOA queries.

	 493.	[func]		Return non-cachable (ttl = 0) NXDOMAIN responses
				for SOA queries.  This makes it easier to locate
				the containing zone without polluting intermediate
				caches.

	 492.	[bug]		attempting to reload a zone caused the server fail
				to shutdown cleanly. [RT #360]

	 491.	[bug]		nsupdate would segfault when sending certain
				prerequisites with empty RDATA. [RT #356]

	 490.	[func]		When a slave/stub zone has not yet successfully
				obtained an SOA containing the zone's configured
				retry time, perform the SOA query retries using
				exponential backoff. [RT #337]

	 489.	[func]		The zone manager now has a "i/o" queue.

	 488.	[bug]		Locks weren't properly destroyed in some cases.

	 487.	[port]		flockfile() is not defined on all systems.

	 486.	[bug]		nslookup: "set all" and "server" commands showed
				the incorrect port number if a port other than 53
				was specified. [RT #352]

	 485.	[func]		When dig had more than one server to query, it would
				send all of the messages at the same time.  Add
				rate limiting of the transmitted messages.

	 484.	[bug]		When the server was reloaded after removing addresses
				from the named.conf "listen-on" statement, sockets
				were still listening on the removed addresses due
				to reference count loops. [RT #325]

	 483.	[bug]		nslookup: "set all" showed a "search" option but it
				was not settable.

	 482.	[bug]		nslookup: a plain "server" or "lserver" should be
				treated as a lookup.

	 481.	[bug]		nslookup:get_next_command() stack size could exceed
				per thread limit.

	 480.	[bug]		strtok() is not thread safe. [RT #349]

	 479.	[func]		The test suite can now be run by typing "make check"
				or "make test" at the top level.

	 478.	[bug]		"make install" failed if the directory specified with
				--prefix did not already exist.

	 477.	[bug]		The the isc-config.sh script could be installed before
				its directory was created. [RT #324]

	 476.	[bug]		A zone could expire while a zone transfer was in
				progress triggering a INSIST failure. [RT #329]

	 475.	[bug]		query_getzonedb() sometimes returned a non-null version
				on failure.  This caused assertion failures when
				generating query responses where names subject to
				additional section processing pointed to a zone
				to which access had been denied by means of the
				allow-query option. [RT #336]

	 474.	[bug]		The mnemonic of the CHAOS class is CH according to
				RFC1035, but it was printed and read only as CHAOS.
				We now accept both forms as input, and print it
				as CH. [RT #305]

	 473.	[bug]		nsupdate overran the end of the list of name servers
				when no servers could be reached, typically causing
				it to print the error message "dns_request_create:
				not implemented".

	 472.	[bug]		Off-by-one error caused isc_time_add() to sometimes
				produce invalid time values.

	 471.	[bug]		nsupdate didn't compile on HP/UX 10.20

	 470.	[func]		$GENERATE is now supported.  See also
				doc/misc/migration.

	 469.	[bug]		"query-source address * port 53;" now works.

	 468.	[bug]		dns_master_load*() failed to report file and line
				number in certain error conditions.

	 467.	[bug]		dns_master_load*() failed to log an error if
				pushfile() failed.

	 466.	[bug]		dns_master_load*() could return success when it failed.

	 465.	[cleanup]	Allow 0 to be set as an omapi_value_t value by
				omapi_value_storeint().

	 464.	[cleanup]	Build with openssl's RSA code instead of dnssafe.

	 463.	[bug]		nsupdate sent malformed SOA queries to the second
				and subsequent name servers in resolv.conf if the
				query sent to the first one failed.

	 462.	[bug]		--disable-ipv6 should work now.

	 461.	[bug]		Specifying an unknown key in the "keys" clause of the
				"controls" statement caused a NULL pointer dereference.
				[RT #316]

	 460.	[bug]		Much of the DNSSEC code only worked with class IN.

	 459.	[bug]		Nslookup processed the "set" command incorrectly.

	 458.	[bug]		Nslookup didn't properly check class and type values.
				[RT #305]

	 457.	[bug]		Dig/host/hslookup didn't properly handle connect
				timeouts in certain situations, causing an
				unnecessary warning message to be printed.

	 456.	[bug]		Stub zones were not resetting the refresh and expire
				counters, loadtime or clearing the DNS_ZONE_REFRESH
				(refresh in progress) flag upon successful update.
				This disabled further refreshing of the stub zone,
				causing it to eventually expire. [RT #300]

	 455.	[doc]		Document IPv4 prefix notation does not require a
				dotted decimal quad but may be just dotted decimal.

	 454.	[bug]		Enforce dotted decimal and dotted decimal quad where
				documented as such in named.conf. [RT #304, RT #311]

	 453.	[bug]		Warn if the obsolete option "maintain-ixfr-base"
				is specified in named.conf. [RT #306]

	 452.	[bug]		Warn if the unimplemented option "statistics-file"
				is specified in named.conf. [RT #301]

	 451.	[func]		Update forwarding implemented.

	 450.	[func]		New function ns_client_sendraw().

	 449.	[bug]		isc_bitstring_copy() only works correctly if the
				two bitstrings have the same lsb0 value, but this
				requirement was not documented, nor was there a
				REQUIRE for it.

	 448.	[bug]		Host output formatting change, to match v8. [RT #255]

	 447.	[bug]		Dig didn't properly retry in TCP mode after
				a truncated reply. [RT #277]

	 446.	[bug]		Confusing notify log message. [RT #298]

	 445.	[bug]		Doing a 0 bit isc_bitstring_copy() of an lsb0
				bitstring triggered a REQUIRE statement.  The REQUIRE
				statement was incorrect. [RT #297]

	 444.	[func]		"recursion denied" messages are always logged at
				debug level 1, now, rather than sometimes at ERROR.
				This silences these warnings in the usual case, where
				some clients set the RD bit in all queries.

	 443.	[bug]		When loading a master file failed because of an
				unrecognized RR type name, the error message
				did not include the file name and line number.
				[RT #285]

	 442.	[bug]		TSIG signed messages that did not match any view
				crashed the server. [RT #290]

	 441.	[bug]		Nodes obscured by a DNAME were inaccessible even
				when DNS_DBFIND_GLUEOK was set.

	 440.	[func]		New function dns_zone_forwardupdate().

	 439.	[func]		New function dns_request_createraw().

	 438.	[func]		New function dns_message_getrawmessage().

	 437.	[func]		Log NOTIFY activity to the notify channel.

	 436.	[bug]		If recvmsg() returned EHOSTUNREACH or ENETUNREACH,
				which sometimes happens on Linux, named would enter
				a busy loop.  Also, unexpected socket errors were
				not logged at a high enough logging level to be
				useful in diagnosing this situation. [RT #275]

	 435.	[bug]		dns_zone_dump() overwrote existing zone files
				rather than writing to a temporary file and
				renaming.  This could lead to empty or partial
				zone files being left around in certain error
				conditions involving the initial transfer of a
				slave zone, interfering with subsequent server
				startup. [RT #282]

	 434.	[func]		New function isc_file_isabsolute().

	 433.	[func]		isc_base64_decodestring() now accepts newlines
				within the base64 data.  This makes it possible
				to break up the key data in a "trusted-keys"
				statement into multiple lines. [RT #284]

	 432.	[func]		Added refresh/retry jitter.  The actual refresh/
				retry time is now a random value between 75% and
				100% of the configured value.

	 431.	[func]		Log at ISC_LOG_INFO when a zone is successfully
				loaded.

	 430.	[bug]		Rewrote the lightweight resolver client management
				code to handle shutdown correctly and general
				cleanup.

	 429.	[bug]		The space reserved for a TSIG record in a response
				was 2 bytes too short, leading to message
				generation failures.

	 428.	[bug]		rbtdb.c:find_closest_nxt() erroneously returned
				DNS_R_BADDB for nodes which had neither NXT nor SIG NXT
				(e.g. glue).  This could cause SERVFAILs when
				generating negative responses in a secure zone.

	 427.	[bug]		Avoid going into an infinite loop when the validator
				gets a negative response to a key query where the
				records are signed by the missing key.

	 426.	[bug]		Attempting to generate an oversized RSA key could
				cause dnssec-keygen to dump core.

	 425.	[bug]		Warn about the auth-nxdomain default value change
				if there is no auth-nxdomain statement in the
				config file. [RT #287]

	 424.	[bug]		notify_createmessage() could trigger an assertion
				failure when creating the notify message failed,
				e.g. due to corrupt zones with multiple SOA records.
				[RT #279]

	 423.	[bug]		When responding to a recursive query, errors that occur
				after following a CNAME should cause the query to fail.
				[RT #274]

	 422.	[func]		get rid of isc_random_t, and make isc_random_get()
				and isc_random_jitter() use rand() internally
				instead of local state.  Note that isc_random_*()
				functions are only for weak, non-critical "randomness"
				such as timing jitter and such.

	 421.	[bug]		nslookup would exit when given a blank line as input.

	 420.	[bug]		nslookup failed to implement the "exit" command.

	 419.	[bug]		The certificate type PKIX was misspelled as SKIX.

	 418.	[bug]		At debug levels >= 10, getting an unexpected
				socket receive error would crash the server
				while trying to log the error message.

	 417.	[func]		Add isc_app_block() and isc_app_unblock(), which
				allow an application to handle signals while
				blocking.

	 416.	[bug]		Slave zones with no master file tried to use a
				NULL pointer for a journal file name when they
				received an IXFR. [RT #273]

	 415.	[bug]		The logging code leaked file descriptors.

	 414.	[bug]		Server did not shut down until all incoming zone
				transfers were finished.

	 413.	[bug]		Notify could attempt to use the zone database after
				it had been unloaded. [RT #267]

	 412.	[bug]		named -v didn't print the version.

	 411.	[bug]		A typo in the HS A code caused an assertion failure.

	 410.	[bug]		lwres_gethostbyname() and company set lwres_h_errno
				to a random value on success.

	 409.	[bug]		If named was shut down early in the startup
				process, ns_omapi_shutdown() would attempt to lock
				an uninitialized mutex. [RT #262]

	 408.	[bug]		stub zones could leak memory and reference counts if
				all the masters were unreachable.

	 407.	[bug]		isc_rwlock_lock() would needlessly block
				readers when it reached the read quota even
				if no writers were waiting.

	 406.	[bug]		Log messages were occasionally lost or corrupted
				due to a race condition in isc_log_doit().

	 405.	[func]		Add support for selective forwarding (forward zones)

	 404.	[bug]		The request library didn't completely work with IPv6.

	 403.	[bug]		"host" did not use the search list.

	 402.	[bug]		Treat undefined acls as errors, rather than
				warning and then later throwing an assertion.
				[RT #252]

	 401.	[func]		Added simple database API.

	 400.	[bug]		SIG(0) signing and verifying was done incorrectly.
				[RT #249]

.. code-block:: none

	 399.	[bug]		When reloading the server with a config file
				containing a syntax error, it could catch an
				assertion failure trying to perform zone
				maintenance on, or sending notifies from,
				tentatively created zones whose views were
				never fully configured and lacked an address
				database and request manager.

	 398.	[bug]		"dig" sometimes caught an assertion failure when
				using TSIG, depending on the key length.

	 397.	[func]		Added utility functions dns_view_gettsig() and
				dns_view_getpeertsig().

	 396.	[doc]		There is now a man page for "nsupdate"
				in doc/man/bin/nsupdate.8.

	 395.	[bug]		nslookup printed incorrect RR type mnemonics
				for RRs of type >= 21 [RT #237].

	 394.	[bug]		Current name was not propagated via $INCLUDE.

	 393.	[func]		Initial answer while loading (awl) support.
				Entry points: dns_master_loadfileinc(),
				dns_master_loadstreaminc(), dns_master_loadbufferinc().
				Note: calls to dns_master_load*inc() should be rate
				be rate limited so as to not use up all file
				descriptors.

	 392.	[func]		Add ISC_R_FAMILYNOSUPPORT.  Returned when OS does
				not support the given address family requested.

	 391.	[clarity]	ISC_R_FAMILY -> ISC_R_FAMILYMISMATCH.

	 390.	[func]		The function dns_zone_setdbtype() now takes
				an argc/argv style vector of words and sets
				both the zone database type and its arguments,
				making the functions dns_zone_adddbarg()
				and dns_zone_cleardbargs() unnecessary.

	 389.	[bug]		Attempting to send a request over IPv6 using
				dns_request_create() on a system without IPv6
				support caused an assertion failure [RT #235].

	 388.	[func]		dig and host can now do reverse ipv6 lookups.

	 387.	[func]		Add dns_byaddr_createptrname(), which converts
				an address into the name used by a PTR query.

	 386.	[bug]		Missing strdup() of ACL name caused random
				ACL matching failures [RT #228].

	 385.	[cleanup]	Removed functions dns_zone_equal(), dns_zone_print(),
				and dns_zt_print().

	 384.	[bug]		nsupdate was incorrectly limiting TTLs to 65535 instead
				of 2147483647.

	 383.	[func]		When writing a master file, print the SOA and NS
				records (and their SIGs) before other records.

	 382.	[bug]		named -u failed on many Linux systems where the
				libc provided kernel headers do not match
				the current kernel.

	 381.	[bug]		Check for IPV6_RECVPKTINFO and use it instead of
				IPV6_PKTINFO if found. [RT #229]

	 380.	[bug]		nsupdate didn't work with IPv6.

	 379.	[func]		New library function isc_sockaddr_anyofpf().

	 378.	[func]		named and lwresd will log the command line arguments
				they were started with in the "starting ..." message.

	 377.	[bug]		When additional data lookups were refused due to
				"allow-query", the databases were still being
				attached causing reference leaks.

	 376.	[bug]		The server should always use good entropy when
				performing cryptographic functions needing entropy.

	 375.	[bug]		Per-zone "allow-query" did not properly override the
				view/global one for CNAME targets and additional
				data [RT #220].

	 374.	[bug]		SOA in authoritative negative responses had wrong TTL.

	 373.	[func]		nslookup is now installed by "make install".

	 372.	[bug]		Deal with Microsoft DNS servers appending two bytes of
				garbage to zone transfer requests.

	 371.	[bug]		At high debug levels, doing an outgoing zone transfer
				of a very large RRset could cause an assertion failure
				during logging.

	 370.	[bug]		The error messages for roll-forward failures were
				overly terse.

	 369.	[func]		Support new named.conf options, view and zone
				statements:

					max-retry-time, min-retry-time,
					max-refresh-time, min-refresh-time.

	 368.	[func]		Restructure the internal ".bind" view so that more
				zones can be added to it.

	 367.	[bug]		Allow proper selection of server on nslookup command
				line.

	 366.	[func]		Allow use of '-' batch file in dig for stdin.

	 365.	[bug]		nsupdate -k leaked memory.

	 364.	[func]		Added additional-from-{cache,auth}

	 363.	[placeholder]

	 362.	[bug]		rndc no longer aborts if the configuration file is
				missing an options statement. [RT #209]

	 361.	[func]		When the RBT find or chain functions set the name and
				origin for a node that stores the root label
				the name is now set to an empty name, instead of ".",
				to simplify later use of the name and origin by
				dns_name_concatenate(), dns_name_totext() or
				dns_name_format().

	 360.	[func]		dns_name_totext() and dns_name_format() now allow
				an empty name to be passed, which is formatted as "@".

	 359.	[bug]		dnssec-signzone occasionally signed glue records.

	 358.	[cleanup]	Rename the intermediate files used by the dnssec
				programs.

	 357.	[bug]		The zone file parser crashed if the argument
				to $INCLUDE was a quoted string.

	 356.	[cleanup]	isc_task_send no longer requires event->sender to
				be non-null.

	 355.	[func]		Added isc_dir_createunique(), similar to mkdtemp().

	 354.	[doc]		Man pages for the dnssec tools are now included in
				the distribution, in doc/man/dnssec.

	 353.	[bug]		double increment in lwres/gethost.c:copytobuf().
				[RT #187]

	 352.	[bug]		Race condition in dns_client_t startup could cause
				an assertion failure.

	 351.	[bug]		Constructing a response with rcode SERVFAIL to a TSIG
				signed query could crash the server.

	 350.	[bug]		Also-notify lists specified in the global options
				block were not correctly reference counted, causing
				a memory leak.

	 349.	[bug]		Processing a query with the CD bit set now works
				as expected.

	 348.	[func]		New boolean named.conf options 'additional-from-auth'
				and 'additional-from-cache' now supported in view and
				global options statement.

	 347.	[bug]		Don't crash if an argument is left off options in dig.

	 346.	[placeholder]

	 345.	[bug]		Large-scale changes/cleanups to dig:
				* Significantly improve structure handling
				* Don't pre-load entire batch files
				* Add name/rr counting/limiting
				* Fix SIGINT handling
				* Shorten timeouts to match v8's behavior

	 344.	[bug]		When shutting down, lwresd sometimes tried
				to shut down its client tasks twice,
				triggering an assertion.

	 343.	[bug]		Although zone maintenance SOA queries and
				notify requests were signed with TSIG keys
				when configured for the server in case,
				the TSIG was not verified on the response.

	 342.	[bug]		The wrong name was being passed to
				dns_name_dup() when generating a TSIG
				key using TKEY.

	 341.	[func]		Support 'key' clause in named.conf zone masters
				statement to allow authentication via TSIG keys:

					masters {
						10.0.0.1 port 5353 key "foo";
						10.0.0.2 ;
					};

	 340.	[bug]		The top-level COPYRIGHT file was missing from
				the distribution.

	 339.	[bug]		DNSSEC validation of the response to an ANY
				query at a name with a CNAME RR in a secure
				zone triggered an assertion failure.

	 338.	[bug]		lwresd logged to syslog as named, not lwresd.

	 337.	[bug]		"dig" did not recognize "nsap-ptr" as an RR type
				on the command line.

	 336.	[bug]		"dig -f" used 64 k of memory for each line in
				the file.  It now uses much less, though still
				proportionally to the file size.

	 335.	[bug]		named would occasionally attempt recursion when
				it was disallowed or undesired.

	 334.	[func]		Added hmac-md5 to libisc.

	 333.	[bug]		The resolver incorrectly accepted referrals to
				domains that were not parents of the query name,
				causing assertion failures.

	 332.	[func]		New function dns_name_reset().

	 331.	[bug]		Only log "recursion denied" if RD is set. [RT #178]

	 330.	[bug]		Many debugging messages were partially formatted
				even when debugging was turned off, causing a
				significant decrease in query performance.

	 329.	[func]		omapi_auth_register() now takes a size_t argument for
				the length of a key's secret data.  Previously
				OMAPI only stored secrets up to the first NUL byte.

	 328.	[func]		Added isc_base64_decodestring().

	 327.	[bug]		rndc.conf parser wasn't correctly recognizing an IP
				address where a host specification was required.

	 326.	[func]		'keys' in an 'inet' control statement is now
				required and must have at least one item in it.
				A "not supported" warning is now issued if a 'unix'
				control channel is defined.

	 325.	[bug]		isc_lex_gettoken was processing octal strings when
				ISC_LEXOPT_CNUMBER was not set.

	 324.	[func]		In the resolver, turn EDNS0 off if there is no
				response after a number of retransmissions.
				This is to allow queries some chance of succeeding
				even if all the authoritative servers of a zone
				silently discard EDNS0 requests instead of
				sending an error response like they ought to.

	 323.	[bug]		dns_rbt_findname() did not ignore empty rbt nodes.
				Because of this, servers authoritative for a parent
				and grandchild zone but not authoritative for the
				intervening child zone did not correctly issue
				referrals to the servers of the child zone.

	 322.	[bug]		Queries for KEY RRs are now sent to the parent
				server before the authoritative one, making
				DNSSEC insecurity proofs work in many cases
				where they previously didn't.

	 321.	[bug]		When synthesizing a CNAME RR for a DNAME
				response, query_addcname() failed to initialize
				the type and class of the CNAME dns_rdata_t,
				causing random failures.

	 320.	[func]		Multiple rndc changes: parses an rndc.conf file,
				uses authentication to talk to named, command
				line syntax changed.  This will all be described
				in the ARM.

	 319.	[func]		The named.conf "controls" statement is now used
				to configure the OMAPI command channel.

	 318.	[func]		dns_c_ndcctx_destroy() could never return anything
				except ISC_R_SUCCESS; made it have void return instead.

	 317.	[func]		Use callbacks from libomapi to determine if a
				new connection is valid, and if a key requested
				to be used with that connection is valid.

	 316.	[bug]		Generate a warning if we detect an unexpected <eof>
				but treat as <eol><eof>.

	 315.	[bug]		Handle non-empty blanks lines. [RT #163]

	 314.	[func]		The named.conf controls statement can now have
				more than one key specified for the inet clause.

	 313.	[bug]		When parsing resolv.conf, don't terminate on an
				error.  Instead, parse as much as possible, but
				still return an error if one was found.

	 312.	[bug]		Increase the number of allowed elements in the
				resolv.conf search path from 6 to 8.  If there
				are more than this, ignore the remainder rather
				than returning a failure in lwres_conf_parse.

	 311.	[bug]		lwres_conf_parse failed when the first line of
				resolv.conf was empty or a comment.

	 310.	[func]		Changes to named.conf "controls" statement (inet
				subtype only)

				  - support "keys" clause

					controls {
					   inet * port 1024
						allow { any; } keys { "foo"; }
					}

				  - allow "port xxx" to be left out of statement,
				    in which case it defaults to omapi's default port
				    of 953.

	 309.	[bug]		When sending a referral, the server did not look
				for name server addresses as glue in the zone
				holding the NS RRset in the case where this zone
				was not the same as the one where it looked for
				name server addresses as authoritative data.

	 308.	[bug]		Treat a SOA record not at top of zone as an error
				when loading a zone. [RT #154]

	 307.	[bug]		When canceling a query, the resolver didn't check for
				isc_socket_sendto() calls that did not yet have their
				completion events posted, so it could (rarely) end up
				destroying the query context and then want to use
				it again when the send event posted, triggering an
				assertion as it tried to cancel an already-canceled
				query.  [RT #77]

	 306.	[bug]		Reading HMAC-MD5 private key files didn't work.

	 305.	[bug]		When reloading the server with a config file
				containing a syntax error, it could catch an
				assertion failure trying to perform zone
				maintenance on tentatively created zones whose
				views were never fully configured and lacked
				an address database.

	 304.	[bug]		If more than LWRES_CONFMAXNAMESERVERS servers
				are listed in resolv.conf, silently ignore them
				instead of returning failure.

	 303.	[bug]		Add additional sanity checks to differentiate a AXFR
				response vs a IXFR response. [RT #157]

	 302.	[bug]		In dig, host, and nslookup, MXNAME should be large
				enough to hold any legal domain name in presentation
				format + terminating NULL.

	 301.	[bug]		Uninitialized pointer in host:printmessage(). [RT #159]

	 300.	[bug]		Using both <isc/net.h> and <lwres/net.h> didn't work
				on platforms lacking IPv6 because each included their
				own ipv6 header file for the missing definitions.  Now
				each library's ipv6.h defines the wrapper symbol of
				the other (ISC_IPV6_H and LWRES_IPV6_H).

	 299.	[cleanup]	Get the user and group information before changing the
				root directory, so the administrator does not need to
				keep a copy of the user and group databases in the
				chroot'ed environment.  Suggested by Hakan Olsson.

	 298.	[bug]		A mutex deadlock occurred during shutdown of the
				interface manager under certain conditions.
				Digital Unix systems were the most affected.

	 297.	[bug]		Specifying a key name that wasn't fully qualified
				in certain parts of the config file could cause
				an assertion failure.

	 296.	[bug]		"make install" from a separate build directory
				failed unless configure had been run in the source
				directory, too.

	 295.	[bug]		When invoked with type==CNAME and a message
				not constructed by dns_message_parse(),
				dns_message_findname() failed to find anything
				due to checking for attribute bits that are set
				only in dns_message_parse().  This caused an
				infinite loop when constructing the response to
				an ANY query at a CNAME in a secure zone.

	 294.	[bug]		If we run out of space in while processing glue
				when reading a master file and commit "current name"
				reverts to "name_current" instead of staying as
				"name_glue".

	 293.	[port]		Add support for FreeBSD 4.0 system tests.

	 292.	[bug]		Due to problems with the way some operating systems
				handle simultaneous listening on IPv4 and IPv6
				addresses, the server no longer listens on IPv6
				addresses by default.  To revert to the previous
				behavior, specify "listen-on-v6 { any; };" in
				the config file.

	 291.	[func]		Caching servers no longer send outgoing queries
				over TCP just because the incoming recursive query
				was a TCP one.

	 290.	[cleanup]	+twiddle option to dig (for testing only) removed.

	 289.	[cleanup]	dig is now installed in $bindir instead of $sbindir.
				host is now installed in $bindir.  (Be sure to remove
				any $sbindir/dig from a previous release.)

	 288.	[func]		rndc is now installed by "make install" into $sbindir.

	 287.	[bug]		rndc now works again as "rndc 127.1 reload" (for
				only that task).  Parsing its configuration file and
				using digital signatures for authentication has been
				disabled until named supports the "controls" statement,
				post-9.0.0.

	 286.	[bug]		On Solaris 2, when named inherited a signal state
				where SIGHUP had the SIG_IGN action, SIGHUP would
				be ignored rather than causing the server to reload
				its configuration.

	 285.	[bug]		A change made to the dst API for beta4 inadvertently
				broke OMAPI's creation of a dst key from an incoming
				message, causing an assertion to be triggered.  Fixed.

	 284.	[func]		The DNSSEC key generation and signing tools now
				generate randomness from keyboard input on systems
				that lack /dev/random.

	 283.	[cleanup]	The 'lwresd' program is now a link to 'named'.

	 282.	[bug]		The lexer now returns ISC_R_RANGE if parsed integer is
				too big for an unsigned long.

	 281.	[bug]		Fixed list of recognized config file category names.

	 280.	[func]		Add isc-config.sh, which can be used to more
				easily build applications that link with
				our libraries.

	 279.	[bug]		Private omapi function symbols shared between
				two or more files in libomapi.a were not namespace
				protected using the ISC convention of starting with
				the library name and two underscores ("omapi__"...)

	 278.	[bug]		bin/named/logconf.c:category_fromconf() didn't take
				note of when isc_log_categorybyname() wasn't able
				to find the category name and would then apply the
				channel list of the unknown category to all categories.

	 277.	[bug]		isc_log_categorybyname() and isc_log_modulebyname()
				would fail to find the first member of any category
				or module array apart from the internal defaults.
				Thus, for example, the "notify" category was improperly
				configured by named.

	 276.	[bug]		dig now supports maximum sized TCP messages.

	 275.	[bug]		The definition of lwres_gai_strerror() was missing
				the lwres_ prefix.

	 274.	[bug]		TSIG AXFR verify failed when talking to a BIND 8
				server.

	 273.	[func]		The default for the 'transfer-format' option is
				now 'many-answers'.  This will break zone transfers
				to BIND 4.9.5 and older unless there is an explicit
				'one-answer' configuration.

	 272.	[bug]		The sending of large TCP responses was canceled
				in mid-transmission due to a race condition
				caused by the failure to set the client object's
				"newstate" variable correctly when transitioning
				to the "working" state.

	 271.	[func]		Attempt to probe the number of cpus in named
				if unspecified rather than defaulting to 1.

	 270.	[func]		Allow maximum sized TCP answers.

	 269.	[bug]		Failed DNSSEC validations could cause an assertion
				failure by causing clone_results() to be called with
				with hevent->node == NULL.

	 268.	[doc]		A plain text version of the Administrator
				Reference Manual is now included in the distribution,
				as doc/arm/Bv9ARM.txt.

	 267.	[func]		Nsupdate is now provided in the distribution.

	 266.	[bug]		zone.c:save_nsrrset() node was not initialized.

	 265.	[bug]		dns_request_create() now works for TCP.

	 264.	[func]		Dispatch can not take TCP sockets in connecting
				state.  Set DNS_DISPATCHATTR_CONNECTED when calling
				dns_dispatch_createtcp() for connected TCP sockets
				or call dns_dispatch_starttcp() when the socket is
				connected.

	 263.	[func]		New logging channel type 'stderr'

					channel some-name {
						stderr;
						severity error;
					}

	 262.	[bug]		'master' was not initialized in zone.c:stub_callback().

	 261.	[func]		Add dns_zone_markdirty().

	 260.	[bug]		Running named as a non-root user failed on Linux
				kernels new enough to support retaining capabilities
				after setuid().

	 259.	[func]		New random-device and random-seed-file statements
				for global options block of named.conf. Both accept
				a single string argument.

	 258.	[bug]		Fixed printing of lwres_addr_t.address field.

	 257.	[bug]		The server detached the last zone manager reference
				too early, while it could still be in use by queries.
				This manifested itself as assertion failures during the
				shutdown process for busy name servers. [RT #133]

	 256.	[func]		isc_ratelimiter_t now has attach/detach semantics, and
				isc_ratelimiter_shutdown guarantees that the rate
				limiter is detached from its task.

	 255.	[func]		New function dns_zonemgr_attach().

	 254.	[bug]		Suppress "query denied" messages on additional data
				lookups.

.. code-block:: none

		--- 9.0.0b4 released ---

	 253.	[func]		resolv.conf parser now recognizes ';' and '#' as
				comments (anywhere in line, not just as the beginning).

	 252.	[bug]		resolv.conf parser mishandled masks on sortlists.
				It also aborted when an unrecognized keyword was seen,
				now it silently ignores the entire line.

	 251.	[bug]		lwresd caught an assertion failure on startup.

	 250.	[bug]		fixed handling of size+unit when value would be too
				large for internal representation.

	 249.	[cleanup]	max-cache-size config option now takes a size-spec
				like 'datasize', except 'default' is not allowed.

	 248.	[bug]		global lame-ttl option was not being printed when
				config structures were written out.

	 247.	[cleanup]	Rename cache-size config option to max-cache-size.

	 246.	[func]		Rename global option cachesize to cache-size and
				add corresponding option to view statement.

	 245.	[bug]		If an uncompressed name will take more than 255
				bytes and the buffer is sufficiently long,
				dns_name_fromwire should return DNS_R_FORMERR,
				not ISC_R_NOSPACE.  This bug caused cause the
				server to catch an assertion failure when it
				received a query for a name longer than 255
				bytes.

	 244.	[bug]		empty named.conf file and empty options statement are
				now parsed properly.

	 243.	[func]		new cachesize option for named.conf

	 242.	[cleanup]	fixed incorrect warning about auth-nxdomain usage.

	 241.	[cleanup]	nscount and soacount have been removed from the
				dns_master_*() argument lists.

	 240.	[func]		databases now come in three flavours: zone, cache
				and stub.

	 239.	[func]		If ISC_MEM_DEBUG is enabled, the variable
				isc_mem_debugging controls whether messages
				are printed or not.

	 238.	[cleanup]	A few more compilation warnings have been quieted:
				+ missing sigwait prototype on BSD/OS 4.0/4.0.1.
				+ PTHREAD_ONCE_INIT unbraced initializer warnings on
					Solaris 2.8.
				+ IN6ADDR_ANY_INIT unbraced initializer warnings on
					BSD/OS 4.*, Linux and Solaris 2.8.

	 237.	[bug]		If connect() returned ENOBUFS when the resolver was
				initiating a TCP query, the socket didn't get
				destroyed, and the server did not shut down cleanly.

	 236.	[func]		Added new listen-on-v6 config file statement.

	 235.	[func]		Consider it a config file error if a listen-on
				statement has an IPv6 address in it, or a
				listen-on-v6 statement has an IPv4 address in it.

	 234.	[bug]		Allow a trusted-key's first field (domain-name) be
				either a quoted or an unquoted string, instead of
				requiring a quoted string.

	 233.	[cleanup]	Convert all config structure integer values to unsigned
				integer (isc_uint32_t) to match grammar.

	 232.	[bug]		Allow slave zones to not have a file.

	 231.	[func]		Support new 'port' clause in config file options
				section. Causes 'listen-on', 'masters' and
				'also-notify' statements to use its value instead of
				default (53).

	 230.	[func]		Replace the dst sign/verify API with a cleaner one.

	 229.	[func]		Support config file sig-validity-interval statement
				in options, views and zone statements (master
				zones only).

	 228.	[cleanup]	Logging messages in config module stripped of
				trailing period.

	 227.	[cleanup]	The enumerated identifiers dns_rdataclass_*,
				dns_rcode_*, dns_opcode_*, and dns_trust_* are
				also now cast to their appropriate types, as with
				dns_rdatatype_* in item number 225 below.

	 226.	[func]		dns_name_totext() now always prints the root name as
				'.', even when omit_final_dot is true.

	 225.	[cleanup]	The enumerated dns_rdatatype_* identifiers are now
				cast to dns_rdatatype_t via macros of their same name
				so that they are of the proper integral type wherever
				a dns_rdatatype_t is needed.

	 224.	[cleanup]	The entire project builds cleanly with gcc's
				-Wcast-qual and -Wwrite-strings warnings enabled,
				which is now the default when using gcc.  (Warnings
				from confparser.c, because of yacc's code, are
				unfortunately to be expected.)

	 223.	[func]		Several functions were re-prototyped to qualify one
				or more of their arguments with "const".  Similarly,
				several functions that return pointers now have
				those pointers qualified with const.

	 222.	[bug]		The global 'also-notify' option was ignored.

	 221.	[bug]		An uninitialized variable was sometimes passed to
				dns_rdata_freestruct() when loading a zone, causing
				an assertion failure.

	 220.	[cleanup]	Set the default outgoing port in the view, and
				set it in sockaddrs returned from the ADB.
				[31-May-2000 explorer]

	 219.	[bug]		Signed truncated messages more correctly follow
				the respective specs.

	 218.	[func]		When an rdataset is signed, its ttl is normalized
				based on the signature validity period.

	 217.	[func]		Also-notify and trusted-keys can now be used in
				the 'view' statement.

	 216.	[func]		The 'max-cache-ttl' and 'max-ncache-ttl' options
				now work.

	 215.	[bug]		Failures at certain points in request processing
				could cause the assertion INSIST(client->lockview
				== NULL) to be triggered.

	 214.	[func]		New public function isc_netaddr_format(), for
				formatting network addresses in log messages.

	 213.	[bug]		Don't leak memory when reloading the zone if
				an update-policy clause was present in the old zone.

	 212.	[func]		Added dns_message_get/settsigkey, to make TSIG
				key management reasonable.

	 211.	[func]		The 'key' and 'server' statements can now occur
				inside 'view' statements.

	 210.	[bug]		The 'allow-transfer' option was ignored for slave
				zones, and the 'transfers-per-ns' option was
				was ignored for all zones.

	 209.	[cleanup]	Upgraded openssl files to new version 0.9.5a

	 208.	[func]		Added ISC_OFFSET_MAXIMUM for the maximum value
				of an isc_offset_t.

	 207.	[func]		The dnssec tools properly use the logging subsystem.

	 206.	[cleanup]	dst now stores the key name as a dns_name_t, not
				a char *.

	 205.	[cleanup]	On IRIX, turn off the mostly harmless warnings 1692
				("prototyped function redeclared without prototype")
				and 1552 ("variable ... set but not used") when
				compiling in the lib/dns/sec/{dnssafe,openssl}
				directories, which contain code imported from outside
				sources.

	 204.	[cleanup]	On HP/UX, pass +vnocompatwarnings to the linker
				to quiet the warnings that "The linked output may not
				run on a PA 1.x system."

	 203.	[func]		notify and zone soa queries are now tsig signed when
				appropriate.

	 202.	[func]		isc_lex_getsourceline() changed from returning int
				to returning unsigned long, the type of its underlying
				counter.

	 201.	[cleanup]	Removed the test/sdig program, it has been
				replaced by bin/dig/dig.

.. code-block:: none

		--- 9.0.0b3 released ---

	 200.	[bug]		Failures in sending query responses to clients
				(e.g., running out of network buffers) were
				not logged.

	 199.	[bug]		isc_heap_delete() sometimes violated the heap
				invariant, causing timer events not to be posted
				when due.

	 198.	[func]		Dispatch managers hold memory pools which
				any managed dispatcher may use.  This allows
				us to avoid dipping into the memory context for
				most allocations. [19-May-2000 explorer]

	 197.	[bug]		When an incoming AXFR or IXFR completes, the
				zone's internal state is refreshed from the
				SOA data. [19-May-2000 explorer]

	 196.	[func]		Dispatchers can be shared easily between views
				and/or interfaces. [19-May-2000 explorer]

	 195.	[bug]		Including the NXT record of the root domain
				in a negative response caused an assertion
				failure.

	 194.	[doc]		The PDF version of the Administrator's Reference
				Manual is no longer included in the ISC BIND9
				distribution.

	 193.	[func]		changed dst_key_free() prototype.

	 192.	[bug]		Zone configuration validation is now done at end
				of config file parsing, and before loading
				callbacks.

	 191.	[func]		Patched to compile on UnixWare 7.x.  This platform
				is not directly supported by the ISC.

	 190.	[cleanup]	The DNSSEC tools have been moved to a separate
				directory dnssec/ and given the following new,
				more descriptive names:

				      dnssec-keygen
				      dnssec-signzone
				      dnssec-signkey
				      dnssec-makekeyset

				Their command line arguments have also been changed to
				be more consistent.  dnssec-keygen now prints the
				name of the generated key files (sans extension)
				on standard output to simplify its use in automated
				scripts.

	 189.	[func]		isc_time_secondsastimet(), a new function, will ensure
				that the number of seconds in an isc_time_t does not
				exceed the range of a time_t, or return ISC_R_RANGE.
				Similarly, isc_time_now(), isc_time_nowplusinterval(),
				isc_time_add() and isc_time_subtract() now check the
				range for overflow/underflow.  In the case of
				isc_time_subtract, this changed a calling requirement
				(ie, something that could generate an assertion)
				into merely a condition that returns an error result.
				isc_time_add() and isc_time_subtract() were void-
				valued before but now return isc_result_t.

	 188.	[func]		Log a warning message when an incoming zone transfer
				contains out-of-zone data.

	 187.	[func]		isc_ratelimiter_enqueue() has an additional argument
				'task'.

	 186.	[func]		dns_request_getresponse() has an additional argument
				'preserve_order'.

	 185.	[bug]		Fixed up handling of ISC_MEMCLUSTER_LEGACY.  Several
				public functions did not have an isc__ prefix, and
				referred to functions that had previously been
				renamed.

	 184.	[cleanup]	Variables/functions which began with two leading
				underscores were made to conform to the ANSI/ISO
				standard, which says that such names are reserved.

	 183.	[func]		ISC_LOG_PRINTTAG option for log channels.  Useful
				for logging the program name or other identifier.

	 182.	[cleanup]	New command-line parameters for dnssec tools

	 181.	[func]		Added dst_key_buildfilename and dst_key_parsefilename

	 180.	[func]		New isc_result_t ISC_R_RANGE.  Supersedes DNS_R_RANGE.

	 179.	[func]		options named.conf statement *must* now come
				before any zone or view statements.

	 178.	[func]		Post-load of named.conf check verifies a slave zone
				has non-empty list of masters defined.

	 177.	[func]		New per-zone boolean:

					enable-zone yes | no ;

				intended to let a zone be disabled without having
				to comment out the entire zone statement.

	 176.	[func]		New global and per-view option:

					max-cache-ttl number

	 175.	[func]		New global and per-view option:

					additional-data internal | minimal | maximal;

	 174.	[func]		New public function isc_sockaddr_format(), for
				formatting socket addresses in log messages.

	 173.	[func]		Keep a queue of zones waiting for zone transfer
				quota so that a new transfer can be dispatched
				immediately whenever quota becomes available.

	 172.	[bug]		$TTL directive was sometimes missing from dumped
				master files because totext_ctx_init() failed to
				initialize ctx->current_ttl_valid.

	 171.	[cleanup]	On NetBSD systems, the mit-pthreads or
				unproven-pthreads library is now always used
				unless --with-ptl2 is explicitly specified on
				the configure command line.  The
				--with-mit-pthreads option is no longer needed
				and has been removed.

	 170.	[cleanup]	Remove inter server consistency checks from zone,
				these should return as a separate module in 9.1.
				dns_zone_checkservers(), dns_zone_checkparents(),
				dns_zone_checkchildren(), dns_zone_checkglue().

				Remove dns_zone_setadb(), dns_zone_setresolver(),
				dns_zone_setrequestmgr() these should now be found
				via the view.

	 169.	[func]		ratelimiter can now process N events per interval.

	 168.	[bug]		include statements in named.conf caused syntax errors
				due to not consuming the semicolon ending the include
				statement before switching input streams.

	 167.	[bug]		Make lack of masters for a slave zone a soft error.

	 166.	[bug]		Keygen was overwriting existing keys if key_id
				conflicted, now it will retry, and non-null keys
				with key_id == 0 are not generated anymore.  Key
				was not able to generate NOAUTHCONF DSA key,
				increased RSA key size to 2048 bits.

	 165.	[cleanup]	Silence "end-of-loop condition not reached" warnings
				from Solaris compiler.

	 164.	[func]		Added functions isc_stdio_open(), isc_stdio_close(),
				isc_stdio_seek(), isc_stdio_read(), isc_stdio_write(),
				isc_stdio_flush(), isc_stdio_sync(), isc_file_remove()
				to encapsulate nonportable usage of errno and sync.

	 163.	[func]		Added result codes ISC_R_FILENOTFOUND and
				ISC_R_FILEEXISTS.

	 162.	[bug]		Ensure proper range for arguments to ctype.h functions.

	 161.	[cleanup]	error in yyparse prototype that only HPUX caught.

	 160.	[cleanup]	getnet*() are not going to be implemented at this
				stage.

	 159.	[func]		Redefinition of config file elements is now an
				error (instead of a warning).

	 158.	[bug]		Log channel and category list copy routines
				weren't assigning properly to output parameter.

	 157.	[port]		Fix missing prototype for getopt().

	 156.	[func]		Support new 'database' statement in zone.

					database "quoted-string";

	 155.	[bug]		ns_notify_start() was not detaching the found zone.

	 154.	[func]		The signer now logs libdns warnings to stderr even when
				not verbose, and in a nicer format.

	 153.	[func]		dns_rdata_tostruct() 'mctx' is now optional.  If 'mctx'
				is NULL then you need to preserve the 'rdata' until
				you have finished using the structure as there may be
				references to the associated memory.  If 'mctx' is
				non-NULL it is guaranteed that there are no references
				to memory associated with 'rdata'.

				dns_rdata_freestruct() must be called if 'mctx' was
				non-NULL and may safely be called if 'mctx' was NULL.

	 152.	[bug]		keygen dumped core if domain name argument was omitted
				from command line.

	 151.	[func]		Support 'disabled' statement in zone config (causes
				zone to be parsed and then ignored). Currently must
				come after the 'type' clause.

	 150.	[func]		Support optional ports in masters and also-notify
				statements:

					masters [ port xxx ] { y.y.y.y [ port zzz ] ; }

	 149.	[cleanup]	Removed unused argument 'olist' from
				dns_c_view_unsetordering().

	 148.	[cleanup]	Stop issuing some warnings about some configuration
				file statements that were not implemented, but now are.

	 147.	[bug]		Changed yacc union size to be smaller for yaccs that
				put yacc-stack on the real stack.

	 146.	[cleanup]	More general redundant header file cleanup.  Rather
				than continuing to itemize every header which changed,
				this changelog entry just notes that if a header file
				did not need another header file that it was including
				in order to provide its advertised functionality, the
				inclusion of the other header file was removed.  See
				util/check-includes for how this was tested.

	 145.	[cleanup]	Added <isc/lang.h> and ISC_LANG_BEGINDECLS/
				ISC_LANG_ENDDECLS to header files that had function
				prototypes, and removed it from those that did not.

	 144.	[cleanup]	libdns header files too numerous to name were made
				to conform to the same style for multiple inclusion
				protection.

	 143.	[func]		Added function dns_rdatatype_isknown().

	 142.	[cleanup]	<isc/stdtime.h> does not need <time.h> or
				<isc/result.h>.

	 141.	[bug]		Corrupt requests with multiple questions could
				cause an assertion failure.

	 140.	[cleanup]	<isc/time.h> does not need <time.h> or <isc/result.h>.

	 139.	[cleanup]	<isc/net.h> now includes <isc/types.h> instead of
				<isc/int.h> and <isc/result.h>.

	 138.	[cleanup]	isc_strtouq moved from str.[ch] to string.[ch] and
				renamed isc_string_touint64.  isc_strsep moved from
				strsep.c to string.c and renamed isc_string_separate.

	 137.	[cleanup]	<isc/commandline.h>, <isc/mem.h>, <isc/print.h>
				<isc/serial.h>, <isc/string.h> and <isc/offset.h>
				made to conform to the same style for multiple
				inclusion protection.

	 136.	[cleanup]	<isc/commandline.h>, <isc/interfaceiter.h>,
				<isc/net.h> and Win32's <isc/thread.h> needed
				ISC_LANG_BEGINDECLS/ISC_LANG_ENDDECLS.

	 135.	[cleanup]	Win32's <isc/condition.h> did not need <isc/result.h>
				or <isc/boolean.h>, now uses <isc/types.h> in place
				of <isc/time.h>, and needed ISC_LANG_BEGINDECLS
				and ISC_LANG_ENDDECLS.

	 134.	[cleanup]	<isc/dir.h> does not need <limits.h>.

	 133.	[cleanup]	<isc/ipv6.h> needs <isc/platform.h>.

	 132.	[cleanup]	<isc/app.h> does not need <isc/task.h>, but does
				need <isc/eventclass.h>.

	 131.	[cleanup]	<isc/mutex.h> and <isc/util.h> need <isc/result.h>
				for ISC_R_* codes used in macros.

	 130.	[cleanup]	<isc/condition.h> does not need <pthread.h> or
				<isc/boolean.h>, and now includes <isc/types.h>
				instead of <isc/time.h>.

	 129.	[bug]		The 'default_debug' log channel was not set up when
				'category default' was present in the config file

	 128.	[cleanup]	<isc/dir.h> had ISC_LANG_BEGINDECLS instead of
				ISC_LANG_ENDDECLS at end of header.

	 127.	[cleanup]	The contracts for the comparison routines
				dns_name_fullcompare(), dns_name_compare(),
				dns_name_rdatacompare(), and dns_rdata_compare() now
				specify that the order value returned is < 0, 0, or > 0
				instead of -1, 0, or 1.

	 126.	[cleanup]	<isc/quota.h> and <isc/taskpool.h> need <isc/lang.h>.

	 125.	[cleanup]	<isc/eventclass.h>, <isc/ipv6.h>, <isc/magic.h>,
				<isc/mutex.h>, <isc/once.h>, <isc/region.h>, and
				<isc/resultclass.h> do not need <isc/lang.h>.

	 124.	[func]		signer now imports parent's zone key signature
				and creates null keys/sets zone status bit for
				children when necessary

	 123.	[cleanup]	<isc/event.h> does not need <stddef.h>.

	 122.	[cleanup]	<isc/task.h> does not need <isc/mem.h> or
				<isc/result.h>.

	 121.	[cleanup]	<isc/symtab.h> does not need <isc/mem.h> or
				<isc/result.h>.  Multiple inclusion protection
				symbol fixed from ISC_SYMBOL_H to ISC_SYMTAB_H.
				isc_symtab_t moved to <isc/types.h>.

	 120.	[cleanup]	<isc/socket.h> does not need <isc/boolean.h>,
				<isc/bufferlist.h>, <isc/task.h>, <isc/mem.h> or
				<isc/net.h>.

	 119.	[cleanup]	structure definitions for generic rdata structures do
				not have _generic_ in their names.

	 118.	[cleanup]	libdns.a is now namespace-clean, on NetBSD, excepting
				YACC crust (yyparse, etc) [2000-apr-27 explorer]

	 117.	[cleanup]	libdns.a changes:
				dns_zone_clearnotify() and dns_zone_addnotify()
				are replaced by dns_zone_setnotifyalso().
				dns_zone_clearmasters() and dns_zone_addmaster()
				are replaced by dns_zone_setmasters().

	 116.	[func]		Added <isc/offset.h> for isc_offset_t (aka off_t
				on Unix systems).

	 115.	[port]		Shut up the -Wmissing-declarations warning about
				<stdio.h>'s __sputaux on BSD/OS pre-4.1.

	 114.	[cleanup]	<isc/sockaddr.h> does not need <isc/buffer.h> or
				<isc/list.h>.

	 113.	[func]		Utility programs dig and host added.

	 112.	[cleanup]	<isc/serial.h> does not need <isc/boolean.h>.

	 111.	[cleanup]	<isc/rwlock.h> does not need <isc/result.h> or
				<isc/mutex.h>.

	 110.	[cleanup]	<isc/result.h> does not need <isc/boolean.h> or
				<isc/list.h>.

	 109.	[bug]		"make depend" did nothing for
				bin/tests/{db,mem,sockaddr,tasks,timers}/.

	 108.	[cleanup]	DNS_SETBIT/DNS_GETBIT/DNS_CLEARBIT moved from
				<dns/types.h> to <dns/bit.h> and renamed to
				DNS_BIT_SET/DNS_BIT_GET/DNS_BIT_CLEAR.

	 107.	[func]		Add keysigner and keysettool.

	 106.	[func]		Allow dnssec verifications to ignore the validity
				period.  Used by several of the dnssec tools.

	 105.	[doc]		doc/dev/coding.html expanded with other
				implicit conventions the developers have used.

	 104.	[bug]		Made compress_add and compress_find static to
				lib/dns/compress.c.

	 103.	[func]		libisc buffer API changes for <isc/buffer.h>:
				Added:
					isc_buffer_base(b)          (pointer)
					isc_buffer_current(b)       (pointer)
					isc_buffer_active(b)        (pointer)
					isc_buffer_used(b)          (pointer)
					isc_buffer_length(b)            (int)
					isc_buffer_usedlength(b)        (int)
					isc_buffer_consumedlength(b)    (int)
					isc_buffer_remaininglength(b)   (int)
					isc_buffer_activelength(b)      (int)
					isc_buffer_availablelength(b)   (int)
				Removed:
					ISC_BUFFER_USEDCOUNT(b)
					ISC_BUFFER_AVAILABLECOUNT(b)
					isc_buffer_type(b)
				Changed names:
					isc_buffer_used(b, r) ->
						isc_buffer_usedregion(b, r)
					isc_buffer_available(b, r) ->
						isc_buffer_available_region(b, r)
					isc_buffer_consumed(b, r) ->
						isc_buffer_consumedregion(b, r)
					isc_buffer_active(b, r) ->
						isc_buffer_activeregion(b, r)
					isc_buffer_remaining(b, r) ->
						isc_buffer_remainingregion(b, r)

				Buffer types were removed, so the ISC_BUFFERTYPE_*
				macros are no more, and the type argument to
				isc_buffer_init and isc_buffer_allocate were removed.
				isc_buffer_putstr is now void (instead of isc_result_t)
				and requires that the caller ensure that there
				is enough available buffer space for the string.

	 102.	[port]		Correctly detect inet_aton, inet_pton and inet_ptop
				on BSD/OS 4.1.

	 101.	[cleanup]	Quieted EGCS warnings from lib/isc/print.c.

	 100.	[cleanup]	<isc/random.h> does not need <isc/int.h> or
				<isc/mutex.h>.  isc_random_t moved to <isc/types.h>.

	  99.	[cleanup]	Rate limiter now has separate shutdown() and
				destroy() functions, and it guarantees that all
				queued events are delivered even in the shutdown case.

	  98.	[cleanup]	<isc/print.h> does not need <stdarg.h> or <stddef.h>
				unless ISC_PLATFORM_NEEDVSNPRINTF is defined.

	  97.	[cleanup]	<isc/ondestroy.h> does not need <stddef.h> or
				<isc/event.h>.

	  96.	[cleanup]	<isc/mutex.h> does not need <isc/result.h>.

	  95.	[cleanup]	<isc/mutexblock.h> does not need <isc/result.h>.

	  94.	[cleanup]	Some installed header files did not compile as C++.

	  93.	[cleanup]	<isc/msgcat.h> does not need <isc/result.h>.

	  92.	[cleanup]	<isc/mem.h> does not need <stddef.h>, <isc/boolean.h>,
				or <isc/result.h>.

	  91.	[cleanup]	<isc/log.h> does not need <sys/types.h> or
				<isc/result.h>.

	  90.	[cleanup]	Removed unneeded ISC_LANG_BEGINDECLS/ISC_LANG_ENDDECLS
				from <named/listenlist.h>.

	  89.	[cleanup]	<isc/lex.h> does not need <stddef.h>.

	  88.	[cleanup]	<isc/interfaceiter.h> does not need <isc/result.h> or
				<isc/mem.h>.  isc_interface_t and isc_interfaceiter_t
				moved to <isc/types.h>.

	  87.	[cleanup]	<isc/heap.h> does not need <isc/boolean.h>,
				<isc/mem.h> or <isc/result.h>.

	  86.	[cleanup]	isc_bufferlist_t moved from <isc/bufferlist.h> to
				<isc/types.h>.

	  85.	[cleanup]	<isc/bufferlist.h> does not need <isc/buffer.h>,
				<isc/list.h>, <isc/mem.h>, <isc/region.h> or
				<isc/int.h>.

	  84.	[func]		allow-query ACL checks now apply to all data
				added to a response.

	  83.	[func]		If the server is authoritative for both a
				delegating zone and its (nonsecure) delegatee, and
				a query is made for a KEY RR at the top of the
				delegatee, then the server will look for a KEY
				in the delegator if it is not found in the delegatee.

	  82.	[cleanup]	<isc/buffer.h> does not need <isc/list.h>.

	  81.	[cleanup]	<isc/int.h> and <isc/boolean.h> do not need
				<isc/lang.h>.

	  80.	[cleanup]	<isc/print.h> does not need <stdio.h> or <stdlib.h>.

	  79.	[cleanup]	<dns/callbacks.h> does not need <stdio.h>.

	  78.	[cleanup]	lwres_conftest renamed to lwresconf_test for
				consistency with other *_test programs.

	  77.	[cleanup]	typedef of isc_time_t and isc_interval_t moved from
				<isc/time.h> to <isc/types.h>.

	  76.	[cleanup]	Rewrote keygen.

	  75.	[func]		Don't load a zone if its database file is older
				than the last time the zone was loaded.

	  74.	[cleanup]	Removed mktemplate.o and ufile.o from libisc.a,
				subsumed by file.o.

	  73.	[func]		New "file" API in libisc, including new function
				isc_file_getmodtime, isc_mktemplate renamed to
				isc_file_mktemplate and isc_ufile renamed to
				isc_file_openunique.  By no means an exhaustive API,
				it is just what's needed for now.

	  72.	[func]		DNS_RBTFIND_NOPREDECESSOR and DNS_RBTFIND_NOOPTIONS
				added for dns_rbt_findnode, the former to disable the
				setting of the chain to the predecessor, and the
				latter to make clear when no options are set.

	  71.	[cleanup]	Made explicit the implicit REQUIREs of
				isc_time_seconds, isc_time_nanoseconds, and
				isc_time_subtract.

	  70.	[func]		isc_time_set() added.

	  69.	[bug]		The zone object's master and also-notify lists grew
				longer with each server reload.

	  68.	[func]		Partial support for SIG(0) on incoming messages.

	  67.	[performance]	Allow use of alternate (compile-time supplied)
				OpenSSL libraries/headers.

	  66.	[func]		Data in authoritative zones should have a trust level
				beyond secure.

	  65.	[cleanup]	Removed obsolete typedef of dns_zone_callbackarg_t
				from <dns/types.h>.

	  64.	[func]		The RBT, DB, and zone table APIs now allow the
				caller find the most-enclosing superdomain of
				a name.

	  63.	[func]		Generate NOTIFY messages.

	  62.	[func]		Add UDP refresh support.

	  61.	[cleanup]	Use single quotes consistently in log messages.

	  60.	[func]		Catch and disallow singleton types on message
				parse.

	  59.	[bug]		Cause net/host unreachable to be a hard error
				when sending and receiving.

	  58.	[bug]		bin/named/query.c could sometimes trigger the
				(client->query.attributes & NS_QUERYATTR_NAMEBUFUSED)
				== 0 assertion in query_newname().

	  57.	[func]		Added dns_nxt_typepresent()

	  56.	[bug]		SIG records were not properly returned in cached
				negative answers.

	  55.	[bug]		Responses containing multiple names in the authority
				section were not negatively cached.

	  54.	[bug]		If a fetch with sigrdataset==NULL joined one with
				sigrdataset!=NULL or vice versa, the resolver
				could catch an assertion or lose signature data,
				respectively.

	  53.	[port]		freebsd 4.0: lib/isc/unix/socket.c requires
				<sys/param.h>.

	  52.	[bug]		rndc: taskmgr and socketmgr were not initialized
				to NULL.

	  51.	[cleanup]	dns/compress.h and dns/zt.h did not need to include
				dns/rbt.h; it was needed only by compress.c and zt.c.

	  50.	[func]		RBT deletion no longer requires a valid chain to work,
				and dns_rbt_deletenode was added.

	  49.	[func]		Each cache now has its own mctx.

	  48.	[func]		isc_task_create() no longer takes an mctx.
				isc_task_mem() has been eliminated.

	  47.	[func]		A number of modules now use memory context reference
				counting.

	  46.	[func]		Memory contexts are now reference counted.
				Added isc_mem_inuse() and isc_mem_preallocate().
				Renamed isc_mem_destroy_check() to
				isc_mem_setdestroycheck().

	  45.	[bug]		The trusted-key statement incorrectly loaded keys.

	  44.	[bug]		Don't include authority data if it would force us
				to unset the AD bit in the message.

	  43.	[bug]		DNSSEC verification of cached rdatasets was failing.

	  42.	[cleanup]	Simplified logging of messages with embedded domain
				names by introducing a new convenience function
				dns_name_format().

	  41.	[func]		Use PR_SET_KEEPCAPS on Linux 2.3.99-pre3 and later
				to allow 'named' to run as a non-root user while
				retaining the ability to bind() to privileged
				ports.

	  40.	[func]		Introduced new logging category "dnssec" and
				logging module "dns/validator".

	  39.	[cleanup]	Moved the typedefs for isc_region_t, isc_textregion_t,
				and isc_lex_t to <isc/types.h>.

	  38.	[bug]		TSIG signed incoming zone transfers work now.

	  37.	[bug]		If the first RR in an incoming zone transfer was
				not an SOA, the server died with an assertion failure
				instead of just reporting an error.

	  36.	[cleanup]	Change DNS_R_SUCCESS (and others) to ISC_R_SUCCESS

	  35.	[performance]	Log messages which are of a level too high to be
				logged by any channel in the logging configuration
				will not cause the log mutex to be locked.

	  34.	[bug]		Recursion was allowed even with 'recursion no'.

	  33.	[func]		The RBT now maintains a parent pointer at each node.

	  32.	[cleanup]	bin/lwresd/client.c needs <string.h> for memset()
				prototype.

	  31.	[bug]		Use ${LIBTOOL} to compile bin/named/main.@O@.

	  30.	[func]		config file grammar change to support optional
				class type for a view.

	  29.	[func]		support new config file view options:

					auth-nxdomain recursion query-source
					query-source-v6 transfer-source
					transfer-source-v6 max-transfer-time-out
					max-transfer-idle-out transfer-format
					request-ixfr provide-ixfr cleaning-interval
					fetch-glue notify rfc2308-type1 lame-ttl
					max-ncache-ttl min-roots

	  28.	[func]		support lame-ttl, min-roots and serial-queries
				config global options.

	  27.	[bug]		Only include <netinet6/in6.h> on BSD/OS 4.[01]*.
				Including it on other platforms (eg, NetBSD) can
				cause a forced #error from the C preprocessor.

	  26.	[func]		new match-clients statement in config file view.

	  25.	[bug]		make install failed to install <isc/log.h> and
				<isc/ondestroy.h>.

	  24.	[cleanup]	Eliminate some unnecessary #includes of header
				files from header files.

	  23.	[cleanup]	Provide more context in log messages about client
				requests, using a new function ns_client_log().

	  22.	[bug]		SIGs weren't returned in the answer section when
				the query resulted in a fetch.

	  21.	[port]		Look at STD_CINCLUDES after CINCLUDES during
				compilation, so additional system include directories
				can be searched but header files in the bind9 source
				tree with conflicting names take precedence.  This
				avoids issues with installed versions of dnssafe and
				openssl.

	  20.	[func]		Configuration file post-load validation of zones
				failed if there were no zones.

	  19.	[bug]		dns_zone_notifyreceive() failed to unlock the zone
				lock in certain error cases.

	  18.	[bug]		Use AC_TRY_LINK rather than AC_TRY_COMPILE in
				configure.in to check for presence of in6addr_any.

	  17.	[func]		Do configuration file post-load validation of zones.

	  16.	[bug]		put quotes around key names on config file
				output to avoid possible keyword clashes.

	  15.	[func]		Add dns_name_dupwithoffsets().  This function is
				improves comparison performance for duped names.

	  14.	[bug]		free_rbtdb() could have 'put' unallocated memory in
				an unlikely error path.

	  13.	[bug]		lib/dns/master.c and lib/dns/xfrin.c didn't ignore
				out-of-zone data.

	  12.	[bug]		Fixed possible uninitialized variable error.

	  11.	[bug]		axfr_rrstream_first() didn't check the result code of
				db_rr_iterator_first(), possibly causing an assertion
				to be triggered later.

	  10.	[bug]		A bug in the code which makes EDNS0 OPT records in
				bin/named/client.c and lib/dns/resolver.c could
				trigger an assertion.

	   9.	[cleanup]	replaced bit-setting code in confctx.c and replaced
				repeated code with macro calls.

	   8.	[bug]		Shutdown of incoming zone transfer accessed
				freed memory.

	   7.	[cleanup]	removed 'listen-on' from view statement.

	   6.	[bug]		quote RR names when generating config file to
				prevent possible clash with config file keywords
				(such as 'key').

	   5.	[func]		syntax change to named.conf file: new ssu grant/deny
				statements must now be enclosed by an 'update-policy'
				block.

	   4.	[port]		bin/named/unix/os.c didn't compile on systems with
				linux 2.3 kernel includes due to conflicts between
				C library includes and the kernel includes.  We now
				get only what we need from <linux/capability.h>, and
				avoid pulling in other linux kernel .h files.

	   3.	[bug]		TKEYs go in the answer section of responses, not
				the additional section.

	   2.	[bug]		Generating cryptographic randomness failed on
				systems without /dev/random.

	   1.	[bug]		The installdirs rule in
				lib/isc/unix/include/isc/Makefile.in had a typo which
				prevented the isc directory from being created if it
				didn't exist.

.. code-block:: none

		--- 9.0.0b2 released ---

