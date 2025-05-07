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

#include <isc/loop.h>
#include <isc/result.h>

typedef struct isc_filewatcher isc_filewatcher_t;
typedef void (*isc_filewatcher_cb)(void *arg, const char *filename, int events);

/*
 * File watcher events, matching libuv's events
 */
#define ISC_FILEWATCHER_CHANGE 1
#define ISC_FILEWATCHER_RENAME 2

isc_result_t
isc_filewatcher_create(isc_loop_t *loop, isc_filewatcher_cb cb, void *cbarg,
                      const char *filename, isc_filewatcher_t **watcherp);

isc_result_t
isc_filewatcher_start(isc_filewatcher_t *watcher);

void
isc_filewatcher_stop(isc_filewatcher_t *watcher);

void
isc_filewatcher_destroy(isc_filewatcher_t **watcherp);
