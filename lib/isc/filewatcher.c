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

#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <uv.h>

#include <isc/filewatcher.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/util.h>
#include <isc/log.h>

#include "loop_p.h"

struct isc_filewatcher {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_loop_t *loop;
	uv_fs_event_t handle;
	isc_filewatcher_cb cb;
	void *cbarg;
	char *filename;	 /* Full path to the file */
	char *basename;	 /* Just the filename without the path */
	char *directory; /* Directory containing the file */
};

#define FILEWATCHER_MAGIC    ISC_MAGIC('F', 'W', 'A', 'T')
#define VALID_FILEWATCHER(t) ISC_MAGIC_VALID(t, FILEWATCHER_MAGIC)

static void
filewatcher_callback(uv_fs_event_t *handle, const char *filename, int events,
		     int status) {
	isc_filewatcher_t *watcher = (isc_filewatcher_t *)handle->data;
	REQUIRE(VALID_FILEWATCHER(watcher));

	if (status < 0) {
		isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_ERROR,
				"file watch %s error: %s", watcher->filename, uv_strerror(status));
		return;
	}

	isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_DEBUG(3),
			"file watch %s event detected in directory: %s\n", watcher->filename, watcher->directory);
	// printf("Event filename: %s\n", filename ? filename : "(null)");
	//  printf("  Target basename: %s\n", watcher->basename);
	//  printf("  Event type: %s%s\n",
	//         (events & UV_CHANGE) ? "CHANGE " : "",
	//         (events & UV_RENAME) ? "RENAME " : "");

	int mapped_events = 0;
	if (events & UV_CHANGE) {
		mapped_events |= ISC_FILEWATCHER_CHANGE;
	}
	// if (events & UV_RENAME) {
	//     mapped_events |= ISC_FILEWATCHER_RENAME;
	// }

	// Call the user's callback
	if (watcher->cb != NULL) {
		watcher->cb(watcher->cbarg,
			    filename ? filename : watcher->basename,
			    mapped_events);
	}
}

isc_result_t
isc_filewatcher_create(isc_loop_t *loop, isc_filewatcher_cb cb, void *cbarg,
		       const char *filename, isc_filewatcher_t **watcherp) {
	isc_filewatcher_t *watcher;
	int r;
	char *filename_copy;
	char *directory_copy;

	REQUIRE(VALID_LOOP(loop));
	REQUIRE(filename != NULL);
	REQUIRE(watcherp != NULL && *watcherp == NULL);

	isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_INFO,
		"creating file watcher for: %s", filename);

	watcher = isc_mem_get(loop->mctx, sizeof(*watcher));
	*watcher = (isc_filewatcher_t){
		.magic = FILEWATCHER_MAGIC,
		.mctx = loop->mctx,
		.loop = loop,
		.cb = cb,
		.cbarg = cbarg,
	};

	// Make a copy of the filename for dirname/basename operations
	filename_copy = isc_mem_strdup(watcher->mctx, filename);
	if (filename_copy == NULL) {
		isc_mem_put(watcher->mctx, watcher, sizeof(*watcher));
		return ISC_R_NOMEMORY;
	}

	directory_copy = isc_mem_strdup(watcher->mctx, filename_copy);
	if (directory_copy == NULL) {
		isc_mem_free(watcher->mctx, filename_copy);
		isc_mem_put(watcher->mctx, watcher, sizeof(*watcher));
		return ISC_R_NOMEMORY;
	}

	// Store the full path to the file
	watcher->filename = isc_mem_strdup(watcher->mctx, filename);
	if (watcher->filename == NULL) {
		isc_mem_free(watcher->mctx, filename_copy);
		isc_mem_free(watcher->mctx, directory_copy);
		isc_mem_put(watcher->mctx, watcher, sizeof(*watcher));
		return ISC_R_NOMEMORY;
	}

	// Extract the directory and basename
	watcher->directory = isc_mem_strdup(watcher->mctx,
					    dirname(directory_copy));
	if (watcher->directory == NULL) {
		isc_mem_free(watcher->mctx, filename_copy);
		isc_mem_free(watcher->mctx, directory_copy);
		isc_mem_free(watcher->mctx, watcher->filename);
		isc_mem_put(watcher->mctx, watcher, sizeof(*watcher));
		return ISC_R_NOMEMORY;
	}

	watcher->basename = isc_mem_strdup(watcher->mctx,
					   basename(filename_copy));
	if (watcher->basename == NULL) {
		isc_mem_free(watcher->mctx, filename_copy);
		isc_mem_free(watcher->mctx, directory_copy);
		isc_mem_free(watcher->mctx, watcher->filename);
		isc_mem_free(watcher->mctx, watcher->directory);
		isc_mem_put(watcher->mctx, watcher, sizeof(*watcher));
		return ISC_R_NOMEMORY;
	}
	
	isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_INFO,
			"created filewatcher for %s", watcher->filename);

	// Free the temporary copies
	isc_mem_free(watcher->mctx, filename_copy);
	isc_mem_free(watcher->mctx, directory_copy);

	// Initialize the file watcher with the direct uv_loop_t
	r = uv_fs_event_init(&loop->loop, &watcher->handle);
	if (r < 0) {
		isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_ERROR,
				"failed to initialize file watcher: %s", uv_strerror(r));
		isc_mem_free(watcher->mctx, watcher->filename);
		isc_mem_free(watcher->mctx, watcher->directory);
		isc_mem_free(watcher->mctx, watcher->basename);
		isc_mem_put(watcher->mctx, watcher, sizeof(*watcher));
		return ISC_R_FAILURE;
	}

	// Set the data pointer
	watcher->handle.data = watcher;

	*watcherp = watcher;

	return ISC_R_SUCCESS;
}

isc_result_t
isc_filewatcher_start(isc_filewatcher_t *watcher) {
	int r;

	REQUIRE(VALID_FILEWATCHER(watcher));

	// Start watching the directory containing the file
	r = uv_fs_event_start(&watcher->handle, filewatcher_callback,
			      watcher->directory, UV_FS_EVENT_WATCH_ENTRY);
	if (r < 0) {
		isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_ERROR,
				"failed to start file watcher for directory '%s': %s "
				"(error code: %d)",
				watcher->directory, uv_strerror(r), r);
		return ISC_R_FAILURE;
	}

	isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_INFO,
			"file watcher started successfully for directory: %s .Watching for file: %s)",
			watcher->directory, watcher->basename);
	return ISC_R_SUCCESS;
}

void
isc_filewatcher_stop(isc_filewatcher_t *watcher) {
	REQUIRE(VALID_FILEWATCHER(watcher));

	isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_INFO,
			"stopping file watcher event for: %s", watcher->filename);
	uv_fs_event_stop(&watcher->handle);
}

static void
filewatcher_close_cb(uv_handle_t *handle) {
	isc_filewatcher_t *watcher = (isc_filewatcher_t *)handle->data;

	// This callback is called after the handle is closed
	isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_INFO,
			"file watcher handle closed for: %s", watcher->filename);

	// Free memory now that the handle is closed
	if (watcher->filename != NULL) {
		isc_mem_free(watcher->mctx, watcher->filename);
	}

	if (watcher->directory != NULL) {
		isc_mem_free(watcher->mctx, watcher->directory);
	}

	if (watcher->basename != NULL) {
		isc_mem_free(watcher->mctx, watcher->basename);
	}

	isc_mem_put(watcher->mctx, watcher, sizeof(*watcher));
}

void
isc_filewatcher_destroy(isc_filewatcher_t **watcherp) {
	isc_filewatcher_t *watcher;

	REQUIRE(watcherp != NULL && *watcherp != NULL);
	watcher = *watcherp;
	REQUIRE(VALID_FILEWATCHER(watcher));

	isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER, ISC_LOG_INFO,
			"destroying file watcher for: %s", watcher->filename);

	// Stop the watcher if it's running
	isc_filewatcher_stop(watcher);

	// Set magic to 0 to mark it as invalid
	watcher->magic = 0;

	// Store the watcher pointer in the handle's data field
	// so the close callback can access it
	watcher->handle.data = watcher;

	// Close the handle if it's not already closing
	if (!uv_is_closing((uv_handle_t *)&watcher->handle)) {
		uv_close((uv_handle_t *)&watcher->handle, filewatcher_close_cb);
	}

	// Set the pointer to NULL, but don't free the memory yet
	// The memory will be freed in the close callback
	*watcherp = NULL;
}


const char *
isc_filewatcher_get_basename(isc_filewatcher_t *watcher) {
    REQUIRE(VALID_FILEWATCHER(watcher));
    return watcher->basename;
}