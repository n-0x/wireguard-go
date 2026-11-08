//go:build r2resourceprofile

/* SPDX-License-Identifier: MIT */

package conn

// Idle metadata must not extend the lifetime of buffers discarded by the
// device's bounded caches. Active Send/Receive callers retain their own slices.
const resourceProfileReleaseBuffers = true
