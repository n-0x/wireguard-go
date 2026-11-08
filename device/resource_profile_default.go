//go:build !r2resourceprofile && (!linux || android) && (!darwin || ios)

/* SPDX-License-Identifier: MIT */

package device

const (
	resourceProfileCacheCapacity = 0
	resourceProfileWorkers       = 0
)
