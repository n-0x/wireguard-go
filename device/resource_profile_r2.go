//go:build r2resourceprofile || (linux && !android) || (darwin && !ios)

/* SPDX-License-Identifier: MIT */

package device

// This experimental profile requires the R2 MTU1420, batch8 compact Bind/TUN
// adapter. Its socket-side GRO staging must retain full UDP datagram capacity.
// See RESOURCE_PROFILE.md. This is not a general-purpose device configuration.
const (
	QueueStagedSize              = 2
	QueueOutboundSize            = 8
	QueueInboundSize             = 8
	QueueHandshakeSize           = 8
	MaxSegmentSize               = 2048 - 32
	PreallocatedBuffersPerPool   = 0 // Never wait for another borrower to return a slot.
	resourceProfileCacheCapacity = 32
	resourceProfileWorkers       = 1
)
