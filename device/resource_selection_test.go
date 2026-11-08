/* SPDX-License-Identifier: MIT */

package device

import (
	"runtime"
	"testing"
)

// Expectations are expressed by GOOS, independently of the production build
// expressions: Android and iOS must retain upstream defaults without opt-in.
func TestResourceProfilePlatformSelection(t *testing.T) {
	wantR2 := resourceProfileTestOptIn || runtime.GOOS == "linux" || runtime.GOOS == "darwin"
	size, prealloc, staged, queue, workers, cache := 65535, 0, 128, 1024, 0, 0
	if wantR2 {
		size, staged, queue, workers, cache = 2016, 2, 8, 1, 32
	} else {
		switch runtime.GOOS {
		case "windows":
			size = 2016
		case "android":
			prealloc = 4096
		case "ios":
			size, prealloc = 1700, 1024
		}
	}
	cases := []struct {
		name      string
		got, want int
	}{
		{"message size", MaxMessageSize, size},
		{"preallocated leases", int(PreallocatedBuffersPerPool), prealloc},
		{"staged", QueueStagedSize, staged},
		{"outbound", QueueOutboundSize, queue},
		{"inbound", QueueInboundSize, queue},
		{"handshake", QueueHandshakeSize, queue},
		{"workers", resourceProfileWorkers, workers},
		{"idle cache", resourceProfileCacheCapacity, cache},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("GOOS=%s opt-in=%v: got%d want%d", runtime.GOOS, resourceProfileTestOptIn, tc.got, tc.want)
			}
		})
	}
}
