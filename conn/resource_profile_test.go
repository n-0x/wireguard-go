//go:build r2resourceprofile || (linux && !android) || (darwin && !ios)

/* SPDX-License-Identifier: MIT */

package conn

import "testing"

// Idle socket metadata must not keep payloads alive after the message-buffer
// cache has discarded them. Otherwise bounding the five device pools is not
// enough to bound reachable message arrays.
func TestR2IdleMessagesReleasePayloadReferences(t *testing.T) {
	b := NewStdNetBind().(*StdNetBind)
	msgs := b.getMessages()
	for i := range *msgs {
		(*msgs)[i].Buffers[0] = make([]byte, 65535)
	}
	b.putMessages(msgs)
	reused := b.getMessages()
	defer b.putMessages(reused)
	for i := range *reused {
		for _, buf := range (*reused)[i].Buffers {
			if buf != nil {
				t.Fatalf("idle message%d still retains a %d-byte payload", i, cap(buf))
			}
		}
	}
}
