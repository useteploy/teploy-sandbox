package access

import "fmt"

// StreamMemory is the most memory one access stream can make the daemon
// hold: its HTTP/2 receive window, full, and the two copy buffers.
const StreamMemory = streamWindow + 2*copyChunk

// FilesNeeded is what the access listener adds to the daemon's open file
// limit: one guest socket per stream, and room for the edges' connections.
func FilesNeeded(streamsMax int) int64 { return int64(streamsMax) + 64 }

// CheckMemory refuses a stream cap whose worst case does not fit the
// memory budget the daemon allows the access listener (budgetMB MiB).
func CheckMemory(streamsMax, budgetMB int) error {
	if streamsMax <= 0 {
		return fmt.Errorf("access-streams-max must be positive, got %d", streamsMax)
	}
	need := int64(streamsMax) * StreamMemory
	budget := int64(budgetMB) << 20
	if need > budget {
		return fmt.Errorf("%d access streams can hold up to %d MiB in the daemon (%d KiB each: a full %d KiB HTTP/2 window and two %d KiB copy buffers), more than the %d MiB access memory budget; lower --access-streams-max or raise --access-memory-mb",
			streamsMax, need>>20, StreamMemory>>10, streamWindow>>10, copyChunk>>10, budgetMB)
	}
	return nil
}
