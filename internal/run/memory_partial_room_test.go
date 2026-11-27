package run

import (
	"slices"
	"sync"
	"testing"
	"time"
)

// PR18 review: a destroy whose freeing the pool shows in parts (ZFS
// async_destroy frees a large dataset over several txgs; `zfs get
// freeing` is the outstanding part) moves the reading a little at once
// and the rest later. makeMemoryRoom takes the first small move as the
// pool's whole word (moved → short = after) and evicts another image
// for room that was already on its way.
func TestAStopEvictsNoExtraImageWhileThePoolShowsTheRoomInParts(t *testing.T) {
	const miB = 1 << 20
	m, _, keeper := memoryManager(t, t.TempDir())
	clock := newTestClock(m)
	m.MemorySettle = 2 * time.Second
	keeper.holds = func(memoryMB int) int64 { return int64(memoryMB+64) * miB }
	var mu sync.Mutex
	var free int64 = 1 << 40
	var went []struct {
		at    time.Time
		bytes int64
	}
	keeper.onRelease = func(image *MemoryImage) {
		mu.Lock()
		defer mu.Unlock()
		went = append(went, struct {
			at    time.Time
			bytes int64
		}{time.Now(), keeper.holds(image.MemoryMB)})
	}
	// A quarter of what went shows at once, the rest 300 ms later.
	keeper.shortBy = func(need int64) (int64, error) {
		mu.Lock()
		defer mu.Unlock()
		shown := free
		for _, gone := range went {
			shown += gone.bytes / 4
			if time.Since(gone.at) >= 300*time.Millisecond {
				shown += gone.bytes - gone.bytes/4
			}
		}
		return max(need-shown, 0), nil
	}
	stopOfSize := func(memoryMB int) (id, image string) {
		t.Helper()
		keeper.memoryMB = memoryMB
		created := mustCreate(t, m, CreateRequest{Limits: &Limits{MemoryMB: memoryMB}})
		mustStop(t, m, created.ID)
		clock.advance(time.Minute)
		return created.ID, memoryOf(t, m, created.ID).Image
	}
	_, smallImage := stopOfSize(256)  // may hold 320 MiB
	_, middleImage := stopOfSize(512) // may hold 576 MiB
	large, _ := stopOfSize(1024)      // may hold 1088 MiB

	mu.Lock()
	free = keeper.holds(1024) - 700*miB // short by 700 MiB
	mu.Unlock()
	keeper.memoryMB = 1024
	newest := mustCreate(t, m, CreateRequest{Limits: &Limits{MemoryMB: 1024}})
	mustStop(t, m, newest.ID)

	// small + middle (896 MiB) cover 700 MiB once the pool has shown it.
	if want := []string{smallImage, middleImage}; !slices.Equal(keeper.released, want) {
		t.Fatalf("released %v, want %v and no more (large: %+v)", keeper.released, want, memoryOf(t, m, large))
	}
}
