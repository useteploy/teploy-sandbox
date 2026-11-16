package server

import (
	"bufio"
	"bytes"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// hostMemoryMB is the host's total memory, 0 when it cannot be told.
// Linux only, from /proc/meminfo: every other way of asking costs a
// dependency or cgo.
func hostMemoryMB() int {
	if runtime.GOOS != "linux" {
		return 0
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	return parseMemTotalMB(data)
}

// parseMemTotalMB reads the "MemTotal:  16314172 kB" line of a meminfo.
func parseMemTotalMB(meminfo []byte) int {
	scanner := bufio.NewScanner(bytes.NewReader(meminfo))
	for scanner.Scan() {
		rest, ok := strings.CutPrefix(scanner.Text(), "MemTotal:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) != 2 || fields[1] != "kB" {
			return 0
		}
		kb, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || kb < 0 {
			return 0
		}
		return int(kb / 1024)
	}
	return 0
}
