//go:build !linux

package main

import "log/slog"

func clearMemoryMerge(*slog.Logger) {}
