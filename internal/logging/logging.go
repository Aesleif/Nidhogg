package logging

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// ParseLevel parses a config string into a slog.Level.
// Empty string defaults to LevelInfo.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level: %q", s)
}

// Setup installs a text slog handler at the given level as the default logger.
func Setup(level slog.Level) {
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))
}
