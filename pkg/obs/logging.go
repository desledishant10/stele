// Package obs provides stele's observability primitives: structured
// logging via log/slog, Prometheus metrics, and HTTP health endpoints.
//
// Every binary should call obs.Init early in main(). Components
// downstream of main() should use the package-level slog helpers and
// the metrics declared in metrics.go directly.
package obs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Component labels every log line and metric with which binary it came
// from. Set via Init.
var component = "stele"

// Logger is the configured slog.Logger. Replaced by Init; defaults to a
// text handler at INFO so unit tests get something sensible without
// requiring Init.
var Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

// Init configures the global slog.Logger and component label. Reads:
//
//   - STELE_LOG_LEVEL: debug|info|warn|error (default info)
//   - STELE_LOG_FORMAT: json|text (default json — production-friendly)
//
// `comp` is a short binary name like "steled" or "witness" that gets
// attached to every log record and to certain metrics labels.
func Init(comp string, out io.Writer) {
	component = comp
	if out == nil {
		out = os.Stderr
	}
	level := parseLevel(os.Getenv("STELE_LOG_LEVEL"))
	format := strings.ToLower(os.Getenv("STELE_LOG_FORMAT"))
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	switch format {
	case "text":
		h = slog.NewTextHandler(out, opts)
	default:
		h = slog.NewJSONHandler(out, opts)
	}
	Logger = slog.New(h).With(slog.String("component", comp))
}

// Component returns the configured binary name. Useful for metric labels.
func Component() string { return component }

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Convenience wrappers so callers don't have to know about slog.Default.

func Debug(msg string, attrs ...any) { Logger.Debug(msg, attrs...) }
func Info(msg string, attrs ...any)  { Logger.Info(msg, attrs...) }
func Warn(msg string, attrs ...any)  { Logger.Warn(msg, attrs...) }
func Error(msg string, attrs ...any) { Logger.Error(msg, attrs...) }

// Fatal logs at ERROR then exits non-zero. Replaces log.Fatalf at the
// top of main(); never call from a library.
func Fatal(msg string, attrs ...any) {
	Logger.Error(msg, attrs...)
	os.Exit(1)
}

// Fatalf formats with fmt.Sprintf and exits. Bridge for main() sites
// that were using log.Fatalf("binary: %v", err) historically — prefer
// Fatal(msg, "err", err) for new code.
func Fatalf(format string, args ...any) {
	Logger.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

// WithCtx returns a logger that records the context's request_id (if
// any) on every line. Use inside HTTP handlers.
func WithCtx(ctx context.Context) *slog.Logger {
	if rid, ok := ctx.Value(requestIDKey).(string); ok && rid != "" {
		return Logger.With(slog.String("request_id", rid))
	}
	return Logger
}

type ctxKey int

const requestIDKey ctxKey = 1

// WithRequestID attaches a request ID to ctx; pair with WithCtx to log
// it. Caller is responsible for generating the ID.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}
