// Package logging provides structured logging with logrus.
package logging

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Logger is a configured logrus.Logger.
var Logger *logrus.Logger

// StructuredLogger is a structured logrus Logger.
type StructuredLogger struct {
	Logger *logrus.Logger
}

type logEntryCtxKeyType struct{}

// LogEntryCtxKey is the request context key holding the request scoped log entry.
var LogEntryCtxKey = logEntryCtxKeyType{}

// NewLogger creates and configures a new logrus Logger.
func NewLogger() *logrus.Logger {
	Logger = logrus.New()
	if viper.GetBool("log_textlogging") {
		Logger.Formatter = &logrus.TextFormatter{
			DisableTimestamp: true,
		}
	} else {
		Logger.Formatter = &logrus.JSONFormatter{
			DisableTimestamp: true,
		}
	}

	level := viper.GetString("log_level")
	if level == "" {
		level = "error"
	}
	l, err := logrus.ParseLevel(level)
	if err != nil {
		log.Fatal(err)
	}
	Logger.Level = l
	return Logger
}

// NewStructuredLogger implements a custom structured logrus Logger.
func NewStructuredLogger(logger *logrus.Logger) gin.HandlerFunc {
	l := &StructuredLogger{logger}
	return func(c *gin.Context) {
		entry := l.NewLogEntry(c.Request)
		ctx := context.WithValue(c.Request.Context(), LogEntryCtxKey, entry)
		c.Request = c.Request.WithContext(ctx)

		ww := &statusWriter{ResponseWriter: c.Writer}
		c.Writer = ww

		t1 := time.Now()
		defer func() {
			entry.Write(ww.status, ww.bytes, ww.Header(), time.Since(t1), nil)
		}()

		c.Next()
	}
}

// statusWriter records the status code of the first response header written through it and the number of
// body bytes written, so that a request answered with nothing, such as one that panicked, logs status 0.
type statusWriter struct {
	gin.ResponseWriter
	status int
	bytes  int
}

// WriteHeader records the first status code before passing it on.
func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

// WriteHeaderNow records the pending status code before writing the response header.
func (w *statusWriter) WriteHeaderNow() {
	if w.status == 0 {
		w.status = w.ResponseWriter.Status()
	}
	w.ResponseWriter.WriteHeaderNow()
}

// Write records an implicit 200 OK and counts the body bytes written.
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = w.ResponseWriter.Status()
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// WriteString records an implicit 200 OK and counts the body bytes written.
func (w *statusWriter) WriteString(s string) (int, error) {
	if w.status == 0 {
		w.status = w.ResponseWriter.Status()
	}
	n, err := w.ResponseWriter.WriteString(s)
	w.bytes += n
	return n, err
}

// NewLogEntry sets default request log fields.
func (l *StructuredLogger) NewLogEntry(r *http.Request) *StructuredLoggerEntry {
	entry := &StructuredLoggerEntry{Logger: logrus.NewEntry(l.Logger)}
	logFields := logrus.Fields{}

	logFields["ts"] = time.Now().UTC().Format(time.RFC1123)

	if reqID := requestIDFromRequest(r); reqID != "" {
		logFields["req_id"] = reqID
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	logFields["http_scheme"] = scheme
	logFields["http_proto"] = r.Proto
	logFields["http_method"] = r.Method

	logFields["remote_addr"] = r.RemoteAddr
	logFields["user_agent"] = r.UserAgent()

	logFields["uri"] = fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI)
	logFields["uri"] = r.RequestURI

	entry.Logger = entry.Logger.WithFields(logFields)

	entry.Logger.Infoln("request started")

	return entry
}

// StructuredLoggerEntry is a logrus.FieldLogger.
type StructuredLoggerEntry struct {
	Logger logrus.FieldLogger
}

func (l *StructuredLoggerEntry) Write(status, bytes int, header http.Header, elapsed time.Duration, extra any) {
	l.Logger = l.Logger.WithFields(logrus.Fields{
		"resp_status":       status,
		"resp_bytes_length": bytes,
		"resp_elapsed_ms":   float64(elapsed.Nanoseconds()) / 1000000.0,
	})

	l.Logger.Infoln("request complete")
}

// Panic prints stack trace
func (l *StructuredLoggerEntry) Panic(v any, stack []byte) {
	l.Logger = l.Logger.WithFields(logrus.Fields{
		"stack": string(stack),
		"panic": fmt.Sprintf("%+v", v),
	})
}

// Helper methods used by the application to get the request-scoped
// logger entry and set additional fields between handlers.

// GetLogEntry return the request scoped logrus.FieldLogger.
func GetLogEntry(r *http.Request) logrus.FieldLogger {
	entry := r.Context().Value(LogEntryCtxKey).(*StructuredLoggerEntry)
	return entry.Logger
}

// LogEntrySetField adds a field to the request scoped logrus.FieldLogger.
func LogEntrySetField(r *http.Request, key string, value any) {
	if entry, ok := r.Context().Value(LogEntryCtxKey).(*StructuredLoggerEntry); ok {
		entry.Logger = entry.Logger.WithField(key, value)
	}
}

// LogEntrySetFields adds multiple fields to the request scoped logrus.FieldLogger.
func LogEntrySetFields(r *http.Request, fields map[string]any) {
	if entry, ok := r.Context().Value(LogEntryCtxKey).(*StructuredLoggerEntry); ok {
		entry.Logger = entry.Logger.WithFields(fields)
	}
}
