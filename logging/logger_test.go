package logging

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func captureLogger() (*logrus.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	l := logrus.New()
	l.Formatter = &logrus.JSONFormatter{DisableTimestamp: true}
	l.Level = logrus.DebugLevel
	l.Out = buf
	return l, buf
}

func entries(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func serve(t *testing.T, handler gin.HandlerFunc, mutate func(*http.Request)) (*bytes.Buffer, *http.Response) {
	t.Helper()
	logger, buf := captureLogger()
	r := gin.New()
	r.Use(RequestID())
	r.Use(NewStructuredLogger(logger))
	r.GET("/seam", handler)
	ts := httptest.NewServer(r)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/seam?q=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "seam-agent")
	if mutate != nil {
		mutate(req)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return buf, resp
}

// TestStructuredLoggerFieldNames pins every field the chi RequestLogger implementation emitted.
// A gin-native logger that renamed or dropped one of them would still compile and still leave the
// inherited suite green, because no test in the source suite reads log output.
func TestStructuredLoggerFieldNames(t *testing.T) {
	buf, _ := serve(t, func(c *gin.Context) { c.String(http.StatusTeapot, "hi") }, nil)

	got := entries(t, buf)
	if len(got) != 2 {
		t.Fatalf("log entries: want 2, got %d (%s)", len(got), buf.String())
	}
	started, complete := got[0], got[1]

	if started["msg"] != "request started" {
		t.Errorf("first message: want %q, got %q", "request started", started["msg"])
	}
	if complete["msg"] != "request complete" {
		t.Errorf("second message: want %q, got %q", "request complete", complete["msg"])
	}

	for _, field := range []string{"ts", "req_id", "http_scheme", "http_proto", "http_method", "remote_addr", "user_agent", "uri"} {
		if _, ok := started[field]; !ok {
			t.Errorf("request started: missing field %q", field)
		}
	}
	for _, field := range []string{"resp_status", "resp_bytes_length", "resp_elapsed_ms"} {
		if _, ok := complete[field]; !ok {
			t.Errorf("request complete: missing field %q", field)
		}
	}

	if started["http_scheme"] != "http" {
		t.Errorf("http_scheme: want http, got %v", started["http_scheme"])
	}
	if started["http_proto"] != "HTTP/1.1" {
		t.Errorf("http_proto: want HTTP/1.1, got %v", started["http_proto"])
	}
	if started["http_method"] != http.MethodGet {
		t.Errorf("http_method: want GET, got %v", started["http_method"])
	}
	if started["user_agent"] != "seam-agent" {
		t.Errorf("user_agent: want seam-agent, got %v", started["user_agent"])
	}
	if complete["resp_status"] != float64(http.StatusTeapot) {
		t.Errorf("resp_status: want 418, got %v", complete["resp_status"])
	}
	if complete["resp_bytes_length"] != float64(2) {
		t.Errorf("resp_bytes_length: want 2, got %v", complete["resp_bytes_length"])
	}
}

// TestStructuredLoggerURIQuirk pins an upstream copy-paste bug. NewLogEntry assigns the uri field
// twice and the second assignment wins, so the scheme and host built by the first are discarded
// and uri is the raw request target. Emitting the absolute form would look like a fix and would
// change every log line the operator greps.
func TestStructuredLoggerURIQuirk(t *testing.T) {
	buf, _ := serve(t, func(c *gin.Context) { c.String(http.StatusOK, "ok") }, nil)

	started := entries(t, buf)[0]
	if started["uri"] != "/seam?q=1" {
		t.Errorf("uri: want the raw request target %q, got %v", "/seam?q=1", started["uri"])
	}
}

// TestStructuredLoggerUnwrittenResponse pins the zero values chi's wrapped response writer
// reported when a handler wrote nothing at all.
func TestStructuredLoggerUnwrittenResponse(t *testing.T) {
	buf, _ := serve(t, func(c *gin.Context) {}, nil)

	complete := entries(t, buf)[1]
	if complete["resp_status"] != float64(0) {
		t.Errorf("resp_status: want 0, got %v", complete["resp_status"])
	}
	if complete["resp_bytes_length"] != float64(0) {
		t.Errorf("resp_bytes_length: want 0, got %v", complete["resp_bytes_length"])
	}
}

// TestRequestIDReusesInboundHeader pins chi middleware.RequestID's behaviour of trusting an
// existing X-Request-Id header instead of always minting a new identifier.
func TestRequestIDReusesInboundHeader(t *testing.T) {
	buf, _ := serve(t, func(c *gin.Context) { c.String(http.StatusOK, "ok") }, func(r *http.Request) {
		r.Header.Set(RequestIDHeader, "inbound-id")
	})

	started := entries(t, buf)[0]
	if started["req_id"] != "inbound-id" {
		t.Errorf("req_id: want the inbound header value, got %v", started["req_id"])
	}
}

// TestRequestIDGeneratesWhenAbsent pins the generated shape: a host derived prefix, a hyphen,
// and a six digit counter, matching what chi produced.
func TestRequestIDGeneratesWhenAbsent(t *testing.T) {
	buf, _ := serve(t, func(c *gin.Context) { c.String(http.StatusOK, "ok") }, nil)

	started := entries(t, buf)[0]
	id, ok := started["req_id"].(string)
	if !ok || id == "" {
		t.Fatalf("req_id: want a non empty string, got %v", started["req_id"])
	}
	idx := strings.LastIndex(id, "-")
	if idx < 1 || len(id)-idx-1 != 6 {
		t.Errorf("req_id: want a prefix and a six digit counter, got %q", id)
	}
}

// TestGetLogEntryRequiresMiddleware pins the unchecked type assertion carried over from the
// source: without the structured logger in the chain, GetLogEntry panics rather than returning nil.
func TestGetLogEntryRequiresMiddleware(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("GetLogEntry: want a panic when the logger middleware is absent")
		}
	}()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	GetLogEntry(req)
}

// TestLogEntrySetFieldAddsField pins the helper handlers use to enrich the request scoped entry.
func TestLogEntrySetFieldAddsField(t *testing.T) {
	logger, buf := captureLogger()
	r := gin.New()
	r.Use(RequestID())
	r.Use(NewStructuredLogger(logger))
	r.GET("/seam", func(c *gin.Context) {
		LogEntrySetField(c.Request, "extra", "value")
		GetLogEntry(c.Request).Info("handler ran")
		c.String(http.StatusOK, "ok")
	})
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/seam")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	for _, e := range entries(t, buf) {
		if e["msg"] == "handler ran" {
			if e["extra"] != "value" {
				t.Errorf("extra: want %q, got %v", "value", e["extra"])
			}
			return
		}
	}
	t.Errorf("no handler log entry found in %s", buf.String())
}
