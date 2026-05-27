package obs

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMountServesMetricsHealthReady(t *testing.T) {
	// Tickle a counter so /metrics has something visible to assert against.
	AppendsTotal.WithLabelValues("ok").Inc()

	// Healthy probe + unhealthy probe — /readyz must return 503 because of
	// the second one, but /healthz must still return 200.
	RegisterProbe("happy", func(context.Context) error { return nil })
	RegisterProbe("sad", func(context.Context) error { return errors.New("oops") })
	t.Cleanup(func() {
		DefaultHealth.Unregister("happy")
		DefaultHealth.Unregister("sad")
	})

	mux := http.NewServeMux()
	Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cases := []struct {
		path    string
		want    int
		mustSub string
	}{
		{"/healthz", 200, "ok"},
		{"/readyz", 503, "\"ok\":false"},
		{"/metrics", 200, "stele_appends_total"},
	}
	for _, tc := range cases {
		resp, err := http.Get(srv.URL + tc.path)
		if err != nil {
			t.Fatalf("GET %s: %v", tc.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("GET %s: status %d want %d, body=%s", tc.path, resp.StatusCode, tc.want, body)
		}
		if !strings.Contains(string(body), tc.mustSub) {
			t.Errorf("GET %s: body missing %q, got %s", tc.path, tc.mustSub, body)
		}
	}
}

func TestHealthAllPass(t *testing.T) {
	// With only happy probes, /readyz returns 200.
	RegisterProbe("a", func(context.Context) error { return nil })
	RegisterProbe("b", func(context.Context) error { return nil })
	t.Cleanup(func() {
		DefaultHealth.Unregister("a")
		DefaultHealth.Unregister("b")
	})
	mux := http.NewServeMux()
	Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("readyz returned %d, body=%s", resp.StatusCode, body)
	}
}
