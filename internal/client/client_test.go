package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListApplications(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-ApiKey"); got != "test-key" {
			t.Fatalf("missing api key header")
		}
		_, _ = w.Write([]byte(`{"error":"Success","response":{"applications":[{"applicationid":"1","name":"App","version":"2"}]}}`))
	}))
	defer s.Close()
	c, err := New(Config{URL: s.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	items, err := c.ListApplications(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != "1" || items[0].Attrs["version"] != "2" {
		t.Fatalf("unexpected items: %#v", items)
	}
}

func TestAPIErrorRedactsBody(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error":"Failure","response":{"secret":"do-not-print"}}`))
	}))
	defer s.Close()
	c, err := New(Config{URL: s.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Post(context.Background(), "/v1/application", nil, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got == "" || contains(got, "do-not-print") {
		t.Fatalf("error leaked body: %s", got)
	}
}

func TestPostRawReturnsExportBody(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-ApiKey"); got != "test-key" {
			t.Fatalf("missing api key header")
		}
		if got := r.URL.Path; got != "/v1/application/export" {
			t.Fatalf("unexpected path: %s", got)
		}
		if got := r.URL.Query().Get("applicationid"); got != "123" {
			t.Fatalf("unexpected applicationid: %s", got)
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<AirlockCapture><sha256>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</sha256></AirlockCapture>`))
	}))
	defer s.Close()
	c, err := New(Config{URL: s.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := c.ExportApplication(context.Background(), "123")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); !contains(got, "<AirlockCapture>") {
		t.Fatalf("unexpected raw body: %s", got)
	}
}

func TestPostRawErrorRedactsBody(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`secret export body`))
	}))
	defer s.Close()
	c, err := New(Config{URL: s.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ExportApplication(context.Background(), "123")
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); contains(got, "secret export body") {
		t.Fatalf("error leaked body: %s", got)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || contains(s[1:], sub) || s[:len(sub)] == sub))
}
