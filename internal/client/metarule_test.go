package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestMetaruleCriterionMutationContracts(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		body   map[string]any
		invoke func(context.Context, *Client) error
	}{
		{
			name: "application add", path: "/v1/application/metarule/criteria/add",
			body: map[string]any{"metaruleid": "rule-1", "field": "path", "operation": "wildcard", "value": "/opt/example/*"},
			invoke: func(ctx context.Context, c *Client) error {
				return c.AddApplicationMetaruleCriterion(ctx, "rule-1", "path", "wildcard", "/opt/example/*")
			},
		},
		{
			name: "application update", path: "/v1/application/metarule/criteria/update",
			body: map[string]any{"criteriaid": "criterion-1", "field": "publisher", "operation": "contains", "value": "Example Publisher"},
			invoke: func(ctx context.Context, c *Client) error {
				return c.UpdateApplicationMetaruleCriterion(ctx, "criterion-1", "publisher", "contains", "Example Publisher")
			},
		},
		{
			name: "application delete", path: "/v1/application/metarule/criteria/delete",
			body: map[string]any{"criteriaid": "criterion-1"},
			invoke: func(ctx context.Context, c *Client) error {
				return c.DeleteApplicationMetaruleCriterion(ctx, "criterion-1")
			},
		},
		{
			name: "blocklist add", path: "/v1/blocklist/metarule/criteria/add",
			body: map[string]any{"metaruleid": "rule-1", "field": "path", "operation": "wildcard", "value": "/tmp/example/*"},
			invoke: func(ctx context.Context, c *Client) error {
				return c.AddBlocklistMetaruleCriterion(ctx, "rule-1", "path", "wildcard", "/tmp/example/*")
			},
		},
		{
			name: "blocklist update", path: "/v1/blocklist/metarule/criteria/update",
			body: map[string]any{"criteriaid": "criterion-1", "field": "path", "operation": "contains", "value": "/var/tmp/"},
			invoke: func(ctx context.Context, c *Client) error {
				return c.UpdateBlocklistMetaruleCriterion(ctx, "criterion-1", "path", "contains", "/var/tmp/")
			},
		},
		{
			name: "blocklist delete", path: "/v1/blocklist/metarule/criteria/delete",
			body: map[string]any{"criteriaid": "criterion-1"},
			invoke: func(ctx context.Context, c *Client) error {
				return c.DeleteBlocklistMetaruleCriterion(ctx, "criterion-1")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Fatalf("method = %q, want POST", r.Method)
				}
				if r.URL.Path != test.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, test.path)
				}
				if r.URL.RawQuery != "" {
					t.Fatalf("unexpected query = %q", r.URL.RawQuery)
				}
				if got := r.Header.Get("Content-Type"); got != "application/json" {
					t.Fatalf("content type = %q, want application/json", got)
				}
				var got map[string]any
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, test.body) {
					t.Fatalf("body = %#v, want %#v", got, test.body)
				}
				_, _ = w.Write([]byte(`{"error":"Success"}`))
			}))
			defer server.Close()

			client, err := New(Config{URL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			if err := test.invoke(context.Background(), client); err != nil {
				t.Fatal(err)
			}
		})
	}
}
