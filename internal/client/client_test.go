package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClientUsesEnvironmentOrExplicitProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://inherited.invalid:9999")
	c, err := New(Config{URL: "https://airlock.example.com:3129", APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	requestURL, _ := url.Parse("https://airlock.example.com:3129/v1/group")
	proxyURL, err := transport.Proxy(&http.Request{URL: requestURL})
	if err != nil {
		t.Fatal(err)
	}
	if got := proxyURL.String(); got != "http://inherited.invalid:9999" {
		t.Fatalf("environment proxy URL = %q", got)
	}

	c, err = New(Config{URL: "https://airlock.example.com:3129", APIKey: "test-key", ProxyURL: "http://proxy.example.com:8083"})
	if err != nil {
		t.Fatal(err)
	}
	transport = c.httpClient.Transport.(*http.Transport)
	proxyURL, err = transport.Proxy(&http.Request{URL: requestURL})
	if err != nil {
		t.Fatal(err)
	}
	if got := proxyURL.String(); got != "http://proxy.example.com:8083" {
		t.Fatalf("proxy URL = %q", got)
	}
}

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

func TestListCloudGroupsUsesInventoryEndpoint(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if got := r.URL.Path; got != "/v1/cloudgroups" {
			t.Fatalf("unexpected path: %s", got)
		}
		if got := r.URL.RawQuery; got != "" {
			t.Fatalf("unexpected query: %s", got)
		}
		if got := r.Header.Get("X-ApiKey"); got != "test-key" {
			t.Fatalf("unexpected api key header")
		}
		_, _ = w.Write([]byte(`{"error":"Success","response":{"cloudgroups":[]}}`))
	}))
	defer s.Close()
	c, err := New(Config{URL: s.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.ListCloudGroups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		CloudGroups []json.RawMessage `json:"cloudgroups"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.CloudGroups == nil || len(decoded.CloudGroups) != 0 {
		t.Fatalf("unexpected cloud groups response: %s", string(out))
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

func TestGetAgentIncludesGroupID(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/v1/agent/find" {
			t.Fatalf("unexpected path: %s", got)
		}
		if got := r.URL.Query().Get("agentid"); got != "agent-1" {
			t.Fatalf("unexpected agentid: %s", got)
		}
		_, _ = w.Write([]byte(`{"error":"Success","response":{"agents":[{"agentid":"agent-1","hostname":"host-1","groupid":"group-1","username":"user-1","status":1}]}}`))
	}))
	defer s.Close()
	c, err := New(Config{URL: s.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	agent, ok, err := c.GetAgent(context.Background(), "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected agent to be found")
	}
	if agent.GroupID != "group-1" {
		t.Fatalf("unexpected group ID: %s", agent.GroupID)
	}
	if got := agent.Named().Attrs["groupid"]; got != "group-1" {
		t.Fatalf("expected groupid attr, got %q", got)
	}
}

func TestMoveAgentUsesArrayBody(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/v1/agent/move" {
			t.Fatalf("unexpected path: %s", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		raw := string(body)
		for _, want := range []string{`"groupid":"group-1"`, `"agentid":["agent-1"]`} {
			if !strings.Contains(raw, want) {
				t.Fatalf("request body %q missing %s", raw, want)
			}
		}
		_, _ = w.Write([]byte(`{"error":"Success"}`))
	}))
	defer s.Close()
	c, err := New(Config{URL: s.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.MoveAgent(context.Background(), "agent-1", "group-1"); err != nil {
		t.Fatal(err)
	}
}

func TestGroupSettingsMutationContracts(t *testing.T) {
	proxyUsername := "proxy-user"
	proxyPassword := "proxy-password"
	tests := []struct {
		name   string
		path   string
		query  url.Values
		invoke func(context.Context, *Client) error
	}{
		{name: "audit mode", path: "/v1/group/settings/auditmode", query: Values("groupid", "group-1", "auditmode", "1"), invoke: func(ctx context.Context, c *Client) error {
			return c.SetGroupAuditMode(ctx, "group-1", 1)
		}},
		{name: "notifications enabled", path: "/v1/group/settings/enable_notifications", query: Values("groupid", "group-1", "enable_notifications", "1"), invoke: func(ctx context.Context, c *Client) error {
			return c.SetGroupNotificationsEnabled(ctx, "group-1", 1)
		}},
		{name: "notification message", path: "/v1/group/settings/notification_message", query: Values("groupid", "group-1", "notification_message", "Blocked by policy"), invoke: func(ctx context.Context, c *Client) error {
			return c.SetGroupNotificationMessage(ctx, "group-1", "Blocked by policy")
		}},
		{name: "communication list", path: "/v1/group/settings/commlist", query: Values("groupid", "group-1", "commlistid", "list-1"), invoke: func(ctx context.Context, c *Client) error {
			return c.SetGroupCommunicationList(ctx, "group-1", "list-1")
		}},
		{name: "reflection", path: "/v1/group/settings/reflection", query: Values("groupid", "group-1", "reflection", "1"), invoke: func(ctx context.Context, c *Client) error {
			return c.SetGroupReflection(ctx, "group-1", 1)
		}},
		{name: "PowerShell lockdown", path: "/v1/group/settings/pslockdown", query: Values("groupid", "group-1", "pslockdown", "2"), invoke: func(ctx context.Context, c *Client) error {
			return c.SetGroupPowerShellLockdown(ctx, "group-1", 2)
		}},
		{name: "poll time", path: "/v1/group/settings/polltime", query: Values("groupid", "group-1", "polltime", "300"), invoke: func(ctx context.Context, c *Client) error {
			return c.SetGroupPollTime(ctx, "group-1", 300)
		}},
		{name: "proxy enabled", path: "/v1/group/settings/proxy", query: Values("groupid", "group-1", "proxy", "1"), invoke: func(ctx context.Context, c *Client) error {
			return c.SetGroupProxyEnabled(ctx, "group-1", 1)
		}},
		{name: "proxy settings", path: "/v1/group/settings/proxy/settings", query: Values("groupid", "group-1", "server", "proxy.example", "port", "8080", "authentication", "1", "username", proxyUsername, "password", proxyPassword), invoke: func(ctx context.Context, c *Client) error {
			return c.SetGroupProxySettings(ctx, "group-1", "proxy.example", "8080", 1, &proxyUsername, &proxyPassword)
		}},
		{name: "script control", path: "/v1/group/settings/script", query: Values("groupid", "group-1", "scripts", "2"), invoke: func(ctx context.Context, c *Client) error {
			return c.SetGroupScriptControl(ctx, "group-1", 2)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.Path; got != test.path {
					t.Fatalf("path = %q, want %q", got, test.path)
				}
				if got := r.URL.Query().Encode(); got != test.query.Encode() {
					t.Fatalf("query = %q, want %q", got, test.query.Encode())
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if len(body) != 0 {
					t.Fatalf("request unexpectedly used a body")
				}
				_, _ = w.Write([]byte(`{"error":"Success"}`))
			}))
			defer s.Close()
			c, err := New(Config{URL: s.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			if err := test.invoke(context.Background(), c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGroupProxySettingsOmitsOptionalCredentials(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := Values("groupid", "group-1", "authentication", "0")
		want.Set("server", "")
		want.Set("port", "")
		if got := r.URL.Query().Encode(); got != want.Encode() {
			t.Fatalf("query = %q, want %q", got, want.Encode())
		}
		_, _ = w.Write([]byte(`{"error":"Success"}`))
	}))
	defer s.Close()
	c, err := New(Config{URL: s.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetGroupProxySettings(context.Background(), "group-1", "", "", 0, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestGetGroupPolicyReadsBlocklistAudit(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"error":"Success","response":{"groupid":"group-1","blocklists":[{"blocklistid":"block-1","name":"Example","audit":"1"}]}}`))
	}))
	defer s.Close()
	c, err := New(Config{URL: s.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := c.GetGroupPolicy(context.Background(), "group-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Blocklists) != 1 || policy.Blocklists[0].Attrs["audit"] != "1" {
		t.Fatalf("audit readback missing: %#v", policy.Blocklists)
	}
}

func TestHashMembershipMutationContracts(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		call     func(context.Context, *Client) error
		bodyKeys []string
		queryKey string
	}{
		{name: "application add", path: "/v1/hash/application/add", call: func(ctx context.Context, c *Client) error {
			return c.AddApplicationHash(ctx, "app-1", []string{"hash-1", "hash-2"})
		}, bodyKeys: []string{"applicationid", "hashes"}},
		{name: "application remove", path: "/v1/hash/application/remove", call: func(ctx context.Context, c *Client) error {
			return c.RemoveApplicationHash(ctx, "app-1", []string{"hash-1", "hash-2"})
		}, queryKey: "applicationid"},
		{name: "blocklist add", path: "/v1/hash/blocklist/add", call: func(ctx context.Context, c *Client) error {
			return c.AddBlocklistHash(ctx, "block-1", []string{"hash-1", "hash-2"})
		}, bodyKeys: []string{"blocklistid", "hashes"}},
		{name: "blocklist remove", path: "/v1/hash/blocklist/remove", call: func(ctx context.Context, c *Client) error {
			return c.RemoveBlocklistHash(ctx, "block-1", []string{"hash-1", "hash-2"})
		}, bodyKeys: []string{"blocklistid", "hashes"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.path)
				}
				if tt.queryKey != "" {
					if r.URL.Query().Get(tt.queryKey) == "" || r.URL.Query().Get("hashes") != "hash-1,hash-2" {
						t.Fatalf("unexpected query: %s", r.URL.RawQuery)
					}
				} else {
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					for _, key := range tt.bodyKeys {
						if _, ok := body[key]; !ok {
							t.Fatalf("body missing %q: %#v", key, body)
						}
					}
				}
				_, _ = w.Write([]byte(`{"error":"Success"}`))
			}))
			defer s.Close()
			c, err := New(Config{URL: s.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			if err := tt.call(context.Background(), c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || contains(s[1:], sub) || s[:len(sub)] == sub))
}
