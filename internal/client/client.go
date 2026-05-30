// Package client implements a small Airlock Digital REST API client.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultTimeout = 30 * time.Second

// Client talks to the Airlock Digital REST API.
type Client struct {
	baseURL    *url.URL
	apiKey     string
	httpClient *http.Client
	userAgent  string
}

// Config holds Airlock client configuration.
type Config struct {
	URL       string
	APIKey    string
	Insecure  bool
	UserAgent string
	Timeout   time.Duration
}

// APIError is returned for non-successful Airlock API calls. Response bodies are not included because they may contain environment data.
type APIError struct {
	StatusCode int
	Path       string
	AirlockErr string
}

func (e *APIError) Error() string {
	if e.AirlockErr != "" {
		return fmt.Sprintf("airlock: POST %s returned %d: %s", e.Path, e.StatusCode, e.AirlockErr)
	}
	return fmt.Sprintf("airlock: POST %s returned %d", e.Path, e.StatusCode)
}

// New returns a configured API client.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("airlock: url is required")
	}
	if cfg.APIKey == "" {
		return nil, errors.New("airlock: api_key is required")
	}
	u, err := url.Parse(strings.TrimRight(cfg.URL, "/"))
	if err != nil {
		return nil, fmt.Errorf("airlock: invalid url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("airlock: url must include scheme and host, got %q", cfg.URL)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicit provider opt-in
	}
	ua := cfg.UserAgent
	if ua == "" {
		ua = "terraform-provider-airlock"
	}
	return &Client{baseURL: u, apiKey: cfg.APIKey, httpClient: &http.Client{Timeout: timeout, Transport: transport}, userAgent: ua}, nil
}

type envelope struct {
	Error    string          `json:"error"`
	Response json.RawMessage `json:"response"`
}

// Post sends Airlock's POST-style API request. Parameters are encoded as query parameters unless body is non-nil.
func (c *Client) Post(ctx context.Context, path string, params url.Values, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("airlock: marshal request for %s: %w", path, err)
		}
		reqBody = bytes.NewReader(b)
	}
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(path, "/")
	if len(params) > 0 {
		u.RawQuery = params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), reqBody)
	if err != nil {
		return fmt.Errorf("airlock: build request for %s: %w", path, err)
	}
	req.Header.Set("X-ApiKey", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("airlock: POST %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("airlock: read response for %s: %w", path, err)
	}
	var env envelope
	if len(respBody) > 0 {
		_ = json.Unmarshal(respBody, &env)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Path: path, AirlockErr: env.Error}
	}
	if env.Error != "" && !strings.EqualFold(env.Error, "success") {
		return &APIError{StatusCode: resp.StatusCode, Path: path, AirlockErr: env.Error}
	}
	if out == nil || len(env.Response) == 0 || string(env.Response) == "null" {
		return nil
	}
	if err := json.Unmarshal(env.Response, out); err != nil {
		return fmt.Errorf("airlock: decode response for %s: %w", path, err)
	}
	return nil
}

// PostRaw sends an Airlock POST request and returns the raw response body. Use this for documented non-JSON endpoints such as XML exports.
func (c *Client) PostRaw(ctx context.Context, path string, params url.Values, body any) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("airlock: marshal request for %s: %w", path, err)
		}
		reqBody = bytes.NewReader(b)
	}
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(path, "/")
	if len(params) > 0 {
		u.RawQuery = params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), reqBody)
	if err != nil {
		return nil, fmt.Errorf("airlock: build request for %s: %w", path, err)
	}
	req.Header.Set("X-ApiKey", c.apiKey)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("airlock: POST %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("airlock: read response for %s: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{StatusCode: resp.StatusCode, Path: path}
	}
	return respBody, nil
}

func Values(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			v.Set(kv[i], kv[i+1])
		}
	}
	return v
}

func BoolInt(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func IntString(v int64) string { return strconv.FormatInt(v, 10) }

// Named is the common list shape used by provider resources and data sources.
type Named struct {
	ID    string            `json:"id"`
	Name  string            `json:"name"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

func sortNamed(items []Named) []Named {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name == items[j].Name {
			return items[i].ID < items[j].ID
		}
		return items[i].Name < items[j].Name
	})
	return items
}

func FindByID(items []Named, id string) (Named, bool) {
	for _, item := range items {
		if item.ID == id {
			return item, true
		}
	}
	return Named{}, false
}

func FindByName(items []Named, name string) (Named, bool) {
	for _, item := range items {
		if item.Name == name {
			return item, true
		}
	}
	return Named{}, false
}
