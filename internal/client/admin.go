package client

import (
	"context"
	"encoding/json"
)

type Metarule struct {
	ID       string          `json:"metaruleid"`
	Name     string          `json:"name"`
	OS       string          `json:"os"`
	Criteria json.RawMessage `json:"criteria,omitempty"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

type HashQueryResult struct {
	Hash string `json:"hash"`
	Data struct {
		Applications []application `json:"applications"`
		Baselines    []baseline    `json:"baselines"`
		Blocklists   []blocklist   `json:"blocklists"`
	} `json:"data"`
}

func (c *Client) GetGroupPolicyRaw(ctx context.Context, groupID string) (map[string]any, error) {
	out := map[string]any{}
	err := c.Post(ctx, "/v1/group/policies", Values("groupid", groupID), nil, &out)
	return out, err
}

func (c *Client) UpdateGroupSettings(ctx context.Context, settings map[string]any) error {
	return c.Post(ctx, "/v1/group/settings/updateall", nil, settings, nil)
}

func (c *Client) ListApplicationMetarules(ctx context.Context, applicationID string, includeCriteria bool) ([]Metarule, error) {
	var out struct {
		Metarules []Metarule `json:"metarules"`
	}
	err := c.Post(ctx, "/v1/application/metarule", Values("applicationid", applicationID, "include_criteria", BoolInt(includeCriteria)), nil, &out)
	return out.Metarules, err
}

func (c *Client) CreateApplicationMetarule(ctx context.Context, body map[string]any) (string, error) {
	var out struct {
		MetaruleID string `json:"metaruleid"`
	}
	if err := c.Post(ctx, "/v1/application/metarule/new", nil, body, &out); err != nil {
		return "", err
	}
	return out.MetaruleID, nil
}

func (c *Client) UpdateApplicationMetaruleName(ctx context.Context, id, name string) error {
	return c.Post(ctx, "/v1/application/metarule/update", nil, map[string]any{"metaruleid": id, "name": name}, nil)
}

func (c *Client) DeleteApplicationMetarule(ctx context.Context, id string) error {
	return c.Post(ctx, "/v1/application/metarule/delete", nil, map[string]any{"metaruleid": id}, nil)
}

func (c *Client) ListBlocklistMetarules(ctx context.Context, blocklistID string, includeCriteria bool) ([]Metarule, error) {
	var out struct {
		Metarules []Metarule `json:"metarules"`
	}
	err := c.Post(ctx, "/v1/blocklist/metarule", nil, map[string]any{"blocklistid": blocklistID, "include_criteria": includeCriteria}, &out)
	return out.Metarules, err
}

func (c *Client) CreateBlocklistMetarule(ctx context.Context, body map[string]any) (string, error) {
	var out struct {
		MetaruleID string `json:"metaruleid"`
	}
	if err := c.Post(ctx, "/v1/blocklist/metarule/new", nil, body, &out); err != nil {
		return "", err
	}
	return out.MetaruleID, nil
}

func (c *Client) UpdateBlocklistMetaruleName(ctx context.Context, id, name string) error {
	return c.Post(ctx, "/v1/blocklist/metarule/update", nil, map[string]any{"metaruleid": id, "name": name}, nil)
}

func (c *Client) DeleteBlocklistMetarule(ctx context.Context, id string) error {
	return c.Post(ctx, "/v1/blocklist/metarule/delete", nil, map[string]any{"metaruleid": id}, nil)
}

func (c *Client) QueryHashes(ctx context.Context, hashes []string) ([]HashQueryResult, error) {
	var out struct {
		Results []HashQueryResult `json:"results"`
	}
	err := c.Post(ctx, "/v1/hash/query", nil, map[string]any{"hashes": hashes}, &out)
	return out.Results, err
}

func (c *Client) AddRepositoryHashes(ctx context.Context, hashes []map[string]string) error {
	return c.Post(ctx, "/v1/hash/add", nil, map[string]any{"hashes": hashes}, nil)
}

func (c *Client) AddBlocklistHash(ctx context.Context, blocklistID string, hashes []string) error {
	return c.Post(ctx, "/v1/hash/blocklist/add", nil, map[string]any{"blocklistid": blocklistID, "hashes": hashes}, nil)
}

func (c *Client) RemoveBlocklistHash(ctx context.Context, blocklistID string, hashes []string) error {
	return c.Post(ctx, "/v1/hash/blocklist/remove", nil, map[string]any{"blocklistid": blocklistID, "hashes": hashes}, nil)
}

func (c *Client) ListCommunicationLists(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.Post(ctx, "/v1/commlist", nil, nil, &out)
	return out, err
}

func (c *Client) ListGroupAgentsRaw(ctx context.Context, groupID string) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.Post(ctx, "/v1/group/agents", Values("groupid", groupID), nil, &out)
	return out, err
}

func (c *Client) ListDomainGroups(ctx context.Context) ([]string, error) {
	var out struct {
		DomainGroups []string `json:"domaingroups"`
	}
	err := c.Post(ctx, "/v1/domaingroups", nil, nil, &out)
	return out.DomainGroups, err
}

func (c *Client) ListReferenceBaselines(ctx context.Context) ([]Named, error) {
	var out struct {
		ReferenceBaselines []struct {
			Name string `json:"name"`
		} `json:"reference_baselines"`
	}
	if err := c.Post(ctx, "/v1/baseline/reference", nil, nil, &out); err != nil {
		return nil, err
	}
	items := make([]Named, 0, len(out.ReferenceBaselines))
	for _, b := range out.ReferenceBaselines {
		items = append(items, Named{ID: b.Name, Name: b.Name})
	}
	return sortNamed(items), nil
}

func (c *Client) ImportReferenceBaseline(ctx context.Context, name string) error {
	return c.Post(ctx, "/v1/baseline/import_reference", Values("name", name), nil, nil)
}
