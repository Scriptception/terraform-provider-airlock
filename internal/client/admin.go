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

func (c *Client) SetGroupAuditMode(ctx context.Context, groupID string, auditMode int64) error {
	return c.Post(ctx, "/v1/group/settings/auditmode", Values("groupid", groupID, "auditmode", IntString(auditMode)), nil, nil)
}

func (c *Client) SetGroupNotificationsEnabled(ctx context.Context, groupID string, enabled int64) error {
	return c.Post(ctx, "/v1/group/settings/enable_notifications", Values("groupid", groupID, "enable_notifications", IntString(enabled)), nil, nil)
}

func (c *Client) SetGroupNotificationMessage(ctx context.Context, groupID, message string) error {
	params := Values("groupid", groupID)
	params.Set("notification_message", message)
	return c.Post(ctx, "/v1/group/settings/notification_message", params, nil, nil)
}

func (c *Client) SetGroupCommunicationList(ctx context.Context, groupID, communicationListID string) error {
	return c.Post(ctx, "/v1/group/settings/commlist", Values("groupid", groupID, "commlistid", communicationListID), nil, nil)
}

func (c *Client) SetGroupReflection(ctx context.Context, groupID string, reflection int64) error {
	return c.Post(ctx, "/v1/group/settings/reflection", Values("groupid", groupID, "reflection", IntString(reflection)), nil, nil)
}

func (c *Client) SetGroupPowerShellLockdown(ctx context.Context, groupID string, lockdown int64) error {
	return c.Post(ctx, "/v1/group/settings/pslockdown", Values("groupid", groupID, "pslockdown", IntString(lockdown)), nil, nil)
}

func (c *Client) SetGroupPollTime(ctx context.Context, groupID string, pollTime int64) error {
	return c.Post(ctx, "/v1/group/settings/polltime", Values("groupid", groupID, "polltime", IntString(pollTime)), nil, nil)
}

func (c *Client) SetGroupProxyEnabled(ctx context.Context, groupID string, enabled int64) error {
	return c.Post(ctx, "/v1/group/settings/proxy", Values("groupid", groupID, "proxy", IntString(enabled)), nil, nil)
}

func (c *Client) SetGroupProxySettings(ctx context.Context, groupID, server, port string, authentication int64, username, password *string) error {
	params := Values("groupid", groupID, "authentication", IntString(authentication))
	params.Set("server", server)
	params.Set("port", port)
	if username != nil {
		params.Set("username", *username)
	}
	if password != nil {
		params.Set("password", *password)
	}
	return c.Post(ctx, "/v1/group/settings/proxy/settings", params, nil, nil)
}

func (c *Client) SetGroupScriptControl(ctx context.Context, groupID string, scripts int64) error {
	return c.Post(ctx, "/v1/group/settings/script", Values("groupid", groupID, "scripts", IntString(scripts)), nil, nil)
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

func (c *Client) AddApplicationMetaruleCriterion(ctx context.Context, metaruleID, field, operation, value string) error {
	return c.addMetaruleCriterion(ctx, "/v1/application/metarule/criteria/add", metaruleID, field, operation, value)
}

func (c *Client) UpdateApplicationMetaruleCriterion(ctx context.Context, criterionID, field, operation, value string) error {
	return c.updateMetaruleCriterion(ctx, "/v1/application/metarule/criteria/update", criterionID, field, operation, value)
}

func (c *Client) DeleteApplicationMetaruleCriterion(ctx context.Context, criterionID string) error {
	return c.deleteMetaruleCriterion(ctx, "/v1/application/metarule/criteria/delete", criterionID)
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

func (c *Client) AddBlocklistMetaruleCriterion(ctx context.Context, metaruleID, field, operation, value string) error {
	return c.addMetaruleCriterion(ctx, "/v1/blocklist/metarule/criteria/add", metaruleID, field, operation, value)
}

func (c *Client) UpdateBlocklistMetaruleCriterion(ctx context.Context, criterionID, field, operation, value string) error {
	return c.updateMetaruleCriterion(ctx, "/v1/blocklist/metarule/criteria/update", criterionID, field, operation, value)
}

func (c *Client) DeleteBlocklistMetaruleCriterion(ctx context.Context, criterionID string) error {
	return c.deleteMetaruleCriterion(ctx, "/v1/blocklist/metarule/criteria/delete", criterionID)
}

func (c *Client) DeleteBlocklistMetarule(ctx context.Context, id string) error {
	return c.Post(ctx, "/v1/blocklist/metarule/delete", nil, map[string]any{"metaruleid": id}, nil)
}

func (c *Client) addMetaruleCriterion(ctx context.Context, path, metaruleID, field, operation, value string) error {
	return c.Post(ctx, path, nil, map[string]any{
		"metaruleid": metaruleID,
		"field":      field,
		"operation":  operation,
		"value":      value,
	}, nil)
}

func (c *Client) updateMetaruleCriterion(ctx context.Context, path, criterionID, field, operation, value string) error {
	return c.Post(ctx, path, nil, map[string]any{
		"criteriaid": criterionID,
		"field":      field,
		"operation":  operation,
		"value":      value,
	}, nil)
}

func (c *Client) deleteMetaruleCriterion(ctx context.Context, path, criterionID string) error {
	return c.Post(ctx, path, nil, map[string]any{"criteriaid": criterionID}, nil)
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

func (c *Client) ExportApplication(ctx context.Context, applicationID string) ([]byte, error) {
	return c.PostRaw(ctx, "/v1/application/export", Values("applicationid", applicationID), nil)
}

func (c *Client) ExportBaseline(ctx context.Context, baselineID string) ([]byte, error) {
	return c.PostRaw(ctx, "/v1/baseline/export", Values("baselineid", baselineID), nil)
}

func (c *Client) ExportBlocklist(ctx context.Context, blocklistID string) ([]byte, error) {
	return c.PostRaw(ctx, "/v1/blocklist/export", Values("blocklistid", blocklistID), nil)
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

func (c *Client) ListCloudGroups(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.Post(ctx, "/v1/cloudgroups", nil, nil, &out)
	return out, err
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
