package client

import (
	"context"
	"strings"
)

type Policy struct {
	GroupID      string
	Applications []Named
	Baselines    []Named
	Blocklists   []Named
	Paths        []Named
	Processes    []Named
	Publishers   []Named
}

type policyResponse struct {
	GroupID      string        `json:"groupid"`
	Applications []application `json:"applications"`
	Baselines    []baseline    `json:"baselines"`
	Blocklists   []blocklist   `json:"blocklists"`
	Paths        []nameComment `json:"paths"`
	PProcesses   []nameComment `json:"pprocesses"`
	GProcesses   []nameComment `json:"gprocesses"`
	Publishers   []nameComment `json:"publishers"`
}

type nameComment struct {
	Name    string `json:"name"`
	Comment string `json:"comment"`
}

func (c *Client) GetGroupPolicy(ctx context.Context, groupID string) (*Policy, error) {
	var out policyResponse
	if err := c.Post(ctx, "/v1/group/policies", Values("groupid", groupID), nil, &out); err != nil {
		return nil, err
	}
	p := &Policy{GroupID: out.GroupID}
	for _, a := range out.Applications {
		p.Applications = append(p.Applications, Named{ID: a.ApplicationID, Name: a.Name})
	}
	for _, b := range out.Baselines {
		p.Baselines = append(p.Baselines, Named{ID: b.BaselineID, Name: b.Name})
	}
	for _, b := range out.Blocklists {
		p.Blocklists = append(p.Blocklists, Named{ID: b.BlocklistID, Name: b.Name})
	}
	for _, v := range out.Paths {
		p.Paths = append(p.Paths, Named{ID: v.Name, Name: v.Name, Attrs: map[string]string{"comment": v.Comment}})
	}
	for _, v := range out.PProcesses {
		p.Processes = append(p.Processes, Named{ID: "pprocess:" + v.Name, Name: v.Name, Attrs: map[string]string{"type": "pprocess", "comment": v.Comment}})
	}
	for _, v := range out.GProcesses {
		p.Processes = append(p.Processes, Named{ID: "gprocess:" + v.Name, Name: v.Name, Attrs: map[string]string{"type": "gprocess", "comment": v.Comment}})
	}
	for _, v := range out.Publishers {
		p.Publishers = append(p.Publishers, Named{ID: v.Name, Name: v.Name, Attrs: map[string]string{"comment": v.Comment}})
	}
	return p, nil
}

func (c *Client) SetGroupApplication(ctx context.Context, groupID, applicationID string, approved bool) error {
	path := "/v1/group/application/deny"
	if approved {
		path = "/v1/group/application/approve"
	}
	return c.Post(ctx, path, Values("groupid", groupID, "applicationid", applicationID), nil, nil)
}
func (c *Client) SetGroupBaseline(ctx context.Context, groupID, baselineID string, approved bool) error {
	path := "/v1/group/baseline/deny"
	if approved {
		path = "/v1/group/baseline/approve"
	}
	return c.Post(ctx, path, Values("groupid", groupID, "baselineid", baselineID), nil, nil)
}
func (c *Client) SetGroupBlocklist(ctx context.Context, groupID, blocklistID string, approved bool, audit bool) error {
	path := "/v1/group/blocklist/deny"
	if approved {
		path = "/v1/group/blocklist/approve"
	}
	return c.Post(ctx, path, Values("groupid", groupID, "blocklistid", blocklistID, "audit", BoolInt(audit)), nil, nil)
}
func (c *Client) AddGroupPath(ctx context.Context, groupID, path, comment string) error {
	return c.Post(ctx, "/v1/group/path/add", nil, map[string]string{"groupid": groupID, "path": path, "comment": comment}, nil)
}
func (c *Client) RemoveGroupPath(ctx context.Context, groupID, path string) error {
	return c.Post(ctx, "/v1/group/path/remove", Values("groupid", groupID, "path", path), nil, nil)
}
func (c *Client) AddGroupProcess(ctx context.Context, groupID, process, typ, comment string) error {
	return c.Post(ctx, "/v1/group/process/add", nil, map[string]string{"groupid": groupID, "process": process, "type": typ, "comment": comment}, nil)
}
func (c *Client) RemoveGroupProcess(ctx context.Context, groupID, process, typ string) error {
	return c.Post(ctx, "/v1/group/process/remove", Values("groupid", groupID, "process", process, "type", typ), nil, nil)
}
func (c *Client) AddGroupPublisher(ctx context.Context, groupID, publisher, comment string) error {
	return c.Post(ctx, "/v1/group/publisher/add", nil, map[string]string{"groupid": groupID, "publisher": publisher, "comment": comment}, nil)
}
func (c *Client) RemoveGroupPublisher(ctx context.Context, groupID, publisher string) error {
	return c.Post(ctx, "/v1/group/publisher/remove", Values("groupid", groupID, "publisher", publisher), nil, nil)
}
func (c *Client) MoveAgent(ctx context.Context, agentID, groupID string) error {
	return c.Post(ctx, "/v1/agent/move", nil, map[string]any{"groupid": groupID, "agentid": []string{agentID}}, nil)
}
func (c *Client) AddApplicationHash(ctx context.Context, applicationID string, hashes []string) error {
	return c.Post(ctx, "/v1/hash/application/add", nil, map[string]any{"applicationid": applicationID, "hashes": hashes}, nil)
}
func (c *Client) RemoveApplicationHash(ctx context.Context, applicationID string, hashes []string) error {
	return c.Post(ctx, "/v1/hash/application/remove", Values("applicationid", applicationID, "hashes", strings.Join(hashes, ",")), nil, nil)
}
func (c *Client) AddBaselineHash(ctx context.Context, baselineID string, hashes []string) error {
	return c.Post(ctx, "/v1/hash/baseline/add", nil, map[string]any{"baselineid": baselineID, "hashes": hashes}, nil)
}
func (c *Client) RemoveBaselineHash(ctx context.Context, baselineID string, hashes []string) error {
	return c.Post(ctx, "/v1/hash/baseline/remove", nil, map[string]any{"baselineid": baselineID, "hashes": hashes}, nil)
}
