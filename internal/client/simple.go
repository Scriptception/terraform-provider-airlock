package client

import (
	"context"
	"fmt"
	"net/url"
)

type application struct {
	ApplicationID string `json:"applicationid"`
	Name          string `json:"name"`
	Version       string `json:"version"`
}

type category struct {
	CategoryID    string     `json:"categoryid"`
	Name          string     `json:"name"`
	Subcategories []category `json:"subcategories"`
}

type baseline struct {
	BaselineID string `json:"baselineid"`
	Name       string `json:"name"`
}

type blocklist struct {
	BlocklistID string `json:"blocklistid"`
	Name        string `json:"name"`
}

type group struct {
	GroupID string `json:"groupid"`
	Name    string `json:"name"`
	Parent  string `json:"parent"`
	Hidden  int    `json:"hidden"`
}

type Agent struct {
	AgentID       string `json:"agentid"`
	ClientVersion string `json:"clientversion"`
	Domain        string `json:"domain"`
	FreeSpace     string `json:"freespace"`
	GroupID       string `json:"groupid"`
	Hostname      string `json:"hostname"`
	IP            string `json:"ip"`
	LocalIP       string `json:"localip"`
	LastCheckin   string `json:"lastcheckin"`
	OS            string `json:"os"`
	PolicyVersion string `json:"policyversion"`
	Status        any    `json:"status"`
	Username      string `json:"username"`
}

func (c *Client) ListApplications(ctx context.Context) ([]Named, error) {
	var out struct {
		Applications []application `json:"applications"`
	}
	if err := c.Post(ctx, "/v1/application", nil, nil, &out); err != nil {
		return nil, err
	}
	items := make([]Named, 0, len(out.Applications))
	for _, a := range out.Applications {
		items = append(items, Named{ID: a.ApplicationID, Name: a.Name, Attrs: map[string]string{"version": a.Version}})
	}
	return sortNamed(items), nil
}

func (c *Client) CreateApplication(ctx context.Context, name, version, categoryID string) (string, error) {
	before, err := c.ListApplications(ctx)
	if err != nil {
		return "", err
	}
	var out struct {
		ApplicationID string `json:"applicationid"`
	}
	if err := c.Post(ctx, "/v1/application/new", Values("name", name, "version", version, "categoryid", categoryID), nil, &out); err != nil {
		return "", err
	}
	if out.ApplicationID != "" {
		return out.ApplicationID, nil
	}
	items, err := c.ListApplications(ctx)
	if err != nil {
		return "", err
	}
	return createdNamedID(before, items, name, map[string]string{"version": version})
}
func (c *Client) DeleteApplication(ctx context.Context, id string) error {
	return c.Post(ctx, "/v1/application/delete", Values("applicationid", id), nil, nil)
}

func (c *Client) ListApplicationCategories(ctx context.Context) ([]Named, error) {
	var out struct {
		Categories []category `json:"categories"`
	}
	if err := c.Post(ctx, "/v1/application/categories", nil, nil, &out); err != nil {
		return nil, err
	}
	var items []Named
	var walk func(category, string)
	walk = func(cat category, parent string) {
		items = append(items, Named{ID: cat.CategoryID, Name: cat.Name, Attrs: map[string]string{"parent_category_id": parent}})
		for _, sub := range cat.Subcategories {
			walk(sub, cat.CategoryID)
		}
	}
	for _, cat := range out.Categories {
		walk(cat, "")
	}
	return sortNamed(items), nil
}
func (c *Client) CreateApplicationCategory(ctx context.Context, name, parentID string) (string, error) {
	before, err := c.ListApplicationCategories(ctx)
	if err != nil {
		return "", err
	}
	var out struct {
		SubcategoryID string `json:"subcategoryid"`
	}
	if err := c.Post(ctx, "/v1/application/categories/new", Values("name", name, "categoryid", parentID), nil, &out); err != nil {
		return "", err
	}
	if out.SubcategoryID != "" {
		return out.SubcategoryID, nil
	}
	items, err := c.ListApplicationCategories(ctx)
	if err != nil {
		return "", err
	}
	return createdNamedID(before, items, name, map[string]string{"parent_category_id": parentID})
}
func (c *Client) DeleteApplicationCategory(ctx context.Context, id string) error {
	return c.Post(ctx, "/v1/application/categories/delete", Values("categoryid", id), nil, nil)
}

func (c *Client) ListBaselines(ctx context.Context) ([]Named, error) {
	var out struct {
		Baselines []baseline `json:"baselines"`
	}
	if err := c.Post(ctx, "/v1/baseline", nil, nil, &out); err != nil {
		return nil, err
	}
	items := make([]Named, 0, len(out.Baselines))
	for _, b := range out.Baselines {
		items = append(items, Named{ID: b.BaselineID, Name: b.Name})
	}
	return sortNamed(items), nil
}
func (c *Client) CreateBaseline(ctx context.Context, name string) (string, error) {
	before, err := c.ListBaselines(ctx)
	if err != nil {
		return "", err
	}
	var out struct {
		BaselineID string `json:"baselineid"`
	}
	if err := c.Post(ctx, "/v1/baseline/new", Values("name", name), nil, &out); err != nil {
		return "", err
	}
	if out.BaselineID != "" {
		return out.BaselineID, nil
	}
	items, err := c.ListBaselines(ctx)
	if err != nil {
		return "", err
	}
	return createdNamedID(before, items, name, nil)
}
func (c *Client) DeleteBaseline(ctx context.Context, id string) error {
	return c.Post(ctx, "/v1/baseline/delete", Values("baselineid", id), nil, nil)
}

func (c *Client) ListBlocklists(ctx context.Context) ([]Named, error) {
	var out struct {
		Blocklists []blocklist `json:"blocklists"`
	}
	if err := c.Post(ctx, "/v1/blocklist", nil, nil, &out); err != nil {
		return nil, err
	}
	items := make([]Named, 0, len(out.Blocklists))
	for _, b := range out.Blocklists {
		items = append(items, Named{ID: b.BlocklistID, Name: b.Name})
	}
	return sortNamed(items), nil
}
func (c *Client) CreateBlocklist(ctx context.Context, name string) (string, error) {
	before, err := c.ListBlocklists(ctx)
	if err != nil {
		return "", err
	}
	var out struct {
		BlocklistID string `json:"blocklistid"`
	}
	if err := c.Post(ctx, "/v1/blocklist/new", Values("name", name), nil, &out); err != nil {
		return "", err
	}
	if out.BlocklistID != "" {
		return out.BlocklistID, nil
	}
	items, err := c.ListBlocklists(ctx)
	if err != nil {
		return "", err
	}
	return createdNamedID(before, items, name, nil)
}
func (c *Client) DeleteBlocklist(ctx context.Context, id string) error {
	return c.Post(ctx, "/v1/blocklist/delete", Values("blocklistid", id), nil, nil)
}

func (c *Client) ListGroups(ctx context.Context) ([]Named, error) {
	var out struct {
		Groups []group `json:"groups"`
	}
	if err := c.Post(ctx, "/v1/group", nil, nil, &out); err != nil {
		return nil, err
	}
	items := make([]Named, 0, len(out.Groups))
	for _, g := range out.Groups {
		items = append(items, Named{ID: g.GroupID, Name: g.Name, Attrs: map[string]string{"parent": g.Parent, "hidden": IntString(int64(g.Hidden))}})
	}
	return sortNamed(items), nil
}
func (c *Client) CreateGroup(ctx context.Context, name, parent string, hidden bool) (string, error) {
	before, err := c.ListGroups(ctx)
	if err != nil {
		return "", err
	}
	if err := c.Post(ctx, "/v1/group/new", Values("name", name, "parent", parent, "hidden", BoolInt(hidden)), nil, nil); err != nil {
		return "", err
	}
	items, err := c.ListGroups(ctx)
	if err != nil {
		return "", err
	}
	return createdNamedID(before, items, name, map[string]string{"parent": parent, "hidden": BoolInt(hidden)})
}
func (c *Client) DeleteGroup(ctx context.Context, id string) error {
	return c.Post(ctx, "/v1/group/remove", Values("groupid", id), nil, nil)
}

func (c *Client) ListAgents(ctx context.Context) ([]Named, error) {
	agents, err := c.FindAgents(ctx, nil)
	if err != nil {
		return nil, err
	}
	items := make([]Named, 0, len(agents))
	for _, a := range agents {
		items = append(items, a.Named())
	}
	return sortNamed(items), nil
}

func (c *Client) FindAgents(ctx context.Context, params url.Values) ([]Agent, error) {
	var out struct {
		Agents []Agent `json:"agents"`
	}
	if err := c.Post(ctx, "/v1/agent/find", params, nil, &out); err != nil {
		return nil, err
	}
	return out.Agents, nil
}

func (c *Client) GetAgent(ctx context.Context, agentID string) (Agent, bool, error) {
	agents, err := c.FindAgents(ctx, Values("agentid", agentID))
	if err != nil {
		return Agent{}, false, err
	}
	for _, agent := range agents {
		if agent.AgentID == agentID {
			return agent, true, nil
		}
	}
	return Agent{}, false, nil
}

func (a Agent) Named() Named {
	return Named{ID: a.AgentID, Name: a.Hostname, Attrs: map[string]string{
		"clientversion": a.ClientVersion,
		"domain":        a.Domain,
		"groupid":       a.GroupID,
		"ip":            a.IP,
		"localip":       a.LocalIP,
		"lastcheckin":   a.LastCheckin,
		"os":            a.OS,
		"policyversion": a.PolicyVersion,
		"status":        fmt.Sprint(a.Status),
		"username":      a.Username,
	}}
}

func createdNamedID(before, after []Named, name string, attrs map[string]string) (string, error) {
	beforeIDs := make(map[string]struct{}, len(before))
	for _, item := range before {
		beforeIDs[item.ID] = struct{}{}
	}
	var matches []Named
	for _, item := range after {
		if _, existed := beforeIDs[item.ID]; existed {
			continue
		}
		if item.Name != name {
			continue
		}
		if !namedAttrsMatch(item, attrs) {
			continue
		}
		matches = append(matches, item)
	}
	switch len(matches) {
	case 0:
		return "", nil
	case 1:
		return matches[0].ID, nil
	default:
		return "", fmt.Errorf("airlock: create returned ambiguous results for %q", name)
	}
}

func namedAttrsMatch(item Named, attrs map[string]string) bool {
	for key, want := range attrs {
		if want == "" {
			continue
		}
		if item.Attrs[key] != want {
			return false
		}
	}
	return true
}
