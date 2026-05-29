package client

import "context"

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

type agent struct {
	AgentID  string `json:"agentid"`
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	Status   any    `json:"status"`
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
	if item, ok := FindByName(items, name); ok {
		return item.ID, nil
	}
	return "", nil
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
	for _, item := range items {
		if item.Name == name && item.Attrs["parent_category_id"] == parentID {
			return item.ID, nil
		}
	}
	return "", nil
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
	if item, ok := FindByName(items, name); ok {
		return item.ID, nil
	}
	return "", nil
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
	if item, ok := FindByName(items, name); ok {
		return item.ID, nil
	}
	return "", nil
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
	if err := c.Post(ctx, "/v1/group/new", Values("name", name, "parent", parent, "hidden", BoolInt(hidden)), nil, nil); err != nil {
		return "", err
	}
	items, err := c.ListGroups(ctx)
	if err != nil {
		return "", err
	}
	if item, ok := FindByName(items, name); ok {
		return item.ID, nil
	}
	return "", nil
}
func (c *Client) DeleteGroup(ctx context.Context, id string) error {
	return c.Post(ctx, "/v1/group/remove", Values("groupid", id), nil, nil)
}

func (c *Client) ListAgents(ctx context.Context) ([]Named, error) {
	var out struct {
		Agents []agent `json:"agents"`
	}
	if err := c.Post(ctx, "/v1/agent/find", nil, nil, &out); err != nil {
		return nil, err
	}
	items := make([]Named, 0, len(out.Agents))
	for _, a := range out.Agents {
		items = append(items, Named{ID: a.AgentID, Name: a.Hostname, Attrs: map[string]string{"username": a.Username}})
	}
	return sortNamed(items), nil
}
