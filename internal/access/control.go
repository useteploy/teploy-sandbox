package access

// Control is what the control API (internal/server) shows and changes of
// the access listener: its configuration and its stream counts.
type Control struct {
	Store    *Store
	Registry *Registry
	// Listener describes where the access listener listens.
	Listener string
}

// ConfigView is GET /v1/access/config: never a key itself, only its kid.
type ConfigView struct {
	Audience      string   `json:"audience"`
	Kids          []string `json:"kids"`
	EdgeDenylist  []string `json:"edgeDenylist"`
	Listener      string   `json:"listener"`
	Enabled       bool     `json:"enabled"`
	ManagedByFile bool     `json:"managedByFile"`

	// ListenerDown: the listener died and nothing is served until a restart.
	ListenerDown bool `json:"listenerDown,omitempty"`
}

// View is the configuration as GET /v1/access/config answers it.
func (c *Control) View() ConfigView {
	config := c.Store.Config()
	kids := make([]string, 0, len(config.IssuerKeys))
	for _, key := range config.IssuerKeys {
		kids = append(kids, key.Kid)
	}
	if c.Registry.ListenerDown() {
		return ConfigView{
			Audience: config.Audience, Kids: kids, EdgeDenylist: config.EdgeDenylist,
			Listener: c.Listener, Enabled: false, ListenerDown: true, ManagedByFile: c.Store.ManagedByFile(),
		}
	}
	return ConfigView{
		Audience: config.Audience, Kids: kids, EdgeDenylist: config.EdgeDenylist,
		Listener: c.Listener, Enabled: true, ManagedByFile: c.Store.ManagedByFile(),
	}
}

// Set replaces the configuration (PUT /v1/access/config).
func (c *Control) Set(config Config) error { return c.Store.Set(config) }

// Streams and StreamsMax are the daemon's open access streams and its cap.
func (c *Control) Streams() int    { return c.Registry.Count() }
func (c *Control) StreamsMax() int { return c.Registry.Limits().Total }
