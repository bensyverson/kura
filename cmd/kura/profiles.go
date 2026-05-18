package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/bensyverson/kura/internal/clio"
)

// profileClient is one client entry in the profiles config: an endpoint
// plus future per-client output preferences. It deliberately has no
// token field — credentials never live on disk in profiles. `kura
// login` caches a short-lived token elsewhere.
type profileClient struct {
	Endpoint string `json:"endpoint"`
}

// profiles is the deserialized ~/.config/kura/config.json. A consultant
// laptop addresses N client servers; named profiles are how the agent
// switches between them without juggling URLs.
type profiles struct {
	Version string                   `json:"version"`
	Clients map[string]profileClient `json:"clients"`
}

// rawProfilesForValidation mirrors profiles but with map[string]any
// values, so the loader can reject extra fields the typed struct would
// silently drop — chiefly any "token" field, which would be a
// credential on disk.
type rawProfilesForValidation struct {
	Version string                    `json:"version"`
	Clients map[string]map[string]any `json:"clients"`
}

// loadProfilesFrom reads the config file at path. A missing file is
// not an error — profiles are optional — but a malformed file or one
// with credential-shaped fields is.
func loadProfilesFrom(path string) (*profiles, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &profiles{Version: "1", Clients: map[string]profileClient{}}, nil
		}
		return nil, clio.InternalError("profiles", "reading %s: %w", path, err)
	}
	var raw rawProfilesForValidation
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, clio.UsageError("profiles", "parsing %s: %w", path, err)
	}
	for name, fields := range raw.Clients {
		for k := range fields {
			switch k {
			case "endpoint":
				// allowed
			default:
				// "token" / "secret" / anything else is rejected loudly:
				// credentials never live in profiles.
				return nil, clio.UsageError("profiles", "client %q has a %q field — credentials never live in profiles (tokens come from `kura login`)", name, k)
			}
		}
	}
	var p profiles
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, clio.UsageError("profiles", "parsing %s: %w", path, err)
	}
	if p.Clients == nil {
		p.Clients = map[string]profileClient{}
	}
	return &p, nil
}

// defaultProfilesPath returns the conventional config file location.
func defaultProfilesPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", clio.InternalError("profiles", "locating config directory: %w", err)
	}
	return filepath.Join(base, "kura", "config.json"), nil
}

// endpoint returns the endpoint URL registered for name. An unknown
// name is an error that enumerates the known names — the agent sees
// the valid set without grepping the config.
func (p *profiles) endpoint(name string) (string, error) {
	if c, ok := p.Clients[name]; ok {
		return c.Endpoint, nil
	}
	known := make([]string, 0, len(p.Clients))
	for n := range p.Clients {
		known = append(known, n)
	}
	sort.Strings(known)
	if len(known) == 0 {
		return "", clio.NotFoundError("profiles", "no client named %q (no profiles are configured — add one under ~/.config/kura/config.json or pass --server directly)", name)
	}
	return "", clio.NotFoundError("profiles", "no client named %q (known: %v)", name, known)
}
