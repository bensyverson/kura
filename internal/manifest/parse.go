package manifest

import (
	"encoding/json"
	"fmt"
	"os"
)

// Parse decodes a manifest from JSON and validates it. A manifest that
// decodes but does not validate is not returned — callers always get
// either a usable Manifest or an error explaining what is wrong.
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: invalid JSON: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// ParseFile reads and parses a manifest from the file at path.
func ParseFile(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifest: read %s: %w", path, err)
	}
	return Parse(data)
}
