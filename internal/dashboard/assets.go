package dashboard

import (
	"embed"
	"fmt"
	"html/template"
)

// templatesFS holds the server-side HTML templates; staticFS holds the
// stylesheet and the progressive-enhancement script. Both are embedded
// so `kura dashboard` ships as one self-contained binary.
//
//go:embed templates
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// pageTemplates are the named page bodies rendered through the base
// layout. Each file defines a "content" block the layout slots in.
var pageTemplates = []string{"index", "users", "policy", "signin", "placeholder", "error"}

// parseTemplates builds one fully-resolved template set per page: the
// base layout cloned and combined with that page's "content" block.
// Cloning per page avoids the last-parsed-"content"-wins problem of a
// single shared set.
func parseTemplates() (map[string]*template.Template, error) {
	base, err := template.ParseFS(templatesFS, "templates/layout.html")
	if err != nil {
		return nil, fmt.Errorf("dashboard: parsing layout template: %w", err)
	}
	out := make(map[string]*template.Template, len(pageTemplates))
	for _, name := range pageTemplates {
		clone, err := base.Clone()
		if err != nil {
			return nil, fmt.Errorf("dashboard: cloning layout for %s: %w", name, err)
		}
		t, err := clone.ParseFS(templatesFS, "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("dashboard: parsing %s template: %w", name, err)
		}
		out[name] = t
	}
	return out, nil
}
