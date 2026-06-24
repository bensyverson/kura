package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Two independent lineages, embedded separately. The main set lives at the
// package root and targets the kura database; the keystore set lives under
// keystore/ and targets the physically separate key-store instance (ADR
// 0002). Each is numbered from 1 on its own — they are never interleaved.
//
//go:embed *.sql
var mainFiles embed.FS

//go:embed keystore/*.sql
var keystoreFiles embed.FS

// Migration is one forward-only schema change: its sequence number, its
// human-readable name, and the SQL that applies it.
type Migration struct {
	Number int
	Name   string
	SQL    string
}

// All returns the main lineage — every migration at the package root,
// ordered by sequence number. See load for the contiguity guarantee.
func All() ([]Migration, error) {
	return load(mainFiles, ".")
}

// Keystore returns the key-store lineage from keystore/, ordered by sequence
// number. It is numbered independently of the main set and applied against
// the separate key-store DSN.
func Keystore() ([]Migration, error) {
	return load(keystoreFiles, "keystore")
}

// load reads the .sql files in dir of fsys into an ordered Migration slice.
// It errors if a filename is malformed or if the numbers are not a
// contiguous 1-based run — a gap or a duplicate means a migration was lost
// or misnamed, and applying a partial schema must fail loudly rather than
// silently.
func load(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}

	var ms []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		num, name, err := parseFilename(e.Name())
		if err != nil {
			return nil, err
		}
		sql, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		ms = append(ms, Migration{Number: num, Name: name, SQL: string(sql)})
	}

	sort.Slice(ms, func(i, j int) bool { return ms[i].Number < ms[j].Number })
	for i, m := range ms {
		if m.Number != i+1 {
			return nil, fmt.Errorf("migrations: non-contiguous numbering at position %d: found migration %d (%s)", i+1, m.Number, m.Name)
		}
	}
	return ms, nil
}

// parseFilename splits a migration filename of the form NNNN_name.sql into
// its sequence number and name.
func parseFilename(fn string) (int, string, error) {
	base := strings.TrimSuffix(fn, ".sql")
	prefix, name, found := strings.Cut(base, "_")
	if !found {
		return 0, "", fmt.Errorf("migrations: malformed filename %q: want NNNN_name.sql", fn)
	}
	num, err := strconv.Atoi(prefix)
	if err != nil {
		return 0, "", fmt.Errorf("migrations: malformed filename %q: %q is not a number", fn, prefix)
	}
	if num < 1 {
		return 0, "", fmt.Errorf("migrations: malformed filename %q: sequence number must be >= 1", fn)
	}
	if name == "" {
		return 0, "", fmt.Errorf("migrations: malformed filename %q: empty name", fn)
	}
	return num, name, nil
}
