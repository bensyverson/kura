package backup

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// PGDumper is the production Dumper: it shells out to pg_dump and
// pg_restore. Dump uses the custom format (-Fc), which is compressed and
// is what pg_restore consumes; it captures the dump on stdout. Restore
// applies it with --clean --if-exists so a restore into a populated
// target replaces existing objects rather than failing on conflicts.
//
// The binaries are resolved from PATH by default; DumpPath/RestorePath
// override them for a deployment that pins a specific PostgreSQL version's
// client tools.
type PGDumper struct {
	DumpPath    string
	RestorePath string
}

// dumpBin returns the pg_dump binary path, defaulting to "pg_dump".
func (p PGDumper) dumpBin() string {
	if p.DumpPath != "" {
		return p.DumpPath
	}
	return "pg_dump"
}

// restoreBin returns the pg_restore binary path, defaulting to
// "pg_restore".
func (p PGDumper) restoreBin() string {
	if p.RestorePath != "" {
		return p.RestorePath
	}
	return "pg_restore"
}

// Dump runs `pg_dump -Fc <dsn>` and returns the dump bytes. The DSN is
// passed as the connection argument, so credentials never appear in a
// separate env file. stderr is folded into the error on failure.
func (p PGDumper) Dump(ctx context.Context, dsn string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, p.dumpBin(), "-Fc", "--no-owner", "--no-privileges", "--dbname", dsn)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("pg_dump: %w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// Restore runs `pg_restore --clean --if-exists -d <dsn>`, feeding the
// dump on stdin. --clean --if-exists makes the restore idempotent against
// a populated target. stderr is folded into the error on failure.
func (p PGDumper) Restore(ctx context.Context, dsn string, dump []byte) error {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, p.restoreBin(), "--clean", "--if-exists", "--no-owner", "--no-privileges", "--dbname", dsn)
	cmd.Stdin = bytes.NewReader(dump)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_restore: %w: %s", err, stderr.String())
	}
	return nil
}
