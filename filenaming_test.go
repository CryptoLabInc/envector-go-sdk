package envector_test

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestFileNamingConvention enforces: .go files may not contain an underscore
// in the base name, with two exceptions:
//   - _test.go suffix (required by the Go test tooling)
//   - generated code: *.pb.go
func TestFileNamingConvention(t *testing.T) {
	var offenders []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "third_party", "proto":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		if strings.HasSuffix(name, ".pb.go") {
			return nil
		}
		stem := strings.TrimSuffix(name, ".go")
		stem = strings.TrimSuffix(stem, "_test")
		if strings.Contains(stem, "_") {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("files with underscores in base name (not allowed except _test.go / *.pb.go):\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
