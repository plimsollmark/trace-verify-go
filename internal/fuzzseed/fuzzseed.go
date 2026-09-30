// Package fuzzseed collects the repository's JSON files as fuzz seeds: the vendored
// vectors under testdata and the worked examples, so every fuzz target starts from
// inputs the verifier is known to handle.
package fuzzseed

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// JSON returns the contents of every .json file under the given directories.
func JSON(tb testing.TB, dirs ...string) [][]byte {
	tb.Helper()
	var out [][]byte
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".json") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out = append(out, b)
			return nil
		})
		if err != nil {
			tb.Fatal(err)
		}
	}
	if len(out) == 0 {
		tb.Fatal("fuzzseed: no JSON files found")
	}
	return out
}
