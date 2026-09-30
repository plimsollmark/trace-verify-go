// Package policydir resolves policy_uri values through a directory holding a
// resolutions.json manifest (URI to relative path), the layout the TRACE suite's
// --policy-dir uses. The manifest is checked for form when it loads: an object of
// strings to relative paths with no parent traversal. Whether a mapped file exists is a
// resolve-time fact, so a missing bundle is an error from the resolver, not from Open.
package policydir

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Open returns a resolver for dir.
func Open(dir string) (func(uri string) ([]byte, error), error) {
	b, err := os.ReadFile(filepath.Join(dir, "resolutions.json"))
	if err != nil {
		return nil, err
	}
	var manifest map[string]string
	if err := json.Unmarshal(b, &manifest); err != nil {
		return nil, fmt.Errorf("resolutions.json: %w", err)
	}
	for u, p := range manifest {
		if filepath.IsAbs(p) || strings.Contains(filepath.ToSlash(p), "..") {
			return nil, fmt.Errorf("resolutions.json: %q maps to %q, outside the directory", u, p)
		}
	}
	return func(uri string) ([]byte, error) {
		p, ok := manifest[uri]
		if !ok {
			return nil, fmt.Errorf("no route for %s", uri)
		}
		return os.ReadFile(filepath.Join(dir, p))
	}, nil
}
