package idp

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// readScopedFile reads path via an os.Root anchored at the file's directory
// so a crafted path cannot traverse outside it (gosec G304/G703).
func readScopedFile(path string) ([]byte, error) {
	dir, name := filepath.Split(filepath.Clean(path))
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open directory %q: %w", dir, err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// saveJSONFile atomically writes data to path: a uniquely named temp file in
// the same directory (instead of a fixed <name>.tmp, so concurrent tool
// invocations cannot clobber each other's temp file), created exclusively
// (O_EXCL) with mode 0600, then renamed over the final path — so a crash
// mid-write can never corrupt the existing file. Used for the clients file,
// which holds client secrets and password hashes and therefore must stay
// private.
func saveJSONFile(path string, data []byte) error {
	dir, name := filepath.Split(filepath.Clean(path))
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open directory %q: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	suffix, err := randomToken()
	if err != nil {
		return fmt.Errorf("generate temp file name: %w", err)
	}
	tmpName := name + ".tmp-" + suffix
	tmp, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temp file in %q: %w", dir, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = root.Remove(tmpName)
		return fmt.Errorf("write file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = root.Remove(tmpName)
		return fmt.Errorf("close file: %w", err)
	}
	if err := os.Rename(filepath.Join(dir, tmpName), path); err != nil {
		_ = root.Remove(tmpName)
		return fmt.Errorf("persist file to %q: %w", path, err)
	}
	return nil
}
