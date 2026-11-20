// Package parserarchive preserves evidence before a live parser generation is
// replaced. These files confer no approval and are never loaded automatically.
package parserarchive

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"nexora.local/nli-v20/internal/canonicaljson"
)

const MaxGenerations = 10
const MaxBundleBytes = 16 << 20

func Read(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxBundleBytes {
		return nil, errors.New("parser evidence must be a regular file no larger than 16 MiB")
	}
	return os.ReadFile(path)
}

// BeforeReplace is called while the caller serializes generation changes.
// A failed archive prevents replacement; a missing initial generation is valid.
func BeforeReplace(assetDir string, verify func([]byte) (string, error)) error {
	data, err := Read(filepath.Join(assetDir, "bundle.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	hash, err := verify(data)
	if err != nil {
		return fmt.Errorf("prior generation is unverifiable: %w", err)
	}
	if !validHash(hash) {
		return errors.New("invalid prior generation identity")
	}
	canonical, err := canonicaljson.Normalize(data)
	if err != nil {
		return err
	}
	dir := filepath.Join(filepath.Dir(assetDir), "parser-assets-history")
	if info, err := os.Lstat(dir); err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("parser evidence directory is unsafe")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > MaxGenerations+1 {
		return errors.New("parser evidence directory exceeds bounded inventory; review it before replacing assets")
	}
	type saved struct {
		name  string
		order int64
	}
	items := []saved{}
	exists := false
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		expected := strings.TrimSuffix(name, ".json")
		if !validHash(expected) {
			return errors.New("unrecognized parser evidence filename")
		}
		path := filepath.Join(dir, name)
		previous, err := Read(path)
		if err != nil {
			return err
		}
		actual, err := verify(previous)
		if err != nil || actual != expected {
			return fmt.Errorf("parser evidence %s failed verification", name)
		}
		if err := os.Chmod(path, 0600); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		items = append(items, saved{name, info.ModTime().UnixNano()})
		exists = exists || actual == hash
	}
	if !exists {
		file, err := os.CreateTemp(dir, ".pending-")
		if err != nil {
			return err
		}
		temporary := file.Name()
		defer os.Remove(temporary)
		if err = file.Chmod(0600); err == nil {
			_, err = file.Write(canonical)
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err := os.Rename(temporary, filepath.Join(dir, hash+".json")); err != nil {
			return err
		}
	}
	// New evidence must reach stable storage before removal of any old archive.
	if err := syncDir(dir); err != nil {
		return err
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].order == items[j].order {
			return items[i].name < items[j].name
		}
		return items[i].order < items[j].order
	})
	total := len(items)
	if !exists {
		total++
	}
	for _, item := range items {
		if total <= MaxGenerations {
			break
		}
		if item.name == hash+".json" {
			continue
		}
		if err := os.Remove(filepath.Join(dir, item.name)); err != nil {
			return err
		}
		total--
	}
	return syncDir(dir)
}

func validHash(hash string) bool {
	decoded, err := hex.DecodeString(hash)
	return err == nil && len(decoded) == 32 && hash == strings.ToLower(hash)
}
func syncDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
