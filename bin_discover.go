package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const binSearchMaxDepth = 2

func collectBinPaths(root string) []string {
	root = filepath.Clean(root)
	var out []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			depth := strings.Count(rel, string(os.PathSeparator)) + 1
			if depth >= binSearchMaxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".bin") == false {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out
}

func pickDefaultBinPath(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	plain := filterBinCandidates(paths, true)
	if len(plain) == 0 {
		plain = filterBinCandidates(paths, false)
	}
	if len(plain) == 0 {
		return paths[0]
	}
	for _, p := range plain {
		base := strings.ToUpper(filepath.Base(p))
		if strings.HasPrefix(base, "MEMORY_G3") || strings.HasPrefix(base, "MEMORY_") {
			return p
		}
	}
	return plain[0]
}

func filterBinCandidates(paths []string, skipDumps bool) []string {
	var out []string
	for _, p := range paths {
		if strings.Contains(strings.ToLower(p), ".patched.") {
			continue
		}
		if skipDumps && strings.HasPrefix(filepath.ToSlash(p), "DUMPS/") {
			continue
		}
		out = append(out, p)
	}
	return out
}

func findDefaultBinFile() string {
	return pickDefaultBinPath(collectBinPaths("."))
}
