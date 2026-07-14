package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ignore "github.com/crackcomm/go-gitignore"
)

const (
	addGitignoreName  = ".gitignore"
	addMaltignoreName = ".maltignore"
)

type addIgnoreOptions struct {
	NoGitignore  bool
	NoMaltignore bool
	IgnoreFiles  []string
}

type addIgnoreRuleSet struct {
	baseRel string
	matcher *ignore.GitIgnore
	negated bool
}

type addIgnoreFilter struct {
	root         string
	rules        []addIgnoreRuleSet
	loadedByDir  map[string]struct{}
	noGitignore  bool
	noMaltignore bool
}

func newAddIgnoreFilter(root string, opts addIgnoreOptions) (*addIgnoreFilter, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve ignore root %q: %w", root, err)
	}
	filter := &addIgnoreFilter{
		root:         filepath.Clean(absRoot),
		loadedByDir:  make(map[string]struct{}),
		noGitignore:  opts.NoGitignore,
		noMaltignore: opts.NoMaltignore,
	}
	for _, raw := range opts.IgnoreFiles {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if err := filter.loadRuleFile("", raw, false); err != nil {
			return nil, err
		}
	}
	return filter, nil
}

func (f *addIgnoreFilter) LoadDirectoryRules(localDir string) error {
	return f.loadDirectoryRules(localDir)
}

func (f *addIgnoreFilter) Ignored(localPath string, isDir bool) (bool, error) {
	return f.ignored(localPath, isDir)
}

func (f *addIgnoreFilter) loadDirectoryRules(localDir string) error {
	absDir, err := filepath.Abs(localDir)
	if err != nil {
		return fmt.Errorf("resolve ignore directory %q: %w", localDir, err)
	}
	absDir = filepath.Clean(absDir)
	if _, ok := f.loadedByDir[absDir]; ok {
		return nil
	}
	f.loadedByDir[absDir] = struct{}{}

	baseRel, err := f.relativePath(absDir)
	if err != nil {
		return err
	}
	if !f.noGitignore {
		if err := f.loadRuleFile(baseRel, filepath.Join(absDir, addGitignoreName), true); err != nil {
			return err
		}
	}
	if !f.noMaltignore {
		if err := f.loadRuleFile(baseRel, filepath.Join(absDir, addMaltignoreName), true); err != nil {
			return err
		}
	}
	return nil
}

func (f *addIgnoreFilter) loadRuleFile(baseRel, name string, optional bool) error {
	data, err := os.ReadFile(name)
	if err != nil {
		if optional && os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read ignore file %q: %w", name, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		negated := strings.HasPrefix(line, "!") && !strings.HasPrefix(line, `\!`)
		compileLine := line
		if negated {
			compileLine = strings.TrimPrefix(line, "!")
		}
		matcher, err := ignore.CompileIgnoreLines(compileLine)
		if err != nil {
			return fmt.Errorf("parse ignore file %q: %w", name, err)
		}
		f.rules = append(f.rules, addIgnoreRuleSet{
			baseRel: baseRel,
			matcher: matcher,
			negated: negated,
		})
	}
	return nil
}

func (f *addIgnoreFilter) ignored(localPath string, isDir bool) (bool, error) {
	rel, err := f.relativePath(localPath)
	if err != nil {
		return false, err
	}
	if rel == "" {
		return false, nil
	}
	for _, part := range strings.Split(rel, "/") {
		if part == ".git" {
			return true, nil
		}
	}
	if strings.HasPrefix(rel, ".git/") {
		return true, nil
	}

	ignored := false
	for _, ruleSet := range f.rules {
		ruleRel := rel
		if ruleSet.baseRel != "" {
			if rel == ruleSet.baseRel {
				ruleRel = ""
			} else if strings.HasPrefix(rel, ruleSet.baseRel+"/") {
				ruleRel = strings.TrimPrefix(rel, ruleSet.baseRel+"/")
			} else {
				continue
			}
		}
		if ruleRel == "" {
			continue
		}
		if isDir {
			ruleRel += "/"
		}
		if ruleSet.matcher.MatchesPath(ruleRel) {
			ignored = !ruleSet.negated
		}
	}
	return ignored, nil
}

func (f *addIgnoreFilter) relativePath(localPath string) (string, error) {
	absPath, err := filepath.Abs(localPath)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", localPath, err)
	}
	rel, err := filepath.Rel(f.root, filepath.Clean(absPath))
	if err != nil {
		return "", fmt.Errorf("compute ignore relative path %q: %w", localPath, err)
	}
	if rel == "." {
		return "", nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside ignore root %q", localPath, f.root)
	}
	return filepath.ToSlash(rel), nil
}
