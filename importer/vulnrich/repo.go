package vulnrich

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type CVEEntry struct {
	Content io.ReadCloser
	Name    string
}

func GetRepo(remote, path string) (*git.Repository, error) {
	repo, err := git.PlainOpen(path)
	if err == nil {
		return repo, nil
	}

	if !errors.Is(err, git.ErrRepositoryNotExists) {
		return nil, err
	}

	repo, err = git.PlainClone(path, true, &git.CloneOptions{
		URL:      remote,
		Progress: nil,
	})

	return repo, err
}

func UpdateRepo(repo *git.Repository) error {
	err := repo.Fetch(&git.FetchOptions{
		RefSpecs: []config.RefSpec{config.RefSpec("+refs/heads/*:refs/heads/*")},
	})

	if !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return err
	}
	return nil
}

func GetCVEFiles(repo *git.Repository) ([]CVEEntry, error) {
	cveEntries := []CVEEntry{}
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("could not read HEAD: %w", err)
	}

	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("could not read commit object: %w", err)
	}

	tree, err := repo.TreeObject(commit.TreeHash)
	if err != nil {
		return nil, fmt.Errorf("could not read tree object: %w", err)
	}

	seen := map[plumbing.Hash]bool{}
	walker := object.NewTreeWalker(tree, true, seen)
	defer walker.Close()

	var entry object.TreeEntry
	for name := ""; !errors.Is(err, io.EOF); name, entry, err = walker.Next() {
		if !entry.Mode.IsFile() {
			continue
		}
		if filepath.Ext(name) != ".json" {
			continue
		}

		blob, err := repo.BlobObject(entry.Hash)
		if err != nil {
			return nil, fmt.Errorf("could not read blob: %w", err)
		}

		reader, err := blob.Reader()
		if err != nil {
			return nil, fmt.Errorf("coult not create reader for blob: %w", err)
		}
		cveEntries = append(cveEntries, CVEEntry{Name: name, Content: reader})
	}

	return cveEntries, nil
}
