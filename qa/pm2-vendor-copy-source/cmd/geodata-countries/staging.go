package main

import (
	"errors"
	"os"
	"path/filepath"
)

type countryPublisherStage struct {
	parent, root     *os.Root
	parentName, leaf string
	parentInfo, info os.FileInfo
}

func openCountryPublisherStage(directory string) (*countryPublisherStage, error) {
	if directory == "" || filepath.Clean(directory) != directory {
		return nil, errors.New("offline staging path not explicit")
	}
	abs, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	parentName, leaf := filepath.Dir(abs), filepath.Base(abs)
	if leaf == "." || leaf == ".." || leaf == string(filepath.Separator) {
		return nil, errors.New("offline staging leaf not explicit")
	}
	parentInfo, err := os.Lstat(parentName)
	if err != nil || !parentInfo.IsDir() {
		return nil, errors.New("offline staging parent missing or linked")
	}
	parent, err := os.OpenRoot(parentName)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			parent.Close()
		}
	}()
	openedParent, err := parent.Stat(".")
	visibleParent, visibleErr := os.Lstat(parentName)
	if err != nil || visibleErr != nil || !visibleParent.IsDir() || !os.SameFile(parentInfo, openedParent) || !os.SameFile(openedParent, visibleParent) {
		return nil, errors.New("offline staging parent changed")
	}
	if _, err := parent.Lstat(leaf); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("offline staging directory already exists; never overwrite or replay")
	}
	if err := parent.Mkdir(leaf, 0700); err != nil {
		return nil, err
	}
	named, err := parent.Lstat(leaf)
	if err != nil || !named.IsDir() || named.Mode().Perm() != 0700 {
		return nil, errors.New("offline staging directory identity invalid")
	}
	root, err := parent.OpenRoot(leaf)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(named, opened) {
		root.Close()
		return nil, errors.New("offline staging directory changed during open")
	}
	stage := &countryPublisherStage{parent, root, parentName, leaf, parentInfo, opened}
	if err := stage.Current(); err != nil {
		root.Close()
		return nil, err
	}
	keep = true
	return stage, nil
}

func (s *countryPublisherStage) Current() error {
	parent, err := os.Lstat(s.parentName)
	openedParent, openErr := s.parent.Stat(".")
	named, nameErr := s.parent.Lstat(s.leaf)
	opened, dirErr := s.root.Stat(".")
	if err != nil || openErr != nil || nameErr != nil || dirErr != nil || !parent.IsDir() || !named.IsDir() || named.Mode().Perm() != 0700 || !os.SameFile(parent, s.parentInfo) || !os.SameFile(parent, openedParent) || !os.SameFile(named, s.info) || !os.SameFile(named, opened) {
		return errors.New("offline staging original parent or directory identity changed; no success publication")
	}
	return nil
}

func (s *countryPublisherStage) Close() { s.root.Close(); s.parent.Close() }
