//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
	"local/panel/internal/geodata"
)

func countryCacheVerifySelection(ctx context.Context, root *os.Root, a geodata.CountryAuthority, codes []string) (geodata.CountrySelectionMetadata, error) {
	var empty geodata.CountrySelectionMetadata
	if ctx == nil || root == nil {
		return empty, errors.New("country cache joint verification context missing")
	}
	assets, err := a.Select(codes)
	if err != nil {
		return empty, err
	}
	files := make([]*os.File, 0, len(assets))
	defer func() {
		for _, file := range files {
			file.Close()
		}
	}()
	identities := make([]os.FileInfo, 0, len(assets))
	inputs := make([]io.Reader, 0, len(assets))
	for _, asset := range assets {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		name := asset.Code + ".cidr"
		named, err := root.Lstat(name)
		if err != nil || !moduleRecordInfo(named, false, false) || named.Size() != asset.Bytes {
			return empty, errors.New("country cache signed selection file identity invalid")
		}
		file, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return empty, err
		}
		files = append(files, file)
		opened, err := file.Stat()
		if err != nil || !geoStoreStableInfo(named, opened) {
			return empty, errors.New("country cache selected file changed during open")
		}
		identities = append(identities, opened)
		inputs = append(inputs, file)
	}
	metadata, err := geodata.VerifyCountrySelection(ctx, a, codes, inputs)
	if err != nil {
		return empty, err
	}
	for i, file := range files {
		opened, err := file.Stat()
		named, nerr := root.Lstat(assets[i].Code + ".cidr")
		if err != nil || nerr != nil || !moduleRecordInfo(opened, false, false) || !moduleRecordInfo(named, false, false) || !geoStoreStableInfo(identities[i], opened) || !geoStoreStableInfo(identities[i], named) {
			return empty, errors.New("country cache original selection changed during full independent joint verification")
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return metadata, nil
}
