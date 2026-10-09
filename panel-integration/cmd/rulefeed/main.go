// rulefeed is an offline release-builder, not a panel privilege or network
// endpoint. Preliminary outputs stay in a new private directory and cannot
// install themselves. Production distribution still requires native acceptance
// and the existing reviewed Ed25519 signing/publication workflow.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"local/panel/internal/rulefeed"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

func run(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("rulefeed", flag.ContinueOnError)
	archive := flags.String("archive", "", "reviewed local ET Open gzip archive; never downloaded by this tool")
	digest := flags.String("sha256", "", "independently acquired archive SHA-256; not a publisher signature")
	categories := flags.String("categories", "", "explicit comma-separated categories; no default enable-all")
	variables := flags.String("variables", "HOME_NET,EXTERNAL_NET,HTTP_PORTS,SHELLCODE_PORTS,SSH_PORTS", "names actually supplied by closed native YAML")
	budget := flags.Int("max-rules", 2048, "explicit enabled-rule budget, at most 8192")
	parent := flags.String("output-parent", "", "existing private parent for a fresh private artifact directory")
	list := flags.Bool("list", false, "list validated inventory categories without writing artifacts")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *archive == "" || *digest == "" {
		return errors.New("archive and exact digest are required; positional arguments are not accepted")
	}
	info, err := os.Lstat(*archive)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("rule source must be an existing ordinary local file")
	}
	input, err := os.Open(*archive)
	if err != nil {
		return err
	}
	defer input.Close()
	pinned, err := input.Stat()
	if err != nil || !os.SameFile(info, pinned) {
		return errors.New("rule source identity changed during open")
	}
	source, err := rulefeed.ReadETOpen(ctx, input, *digest)
	if err != nil {
		return err
	}
	if *list {
		data, err := json.Marshal(source.Categories())
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(output, string(data))
		return err
	}
	if *parent == "" || *categories == "" {
		return errors.New("explicit category profile and existing output parent are required")
	}
	parentInfo, err := os.Lstat(*parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0022 != 0 {
		return errors.New("output parent must be an existing ordinary directory not writable by group or others")
	}
	bundle, err := rulefeed.Build(source, rulefeed.Profile{Categories: strings.Split(*categories, ","), Variables: strings.Split(*variables, ","), MaxEnabled: *budget})
	if err != nil {
		return err
	}
	if _, err := rulefeed.VerifyBundle(ctx, bundle.Files, fmt.Sprintf("%x", sha256.Sum256(bundle.Files["manifest.json"]))); err != nil {
		return fmt.Errorf("offline artifact self-verification failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	destination, err := os.MkdirTemp(*parent, "et-open-bsd-")
	if err != nil {
		return err
	}
	// Retain partial output for inspection. Nothing replaces an existing artifact
	// or panel file, and an incomplete output never prints a success result.
	failed := func(err error) error { return fmt.Errorf("private output retained at %s: %w", destination, err) }
	names := make([]string, 0, len(bundle.Files))
	for name := range bundle.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return failed(err)
		}
		file, err := os.OpenFile(filepath.Join(destination, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return failed(err)
		}
		written, writeErr := file.Write(bundle.Files[name])
		if writeErr == nil && written != len(bundle.Files[name]) {
			writeErr = io.ErrShortWrite
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil {
			return failed(writeErr)
		}
		if syncErr != nil {
			return failed(syncErr)
		}
		if closeErr != nil {
			return failed(closeErr)
		}
	}
	directory, err := os.Open(destination)
	if err != nil {
		return failed(err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return failed(syncErr)
	}
	if closeErr != nil {
		return failed(closeErr)
	}
	parentDirectory, err := os.Open(*parent)
	if err != nil {
		return failed(err)
	}
	syncErr = parentDirectory.Sync()
	closeErr = parentDirectory.Close()
	if syncErr != nil {
		return failed(syncErr)
	}
	if closeErr != nil {
		return failed(closeErr)
	}
	data, err := json.Marshal(struct {
		Directory string            `json:"private_directory"`
		Manifest  rulefeed.Manifest `json:"manifest"`
	}{destination, bundle.Manifest})
	if err != nil {
		return failed(err)
	}
	if err := ctx.Err(); err != nil {
		return failed(err)
	}
	_, err = fmt.Fprintln(output, string(data))
	if err != nil {
		return failed(err)
	}
	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "rulefeed:", err)
		os.Exit(1)
	}
}
