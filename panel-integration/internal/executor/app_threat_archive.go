package executor

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"
)

const threatIDSTarLimit = 192 << 20

// Never extract the package tree: select only two ordinary, root-owned files
// into memory after validating the complete bounded stream. Other entries,
// maintainer scripts, symlinks and directories cannot create any host paths.
func readThreatIDSPackageFiles(ctx context.Context, input io.Reader) (map[string][]byte, error) {
	wanted := map[string]int64{"usr/bin/suricata": 0755, "usr/share/doc/suricata/copyright": 0644}
	return readThreatIDSTarSelected(ctx, input, len(wanted), func(name string) (string, int64, bool) {
		mode, ok := wanted[name]
		return name, mode, ok
	})
}

func readThreatIDSLibraryFiles(ctx context.Context, input io.Reader, name, arch string) (map[string][]byte, error) {
	spec, ok := threatIDSEventLibraries[name]
	if !ok || arch != "amd64" && arch != "arm64" {
		return nil, errors.New("IDS 私有库选择未审核")
	}
	triplet := map[string]string{"amd64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}[arch]
	pattern := regexp.MustCompile(spec.FilePattern)
	return readThreatIDSTarSelected(ctx, input, 2, func(file string) (string, int64, bool) {
		if file == "usr/share/doc/"+name+"/copyright" {
			return "copyright", 0644, true
		}
		if (path.Dir(file) == "usr/lib/"+triplet || path.Dir(file) == "lib/"+triplet) && pattern.MatchString(path.Base(file)) {
			return path.Base(file), 0644, true
		}
		return "", 0, false
	})
}

func readThreatIDSTarSelected(ctx context.Context, input io.Reader, required int, selectFile func(string) (string, int64, bool)) (map[string][]byte, error) {
	bounded := &io.LimitedReader{R: input, N: threatIDSTarLimit + 1}
	archive := tar.NewReader(bounded)
	files := map[string][]byte{}
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("IDS 原生包流结构损坏")
		}
		count++
		name := strings.TrimPrefix(header.Name, "./")
		name = strings.TrimSuffix(name, "/")
		if count > 4096 || bounded.N <= 0 || header.Size < 0 || header.Size > threatIDSTarLimit || name != "" && (path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || !threatEVEText(name, 512, true)) {
			return nil, errors.New("IDS 原生包流路径、数量或展开预算异常")
		}
		key, mode, selected := selectFile(name)
		if !selected {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Uid != 0 || header.Gid != 0 || header.Mode != mode || header.Size < 1 || header.Size > 32<<20 || files[key] != nil {
			return nil, errors.New("IDS 所选原生程序或许可文件身份异常、重复或超限")
		}
		data, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
		if err != nil || int64(len(data)) != header.Size {
			return nil, errors.New("IDS 所选原生文件读取不完整")
		}
		files[key] = data
	}
	// Consume bounded trailing bytes too so a child producing data beyond a TAR
	// end marker cannot hang its pipe or hide an unbounded expansion.
	if _, err := io.Copy(io.Discard, bounded); err != nil || bounded.N <= 0 {
		return nil, errors.New("IDS 原生包展开超过 192 MiB 或读取失败")
	}
	if len(files) != required {
		return nil, errors.New("IDS 原生包缺少完整程序或许可")
	}
	return files, nil
}
