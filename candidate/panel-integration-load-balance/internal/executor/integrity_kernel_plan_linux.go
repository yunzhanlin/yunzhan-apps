//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

type integrityKernelTarget struct {
	Path      string                  `json:"path"`
	Directory bool                    `json:"directory"`
	Original  integrityInodeFlagState `json:"original"`
	SHA       string                  `json:"sha256"`
}

type integrityKernelPlan struct {
	Format      int                     `json:"format"`
	OperationID string                  `json:"operation_id"`
	SiteID      string                  `json:"site_id"`
	BaselineSHA string                  `json:"baseline_sha"`
	Site        integrityInodeIdentity  `json:"site"`
	Public      integrityInodeIdentity  `json:"public"`
	Excludes    []string                `json:"excludes"`
	Targets     []integrityKernelTarget `json:"targets"`
}

func integrityKernelDigest(v any) string {
	b, _ := json.Marshal(v)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

func integrityKernelHasCapability() bool {
	h := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	return unix.Capget(&h, &data[0]) == nil && data[unix.CAP_LINUX_IMMUTABLE/32].Effective&(1<<(unix.CAP_LINUX_IMMUTABLE%32)) != 0
}

func integrityKernelFileSHA(ctx context.Context, f *os.File, expected integrityInodeIdentity) (string, error) {
	if expected.Bytes < 0 || expected.Bytes > 8<<20 {
		return "", errors.New("内核保护文件超过现有基线上限")
	}
	h := sha256.New()
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := f.ReadAt(buffer, total)
		if n > 0 {
			total += int64(n)
			if total > expected.Bytes {
				return "", errors.New("内核保护文件长度变化")
			}
			h.Write(buffer[:n])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if n == 0 {
			return "", io.ErrNoProgress
		}
	}
	var after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &after) != nil || total != expected.Bytes || integrityInodeIdentityOf(after) != expected {
		return "", errors.New("内核保护文件读取期间身份或内容元数据变化")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func integrityKernelStatRoot(root *os.Root) (integrityInodeIdentity, error) {
	f, err := root.Open(".")
	if err != nil {
		return integrityInodeIdentity{}, err
	}
	defer f.Close()
	var st unix.Stat_t
	err = unix.Fstat(int(f.Fd()), &st)
	if err != nil {
		return integrityInodeIdentity{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return integrityInodeIdentity{}, errors.New("内核保护根目录类型异常")
	}
	return integrityInodeIdentityOf(st), nil
}

func integrityKernelExcluded(path string, excludes []string) bool {
	for _, p := range excludes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// A writable exception must be a real directory. Excluding only a file while
// protecting its parent would break atomic replacement and misrepresent its
// usability. The excluded directory itself remains fixed under its protected
// parent; creation and writes within it remain available to its original UID.
func (s *Service) integrityKernelPrepare(ctx context.Context, request core.IntegrityKernelRequest) (integrityKernelPlan, error) {
	plan := integrityKernelPlan{Format: 1, OperationID: request.ID, SiteID: request.Input.SiteID, Targets: []integrityKernelTarget{}, Excludes: []string{}}
	baseline, err := s.readIntegrityBaseline(integrityKernelModule, plan.SiteID)
	if err != nil {
		return plan, err
	}
	plan.BaselineSHA = baseline.Signature
	if baseline.Signature != request.Input.BaselineSHA {
		return plan, errors.New("原签名基线已经改变，未启用内核写保护")
	}
	if !integrityKernelHasCapability() {
		return plan, errors.New("当前执行器缺少 CAP_LINUX_IMMUTABLE；未宣称内核保护可用")
	}
	site, _, err := s.openIntegrityWatchFiles(plan.SiteID)
	if err != nil {
		return plan, err
	}
	defer site.Close()
	public, err := site.public.Open(".")
	if err != nil {
		return plan, err
	}
	defer public.Close()
	if plan.Site, err = integrityKernelStatRoot(site.root); err != nil {
		return plan, err
	}
	if plan.Public, err = integrityKernelStatRoot(site.public); err != nil {
		return plan, err
	}
	if len(baseline.Excludes) > 128 {
		return plan, errors.New("内核保护排除目录超过 128 个")
	}
	for _, p := range baseline.Excludes {
		if p == "." {
			return plan, errors.New("不能排除整个网站根目录")
		}
		d, e := openIntegrityFlagTarget(public, p, true)
		if e != nil {
			return plan, errors.New("内核保护只接受实际目录排除项：" + p)
		}
		d.Close()
		if integrityKernelExcluded(p, plan.Excludes) {
			return plan, errors.New("内核保护排除目录重复或相互包含")
		}
		for _, previous := range plan.Excludes {
			if strings.HasPrefix(previous, p+"/") {
				return plan, errors.New("内核保护排除目录相互包含")
			}
		}
		plan.Excludes = append(plan.Excludes, p)
	}
	sort.Strings(plan.Excludes)
	files, directories, total := 0, 0, int64(0)
	err = fs.WalkDir(site.public.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if integrityKernelExcluded(path, plan.Excludes) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return errors.New("排除目录类型发生变化")
		}
		if len(plan.Targets) >= integrityKernelTargets {
			return errors.New("内核保护目录和文件数量超过完整处理预算")
		}
		directory := entry.IsDir()
		f, e := openIntegrityFlagTarget(public, path, directory)
		if e != nil {
			return fmt.Errorf("保护对象 %s 无法核对：%w", path, e)
		}
		defer f.Close()
		state, e := readIntegrityInodeFlags(f, directory)
		if e != nil {
			return e
		}
		if state.Identity.Device != plan.Public.Device {
			return errors.New("内核保护不跨越挂载或文件系统")
		}
		target := integrityKernelTarget{Path: path, Directory: directory, Original: state}
		if directory {
			directories++
			if directories > 4097 {
				return errors.New("内核保护最多 4096 个子目录")
			}
		} else {
			files++
			if files > 10000 {
				return errors.New("内核保护最多 10000 个普通文件")
			}
			total += state.Identity.Bytes
			if total > moduleMaxBytes {
				return errors.New("内核保护超过 256 MiB 现有基线预算")
			}
			old, exists := baseline.Files[path]
			if !exists || old.Size != state.Identity.Bytes || old.Mode != state.Identity.Mode&0777 {
				return errors.New("网站文件清单或权限已偏离原基线；未启用")
			}
			target.SHA, e = integrityKernelFileSHA(ctx, f, state.Identity)
			if e != nil {
				return e
			}
			if target.SHA != old.SHA {
				return errors.New("网站文件内容已偏离原签名基线；未启用")
			}
		}
		plan.Targets = append(plan.Targets, target)
		return nil
	})
	if err != nil {
		return plan, err
	}
	if files != len(baseline.Files) {
		return plan, errors.New("原基线文件缺失，未启用")
	}
	// Seal parent directories before children and files. A tree cannot claim
	// completion after inspecting only the original, still-writable names.
	sort.Slice(plan.Targets, func(i, j int) bool {
		a, b := plan.Targets[i], plan.Targets[j]
		if a.Directory != b.Directory {
			return a.Directory
		}
		if a.Directory {
			da, db := strings.Count(a.Path, "/"), strings.Count(b.Path, "/")
			if a.Path == "." {
				da = -1
			}
			if b.Path == "." {
				db = -1
			}
			if da != db {
				return da < db
			}
		}
		return a.Path < b.Path
	})
	if len(plan.Targets) == 0 || plan.Targets[0].Path != "." || plan.Targets[0].Original.Identity != plan.Public {
		return plan, errors.New("网站根目录原见证不匹配")
	}
	return plan, validateIntegrityKernelPlan(plan)
}

func validateIntegrityKernelPlan(plan integrityKernelPlan) error {
	if plan.Format != 1 || !core.ValidID(plan.OperationID) || !core.ValidID(plan.SiteID) || !phpValidSHA(plan.BaselineSHA) || plan.Site.Inode == 0 || plan.Public.Inode == 0 || len(plan.Targets) < 1 || len(plan.Targets) > integrityKernelTargets || len(plan.Excludes) > 128 {
		return errors.New("内核保护原计划格式、容量或身份无效")
	}
	for i, p := range plan.Excludes {
		if p == "." || !fs.ValidPath(p) || !core.ValidFilePath(p, false) {
			return errors.New("原排除目录路径无效")
		}
		for _, previous := range plan.Excludes[:i] {
			if p == previous || strings.HasPrefix(p, previous+"/") || strings.HasPrefix(previous, p+"/") {
				return errors.New("原排除目录重复或相互包含")
			}
		}
	}
	seen := map[string]bool{}
	files, dirs := 0, 0
	var total int64
	for i, target := range plan.Targets {
		identity := target.Original.Identity
		if !fs.ValidPath(target.Path) || target.Path == "." && !target.Directory || target.Path != "." && !core.ValidFilePath(target.Path, false) || seen[target.Path] || identity.Device != plan.Public.Device || identity.Inode == 0 || target.Original.Flags < 0 || integrityKernelExcluded(target.Path, plan.Excludes) {
			return errors.New("内核保护原对象路径或见证无效")
		}
		seen[target.Path] = true
		if target.Directory {
			dirs++
			if identity.Mode&unix.S_IFMT != unix.S_IFDIR || identity.Links < 1 || target.SHA != "" {
				return errors.New("内核保护目录原见证无效")
			}
			if files > 0 {
				return errors.New("原目录保护顺序无效")
			}
		} else {
			files++
			total += identity.Bytes
			if identity.Mode&unix.S_IFMT != unix.S_IFREG || identity.Links != 1 || identity.Bytes < 0 || identity.Bytes > 8<<20 || !phpValidSHA(target.SHA) {
				return errors.New("内核保护文件原见证无效")
			}
		}
		if i == 0 && (target.Path != "." || !target.Directory || identity != plan.Public) {
			return errors.New("内核保护原根目录不匹配")
		}
		if target.Path != "." {
			parent := "."
			if n := strings.LastIndexByte(target.Path, '/'); n >= 0 {
				parent = target.Path[:n]
			}
			if !seen[parent] {
				return errors.New("内核保护原父目录顺序缺失")
			}
		}
	}
	if files > 10000 || dirs > 4097 || total > moduleMaxBytes {
		return errors.New("内核保护原计划超过完整预算")
	}
	return nil
}

func (s *Service) integrityKernelOpenPlan(plan integrityKernelPlan) (*siteFiles, *os.File, error) {
	return s.integrityKernelOpenPlanMode(plan, false)
}

func (s *Service) integrityKernelOpenPlanMode(plan integrityKernelPlan, releasing bool) (*siteFiles, *os.File, error) {
	if err := validateIntegrityKernelPlan(plan); err != nil {
		return nil, nil, err
	}
	site, _, err := s.openIntegrityWatchFiles(plan.SiteID)
	if err != nil {
		return nil, nil, err
	}
	public, err := site.public.Open(".")
	if err != nil {
		site.Close()
		return nil, nil, err
	}
	currentSite, e1 := integrityKernelStatRoot(site.root)
	currentPublic, e2 := integrityKernelStatRoot(site.public)
	// Parent directory mtime can legitimately change outside public. Its
	// identity/owner/mode still must be the originally trusted site directory.
	parentSame := currentSite.Device == plan.Site.Device && currentSite.Inode == plan.Site.Inode && currentSite.UID == plan.Site.UID && currentSite.GID == plan.Site.GID && currentSite.Mode == plan.Site.Mode
	publicSame := currentPublic == plan.Public
	if releasing && !publicSame && e2 == nil && integrityKernelSameDirectoryIdentity(currentPublic, plan.Public) && plan.Targets[0].Original.Flags&integrityImmutableFlag == 0 {
		// A previous partial release may already have made public writable.
		// New legitimate entries/mtime must not strand original protected
		// children. Only the same original directory with its original flags
		// qualifies; each child still requires its own recorded inode/owner.
		state, e := readIntegrityInodeFlags(public, true)
		publicSame = e == nil && state.Flags == plan.Targets[0].Original.Flags
	}
	if e1 != nil || e2 != nil || !parentSame || !publicSame {
		public.Close()
		site.Close()
		return nil, nil, errors.New("网站或公开根目录原身份发生变化，拒绝跟随替换路径")
	}
	return site, public, nil
}

func integrityKernelSameDirectoryIdentity(a, b integrityInodeIdentity) bool {
	return a.Device == b.Device && a.Inode == b.Inode && a.UID == b.UID && a.GID == b.GID && a.Mode == b.Mode && a.Mode&unix.S_IFMT == unix.S_IFDIR
}
