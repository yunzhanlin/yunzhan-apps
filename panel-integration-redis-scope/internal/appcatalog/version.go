package appcatalog

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

func ValidVersion(v string) bool { return len(v) <= 80 && versionPattern.MatchString(v) }

// Numeric components are compared numerically; legacy 1.0/1.1 and compat1
// versions are supported without lexicographic 1.10 < 1.9 mistakes.
func CompareVersions(a, b string) (int, bool) {
	if !ValidVersion(a) || !ValidVersion(b) {
		return 0, false
	}
	aa, bb := strings.SplitN(a, "-", 2), strings.SplitN(b, "-", 2)
	x, y := strings.Split(aa[0], "."), strings.Split(bb[0], ".")
	for i := 0; i < max(len(x), len(y)); i++ {
		u, v := uint64(0), uint64(0)
		var err error
		if i < len(x) {
			u, err = strconv.ParseUint(x[i], 10, 64)
			if err != nil {
				return 0, false
			}
		}
		if i < len(y) {
			v, err = strconv.ParseUint(y[i], 10, 64)
			if err != nil {
				return 0, false
			}
		}
		if u < v {
			return -1, true
		}
		if u > v {
			return 1, true
		}
	}
	if len(aa) == 1 && len(bb) == 1 {
		return 0, true
	}
	if len(aa) == 1 {
		return 1, true
	}
	if len(bb) == 1 {
		return -1, true
	}
	// Natural comparison handles the existing compat2 -> compat10 revisions.
	xs, ys := aa[1], bb[1]
	for len(xs) > 0 && len(ys) > 0 {
		if xs[0] >= '0' && xs[0] <= '9' && ys[0] >= '0' && ys[0] <= '9' {
			i, j := 0, 0
			for i < len(xs) && xs[i] >= '0' && xs[i] <= '9' {
				i++
			}
			for j < len(ys) && ys[j] >= '0' && ys[j] <= '9' {
				j++
			}
			u, e1 := strconv.ParseUint(xs[:i], 10, 64)
			v, e2 := strconv.ParseUint(ys[:j], 10, 64)
			if e1 != nil || e2 != nil {
				return 0, false
			}
			if u < v {
				return -1, true
			}
			if u > v {
				return 1, true
			}
			xs, ys = xs[i:], ys[j:]
			continue
		}
		if xs[0] < ys[0] {
			return -1, true
		}
		if xs[0] > ys[0] {
			return 1, true
		}
		xs, ys = xs[1:], ys[1:]
	}
	if len(xs) < len(ys) {
		return -1, true
	}
	if len(xs) > len(ys) {
		return 1, true
	}
	return 0, true
}

func boundedRead(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = errors.New("应用缓存超过上限")
	}
	return b, err
}

func catalogProgress(previous, next Catalog) error {
	p, _ := time.Parse(time.RFC3339, previous.GeneratedAt)
	n, _ := time.Parse(time.RFC3339, next.GeneratedAt)
	if n.Before(p) {
		return errors.New("拒绝回退到较旧的签名应用目录")
	}
	for _, item := range next.Apps {
		old, ok := Find(previous, item.ID)
		if !ok {
			continue
		}
		cmp, valid := CompareVersions(item.Version, old.Version)
		if !valid || cmp < 0 {
			return errors.New("拒绝应用版本降级: " + item.ID)
		}
		if item.Version == old.Version && item.SHA256 != old.SHA256 {
			return errors.New("相同应用版本的包被修改，请发布新的版本号: " + item.ID)
		}
	}
	return nil
}
