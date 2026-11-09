package executor

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func loadBalanceStreamNSSFixture() [][]byte {
	name := loadbalancestream.ServiceAccount
	return [][]byte{
		[]byte("root:x:0:0:root:/root:/bin/bash\npanel-memcached:x:992:992:panel-memcached:/nonexistent:/usr/sbin/nologin\n" + name + ":x:991:991:" + name + ":/nonexistent:/usr/sbin/nologin\n"),
		[]byte("root:x:0:\npanel-memcached:x:992:\n" + name + ":x:991:\n"),
		[]byte("root:!*:20000:0:99999:7:::\npanel-memcached:!:20000:0:99999:7:::\n" + name + ":!:20000:0:99999:7:::\n"),
		[]byte("root:!::\npanel-memcached:!::\n" + name + ":!::\n"),
	}
}
func TestLoadBalanceStreamNSSOnlyExactDedicatedLockedIdentity(t *testing.T) {
	data := loadBalanceStreamNSSFixture()
	before := make([][]byte, len(data))
	for i := range data {
		before[i] = bytes.Clone(data[i])
	}
	got, err := validateLoadBalanceStreamNSS(data[0], data[1], data[2], data[3])
	if err != nil || got.UID != 991 || got.GID != 991 || len(got.SHA256) != 64 || !reflect.DeepEqual(data, before) {
		t.Fatal("dedicated identity changed or parser leaked/mutated NSS", got, err)
	}
	again, err := validateLoadBalanceStreamNSS(data[0], data[1], data[2], data[3])
	if err != nil || again != got {
		t.Fatal("NSS digest nondeterministic")
	}
	data[0] = bytes.ReplaceAll(data[0], []byte("/usr/sbin/nologin"), []byte("/sbin/nologin"))
	changed, err := validateLoadBalanceStreamNSS(data[0], data[1], data[2], data[3])
	if err != nil || changed.UID != got.UID || changed.GID != got.GID || changed.SHA256 == got.SHA256 {
		t.Fatal("reviewed alternate nologin shell must rebind original identity", err)
	}
}
func TestLoadBalanceStreamNSSCannotBorrowMemcachedSiteRootOrForeignGroups(t *testing.T) {
	changes := map[string]func([][]byte){
		"missing-user":     func(d [][]byte) { d[0] = bytes.ReplaceAll(d[0], []byte("panel-lbstream"), []byte("foreign-user")) },
		"missing-group":    func(d [][]byte) { d[1] = bytes.ReplaceAll(d[1], []byte("panel-lbstream"), []byte("foreign-group")) },
		"missing-shadow":   func(d [][]byte) { d[2] = bytes.ReplaceAll(d[2], []byte("panel-lbstream"), []byte("foreign-shadow")) },
		"missing-gshadow":  func(d [][]byte) { d[3] = bytes.ReplaceAll(d[3], []byte("panel-lbstream"), []byte("foreign-gshadow")) },
		"UID-zero":         func(d [][]byte) { d[0] = bytes.ReplaceAll(d[0], []byte(":991:991:"), []byte(":0:991:")) },
		"GID-zero":         func(d [][]byte) { d[0] = bytes.ReplaceAll(d[0], []byte(":991:991:"), []byte(":991:0:")) },
		"UID-low":          func(d [][]byte) { d[0] = bytes.ReplaceAll(d[0], []byte(":991:991:"), []byte(":99:991:")) },
		"UID-upper":        func(d [][]byte) { d[0] = bytes.ReplaceAll(d[0], []byte(":991:991:"), []byte(":1000:991:")) },
		"GID-upper":        func(d [][]byte) { d[0] = bytes.ReplaceAll(d[0], []byte(":991:991:"), []byte(":991:1000:")) },
		"UID-leading-zero": func(d [][]byte) { d[0] = bytes.ReplaceAll(d[0], []byte(":991:991:"), []byte(":0991:991:")) },
		"GID-leading-zero": func(d [][]byte) { d[1] = bytes.ReplaceAll(d[1], []byte(":991:"), []byte(":0991:")) },
		"foreign-UID": func(d [][]byte) {
			d[0] = append(d[0], []byte("foreign:x:991:990:foreign:/nonexistent:/usr/sbin/nologin\n")...)
		},
		"foreign-primary-GID": func(d [][]byte) {
			d[0] = append(d[0], []byte("foreign:x:990:991:foreign:/nonexistent:/usr/sbin/nologin\n")...)
		},
		"foreign-group-GID":         func(d [][]byte) { d[1] = append(d[1], []byte("foreign:x:991:\n")...) },
		"supplementary-group":       func(d [][]byte) { d[1] = append(d[1], []byte("foreign:x:990:panel-lbstream\n")...) },
		"supplementary-group-space": func(d [][]byte) { d[1] = append(d[1], []byte("foreign:x:990: panel-lbstream\n")...) },
		"private-group-admin": func(d [][]byte) {
			d[3] = bytes.ReplaceAll(d[3], []byte("panel-lbstream:!::"), []byte("panel-lbstream:!:foreign:"))
		},
		"private-group-member": func(d [][]byte) {
			d[3] = bytes.ReplaceAll(d[3], []byte("panel-lbstream:!::"), []byte("panel-lbstream:!::foreign"))
		},
		"public-group-member": func(d [][]byte) {
			d[1] = bytes.ReplaceAll(d[1], []byte("panel-lbstream:x:991:"), []byte("panel-lbstream:x:991:foreign"))
		},
		"delegated-other-group-admin":  func(d [][]byte) { d[3] = append(d[3], []byte("foreign:!:panel-lbstream:\n")...) },
		"delegated-other-group-member": func(d [][]byte) { d[3] = append(d[3], []byte("foreign:!::panel-lbstream\n")...) },
		"wrong-comment": func(d [][]byte) {
			d[0] = bytes.ReplaceAll(d[0], []byte(":991:991:panel-lbstream:"), []byte(":991:991:foreign:"))
		},
		"wrong-home": func(d [][]byte) {
			d[0] = bytes.ReplaceAll(d[0], []byte(":991:991:panel-lbstream:/nonexistent:"), []byte(":991:991:panel-lbstream:/root:"))
		},
		"interactive-shell": func(d [][]byte) {
			d[0] = bytes.ReplaceAll(d[0], []byte(":991:991:panel-lbstream:/nonexistent:/usr/sbin/nologin"), []byte(":991:991:panel-lbstream:/nonexistent:/bin/bash"))
		},
		"passwd-field": func(d [][]byte) {
			d[0] = bytes.ReplaceAll(d[0], []byte("panel-lbstream:x:"), []byte("panel-lbstream:hash:"))
		},
		"shadow-unlocked": func(d [][]byte) {
			d[2] = bytes.ReplaceAll(d[2], []byte("panel-lbstream:!:"), []byte("panel-lbstream:$6$must-not-leak:"))
		},
		"shadow-empty": func(d [][]byte) {
			d[2] = bytes.ReplaceAll(d[2], []byte("panel-lbstream:!:"), []byte("panel-lbstream::"))
		},
		"gshadow-unlocked": func(d [][]byte) {
			d[3] = bytes.ReplaceAll(d[3], []byte("panel-lbstream:!:"), []byte("panel-lbstream:$6$must-not-leak:"))
		},
		"gshadow-empty": func(d [][]byte) {
			d[3] = bytes.ReplaceAll(d[3], []byte("panel-lbstream:!:"), []byte("panel-lbstream::"))
		},
		"borrow-Memcached-only": func(d [][]byte) {
			for i := range d {
				lines := bytes.SplitAfter(d[i], []byte("\n"))
				d[i] = nil
				for _, line := range lines {
					if !bytes.HasPrefix(line, []byte("panel-lbstream:")) {
						d[i] = append(d[i], line...)
					}
				}
			}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			d := loadBalanceStreamNSSFixture()
			change(d)
			got, err := validateLoadBalanceStreamNSS(d[0], d[1], d[2], d[3])
			if err != errLoadBalanceStreamIdentity || got != (loadBalanceStreamIdentity{}) {
				t.Fatal("foreign/shared/unlocked identity admitted", name, got, err)
			}
			if strings.Contains(err.Error(), "must-not-leak") {
				t.Fatal("password material escaped fixed diagnostic")
			}
		})
	}
	for _, file := range []int{0, 1, 2, 3} {
		t.Run("duplicate-selected-"+string(rune('0'+file)), func(t *testing.T) {
			d := loadBalanceStreamNSSFixture()
			for _, line := range bytes.Split(d[file], []byte("\n")) {
				if bytes.HasPrefix(line, []byte("panel-lbstream:")) {
					d[file] = append(d[file], append(bytes.Clone(line), '\n')...)
					break
				}
			}
			if got, err := validateLoadBalanceStreamNSS(d[0], d[1], d[2], d[3]); err == nil || got != (loadBalanceStreamIdentity{}) {
				t.Fatal("duplicate selected NSS record admitted")
			}
		})
		for _, shape := range []string{"empty", "oversize", "invalid-UTF8", "NUL", "CR", "malformed"} {
			t.Run("bounded-source-"+string(rune('0'+file))+"/"+shape, func(t *testing.T) {
				d := loadBalanceStreamNSSFixture()
				switch shape {
				case "empty":
					d[file] = nil
				case "oversize":
					d[file] = bytes.Repeat([]byte("a"), (1<<20)+1)
				case "invalid-UTF8":
					d[file] = append(d[file], 0xff)
				case "NUL":
					d[file] = append(d[file], 0)
				case "CR":
					d[file] = append(d[file], '\r')
				case "malformed":
					d[file] = append(d[file], []byte("wrong:field-count\n")...)
				}
				if got, err := validateLoadBalanceStreamNSS(d[0], d[1], d[2], d[3]); err == nil || got != (loadBalanceStreamIdentity{}) {
					t.Fatal("unsafe source returned partial identity")
				}
			})
		}
	}
}
