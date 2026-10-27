package executor

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func streamAccountAbsentFixture() [][]byte {
	data := loadBalanceStreamNSSFixture()
	for i, raw := range data {
		var result []byte
		for _, line := range bytes.SplitAfter(raw, []byte("\n")) {
			if !bytes.HasPrefix(line, []byte(loadbalancestream.ServiceAccount+":")) {
				result = append(result, line...)
			}
		}
		data[i] = result
	}
	return data
}

func TestLoadBalanceStreamAccountAbsenceReadsAllFourNamespacesWithoutMutation(t *testing.T) {
	data := streamAccountAbsentFixture()
	original := make([][]byte, 4)
	for i := range data {
		original[i] = bytes.Clone(data[i])
	}
	if err := validateLoadBalanceStreamAccountAbsence(data[0], data[1], data[2], data[3]); err != nil || !reflect.DeepEqual(original, data) {
		t.Fatal("exact four-file missing account refused or input changed", err)
	}
	for i := range data {
		data[i] = bytes.ReplaceAll(data[i], []byte("panel-memcached"), []byte("panel-lbstream-backup"))
	}
	if err := validateLoadBalanceStreamAccountAbsence(data[0], data[1], data[2], data[3]); err != nil {
		t.Fatal("unrelated exact-distinct name was treated as account ownership", err)
	}
}

func TestLoadBalanceStreamAccountAbsenceRefusesResidualNamesMembershipOrMalformedSources(t *testing.T) {
	for file := 0; file < 4; file++ {
		for _, fault := range []string{"existing-name", "duplicate-unrelated", "nil", "empty", "comments-only", "oversize", "invalid-UTF8", "CR", "NUL", "missing-field", "name-space"} {
			t.Run(strings.Join([]string{[]string{"passwd", "group", "shadow", "gshadow"}[file], fault}, "/"), func(t *testing.T) {
				data := streamAccountAbsentFixture()
				switch fault {
				case "existing-name":
					data[file] = loadBalanceStreamNSSFixture()[file]
				case "duplicate-unrelated":
					line := bytes.SplitAfter(data[file], []byte("\n"))[0]
					data[file] = append(data[file], line...)
				case "nil":
					data[file] = nil
				case "empty":
					data[file] = []byte{}
				case "comments-only":
					data[file] = []byte("# missing real NSS rows\n")
				case "oversize":
					data[file] = bytes.Repeat([]byte("x"), (1<<20)+1)
				case "invalid-UTF8":
					data[file] = append(data[file], 255)
				case "CR":
					data[file] = append(data[file], '\r')
				case "NUL":
					data[file] = append(data[file], 0)
				case "missing-field":
					data[file] = bytes.Replace(data[file], []byte("root:"), []byte("root"), 1)
				case "name-space":
					data[file] = bytes.Replace(data[file], []byte("root:"), []byte(" root:"), 1)
				}
				if err := validateLoadBalanceStreamAccountAbsence(data[0], data[1], data[2], data[3]); err == nil {
					t.Fatal("residual or uncheckable namespace accepted as account-creation absence")
				}
			})
		}
	}
	for _, item := range []struct {
		name  string
		file  int
		entry string
	}{
		{"public-member", 1, "foreign:x:800:panel-lbstream\n"},
		{"public-member-whitespace", 1, "foreign:x:800:other, panel-lbstream ,another\n"},
		{"private-admin", 3, "foreign:!:panel-lbstream:\n"},
		{"private-admin-whitespace", 3, "foreign:!:other, panel-lbstream ,another:\n"},
		{"private-member", 3, "foreign:!::panel-lbstream\n"},
		{"private-member-whitespace", 3, "foreign:!::other, panel-lbstream ,another\n"},
	} {
		t.Run(item.name, func(t *testing.T) {
			data := streamAccountAbsentFixture()
			data[item.file] = append(data[item.file], []byte(item.entry)...)
			if validateLoadBalanceStreamAccountAbsence(data[0], data[1], data[2], data[3]) == nil {
				t.Fatal("residual foreign group could grant privileges after same-name creation")
			}
		})
	}
	for _, fault := range []string{"passwd-UID", "passwd-GID", "group-GID"} {
		for _, value := range []string{"", "00", "-1", "1e2", "4294967296", " 123"} {
			t.Run(fault+"-"+value, func(t *testing.T) {
				data := streamAccountAbsentFixture()
				file, column := 0, 2
				if fault == "passwd-GID" {
					column = 3
				} else if fault == "group-GID" {
					file = 1
				}
				lines := strings.Split(string(data[file]), "\n")
				fields := strings.Split(lines[0], ":")
				fields[column] = value
				lines[0] = strings.Join(fields, ":")
				data[file] = []byte(strings.Join(lines, "\n"))
				if validateLoadBalanceStreamAccountAbsence(data[0], data[1], data[2], data[3]) == nil {
					t.Fatal("ambiguous or malformed original numeric namespace accepted")
				}
			})
		}
	}
}
