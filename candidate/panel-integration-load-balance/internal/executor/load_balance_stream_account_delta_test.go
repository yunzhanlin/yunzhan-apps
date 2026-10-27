package executor

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func streamAccountCreationFixture() ([][]byte, [][]byte) {
	after := loadBalanceStreamNSSFixture()
	before := make([][]byte, 4)
	for index, raw := range after {
		for _, line := range bytes.SplitAfter(raw, []byte{'\n'}) {
			if !bytes.HasPrefix(line, []byte("panel-lbstream:")) {
				before[index] = append(before[index], line...)
			}
		}
	}
	return before, after
}

func TestLoadBalanceStreamAccountCreationDeltaOnlyOneNewDedicatedIdentity(t *testing.T) {
	before, after := streamAccountCreationFixture()
	copySources := func(data [][]byte) [][]byte {
		out := make([][]byte, len(data))
		for i := range data {
			out[i] = bytes.Clone(data[i])
		}
		return out
	}
	b, a := copySources(before), copySources(after)
	if validateLoadBalanceStreamAccountCreationSources(before) != nil {
		t.Fatal("canonical original absence refused")
	}
	want, err := validateLoadBalanceStreamNSS(after[0], after[1], after[2], after[3])
	got, deltaErr := validateLoadBalanceStreamAccountCreationDelta(before, after)
	if err != nil || deltaErr != nil || got != want || !reflect.DeepEqual(before, b) || !reflect.DeepEqual(after, a) {
		t.Fatal("exact addition or immutable private inputs were not preserved")
	}
}

func TestLoadBalanceStreamAccountCreationDeltaRejectsUnrelatedNSSChanges(t *testing.T) {
	for index := 0; index < 4; index++ {
		for _, mutation := range []string{"foreign-change", "foreign-delete", "foreign-add", "reorder", "selected-duplicate", "old-selected", "missing-newline-before", "missing-newline-after", "extra-source", "missing-source"} {
			t.Run(string(rune('0'+index))+"/"+mutation, func(t *testing.T) {
				before, after := streamAccountCreationFixture()
				switch mutation {
				case "foreign-change":
					after[index] = bytes.Replace(after[index], []byte("panel-memcached:"), []byte("foreign-change:"), 1)
				case "foreign-delete":
					for _, row := range bytes.SplitAfter(after[index], []byte{'\n'}) {
						if bytes.HasPrefix(row, []byte("panel-memcached:")) {
							after[index] = bytes.Replace(after[index], row, nil, 1)
							break
						}
					}
				case "foreign-add":
					for _, row := range bytes.SplitAfter(before[index], []byte{'\n'}) {
						if bytes.HasPrefix(row, []byte("panel-memcached:")) {
							after[index] = append(after[index], bytes.Replace(row, []byte("panel-memcached:"), []byte("foreign-add:"), 1)...)
							break
						}
					}
				case "reorder":
					rows := bytes.SplitAfter(after[index], []byte{'\n'})
					rows[0], rows[1] = rows[1], rows[0]
					after[index] = bytes.Join(rows, nil)
				case "selected-duplicate", "old-selected":
					for _, row := range bytes.SplitAfter(after[index], []byte{'\n'}) {
						if bytes.HasPrefix(row, []byte("panel-lbstream:")) {
							if mutation == "old-selected" {
								before[index] = append(before[index], row...)
							} else {
								after[index] = append(after[index], row...)
							}
							break
						}
					}
				case "missing-newline-before":
					before[index] = before[index][:len(before[index])-1]
				case "missing-newline-after":
					after[index] = after[index][:len(after[index])-1]
				case "extra-source":
					after = append(after, bytes.Clone(after[index]))
				case "missing-source":
					before = before[:3]
				}
				identity, err := validateLoadBalanceStreamAccountCreationDelta(before, after)
				if err != errLoadBalanceStreamAccount || identity != (loadBalanceStreamIdentity{}) || strings.Contains(err.Error(), "root:") {
					t.Fatal("NSS mutation admitted or secret data exposed")
				}
			})
		}
	}
}
