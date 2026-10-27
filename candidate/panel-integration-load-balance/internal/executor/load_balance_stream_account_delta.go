package executor

import (
	"bytes"

	"local/panel/internal/loadbalancestream"
)

// A successful useradd exit is insufficient. Account publication additionally
// requires exactly one new dedicated record per local NSS file and byte-for-
// byte preservation of every original record, including order and terminators.
// This comparison returns only the dedicated identity digest, never NSS data.
func validateLoadBalanceStreamAccountCreationSources(data [][]byte) error {
	if len(data) != 4 {
		return errLoadBalanceStreamAccount
	}
	for _, raw := range data {
		if len(raw) == 0 || raw[len(raw)-1] != '\n' {
			return errLoadBalanceStreamAccount
		}
	}
	return validateLoadBalanceStreamAccountAbsence(data[0], data[1], data[2], data[3])
}

func validateLoadBalanceStreamAccountCreationDelta(before, after [][]byte) (loadBalanceStreamIdentity, error) {
	empty := loadBalanceStreamIdentity{}
	if validateLoadBalanceStreamAccountCreationSources(before) != nil || len(after) != 4 {
		return empty, errLoadBalanceStreamAccount
	}
	identity, err := validateLoadBalanceStreamNSS(after[0], after[1], after[2], after[3])
	if err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	prefix := []byte(loadbalancestream.ServiceAccount + ":")
	for index, raw := range after {
		if len(raw) == 0 || raw[len(raw)-1] != '\n' {
			return empty, errLoadBalanceStreamAccount
		}
		original := make([]byte, 0, len(raw))
		added := 0
		for _, line := range bytes.SplitAfter(raw, []byte{'\n'}) {
			if bytes.HasPrefix(line, prefix) {
				added++
			} else {
				original = append(original, line...)
			}
		}
		preserved := added == 1 && bytes.Equal(original, before[index])
		clear(original)
		if !preserved {
			return empty, errLoadBalanceStreamAccount
		}
	}
	return identity, nil
}
