package executor

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func streamIPPolicyFixture(prefixes ...string) []byte {
	var out strings.Builder
	fmt.Fprintf(&out, "a(iayu) %d", len(prefixes))
	for _, value := range prefixes {
		p := netip.MustParsePrefix(value)
		family := 10
		if p.Addr().Is4() {
			family = 2
		}
		raw := p.Addr().AsSlice()
		fmt.Fprintf(&out, " %d %d", family, len(raw))
		for _, b := range raw {
			fmt.Fprintf(&out, " %d", b)
		}
		fmt.Fprintf(&out, " %d", p.Bits())
	}
	out.WriteByte('\n')
	return []byte(out.String())
}

func TestLoadBalanceStreamIPPolicyRequiresCompleteExactAllowAndDeny(t *testing.T) {
	want := []string{"127.0.0.0/8", "192.0.2.10/32", "2001:db8::2/128", "::1/128"}
	allow, deny := streamIPPolicyFixture(want...), streamIPPolicyFixture("::/0", "0.0.0.0/0")
	if got, err := streamServiceIPPrefixes(allow); err != nil || !reflect.DeepEqual(got, want) || !streamServiceIPPolicyMatches(allow, deny, want) {
		t.Fatal("complete typed manager policy refused", got, err)
	}
	for _, changed := range [][]byte{
		streamIPPolicyFixture("127.0.0.0/8", "192.0.2.10/32", "2001:db8::2/128", "::1/128", "198.51.100.99/32"),
		streamIPPolicyFixture("127.0.0.0/8", "192.0.2.0/24", "2001:db8::2/128", "::1/128"),
		streamIPPolicyFixture("127.0.0.0/8", "::1/128"), streamIPPolicyFixture("0.0.0.0/0", "::/0"),
	} {
		if streamServiceIPPolicyMatches(changed, deny, want) {
			t.Fatal("missing, broadened or retained grandparent backend accepted")
		}
	}
	for _, changed := range [][]byte{streamIPPolicyFixture("0.0.0.0/0"), streamIPPolicyFixture("127.0.0.0/8", "::1/128"), nil, []byte("a(iayu) 0\n")} {
		if streamServiceIPPolicyMatches(allow, changed, want) {
			t.Fatal("partial or missing deny-all accepted")
		}
	}
}

func TestLoadBalanceStreamIPPolicyMalformedTypedValuesCannotGrantPolicy(t *testing.T) {
	valid := string(streamIPPolicyFixture("127.0.0.0/8", "::1/128"))
	for _, value := range []string{
		"", "a(iayu) 0\n", "a(iayu) 4099\n", "as 2 127.0.0.0/8 ::1/128\n", valid + "trailing\n", strings.TrimSuffix(valid, "\n"), valid + "\x00", valid + "\r\n",
		strings.Replace(valid, "a(iayu) 2", "a(iayu) 3", 1), strings.Replace(valid, "a(iayu) 2", "a(iayu) 02", 1),
		strings.Replace(valid, " 2 4 127", " 3 4 127", 1), strings.Replace(valid, " 2 4 127", " 10 4 127", 1),
		strings.Replace(valid, " 127 ", " 256 ", 1), strings.Replace(valid, " 127 ", " -1 ", 1), strings.Replace(valid, " 127 ", " 0127 ", 1),
		strings.Replace(valid, " 127 0 0 0 8", " 127 0 0 1 8", 1), strings.Replace(valid, " 127 0 0 0 8", " 127 0 0 0 33", 1),
		string(streamIPPolicyFixture("127.0.0.0/8", "127.0.0.0/8")), string(streamIPPolicyFixture("::ffff:127.0.0.1/128")),
	} {
		if got, err := streamServiceIPPrefixes([]byte(value)); err == nil || got != nil {
			t.Fatalf("malformed typed value accepted: %q", value)
		}
	}
}
