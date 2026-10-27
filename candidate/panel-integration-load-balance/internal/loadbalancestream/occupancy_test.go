package loadbalancestream

import "testing"

func TestSetIncludesIndependentTCPAndUDPForeignOccupancy(t *testing.T) {
	udp := fixture()
	udp.Protocol = "udp"
	udp.UDPRequests = 1
	udp.UDPResponses = 1
	cases := []struct {
		name  string
		entry Entry
		tcp   []int
		udp   []int
		valid bool
	}{
		{"foreign-UDP-collision", udp, nil, []int{udp.Port}, false},
		{"foreign-TCP-can-share-UDP-number", udp, []int{udp.Port}, nil, true},
		{"foreign-UDP-does-not-occupy-TCP-probe", udp, nil, []int{udp.ProbePort}, true},
		{"foreign-UDP-can-share-TCP-number", fixture(), nil, []int{udp.Port}, true},
		{"invalid-UDP-zero", udp, nil, []int{0}, false},
		{"invalid-UDP-high", udp, nil, []int{65536}, false},
		{"unbounded-UDP-inventory", udp, nil, make([]int, 1025), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := facts()
			f.OccupiedTCPPorts = c.tcp
			f.OccupiedUDPPorts = c.udp
			if (ValidateSet([]Entry{c.entry}, f) == nil) != c.valid {
				t.Fatal("transport-specific foreign occupancy was widened or confused")
			}
		})
	}
	tcp := fixture()
	udp.Name = "other.invalid"
	udp.ProbePort++
	if ValidateSet([]Entry{tcp, udp}, facts()) != nil {
		t.Fatal("owned TCP and UDP may intentionally use the same port number with separate generation probes")
	}
}
