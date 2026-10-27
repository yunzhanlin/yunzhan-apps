//go:build linux

package executor

import (
	"context"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamSyntaxOldMissingOrAlreadyIssuedOriginalCannotStartAnything(t *testing.T) {
	for _, p := range []*loadBalanceStreamConfigurationPublication{nil, {}, {syntaxIssued: true}, {syntaxIssued: true, syntaxVerified: true}, {attempted: true}, {promoted: true}} {
		if err := p.verifySyntaxOwned(context.Background(), nil); err != loadbalancestream.ErrRuntime {
			t.Fatal("old/missing original selected syntax effect", err)
		}
		if _, err := p.promoteOwned(context.Background(), nil); err == nil {
			t.Fatal("missing original native syntax or phase promoted host configuration")
		}
	}
}
