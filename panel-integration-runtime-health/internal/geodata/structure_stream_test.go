package geodata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

func TestStructureStreamCompleteTreeExactBytesAndClosedProtocol(t *testing.T) {
	raw := fixtureDatabase(fixtureRecord())
	gz := gzipFixture(t, raw)
	a, _, _, _, _ := testAuthority(t, manifestFor(raw, gz))
	m := a.Manifest()
	for _, kind := range []string{"valid", "wrong-protocol", "duplicate", "alias", "truncated", "extra", "changed-bytes", "changed-metadata", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			frame, err := StructureInput(m, bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(frame)
			ctx := context.Background()
			switch kind {
			case "wrong-protocol":
				data[0] = 'X'
			case "duplicate":
				data = bytes.Replace(data, []byte(`{"format":1,`), []byte(`{"format":1,"format":1,`), 1)
			case "alias":
				data = bytes.Replace(data, []byte(`"format"`), []byte(`"Format"`), 1)
			case "truncated":
				data = data[:len(data)-1]
			case "extra":
				data = append(data, 0)
			case "changed-bytes":
				data[len(data)-1] ^= 1
			case "changed-metadata":
				data = bytes.Replace(data, []byte(`"build_epoch":`+strconv.FormatUint(m.BuildEpoch, 10)), []byte(`"build_epoch":`+strconv.FormatUint(m.BuildEpoch+86400, 10)), 1)
			case "cancelled":
				cancelled, stop := context.WithCancel(ctx)
				stop()
				ctx = cancelled
			}
			var output bytes.Buffer
			err = VerifyStructureStream(ctx, bytes.NewReader(data), &output)
			if (err == nil) != (kind == "valid") {
				t.Fatal(kind, err)
			}
			if err == nil && output.String() != StructureProtocol+m.SHA256+"\n" {
				t.Fatal("unbound verification output", output.String())
			}
			if err != nil && output.Len() != 0 {
				t.Fatal("failed structure check issued receipt")
			}
		})
	}
}

func TestDelegatedStructureCheckPreservesEveryAuthenticatedBoundary(t *testing.T) {
	raw := fixtureDatabase(fixtureRecord())
	gz := gzipFixture(t, raw)
	a, _, _, _, _ := testAuthority(t, manifestFor(raw, gz))
	calls := 0
	verifier := func(ctx context.Context, m Manifest, input io.Reader) error {
		calls++
		frame, err := StructureInput(m, input)
		if err != nil {
			return err
		}
		var out bytes.Buffer
		return VerifyStructureStream(ctx, frame, &out)
	}
	s, err := OpenWithStructureVerifier(context.Background(), a, bytes.NewReader(gz), verifier)
	if err != nil || calls != 1 {
		t.Fatal(err, calls)
	}
	s.Close()
	changed := bytes.Clone(gz)
	changed[len(changed)-1] ^= 1
	if _, err = OpenWithStructureVerifier(context.Background(), a, bytes.NewReader(changed), verifier); err == nil || calls != 1 {
		t.Fatal("unauthenticated source reached verifier", err, calls)
	}
	if _, err = OpenWithStructureVerifier(context.Background(), Authority{}, bytes.NewReader(gz), verifier); err == nil || calls != 1 {
		t.Fatal("unverified authority reached verifier")
	}
	if _, err = OpenWithStructureVerifier(context.Background(), a, bytes.NewReader(gz), nil); err == nil {
		t.Fatal("missing structure check accepted")
	}
	refused := errors.New("owned refusal")
	if _, err = OpenWithStructureVerifier(context.Background(), a, bytes.NewReader(gz), func(context.Context, Manifest, io.Reader) error { return refused }); !errors.Is(err, refused) {
		t.Fatal("delegated failure swallowed", err)
	}
	oversized := StructureProtocol + strings.Repeat("x", maxManifestBytes+2) + "\n"
	if VerifyStructureStream(context.Background(), strings.NewReader(oversized), io.Discard) == nil {
		t.Fatal("unbounded manifest accepted")
	}
}
