package executor

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// A typo in a vendored public key must fail locally, before testing the PPA.
// This checks the OpenPGP v4 primary packet/fingerprint and ASCII armor CRC;
// APT subsequently verifies the real signed catalog with this exact key.
func TestThreatIDSOISFVendoredPublicTrustFingerprintAndArmor(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(threatIDSOISFKey), "\n")
	if lines[0] != "-----BEGIN PGP PUBLIC KEY BLOCK-----" || lines[len(lines)-1] != "-----END PGP PUBLIC KEY BLOCK-----" {
		t.Fatal("key armor framing")
	}
	encoded, checksum := "", ""
	for _, line := range lines[1 : len(lines)-1] {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "=") {
			checksum = strings.TrimPrefix(line, "=")
		} else {
			encoded += line
		}
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) < 600 {
		t.Fatal("invalid vendored public key", err)
	}
	crc := uint32(0xb704ce)
	for _, b := range data {
		crc ^= uint32(b) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= 0x1864cfb
			}
		}
	}
	check, err := base64.StdEncoding.DecodeString(checksum)
	if err != nil || len(check) != 3 || uint32(check[0])<<16|uint32(check[1])<<8|uint32(check[2]) != crc&0xffffff {
		t.Fatal("public key CRC mismatch")
	}
	if data[0] != 0xc6 || data[1] < 192 || data[1] > 223 {
		t.Fatal("unreviewed public key primary packet format")
	}
	n := (int(data[1])-192)*256 + int(data[2]) + 192
	if n > len(data)-3 || data[3] != 4 {
		t.Fatal("primary packet length/version")
	}
	packet := append([]byte{0x99, 0, 0}, data[3:3+n]...)
	binary.BigEndian.PutUint16(packet[1:3], uint16(n))
	digest := sha1.Sum(packet)
	if strings.ToUpper(hex.EncodeToString(digest[:])) != "121504ADE276E141AD704A75AC10378CF205C960" {
		t.Fatal("vendored trust fingerprint differs from official OISF stable PPA")
	}
}
