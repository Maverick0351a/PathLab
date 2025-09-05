package quicinspect

import "testing"

func TestParseInitialTooShort(t *testing.T) {
    s := ParseInitial([]byte{0x80})
    if s.Valid || s.Err == "" { t.Fatalf("expected invalid too short: %#v", s) }
}

func TestParseInitialMinimal(t *testing.T) {
    // Construct a minimal plausible long header Initial-like packet:
    // first byte: 0xC3 (long header + pn len bits=3 -> pn length= (0xC3 & 0x03)+1 = 0x03+1=4)
    // version: 0x00000001
    // dcid len:1 dcid: 0x11
    // scid len:1 scid: 0x22
    // token varint: 0 (1 byte: 0x00)
    // length varint: 5 (0x05)
    pkt := []byte{0xC3, 0,0,0,1, 1, 0x11, 1, 0x22, 0x00, 0x05, 0,0,0,0,0}
    s := ParseInitial(pkt)
    if !s.Valid { t.Fatalf("expected valid: %#v", s) }
    if s.DCIDLen != 1 || s.SCIDLen != 1 || s.TokenLen != 0 || s.DeclaredLen != 5 { t.Fatalf("unexpected fields: %#v", s) }
}
