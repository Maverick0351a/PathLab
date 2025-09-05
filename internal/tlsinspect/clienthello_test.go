package tlsinspect

import (
    "bytes"
    "encoding/binary"
    "io"
    "testing"
)

func TestParseClientHello_Minimal(t *testing.T) {
    // Build minimal ClientHello programmatically to avoid hand-crafted hex mistakes.
    var hs bytes.Buffer
    // legacy_version TLS1.2 (0x0303)
    hs.Write([]byte{0x03, 0x03})
    // random (32 bytes deterministic)
    for i := 0; i < 32; i++ { hs.WriteByte(byte(i)) }
    // session_id length 0
    hs.WriteByte(0x00)
    // cipher_suites length (2 bytes) -> one suite 0x1301 (TLS_AES_128_GCM_SHA256)
    binary.Write(&hs, binary.BigEndian, uint16(2))
    hs.Write([]byte{0x13, 0x01})
    // compression methods length=1 then method 0
    hs.WriteByte(1)
    hs.WriteByte(0)
    // extensions length = 0
    binary.Write(&hs, binary.BigEndian, uint16(0))
    body := hs.Bytes()
    if len(body) != 43 { t.Fatalf("unexpected body len %d", len(body)) }
    // Handshake header: type=01, length (3 bytes)
    var rec bytes.Buffer
    rec.WriteByte(0x01) // ClientHello
    // length: 43 -> 0x00 0x00 0x2b
    rec.Write([]byte{0x00, 0x00, 0x2b})
    rec.Write(body)
    handshake := rec.Bytes()
    if len(handshake) != 47 { t.Fatalf("unexpected handshake total %d", len(handshake)) }
    // TLS record header: type 0x16, version 0x0301, length 47
    var full bytes.Buffer
    full.Write([]byte{0x16, 0x03, 0x01})
    full.Write([]byte{0x00, 0x2f})
    full.Write(handshake)
    raw, res, err := ParseClientHello(&sliceReader{b: full.Bytes()})
    if err != nil { t.Fatalf("ParseClientHello error: %v", err) }
    if len(raw) != res.HandshakeBytes { t.Errorf("raw len %d != handshake bytes %d", len(raw), res.HandshakeBytes) }
    if res.ClientHelloLen != res.HandshakeBytes-4 { t.Errorf("len mismatch: got %d want %d", res.ClientHelloLen, res.HandshakeBytes-4) }
    if res.CipherSuites != 1 { t.Errorf("expected 1 cipher suite, got %d", res.CipherSuites) }
}

type sliceReader struct{ b []byte }
func (s *sliceReader) Read(p []byte) (int, error) {
    if len(s.b) == 0 { return 0, io.EOF }
    n := copy(p, s.b)
    s.b = s.b[n:]
    return n, nil
}
