package quicinspect

// Minimal QUIC Initial packet parser (scaffold).
// Focus: extract version, DCID/SCID lengths, token length, payload length (declared) and packet size.
// It does NOT decrypt or validate integrity.

import (
    "encoding/binary"
)

// InitialSummary holds extracted metadata from a QUIC Initial datagram.
type InitialSummary struct {
    Version      uint32 `json:"version"`
    DCIDLen      int    `json:"dcid_len"`
    SCIDLen      int    `json:"scid_len"`
    TokenLen     int    `json:"token_len"`
    DeclaredLen  int    `json:"declared_length"` // Length field after token (protected payload length)
    PacketNumber int    `json:"packet_number_len"`
    DatagramSize int    `json:"datagram_size"`
    Valid        bool   `json:"valid"`
    Err          string `json:"error,omitempty"`
}

// ParseInitial attempts to parse a single UDP datagram believed to contain a QUIC Initial packet.
func ParseInitial(b []byte) InitialSummary {
    s := InitialSummary{DatagramSize: len(b)}
    if len(b) < 7 { s.Err = "too short"; return s }
    first := b[0]
    if first&0x80 == 0 { s.Err = "not long header"; return s }
    // Packet type bits (for Initial expect 0b00 in bits 3..2) - we accept any long header for now.
    s.PacketNumber = int(first&0x03) + 1 // pn length bits +1
    s.Version = binary.BigEndian.Uint32(b[1:5])
    dcidLen := int(b[5]); off := 6
    if len(b) < off+dcidLen+1 { s.Err = "trunc dcid"; return s }
    s.DCIDLen = dcidLen
    off += dcidLen
    scidLen := int(b[off]); off++
    if len(b) < off+scidLen { s.Err = "trunc scid"; return s }
    s.SCIDLen = scidLen
    off += scidLen
    // Token (varint length + data)
    if off >= len(b) { s.Err = "trunc token len"; return s }
    tlen, n := readVarint(b[off:])
    if n == 0 { s.Err = "bad token varint"; return s }
    off += n
    if len(b) < off+int(tlen) { s.Err = "trunc token"; return s }
    s.TokenLen = int(tlen)
    off += int(tlen)
    // Length field (varint)
    if off >= len(b) { s.Err = "trunc length"; return s }
    dlen, n2 := readVarint(b[off:])
    if n2 == 0 { s.Err = "bad length varint"; return s }
    s.DeclaredLen = int(dlen)
    off += n2
    // Remainder would include packet number + crypto frames (encrypted) - skip.
    s.Valid = (s.Err == "")
    return s
}

// readVarint decodes a QUIC variable-length integer, returning value and bytes consumed.
func readVarint(b []byte) (uint64, int) {
    if len(b) == 0 { return 0, 0 }
    first := b[0]
    prefix := first >> 6
    var length int
    switch prefix {
    case 0: length = 1
    case 1: length = 2
    case 2: length = 4
    case 3: length = 8
    }
    if len(b) < length { return 0, 0 }
    val := uint64(first & 0x3f)
    for i := 1; i < length; i++ { val = (val << 8) | uint64(b[i]) }
    return val, length
}
