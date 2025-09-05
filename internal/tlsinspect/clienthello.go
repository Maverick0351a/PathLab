package tlsinspect

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Result holds parsed information about the ClientHello
type Result struct {
	HandshakeBytes int    // total bytes comprising the ClientHello handshake message (not including record headers)
	RecordsBytes   int    // total bytes of all TLS records that carried the ClientHello
	PQCHint        bool   // best-effort hint if PQC hybrid group id bytes observed (e.g., 0x11ec for X25519MLKEM768)
	ClientHelloLen int    // length field from handshake header
	SNI            string // extracted server_name (first host_name entry) if present
	ALPN           []string // list of advertised ALPN protocol strings
	CipherSuites   int    // number of cipher suites offered
	JA3            string // md5 hash (hex) of JA3 fingerprint
}

// ParseClientHello reads from r until a full ClientHello handshake message is obtained.
// It returns the raw concatenated handshake bytes and a Result. The function tolerates
// multiple TLS records carrying parts of the handshake.
func ParseClientHello(r io.Reader) (raw []byte, res Result, err error) {
	var buf bytes.Buffer
	var totalRecordsBytes int
	var need int = -1 // handshake bytes needed (length + 4 header)
	for {
		// Read TLS record header: 5 bytes
		hdr := make([]byte, 5)
		if _, err = io.ReadFull(r, hdr); err != nil {
			return nil, res, fmt.Errorf("read record header: %w", err)
		}
		contentType := hdr[0]         // expect 0x16 (handshake)
		version := binary.BigEndian.Uint16(hdr[1:3]) // legacy version often 0x0301 in TLS1.3
		length := int(binary.BigEndian.Uint16(hdr[3:5]))
		if length <= 0 || length > 1<<14+256 {
			return nil, res, errors.New("invalid TLS record length")
		}
		body := make([]byte, length)
		if _, err = io.ReadFull(r, body); err != nil {
			return nil, res, fmt.Errorf("read record body: %w", err)
		}
		totalRecordsBytes += 5 + length

		if contentType != 0x16 {
			// Not a handshake record, push back?
			// For simplicity, return error.
			return nil, res, fmt.Errorf("unexpected TLS content type 0x%02x (version 0x%04x)", contentType, version)
		}

		// Append to buffer of handshake bytes
		buf.Write(body)

		// On first record, read handshake header to know total length
		if need < 0 && buf.Len() >= 4 {
			handshakeType := buf.Bytes()[0]
			if handshakeType != 0x01 {
				return nil, res, fmt.Errorf("not a ClientHello (type=0x%02x)", handshakeType)
			}
			hl := int(buf.Bytes()[1])<<16 | int(buf.Bytes()[2])<<8 | int(buf.Bytes()[3])
			need = hl + 4 // include header
			res.ClientHelloLen = hl
		}

		if need > 0 && buf.Len() >= need {
			raw = buf.Bytes()[:need]
			break
		}
		// else continue reading next record
	}

	// heuristic: look for the key_share extension (0x0033) and group id 0x11ec (X25519MLKEM768)
	if bytes.Contains(raw, []byte{0x11, 0xec}) {
		res.PQCHint = true
	}
	res.HandshakeBytes = len(raw)
	res.RecordsBytes = totalRecordsBytes

	// Best-effort deeper parse of ClientHello body for SNI, ALPN, cipher count and JA3.
	// raw layout: HandshakeHeader(4) + body
	if len(raw) >= 4 {
		body := raw[4:]
		off := 0
		// legacy_version (2) + random (32)
		if len(body) >= off+34 {
			off += 34
			// session_id
			if len(body) > off {
				if sidLen := int(body[off]); len(body) >= off+1+sidLen {
					off += 1 + sidLen
					// cipher_suites vector (2 len + data)
					if len(body) >= off+2 {
						csLen := int(binary.BigEndian.Uint16(body[off:off+2]))
						off += 2
						if csLen%2 == 0 && len(body) >= off+csLen {
							cipherStart := off
							res.CipherSuites = csLen / 2
							off += csLen
							// compression methods (1 len + data)
							if len(body) > off {
								compLen := int(body[off])
								if len(body) >= off+1+compLen {
									off += 1 + compLen
									// extensions vector (2 len + data)
									if len(body) >= off+2 {
										extLen := int(binary.BigEndian.Uint16(body[off:off+2]))
										off += 2
										if len(body) >= off+extLen {
											extEnd := off + extLen
											// Prepare JA3 component collectors
											legacyVersion := int(binary.BigEndian.Uint16(body[0:2]))
											var ja3Ciphers []string
											for i := 0; i < csLen; i += 2 { // exclude GREASE
												val := binary.BigEndian.Uint16(body[cipherStart+i : cipherStart+i+2])
												if isGrease(val) { continue }
												ja3Ciphers = append(ja3Ciphers, strconv.Itoa(int(val)))
											}
											var ja3Exts []string
											var ja3Groups []string
											var ja3PF []string
											// Iterate extensions
											for off+4 <= extEnd {
												etype := binary.BigEndian.Uint16(body[off:off+2])
												elen := int(binary.BigEndian.Uint16(body[off+2:off+4]))
												off += 4
												if off+elen > extEnd { break }
												edata := body[off:off+elen]
												switch etype {
												case 0x0000: // server_name
													if len(edata) >= 2 {
														listLen := int(binary.BigEndian.Uint16(edata[:2]))
														if listLen+2 <= len(edata) {
															p := 2
															for p+3 <= 2+listLen {
																nameType := edata[p]
																if p+3 > len(edata) { break }
																nameLen := int(binary.BigEndian.Uint16(edata[p+1:p+3]))
																p += 3
																if p+nameLen > len(edata) { break }
																if nameType == 0 { // host_name
																	res.SNI = strings.ToLower(string(edata[p : p+nameLen]))
																	break
																}
																p += nameLen
															}
														}
													}
												case 0x0010: // ALPN
													if len(edata) >= 2 {
														listLen := int(binary.BigEndian.Uint16(edata[:2]))
														if listLen+2 <= len(edata) {
															p := 2
															for p < 2+listLen && p < len(edata) {
																if p >= len(edata) { break }
																l := int(edata[p])
																p++
																if p+l > len(edata) { break }
																if l > 0 {
																	res.ALPN = append(res.ALPN, string(edata[p:p+l]))
																}
																p += l
															}
														}
													}
												case 0x000a: // supported_groups (elliptic curves)
													if len(edata) >= 2 {
														glen := int(binary.BigEndian.Uint16(edata[:2]))
														if glen+2 <= len(edata) && glen%2 == 0 {
															for p := 2; p < 2+glen; p += 2 {
																gid := binary.BigEndian.Uint16(edata[p : p+2])
																if isGrease(gid) { continue }
																ja3Groups = append(ja3Groups, strconv.Itoa(int(gid)))
															}
														}
													}
												case 0x000b: // ec_point_formats
													if len(edata) >= 1 {
														plen := int(edata[0])
														if plen+1 <= len(edata) {
															for p := 1; p < 1+plen; p++ {
																ja3PF = append(ja3PF, strconv.Itoa(int(edata[p])))
															}
														}
													}
												}
												if !isGrease(etype) && etype != 0x0000 && etype != 0x0010 && etype != 0x000a && etype != 0x000b {
													// we'll record all extension types (including those we processed) except GREASE; duplicates not expected
												}
												if !isGrease(etype) {
													ja3Exts = append(ja3Exts, strconv.Itoa(int(etype)))
												}
												off += elen
											}
											// Build JA3 string: version,ciphers,extensions,groups,points
											ja3Str := fmt.Sprintf("%d,%s,%s,%s,%s", legacyVersion, strings.Join(ja3Ciphers, "-"), strings.Join(ja3Exts, "-"), strings.Join(ja3Groups, "-"), strings.Join(ja3PF, "-"))
											sum := md5.Sum([]byte(ja3Str))
											res.JA3 = hex.EncodeToString(sum[:])
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return raw, res, nil
}

// isGrease returns true if the value matches a GREASE pattern per RFC 8701.
func isGrease(v uint16) bool {
	// pattern 0x?a?a where high and low bytes identical and low byte is 0x0a
	if byte(v>>8) == byte(v&0xff) && byte(v&0xff) == 0x0a {
		return true
	}
	// explicit list (defensive) though pattern covers all defined values
	switch v {
	case 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa:
		return true
	}
	return false
}
