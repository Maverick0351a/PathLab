package rules

// Minimal rule DSL for PathLab.
// Syntax (one rule per line):
//   when ch_bytes > 1400 then MTU1300_BLACKHOLE
//   when pqc_hint == true then ABORT_AFTER_CH
//   when pqc_group == 0x11ec then ABORT_AFTER_CH (future use; currently pqc_hint only)
// Comparators: >, >=, <, <=, ==
// Values: integers (decimal or 0xHEX) or 'true'/'false' for boolean fields.
// Supported fields: 
//   ch_bytes       (numeric comparisons)
//   pqc_hint       (boolean equality)
//   cipher_count   (numeric comparisons)
//   sni_contains   (substring match; syntax: when sni_contains example.com then PROFILE)
//   alpn_contains  (exact protocol token match; syntax: when alpn_contains h2 then PROFILE)
//   ja3 == <md5hex> (full 32-char lowercase hex match)
// Action: impairment profile name.

import (
    "bufio"
    "encoding/hex"
    "fmt"
    "io"
    "strconv"
    "strings"

    "pathlab/internal/impair"
    "pathlab/internal/tlsinspect"
)

type Rule struct {
    Raw       string
    Predicate func(res tlsinspect.Result) bool
    Profile   impair.ProfileName
}

type Set struct {
    Rules []Rule
}

func Parse(r io.Reader) (Set, error) {
    var set Set
    s := bufio.NewScanner(r)
    lineNo := 0
    for s.Scan() {
        lineNo++
        line := strings.TrimSpace(s.Text())
        if line == "" || strings.HasPrefix(line, "#") { continue }
        rw, err := parseLine(line)
        if err != nil { return Set{}, fmt.Errorf("line %d: %w", lineNo, err) }
        set.Rules = append(set.Rules, rw)
    }
    if err := s.Err(); err != nil { return Set{}, err }
    return set, nil
}

func parseLine(line string) (Rule, error) {
    lower := strings.ToLower(line)
    if !strings.HasPrefix(lower, "when ") {
        return Rule{}, fmt.Errorf("missing 'when'")
    }
    parts := strings.SplitN(lower[len("when "):], " then ", 2)
    if len(parts) != 2 { return Rule{}, fmt.Errorf("missing 'then'") }
    cond := strings.TrimSpace(parts[0])
    action := strings.TrimSpace(parts[1])
    prof := impair.ProfileName(strings.ToUpper(action))
    if prof == "" { return Rule{}, fmt.Errorf("invalid profile") }

    // Supported forms:
    //   ch_bytes > N
    //   ch_bytes >= N
    //   pqc_hint == true|false
    //   cipher_count >= N
    //   sni_contains example.com
    //   alpn_contains h2
    //   ja3 == 771f... (md5 hex)
    var predicate func(res tlsinspect.Result) bool
    fields := strings.Fields(cond)
    var field, op, val string
    switch len(fields) {
    case 3:
        field, op, val = fields[0], fields[1], fields[2]
    case 2: // substring style: sni_contains value or alpn_contains value
        field = fields[0]
        val = fields[1]
        op = "contains"
    default:
        return Rule{}, fmt.Errorf("invalid condition format")
    }
    switch field {
    case "ch_bytes":
        n, err := parseInt(val)
        if err != nil { return Rule{}, fmt.Errorf("bad int: %w", err) }
        switch op {
        case ">": predicate = func(r tlsinspect.Result) bool { return r.HandshakeBytes > n }
        case ">=": predicate = func(r tlsinspect.Result) bool { return r.HandshakeBytes >= n }
        case "<": predicate = func(r tlsinspect.Result) bool { return r.HandshakeBytes < n }
        case "<=": predicate = func(r tlsinspect.Result) bool { return r.HandshakeBytes <= n }
        case "==": predicate = func(r tlsinspect.Result) bool { return r.HandshakeBytes == n }
        default: return Rule{}, fmt.Errorf("unsupported operator %s", op)
        }
    case "pqc_hint":
        b, err := strconv.ParseBool(val)
        if err != nil { return Rule{}, fmt.Errorf("bad bool: %w", err) }
        switch op {
        case "==": predicate = func(r tlsinspect.Result) bool { return r.PQCHint == b }
        default: return Rule{}, fmt.Errorf("unsupported operator for pqc_hint: %s", op)
        }
    case "cipher_count":
        n, err := parseInt(val)
        if err != nil { return Rule{}, fmt.Errorf("bad int: %w", err) }
        switch op {
        case ">": predicate = func(r tlsinspect.Result) bool { return r.CipherSuites > n }
        case ">=": predicate = func(r tlsinspect.Result) bool { return r.CipherSuites >= n }
        case "<": predicate = func(r tlsinspect.Result) bool { return r.CipherSuites < n }
        case "<=": predicate = func(r tlsinspect.Result) bool { return r.CipherSuites <= n }
        case "==": predicate = func(r tlsinspect.Result) bool { return r.CipherSuites == n }
        default: return Rule{}, fmt.Errorf("unsupported operator %s", op)
        }
    case "ja3":
        if op != "==" { return Rule{}, fmt.Errorf("ja3 only supports == operator") }
        hexVal := strings.ToLower(val)
        if len(hexVal) != 32 { return Rule{}, fmt.Errorf("expected 32 hex chars for ja3") }
        for _, c := range hexVal { if (c < '0' || c > '9') && (c < 'a' || c > 'f') { return Rule{}, fmt.Errorf("invalid hex in ja3") } }
        predicate = func(r tlsinspect.Result) bool { return r.JA3 == hexVal }
    case "sni_contains":
        if val == "" { return Rule{}, fmt.Errorf("empty substring") }
        needle := strings.ToLower(val)
        predicate = func(r tlsinspect.Result) bool { return r.SNI != "" && strings.Contains(strings.ToLower(r.SNI), needle) }
    case "alpn_contains":
        if val == "" { return Rule{}, fmt.Errorf("empty alpn token") }
        needle := strings.ToLower(val)
        predicate = func(r tlsinspect.Result) bool {
            for _, p := range r.ALPN { if strings.ToLower(p) == needle { return true } }
            return false
        }
    default:
        return Rule{}, fmt.Errorf("unsupported field %s", field)
    }

    return Rule{Raw: line, Predicate: predicate, Profile: prof}, nil
}

func parseInt(v string) (int, error) {
    if strings.HasPrefix(v, "0x") {
        b, err := hex.DecodeString(strings.TrimPrefix(v, "0x"))
        if err != nil { return 0, err }
        var n int
        for _, bb := range b { n = n*256 + int(bb) }
        return n, nil
    }
    return strconv.Atoi(v)
}

// Match returns the first profile whose predicate returns true.
func (s Set) Match(res tlsinspect.Result) (impair.ProfileName, bool) {
    for _, r := range s.Rules {
        if r.Predicate(res) {
            return r.Profile, true
        }
    }
    return "", false
}
