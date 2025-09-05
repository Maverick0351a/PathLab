package rules

import (
    "strings"
    "testing"
    "pathlab/internal/tlsinspect"
    "pathlab/internal/impair"
)

func TestParseSimpleRules(t *testing.T) {
    txt := `# sample
when ch_bytes > 1400 then MTU1300_BLACKHOLE
when pqc_hint == true then ABORT_AFTER_CH
when sni_contains example.com then LATENCY_50MS_JITTER_10
when alpn_contains h2 then LATENCY_50MS_JITTER_10
`
    set, err := Parse(strings.NewReader(txt))
    if err != nil { t.Fatalf("parse failed: %v", err) }
    if len(set.Rules) != 4 { t.Fatalf("expected 4 rules, got %d", len(set.Rules)) }
    // craft a result to match sni rule
    res := tlsinspect.Result{HandshakeBytes:1500, PQCHint:false, SNI:"test.example.com", ALPN:[]string{"h2"}}
    prof, ok := set.Match(res)
    if !ok { t.Fatalf("expected match") }
    if prof != impair.ProfileMTUBlackhole && prof != impair.ProfileLatencyJitter { t.Fatalf("unexpected profile %s", prof) }
}
