package rules

import (
    "strings"
    "testing"
    "pathlab/internal/tlsinspect"
)

func TestRuleMatchOverride(t *testing.T) {
    src := `when ch_bytes > 100 then MTU1300_BLACKHOLE
when sni_contains example.com then ABORT_AFTER_CH`
    set, err := Parse(strings.NewReader(src))
    if err != nil { t.Fatalf("parse: %v", err) }
    // Should match first rule
    r1 := tlsinspect.Result{HandshakeBytes: 120}
    if prof, ok := set.Match(r1); !ok || string(prof) != "MTU1300_BLACKHOLE" { t.Fatalf("unexpected match %#v %v", prof, ok) }
    // Should match second rule
    r2 := tlsinspect.Result{SNI: "api.example.com"}
    if prof, ok := set.Match(r2); !ok || string(prof) != "ABORT_AFTER_CH" { t.Fatalf("unexpected match %#v %v", prof, ok) }
    // No match
    r3 := tlsinspect.Result{HandshakeBytes:50, SNI:"noop"}
    if _, ok := set.Match(r3); ok { t.Fatalf("expected no match") }
}