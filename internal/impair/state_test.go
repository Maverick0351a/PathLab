package impair

import (
    "sync"
    "testing"
)

func TestApplyAndSnapshot(t *testing.T) {
    s := &State{}
    s.Apply(Config{Profile: ProfileAbortAfterCH, ThresholdBytes: 900})
    snap := s.Snapshot()
    if snap.Profile != ProfileAbortAfterCH || snap.ThresholdBytes != 900 {
        t.Fatalf("unexpected snapshot %#v", snap)
    }
    // Ensure defaults fill in
    s.Apply(Config{Profile: ProfileLatencyJitter})
    snap2 := s.Snapshot()
    if snap2.LatencyMs == 0 || snap2.JitterMs == 0 {
        t.Fatalf("latency defaults not applied: %#v", snap2)
    }
}

func TestConcurrentSnapshot(t *testing.T) {
    s := &State{}
    wg := sync.WaitGroup{}
    for i:=0;i<20;i++ { wg.Add(1); go func(){ defer wg.Done(); s.Apply(Config{Profile: ProfileClean}) }() }
    for i:=0;i<50;i++ { _ = s.Snapshot() }
    wg.Wait()
}
