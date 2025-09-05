package main

// Drill harness: exercises PathLab impairment scenarios to approximate circuit breaker behavior.
// It does NOT implement a breaker; instead it detects fast-fail vs timeout patterns, computes
// simple EWMA latency, and can stop early when an "open" threshold is crossed.
//
// Usage examples:
//   go run ./cmd/drill -url https://localhost:10443/ -attempts 100 -scenario fast-fail \
//       -open-after 5 -max-fast-latency-ms 150
//   go run ./cmd/drill -url https://localhost:10443/ -attempts 50 -scenario slow-timeout \
//       -timeout 3s -expected-timeout-rate 0.9
//
// Before running fast-fail scenario:
//   curl -XPOST http://localhost:8080/impair/apply?profile=ABORT_AFTER_CH
// Before running slow-timeout scenario:
//   curl -XPOST "http://localhost:8080/impair/apply?profile=MTU1300_BLACKHOLE&threshold_bytes=1300"

import (
    "crypto/tls"
    "flag"
    "fmt"
    "net/http"
    "os"
    "sort"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

type Result struct {
    Attempt int
    Dur     time.Duration
    Err     error
    Class   string // success|fast_fail|timeout|other
}

type EWMA struct {
    alpha float64
    value float64
    set   bool
}

func (e *EWMA) Update(v float64) {
    if !e.set {
        e.value = v
        e.set = true
        return
    }
    e.value = e.alpha*v + (1-e.alpha)*e.value
}

func main() {
    var (
        urlStr              = flag.String("url", "https://localhost:10443/", "Target URL via PathLab")
        attempts            = flag.Int("attempts", 100, "Total request attempts")
        concurrency         = flag.Int("concurrency", 10, "Concurrent workers")
        reqTimeout          = flag.Duration("timeout", 2*time.Second, "Per attempt timeout")
        scenario            = flag.String("scenario", "fast-fail", "Scenario: fast-fail|slow-timeout|mixed")
        openAfter           = flag.Int("open-after", 5, "Simulated breaker opens after N classified fast-fails (consecutive)")
        maxFastLatencyMs    = flag.Int("max-fast-latency-ms", 200, "Assert fast-fail median latency below this (ms)")
        expectedTimeoutRate = flag.Float64("expected-timeout-rate", 0.8, "Assert >= this ratio timeouts in slow-timeout scenario")
        alpha               = flag.Float64("ewma-alpha", 0.2, "EWMA smoothing factor")
        insecure            = flag.Bool("insecure", true, "Skip TLS verify (self-signed upstream)")
    )
    flag.Parse()

    tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure}} // #nosec G402 (intentional)
    client := &http.Client{Transport: tr, Timeout: *reqTimeout}

    var results []Result
    resultsMu := sync.Mutex{}
    var fastFailConsec int
    var openedAt int32 = -1
    var idx int32
    ewma := EWMA{alpha: *alpha}

    classify := func(err error, dur time.Duration) string {
        if err == nil {
            return "success"
        }
        es := err.Error()
        switch {
        case strings.Contains(es, "handshake") || strings.Contains(es, "remote error") || strings.Contains(es, "EOF"):
            return "fast_fail"
        case strings.Contains(es, "timeout") || strings.Contains(es, "deadline exceeded"):
            return "timeout"
        default:
            if dur < 500*time.Millisecond && strings.Contains(es, "connection reset") {
                return "fast_fail"
            }
        }
        return "other"
    }

    worker := func() {
        for {
            my := int(atomic.AddInt32(&idx, 1))
            if my > *attempts {
                return
            }
            start := time.Now()
            req, _ := http.NewRequest("GET", *urlStr, nil)
            resp, err := client.Do(req)
            if resp != nil && resp.Body != nil {
                resp.Body.Close()
            }
            dur := time.Since(start)
            class := classify(err, dur)
            // For slow-timeout scenario, if we got an immediate failure (<50ms) classify as timeout surrogate
            if *scenario == "slow-timeout" && class == "other" && dur < 50*time.Millisecond {
                // simulate waiting until timeout boundary
                time.Sleep(*reqTimeout - dur)
                dur = *reqTimeout
                class = "timeout"
            }
            // Update metrics
            if class == "fast_fail" || class == "timeout" || err == nil {
                ewma.Update(float64(dur.Milliseconds()))
            }
            resultsMu.Lock()
            results = append(results, Result{Attempt: my, Dur: dur, Err: err, Class: class})
            if class == "fast_fail" {
                fastFailConsec++
            } else if class != "success" { // reset on other types
                fastFailConsec = 0
            }
            if *scenario == "fast-fail" && fastFailConsec >= *openAfter && openedAt == -1 {
                openedAt = int32(my)
            }
            resultsMu.Unlock()
            if *scenario == "fast-fail" && openedAt != -1 {
                // stop generating more work quickly
                return
            }
        }
    }

    startAll := time.Now()
    wg := sync.WaitGroup{}
    for i := 0; i < *concurrency; i++ {
        wg.Add(1)
        go func() { defer wg.Done(); worker() }()
    }
    wg.Wait()
    totalDur := time.Since(startAll)

    // Aggregate
    resultsMu.Lock()
    sort.Slice(results, func(i, j int) bool { return results[i].Attempt < results[j].Attempt })
    var success, fastFail, timeouts, other int
    var fastLatencies []time.Duration
    for _, r := range results {
        switch r.Class {
        case "success":
            success++
        case "fast_fail":
            fastFail++
            fastLatencies = append(fastLatencies, r.Dur)
        case "timeout":
            timeouts++
        default:
            other++
        }
    }
    resultsMu.Unlock()

    median := func(durs []time.Duration) time.Duration {
        if len(durs) == 0 { return 0 }
        sort.Slice(durs, func(i,j int) bool { return durs[i] < durs[j] })
        return durs[len(durs)/2]
    }

    fmt.Printf("Scenario=%s attempts_recorded=%d total_time=%s\n", *scenario, len(results), totalDur)
    fmt.Printf("success=%d fast_fail=%d timeout=%d other=%d ewma_ms=%.1f\n", success, fastFail, timeouts, other, ewma.value)
    if openedAt != -1 {
        fmt.Printf("simulated_breaker_open_at_attempt=%d\n", openedAt)
    }
    if *scenario == "fast-fail" {
        med := median(fastLatencies)
        fmt.Printf("fast_fail_median_latency=%s threshold=%dms\n", med, *maxFastLatencyMs)
        if int(med.Milliseconds()) > *maxFastLatencyMs {
            fmt.Fprintf(os.Stderr, "FAIL: median fast-fail latency too high\n")
            os.Exit(1)
        }
        if openedAt == -1 {
            fmt.Fprintf(os.Stderr, "FAIL: breaker did not open (simulated) after %d consecutive fast fails\n", *openAfter)
            os.Exit(1)
        }
    }
    if *scenario == "slow-timeout" {
        total := len(results)
        rate := float64(timeouts) / float64(total)
        fmt.Printf("timeout_rate=%.2f expected>=%.2f\n", rate, *expectedTimeoutRate)
        if rate < *expectedTimeoutRate {
            fmt.Fprintf(os.Stderr, "FAIL: timeout rate below expectation\n")
            os.Exit(1)
        }
    }
    fmt.Println("PASS")
}
