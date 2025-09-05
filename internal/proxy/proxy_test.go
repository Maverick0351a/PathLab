package proxy

import (
    "io"
    "net"
    "sync"
    "testing"
    "time"
    "pathlab/internal/impair"
    "log"
)

// startDummyUpstream starts a TCP listener that just reads and discards.
func startDummyUpstream(t *testing.T) (addr string, closeFn func()) {
    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil { t.Fatalf("listen: %v", err) }
    done := make(chan struct{})
    go func(){
        for {
            c, err := ln.Accept()
            if err != nil { select { case <-done: return; default: return } }
            go func(conn net.Conn){ io.Copy(io.Discard, conn); conn.Close() }(c)
        }
    }()
    return ln.Addr().String(), func(){ close(done); ln.Close() }
}

func TestHandleConnectionAbortAfterCH(t *testing.T) {
    upstream, closeUp := startDummyUpstream(t); defer closeUp()
    c1, c2 := net.Pipe()
    defer c1.Close(); defer c2.Close()
    cfg := impair.Config{Profile: impair.ProfileAbortAfterCH, ThresholdBytes: 10}
    logger := log.New(io.Discard, "", 0)
    // Run handler in background
    var wg sync.WaitGroup; wg.Add(1)
    go func(){ defer wg.Done(); HandleConnection(c2, upstream, cfg, 1, logger) }()
    // Write some bytes then expect close soon
    _, _ = c1.Write([]byte("hello clienthello"))
    buf := make([]byte, 1)
    c1.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
    _, err := c1.Read(buf)
    if err == nil { t.Fatalf("expected early close or error") }
    wg.Wait()
}

func TestHandleConnectionBandwidthLimit(t *testing.T) {
    upstream, closeUp := startDummyUpstream(t); defer closeUp()
    c1, c2 := net.Pipe()
    defer c1.Close(); defer c2.Close()
    cfg := impair.Config{Profile: impair.ProfileBandwidthLimit, BandwidthKbps: 64} // ~8KB/s
    logger := log.New(io.Discard, "", 0)
    var wg sync.WaitGroup; wg.Add(1)
    go func(){ defer wg.Done(); HandleConnection(c2, upstream, cfg, 2, logger) }()
    payload := make([]byte, 2048)
    start := time.Now()
    _, _ = c1.Write(payload)
    // Set a deadline so read unblocks
    _ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
    buf := make([]byte, 64)
    c1.Read(buf) // ignore result; trigger potential copy path
    elapsed := time.Since(start)
    if elapsed < 100*time.Millisecond { t.Fatalf("bandwidth limit not applied; elapsed=%v", elapsed) }
    if elapsed > 3*time.Second { t.Fatalf("took too long: %v", elapsed) }
    wg.Wait()
}
