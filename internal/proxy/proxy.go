package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"pathlab/internal/impair"
	"pathlab/internal/tlsinspect"
)

// HandleConnection proxies a single connection with optional impairment profile
func HandleConnection(client net.Conn, upstreamAddr string, cfg impair.Config, id int64, logger *log.Logger) error {
	upstream, err := net.DialTimeout("tcp", upstreamAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial upstream: %w", err)
	}
	defer upstream.Close()

	// Buffer the client reader so we can parse first flight without consuming more than needed
	cbr := bufio.NewReader(client)

	switch cfg.Profile {
	case impair.ProfileAbortAfterCH:
		return handleAbortAfterCH(cbr, client, upstream, cfg, id, logger)
	case impair.ProfileMTUBlackhole:
		return handleMTUBlackhole(cbr, client, upstream, cfg, id, logger)
	case impair.ProfileLatencyJitter:
		return handleLatencyJitter(cbr, client, upstream, cfg, id, logger)
	case impair.ProfileBandwidthLimit:
		return handleBandwidthLimit(cbr, client, upstream, cfg, id, logger)
	default:
		return handleCleanPassthrough(cbr, client, upstream, cfg, id, logger)
	}
}

func handleCleanPassthrough(cbr *bufio.Reader, client net.Conn, upstream net.Conn, cfg impair.Config, id int64, logger *log.Logger) error {
	// Start copying both directions. First feed any buffered bytes to upstream.
	// Peek to see if there are buffered bytes (without consuming)
	if cbr.Buffered() > 0 {
		buf, _ := cbr.Peek(cbr.Buffered())
		if len(buf) > 0 {
			if _, err := upstream.Write(buf); err != nil {
				return err
			}
			// discard from reader
			_, _ = cbr.Discard(len(buf))
		}
	}
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, cbr)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(client, upstream)
		errc <- err
	}()
	// wait for one side to finish
	err1 := <-errc
	_ = client.Close()
	_ = upstream.Close()
	err2 := <-errc
	if err1 != nil && !errors.Is(err1, io.EOF) {
		return err1
	}
	if err2 != nil && !errors.Is(err2, io.EOF) {
		return err2
	}
	return nil
}

func handleAbortAfterCH(cbr *bufio.Reader, client net.Conn, upstream net.Conn, cfg impair.Config, id int64, logger *log.Logger) error {
	// Parse ClientHello from client
	raw, res, err := tlsinspect.ParseClientHello(cbr)
	if err != nil {
		return fmt.Errorf("parse clienthello: %w", err)
	}
	logger.Printf("[conn %d] ABORT_AFTER_CH: ch_len=%d records_bytes=%d pqc_hint=%v", id, res.HandshakeBytes, res.RecordsBytes, res.PQCHint)

	// Forward the ClientHello to upstream, then immediately abort both sides
	if _, err := upstream.Write(raw); err != nil {
		return fmt.Errorf("write CH to upstream: %w", err)
	}

	// Also forward any additional bytes that already arrived with the first flight,
	// up to the end of the buffered data
	if cbr.Buffered() > 0 {
		buf, _ := cbr.Peek(cbr.Buffered())
		if len(buf) > 0 {
			_, _ = upstream.Write(buf)
			_, _ = cbr.Discard(len(buf))
		}
	}

	// small delay to increase likelihood upstream receives data
	time.Sleep(5 * time.Millisecond)
	abortConn(client)
	abortConn(upstream)
	return nil
}

func handleMTUBlackhole(cbr *bufio.Reader, client net.Conn, upstream net.Conn, cfg impair.Config, id int64, logger *log.Logger) error {
	// Read the first TLS record(s) to get the ClientHello
	raw, res, err := tlsinspect.ParseClientHello(cbr)
	if err != nil {
		return fmt.Errorf("parse clienthello: %w", err)
	}
	th := cfg.ThresholdBytes
	if th <= 0 {
		th = 1300
	}
	logger.Printf("[conn %d] MTU1300_BLACKHOLE: threshold=%d ch_len=%d pqc_hint=%v", id, th, res.HandshakeBytes, res.PQCHint)

	// Forward only the first 'threshold' bytes to upstream; silently drop the rest
	toSend := raw
	if len(toSend) > th {
		toSend = toSend[:th]
	}

	if _, err := upstream.Write(toSend); err != nil {
		return fmt.Errorf("write partial CH: %w", err)
	}
	// Discard any remaining buffered bytes (beyond threshold) for this first flight
	remaining := len(raw) - len(toSend)
	if remaining > 0 {
		// already not forwarded
	}

	if cbr.Buffered() > 0 {
		// There may be extra bytes (after the CH) already read; drop them
		_, _ = cbr.Discard(cbr.Buffered())
	}

	// Now, simulate blackhole by discarding further client->server bytes for some time
	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := cbr.Read(buf)
			if n > 0 {
				// drop silently
				continue
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// loop
				continue
			}
			if err != nil {
				return
			}
		}
	}()

	// Meanwhile, allow server->client to flow (server will likely time out)
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(client, upstream)
	}()

	// Hold connection open to mimic hang, then close (configurable)
	dur := time.Duration(cfg.BlackholeSeconds) * time.Second
	if dur <= 0 { dur = 30 * time.Second }
	time.Sleep(dur)
	close(stop)
	_ = client.Close()
	_ = upstream.Close()
	wg.Wait()
	return nil
}

// handleLatencyJitter introduces an added one-way latency with optional jitter before proxying data.
func handleLatencyJitter(cbr *bufio.Reader, client net.Conn, upstream net.Conn, cfg impair.Config, id int64, logger *log.Logger) error {
	// Parse ClientHello once to keep behavior consistent (still full pass through after delay)
	raw, res, err := tlsinspect.ParseClientHello(cbr)
 	if err != nil {
 		return fmt.Errorf("parse clienthello: %w", err)
 	}
 	logger.Printf("[conn %d] LATENCY profile base=%dms jitter=%dms ch_len=%d", id, cfg.LatencyMs, cfg.JitterMs, res.HandshakeBytes)
 	// Apply latency + jitter (best-effort)
 	delay := time.Duration(cfg.LatencyMs) * time.Millisecond
 	if cfg.JitterMs > 0 {
 		// simple symmetrical jitter: +/- JitterMs/2
 		j := time.Duration(cfg.JitterMs) * time.Millisecond
 		delay += (time.Duration(time.Now().UnixNano()) % j) - (j / 2)
 		if delay < 0 { delay = 0 }
 	}
 	time.Sleep(delay)
 	if _, err := upstream.Write(raw); err != nil { return err }
 	// Flush any extra buffered bytes already read
 	if cbr.Buffered() > 0 {
 		buf, _ := cbr.Peek(cbr.Buffered())
 		if len(buf) > 0 { _, _ = upstream.Write(buf); _, _ = cbr.Discard(len(buf)) }
 	}
 	// Continue bidirectional copy with per-chunk latency on client->upstream path only
 	errc := make(chan error, 2)
 	go func() {
 		// client -> upstream (after initial handshake) with delay per chunk
 		buf := make([]byte, 16*1024)
 		for {
 			n, er := cbr.Read(buf)
 			if n > 0 {
 				if delay > 0 { time.Sleep(delay) }
 				if _, ew := upstream.Write(buf[:n]); ew != nil { er = ew }
 			}
 			if er != nil { errc <- er; return }
 		}
 	}()
 	go func() { _, er := io.Copy(client, upstream); errc <- er }()
 	err1 := <-errc
 	_ = client.Close(); _ = upstream.Close()
 	err2 := <-errc
 	if err1 != nil && !errors.Is(err1, io.EOF) { return err1 }
 	if err2 != nil && !errors.Is(err2, io.EOF) { return err2 }
 	return nil
}

// handleBandwidthLimit applies a simple token bucket style throttle on client->upstream direction.
func handleBandwidthLimit(cbr *bufio.Reader, client net.Conn, upstream net.Conn, cfg impair.Config, id int64, logger *log.Logger) error {
 	raw, res, err := tlsinspect.ParseClientHello(cbr)
 	if err != nil { return fmt.Errorf("parse clienthello: %w", err) }
 	limitKbps := cfg.BandwidthKbps
 	if limitKbps <= 0 { limitKbps = 1000 }
 	logger.Printf("[conn %d] BANDWIDTH limit=%dkbps ch_len=%d", id, limitKbps, res.HandshakeBytes)
 	if _, err := upstream.Write(raw); err != nil { return err }
 	if cbr.Buffered() > 0 { buf, _ := cbr.Peek(cbr.Buffered()); if len(buf)>0 { _, _ = upstream.Write(buf); _, _ = cbr.Discard(len(buf)) } }
 	bytesPerSec := limitKbps * 125 // kbps -> bytes/sec (1000/8)
 	if bytesPerSec <= 0 { bytesPerSec = 125000 }
 	chunk := 8 * 1024
 	if chunk > bytesPerSec { chunk = bytesPerSec }
 	tick := time.NewTicker(200 * time.Millisecond) // 5 intervals per second
 	defer tick.Stop()
 	bucketCap := bytesPerSec / 5
 	bucket := bucketCap
 	errc := make(chan error, 2)
 	go func() {
 		buf := make([]byte, chunk)
 		for {
 			if bucket <= 0 { <-tick.C; bucket = bucketCap }
 			n, er := cbr.Read(buf)
 			if n > 0 {
 				if n > bucket { // if read more than allowance, send partial then sleep
 					toSend := bucket
 					if toSend > 0 { _, _ = upstream.Write(buf[:toSend]); n -= toSend }
 					bucket = 0
 					// put remainder back is non-trivial; fallback: short sleep and write rest next loop
 					// simplistic approach: write remainder after refill
 					for n > 0 {
 						<-tick.C; bucket = bucketCap
 						w := n
 						if w > bucket { w = bucket }
 						_, _ = upstream.Write(buf[toSend:toSend+w])
 						bucket -= w; n -= w; toSend += w
 					}
 				} else {
 					_, _ = upstream.Write(buf[:n]); bucket -= n
 				}
 			}
 			if er != nil { errc <- er; return }
 		}
 	}()
	// Downstream (upstream -> client) shaping if configured
	downLimit := cfg.BandwidthDownKbps
	if downLimit > 0 {
		go func() {
			bytesPerSecDown := downLimit * 125
			if bytesPerSecDown <= 0 { bytesPerSecDown = 125000 }
			chunkDown := 8 * 1024
			if chunkDown > bytesPerSecDown { chunkDown = bytesPerSecDown }
			intervals := 5
			bucketCapDown := bytesPerSecDown / intervals
			if bucketCapDown <= 0 { bucketCapDown = bytesPerSecDown }
			tickDown := time.NewTicker(time.Second / time.Duration(intervals))
			defer tickDown.Stop()
			bucketDown := bucketCapDown
			bufDown := make([]byte, chunkDown)
			for {
				if bucketDown <= 0 { <-tickDown.C; bucketDown = bucketCapDown }
				n, er := upstream.Read(bufDown)
				if n > 0 {
					toSend := n
					off := 0
					for toSend > 0 {
						if bucketDown <= 0 { <-tickDown.C; bucketDown = bucketCapDown }
						w := toSend
						if w > bucketDown { w = bucketDown }
						_, _ = client.Write(bufDown[off:off+w])
						bucketDown -= w
						off += w
						toSend -= w
					}
				}
				if er != nil { errc <- er; return }
			}
		}()
	} else {
		go func() { _, er := io.Copy(client, upstream); errc <- er }()
	}
 	err1 := <-errc
 	_ = client.Close(); _ = upstream.Close()
 	err2 := <-errc
 	if err1 != nil && !errors.Is(err1, io.EOF) { return err1 }
 	if err2 != nil && !errors.Is(err2, io.EOF) { return err2 }
 	return nil
}

func abortConn(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		// SetLinger(0) generally results in an RST on close (Unix, Windows).
		_ = tcp.SetLinger(0)
		_ = tcp.Close()
		return
	}
	// best-effort for non-TCPConn
	_ = c.Close()
}
