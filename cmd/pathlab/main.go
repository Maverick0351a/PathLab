package main

import (
	"context"
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"strings"

	"pathlab/internal/impair"
	"pathlab/internal/proxy"
	"pathlab/internal/rules"
	"pathlab/internal/tlsinspect"
	"pathlab/internal/receipts"
	"pathlab/internal/quicinspect"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	var (
		listenAddr   = flag.String("listen", getenv("PATHLAB_LISTEN", ":10443"), "TCP listen address for proxy (client connects here)")
		upstreamAddr = flag.String("upstream", getenv("PATHLAB_UPSTREAM", "127.0.0.1:8443"), "Upstream server address (host:port)")
		adminAddr    = flag.String("admin", getenv("PATHLAB_ADMIN", ":8080"), "Admin HTTP API address")
		readTimeout  = flag.Duration("read-timeout", 30*time.Second, "I/O read timeout")
		writeTimeout = flag.Duration("write-timeout", 30*time.Second, "I/O write timeout")
		keyFile     = flag.String("keyfile", getenv("PATHLAB_KEYFILE", "pathlab-ed25519.key"), "Path to Ed25519 seed file (created if missing)")
	)
	flag.Parse()

	// Shared impairment state
	state := &impair.State{}
	state.Apply(impair.Config{Profile: impair.ProfileClean, ThresholdBytes: 1300})

	// Start proxy listener
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen error on %s: %v", *listenAddr, err)
	}
	log.Printf("[pathlab] listening on %s, upstream %s, admin %s", *listenAddr, *upstreamAddr, *adminAddr)

	// Rules state
	var ruleSet atomic.Value // stores rules.Set
	ruleSet.Store(rules.Set{})

	// Receipts key management: load or create Ed25519 seed file (32 bytes)
	seed, err := os.ReadFile(*keyFile)
	if err != nil || len(seed) != 32 {
		var newSeed [32]byte
		if _, rerr := rand.Read(newSeed[:]); rerr != nil {
			log.Fatalf("generate ed25519 seed: %v", rerr)
		}
		if werr := os.WriteFile(*keyFile, newSeed[:], 0600); werr != nil {
			log.Fatalf("write keyfile: %v", werr)
		}
		seed = newSeed[:]
		log.Printf("[pathlab] generated new ed25519 keyfile %s", *keyFile)
	} else {
		log.Printf("[pathlab] loaded ed25519 keyfile %s", *keyFile)
	}
	pubPriv := ed25519.NewKeyFromSeed(seed)
	rcpts := receipts.NewManager(256, pubPriv)

	// Start admin API
	mux := http.NewServeMux()
	var connCount int64

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/quic/parse_initial", func(w http.ResponseWriter, r *http.Request) {
		// Accept hex body of a UDP datagram containing a QUIC Initial.
		data, _ := io.ReadAll(r.Body)
		hexStr := strings.TrimSpace(string(data))
		if hexStr == "" { http.Error(w, "hex body required", http.StatusBadRequest); return }
		buf, err := hex.DecodeString(hexStr)
		if err != nil { http.Error(w, "bad hex", http.StatusBadRequest); return }
		s := quicinspect.ParseInitial(buf)
		json.NewEncoder(w).Encode(s)
	})
	mux.HandleFunc("/receipts/pubkey", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"ed25519_pubkey_hex": rcpts.PublicKeyHex()})
	})
	mux.HandleFunc("/receipts", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if idStr := q.Get("id"); idStr != "" {
			var id int64
			fmt.Sscanf(idStr, "%d", &id)
			rec, err := rcpts.Get(id)
			if err != nil { http.Error(w, "not found", http.StatusNotFound); return }
			json.NewEncoder(w).Encode(rec); return
		}
		limit := 0
		if v := q.Get("limit"); v != "" { fmt.Sscanf(v, "%d", &limit) }
		json.NewEncoder(w).Encode(map[string]any{"receipts": rcpts.List(limit)})
	})
	mux.HandleFunc("/receipts/verify", func(w http.ResponseWriter, r *http.Request) {
		idStr := r.URL.Query().Get("id")
		if idStr == "" { http.Error(w, "id required", http.StatusBadRequest); return }
		var id int64
		fmt.Sscanf(idStr, "%d", &id)
		rec, err := rcpts.Get(id)
		if err != nil { http.Error(w, "not found", http.StatusNotFound); return }
		hashOK, sigOK := rcpts.Verify(rec)
		json.NewEncoder(w).Encode(map[string]any{"id": id, "hash_ok": hashOK, "sig_ok": sigOK})
	})
	mux.HandleFunc("/receipts/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok { http.Error(w, "stream unsupported", http.StatusInternalServerError); return }
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Cache-Control", "no-cache")
		ch, cancel := rcpts.Subscribe(64)
		defer cancel()
		enc := json.NewEncoder(w)
		done := r.Context().Done()
		for {
			select {
			case <-done:
				return
			case rec := <-ch:
				_ = enc.Encode(rec)
				flusher.Flush()
			}
		}
	})
	mux.HandleFunc("/impair/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(state.Snapshot())
	})
	mux.HandleFunc("/impair/clear", func(w http.ResponseWriter, r *http.Request) {
		state.Apply(impair.Config{Profile: impair.ProfileClean, ThresholdBytes: 1300})
		json.NewEncoder(w).Encode(state.Snapshot())
	})
	mux.HandleFunc("/impair/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var cfg impair.Config
		if r.Header.Get("Content-Type") == "application/json" {
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			// Accept query params for quick testing
			q := r.URL.Query()
			cfg.Profile = impair.ProfileName(q.Get("profile"))
			if cfg.Profile == "" {
				cfg.Profile = impair.ProfileClean
			}
			if v := q.Get("threshold_bytes"); v != "" {
				var tb int
				fmt.Sscanf(v, "%d", &tb)
				cfg.ThresholdBytes = tb
			}
			if v := q.Get("latency_ms"); v != "" {
				fmt.Sscanf(v, "%d", &cfg.LatencyMs)
			}
			if v := q.Get("bandwidth_kbps"); v != "" {
				fmt.Sscanf(v, "%d", &cfg.BandwidthKbps)
			}
			if v := q.Get("bandwidth_down_kbps"); v != "" { fmt.Sscanf(v, "%d", &cfg.BandwidthDownKbps) }
			if v := q.Get("blackhole_seconds"); v != "" { fmt.Sscanf(v, "%d", &cfg.BlackholeSeconds) }
		}
		state.Apply(cfg)
		json.NewEncoder(w).Encode(state.Snapshot())
	})

	mux.HandleFunc("/rules", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// list current rules
			curr := ruleSet.Load().(rules.Set)
			var out []string
			for _, ru := range curr.Rules { out = append(out, ru.Raw) }
			json.NewEncoder(w).Encode(map[string]any{"rules": out})
		case http.MethodPost:
			// accept plain text body
			set, err := rules.Parse(r.Body)
			if err != nil {
				http.Error(w, "parse error: "+err.Error(), http.StatusBadRequest)
				return
			}
			ruleSet.Store(set)
			json.NewEncoder(w).Encode(map[string]any{"loaded": len(set.Rules)})
		case http.MethodDelete:
			ruleSet.Store(rules.Set{})
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/rules/test", func(w http.ResponseWriter, r *http.Request) {
		// Accept query parameters to synthesize a tlsinspect.Result and show matched profile.
		q := r.URL.Query()
		var fake tlsinspect.Result
		if v := q.Get("ch_bytes"); v != "" { fmt.Sscanf(v, "%d", &fake.HandshakeBytes) }
		if v := q.Get("pqc_hint"); v != "" { b := v == "1" || v == "true"; fake.PQCHint = b }
		if v := q.Get("cipher_count"); v != "" { fmt.Sscanf(v, "%d", &fake.CipherSuites) }
		if v := q.Get("sni"); v != "" { fake.SNI = v }
		if v := q.Get("alpn"); v != "" { fake.ALPN = append(fake.ALPN, v) }
		if v := r.URL.Query().Get("ja3"); v != "" { fake.JA3 = strings.ToLower(v) }
		set := ruleSet.Load().(rules.Set)
		if prof, ok := set.Match(fake); ok {
			json.NewEncoder(w).Encode(map[string]any{"matched": true, "profile": prof})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"matched": false})
	})

	adminSrv := &http.Server{
		Addr:         *adminAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("[pathlab] admin API on %s", *adminAddr)
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("admin server error: %v", err)
		}
	}()

	// Accept loop
	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("accept error: %v", err)
				continue
			}
			id := atomic.AddInt64(&connCount, 1)
			wg.Add(1)
			go func(id int64, c net.Conn) {
				defer wg.Done()
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(*readTimeout))
				_ = c.SetWriteDeadline(time.Now().Add(*writeTimeout))
				baseCfg := state.Get()
				logger := log.New(os.Stdout, "", log.LstdFlags)

				// Peek ClientHello for rule matching (non-destructive) by creating a tee buffer
				// We re-use tlsinspect.ParseClientHello by wrapping a reader that accumulates bytes then
				// replays them to the normal proxy handlers according to chosen profile.
				br := bufio.NewReader(c)
				raw, res, perr := tlsinspect.ParseClientHello(br)
				var chosen impair.ProfileName = baseCfg.Profile
				if perr == nil {
					set := ruleSet.Load().(rules.Set)
					if prof, ok := set.Match(res); ok {
						chosen = prof
						logger.Printf("[conn %d] rule matched -> profile=%s (ch_bytes=%d pqc_hint=%v)", id, chosen, res.HandshakeBytes, res.PQCHint)
					}
				}
				// Reconstruct reader including already-read bytes for handler
				full := append(raw, drainBuffered(br)...) // raw includes only handshake bytes; additional buffered bytes appended
				replay := bufio.NewReader(&prependReader{prefix: full, rest: c})
				cfg := baseCfg; cfg.Profile = chosen
				logger.Printf("[conn %d] accepted from %s -> upstream %s, profile=%s", id, c.RemoteAddr(), *upstreamAddr, cfg.Profile)
				// Hand off using replay reader by temporarily swapping in proxy internals (simpler: dial upstream inside this path again)
				// Simplify: call specialized entry passing pre-read bytes (future refactor)
				// Fallback: if parse failed, just use original conn (already consumed unknown bytes though)
				if perr != nil {
					logger.Printf("[conn %d] clienthello parse error (rules skipped): %v", id, perr)
				}
				start := time.Now()
				err := proxy.HandleConnection(replayConn{Conn: c, reader: replay}, *upstreamAddr, cfg, id, logger)
				dur := time.Since(start)
				outcome := "closed"
				var errStr string
				if err != nil { outcome = "error"; errStr = err.Error() }
				logger.Printf("[conn %d] %s (%.0fms)", id, outcome, dur.Seconds()*1000)
				// Emit receipt
				receipt := receipts.Receipt{
					ConnID:         id,
					Timestamp:      time.Now().UTC(),
					ClientAddr:     c.RemoteAddr().String(),
					UpstreamAddr:   *upstreamAddr,
					AppliedProfile: string(cfg.Profile),
					GlobalProfile:  string(baseCfg.Profile),
					RuleMatched:    string(chosen),
					HandshakeBytes: res.HandshakeBytes,
					CipherCount:    res.CipherSuites,
					PQCHint:        res.PQCHint,
					SNI:            res.SNI,
					ALPN:           res.ALPN,
					JA3:            res.JA3,
					Outcome:        outcome,
					Error:          errStr,
				}
				_ = hex.EncodeToString // keep import used until we add manual verification example later
				rcpts.Add(receipt)
			}(id, conn)
		}
	}()

	// graceful shutdown
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
	log.Printf("[pathlab] shutting down...")
	ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = adminSrv.Shutdown(ctx)
	wg.Wait()
	log.Printf("[pathlab] bye")
}

// bufferedConn is a thin wrapper (unused now but placeholder for future enhancements)
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// prependReader allows us to replay already-parsed bytes before reading from the live conn.
type prependReader struct {
	prefix []byte
	rest   net.Conn
}

func (p *prependReader) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.rest.Read(b)
}

// replayConn injects a custom reader while satisfying net.Conn.
type replayConn struct {
	net.Conn
	reader *bufio.Reader
}

func (r replayConn) Read(b []byte) (int, error) { return r.reader.Read(b) }

func drainBuffered(br *bufio.Reader) []byte {
	var buf bytes.Buffer
	for br.Buffered() > 0 {
		chunk, _ := br.Peek(br.Buffered())
		buf.Write(chunk)
		br.Discard(len(chunk))
	}
	return buf.Bytes()
}
