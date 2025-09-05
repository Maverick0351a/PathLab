package main

// Minimal self-signed HTTPS upstream server for PathLab Option A.
// Listens on :9443 and serves a plain text response. Generates an in-memory
// self-signed certificate for CN=localhost so you can test quickly without
// external tooling.
//
// Run (from repo root or inside module):
//   go run ./example/upstream.go
// Then start PathLab (separate terminal):
//   ./bin/pathlab -listen :10443 -upstream 127.0.0.1:9443 -admin :8080
// Test:
//   curl -k https://localhost:10443/
//
// NOTE: -k skips certificate verification (self-signed cert).

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net/http"
	"time"
)

func main() {
	port := flag.String("port", "9443", "listen port")
	flag.Parse()
	cert, key := mustSelfSignedCert()
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		log.Fatalf("load self-signed pair: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from Go upstream\n"))
	})

	srv := &http.Server{
		Addr:      ":" + *port,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},
	}
	log.Printf("[upstream] listening on :%s (self-signed CN=localhost)", *port)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func mustSelfSignedCert() (certPEM, keyPEM []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return
}
