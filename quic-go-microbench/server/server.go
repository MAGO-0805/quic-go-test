package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

const MAX_DATAGRAM_SIZE = 1350

func main() {
	bindAddr := flag.String("p", "127.0.0.1:8080", "bind IP and port")
	flag.Parse()

	udpAddr, err := net.ResolveUDPAddr("udp", *bindAddr)
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Listen UDP error: %v", err)
	}

	tlsConf, err := generateTLSConfig()
	if err != nil {
		log.Fatalf("TLS config error: %v", err)
	}

	listener, err := quic.Listen(conn, tlsConf, &quic.Config{})
	if err != nil {
		log.Fatalf("QUIC listen error: %v", err)
	}

	log.Printf("Server running on %s", *bindAddr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		handleConnection(conn)
	}
}

func handleConnection(conn *quic.Conn) {
	defer conn.CloseWithError(0, "")

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Println("Accept stream error:", err)
		return
	}

	buf := make([]byte, 4096)

	n, err := stream.Read(buf)
	if err != nil {
		log.Println("Read error:", err)
		return
	}

	request := strings.TrimSpace(string(buf[:n]))
	if strings.HasPrefix(request, "GETN") {
		numStr := strings.TrimSpace(strings.TrimPrefix(request, "GETN"))
		numPackets, err := strconv.Atoi(numStr)
		if err != nil || numPackets <= 0 {
			stream.CancelWrite(42)
			return
		}

		packetBuf := make([]byte, numPackets*(MAX_DATAGRAM_SIZE-50))
		_, err = stream.Write(packetBuf)
		if err != nil {
			log.Println("Write error:", err)
		}
		return
	}
}

func generateTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Subject:      pkix.Name{CommonName: "localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/0.9"},
	}, nil
}
