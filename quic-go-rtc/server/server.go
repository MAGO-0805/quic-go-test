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

const (
	FRAME_INTERVAL = 33 * time.Millisecond // 30fps
)

func main() {
	bindAddr := flag.String("p", "127.0.0.1:8080", "bind IP and port")
	frameSize := flag.Int("f", 5000, "frame size in bytes")
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
		session, err := listener.Accept(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		go handleSession(session, *frameSize)
	}
}

func handleSession(session *quic.Conn, frameSize int) {
	defer session.CloseWithError(0, "")

	stream, err := session.AcceptStream(context.Background())
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
	if !strings.HasPrefix(request, "GETN") {
		log.Println("Unknown request:", request)
		return
	}

	numStr := strings.TrimSpace(strings.TrimPrefix(request, "GETN"))
	numFrames, err := strconv.Atoi(numStr)
	if err != nil || numFrames <= 0 {
		log.Println("Invalid frame number:", numStr)
		return
	}
	log.Printf("RTC Server GetN request: %d frames", numFrames)
	log.Printf("Sending %d frames of %d bytes each", numFrames, frameSize)

	totalBytes := 0
	startTime := time.Now()

	// 按帧发送，每帧开一个 stream
	for i := 0; i < numFrames; i++ {
		frame := make([]byte, frameSize)
		frameStream, err := session.OpenStreamSync(context.Background())
		if err != nil {
			log.Println("Open stream error:", err)
			return
		}

		written, err := frameStream.Write(frame)
		if err != nil {
			log.Println("Write error:", err)
			return
		}

		totalBytes += written

		// 33ms 间隔
		time.Sleep(FRAME_INTERVAL)
	}

	elapsed := time.Since(startTime).Seconds()
	mb := float64(totalBytes) / 1_000_000.0
	mbps := mb * 8.0 / elapsed

	log.Printf("Sent %.2f MB in %.3f seconds, goodput: %.2f Mbps", mb, elapsed, mbps)
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
