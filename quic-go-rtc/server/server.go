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
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	FRAME_INTERVAL = 33 * time.Millisecond // 30fps
)

func main() {
	// 命令行参数
	addr := flag.String("p", "127.0.0.1:8080", "server port")
	frameSize := flag.Int("f", 5000, "size of each frame in bytes")
	flag.Parse()

	tlsConf := generateTLSConfig()
	quicConfig := &quic.Config{
		MaxIncomingStreams:    3000,
		MaxIncomingUniStreams: 3000,
	}

	listener, err := quic.ListenAddr(*addr, tlsConf, quicConfig)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Server running on %s, frame size: %d bytes", *addr, *frameSize)

	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			log.Println("Accept session error:", err)
			continue
		}
		go handleSession(session, *frameSize)
	}
}

func handleSession(session *quic.Conn, frameSize int) {
	defer session.CloseWithError(0, "")
	buf := make([]byte, 4096)

	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		log.Println("Accept stream error:", err)
		return
	}

	n, _ := stream.Read(buf)
	req := strings.TrimSpace(string(buf[:n]))
	if !strings.HasPrefix(req, "GETN") {
		log.Println("Unknown request:", req)
		return
	}

	numFrames, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(req, "GETN")))
	log.Printf("RTC Server GetN request: %d frames, each is %d B", numFrames, frameSize)

	for i := 0; i < numFrames; i++ {
		frame := make([]byte, frameSize) // 每帧大小可通过参数控制
		go func(f []byte) {
			fs, err := session.OpenStreamSync(context.Background())
			if err != nil {
				if qerr, ok := err.(*quic.ApplicationError); ok && qerr.ErrorCode == 0 {
					return
				} else {
					log.Println("OpenStreamSync error:", err)
					return
				}
			}
			_, err = fs.Write(f)
			if err != nil {
				log.Println("Stream write error:", err)
			}
			fs.Close()
		}(frame)
		time.Sleep(FRAME_INTERVAL)
	}
}

func generateTLSConfig() *tls.Config {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Subject:      pkix.Name{CommonName: "localhost"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/0.9"},
	}
}
