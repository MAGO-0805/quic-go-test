package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	addr := "127.0.0.1:8080"
	udpAddr, _ := net.ResolveUDPAddr("udp", addr)
	conn, _ := net.ListenUDP("udp", udpAddr)

	tlsConf := generateTLSConfig()
	quicConfig := &quic.Config{
		MaxIncomingStreams:    3000,
		MaxIncomingUniStreams: 3000,
	}

	listener, err := quic.Listen(conn, tlsConf, quicConfig)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Server running on %s", addr)

	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			log.Println("Accept session error:", err)
			continue
		}
		go handleSession(session)
	}
}

func handleSession(session *quic.Conn) {
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
	log.Printf("GetN request: %d frames", numFrames)

	for i := 0; i < numFrames; i++ {
		frame := make([]byte, 5000) // 每帧 5000B
		go func(f []byte) {
			fs, err := session.OpenStreamSync(context.Background())
			if err != nil {
				if qerr, ok := err.(*quic.ApplicationError); ok && qerr.ErrorCode == 0 {
					// 正常关闭的 stream，忽略
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
