package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	HTTP_REQ_STREAM_ID = 4
)

// MODE for GET or GetN
type MODE int

const (
	GET MODE = iota
	GetN
)

var REQUEST_MODE = GetN

// generate fake packet id (since quic-go won't expose QUIC packet numbers)
func fakePacketID() string {
	return fmt.Sprintf("%016x", rand.Uint64())
}

// print timestamp + packetID (simulate microbench)
func logSend(t0 time.Time) {
	fmt.Printf("send %.6f %s\n", time.Since(t0).Seconds(), fakePacketID())
}

func logRecv(t0 time.Time) {
	fmt.Printf("recv %.6f %s\n", time.Since(t0).Seconds(), fakePacketID())
}

// return QUIC listener
func createListener(addr, certFile, keyFile string) (quic.Listener, error) {
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		NextProtos:         []string{"hq-interop", "hq-29", "hq-28", "hq-27", "http/0.9"},
		InsecureSkipVerify: true,
	}

	return quic.ListenAddr(addr, tlsCfg, &quic.Config{
		EnableDatagrams: false,
		MaxIdleTimeout:  time.Second * 5,
		KeepAlivePeriod: time.Second * 2,
	})
}

func serveConn(conn quic.Connection, t0 time.Time) {
	defer conn.CloseWithError(0, "bye")

	stream, err := conn.AcceptStream(nil)
	if err != nil {
		log.Println("accept stream error:", err)
		return
	}

	reader := bufio.NewReader(stream)
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Println("read request err:", err)
		return
	}

	line = strings.TrimSpace(line)

	var requestN int
	var mode MODE = GET

	if strings.HasPrefix(line, "GetN ") {
		mode = GetN
		requestN, _ = strconv.Atoi(strings.TrimPrefix(line, "GetN "))
	} else if strings.HasPrefix(line, "GET ") {
		mode = GET
	}

	if mode == GET {
		body := "Hello from quic-go microbench GET\n"
		logSend(t0)
		stream.Write([]byte(body))
		stream.Close()
		return
	}

	if mode == GetN {
		packet := make([]byte, 1200)
		for i := 0; i < requestN; i++ {
			rand.Read(packet) // fill junk data
			logSend(t0)
			_, err := stream.Write(packet)
			if err != nil {
				log.Println("send error:", err)
				break
			}
		}
		stream.Close()
		return
	}
}

func main() {
	addr := flag.String("addr", ":4433", "listen address")
	cert := flag.String("cert", "cert/cert.pem", "path to cert")
	key := flag.String("key", "cert/key.pem", "path to key")
	flag.Parse()

	rand.Seed(time.Now().UnixNano())

	l, err := createListener(*addr, *cert, *key)
	if err != nil {
		log.Fatal("listener error:", err)
	}

	log.Println("QUIC server running at", *addr)

	var wg sync.WaitGroup

	for {
		conn, err := l.Accept(nil)
		if err != nil {
			log.Println("accept conn error:", err)
			continue
		}

		wg.Add(1)
		go func(c quic.Connection) {
			defer wg.Done()
			start0 := time.Now()
			logRecv(start0)
			serveConn(c, start0)
		}(conn)
	}
}
