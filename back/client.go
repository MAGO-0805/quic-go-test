package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

const HTTP_REQ_STREAM_ID = 4

// MODE for GET or GetN
type MODE int

const (
	GET MODE = iota
	GetN
)

var REQUEST_MODE = GetN

func fakePacketID() string {
	return fmt.Sprintf("%016x", rand.Uint64())
}

func logSend(t0 time.Time) {
	fmt.Printf("send %.6f %s\n", time.Since(t0).Seconds(), fakePacketID())
}

func logRecv(t0 time.Time) {
	fmt.Printf("recv %.6f %s\n", time.Since(t0).Seconds(), fakePacketID())
}

func main() {
	startTime := flag.Float64("start", 0.0, "start time float")
	urlStr := flag.String("url", "https://127.0.0.1:4433", "server url")
	requestPackets := flag.Int("n", 10, "number of packets for GetN")
	flag.Parse()

	rand.Seed(time.Now().UnixNano())
	t0 := time.Now()

	parsed, err := url.Parse(*urlStr)
	if err != nil {
		log.Fatal("url parse error:", err)
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"hq-interop", "hq-29", "hq-28", "hq-27", "http/0.9"},
	}

	quicConf := &quic.Config{
		EnableDatagrams: false,
		MaxIdleTimeout:  time.Second * 5,
		KeepAlivePeriod: time.Second * 2,
	}

	conn, err := quic.DialAddr(parsed.Host, tlsConf, quicConf)
	if err != nil {
		log.Fatal("dial error:", err)
	}
	defer conn.CloseWithError(0, "bye")

	stream, err := conn.OpenStreamSync()
	if err != nil {
		log.Fatal("open stream error:", err)
	}

	// Send request
	var req string
	if REQUEST_MODE == GET {
		req = fmt.Sprintf("GET %s\r\n", parsed.Path)
	} else {
		req = fmt.Sprintf("GetN %d\r\n", *requestPackets)
	}

	_, err = stream.Write([]byte(req))
	if err != nil {
		log.Fatal("send request error:", err)
	}
	logSend(t0)

	reader := bufio.NewReader(stream)

	for {
		buf := make([]byte, 1500)
		n, err := reader.Read(buf)
		if n > 0 {
			logRecv(t0)
			if REQUEST_MODE == GET {
				fmt.Print(string(buf[:n]))
			} else {
				// GetN, ignore content, just debug
				log.Printf("received %d bytes", n)
			}
		}
		if err != nil {
			break
		}
	}
}
