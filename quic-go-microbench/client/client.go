package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/quic-go/quic-go"
)

const MAX_DATAGRAM_SIZE = 1350

type ClientStats struct {
	bytesRecv     int
	intervalRecv  int
	startTime     time.Time
	lastPrintTime time.Time
}

func NewClientStats() *ClientStats {
	now := time.Now()
	return &ClientStats{
		bytesRecv:     0,
		intervalRecv:  0,
		lastPrintTime: now,
		startTime:     now,
	}
}

func (s *ClientStats) Add(n int) {
	s.bytesRecv += n
	s.intervalRecv += n
	if time.Since(s.lastPrintTime) >= time.Second {
		fmt.Printf("%d-%d sec   %.2f MB   %.2f Mbits/sec\n",
			int(time.Since(s.startTime).Seconds())-1,
			int(time.Since(s.startTime).Seconds()),
			float64(s.intervalRecv)/1_000_000.0,
			float64(s.intervalRecv)/1_000_000.0*8.0)
		s.intervalRecv = 0
		s.lastPrintTime = time.Now()
	}
}

func (s *ClientStats) PrintFinal() {
	elapsed := time.Since(s.startTime).Seconds()
	fmt.Printf("Recv %.2f MB in %.3f s, goodput %.2f Mbps\n",
		float64(s.bytesRecv)/1_000_000.0,
		elapsed,
		float64(s.bytesRecv)/1_000_000.0*8.0/elapsed)
}

func main() {
	serverAddr := flag.String("p", "127.0.0.1:8080", "server IP and port")
	requestPacketNum := flag.String("n", "1", "request_packet_num")
	flag.Parse()

	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/0.9"}}

	session, err := quic.DialAddr(context.Background(), *serverAddr, tlsConf, nil)
	if err != nil {
		log.Fatal("Dial error:", err)
	}
	defer session.CloseWithError(0, "")

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatal("Open stream error:", err)
	}

	// 发送 GETN 请求
	cmd := "GETN " + *requestPacketNum + "\r\n"
	_, err = stream.Write([]byte(cmd))
	if err != nil {
		log.Fatal("Write GETN error:", err)
	}

	stats := NewClientStats()
	buf := make([]byte, 65536)

	for {
		n, err := stream.Read(buf)
		if n > 0 {
			stats.Add(n)
		}
		if err != nil {
			if err != io.EOF {
				log.Println("Read error:", err)
			}
			break
		}
	}

	stats.PrintFinal()
}
