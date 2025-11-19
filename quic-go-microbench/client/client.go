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

	elapsedSec := time.Since(s.startTime).Seconds()
	if elapsedSec-s.lastPrintTime.Sub(s.startTime).Seconds() >= 1.0 {
		start := int(elapsedSec) - 1
		end := int(elapsedSec)
		fmt.Printf("%d-%d sec   %.2f MB   %.2f Mbits/sec\n",
			start,
			end,
			float64(s.intervalRecv)/1_000_000.0,
			float64(s.intervalRecv)/1_000_000.0*8.0)
		s.intervalRecv = 0
		s.lastPrintTime = time.Now()
	}
}

func (s *ClientStats) PrintFinal() {
	elapsed := time.Since(s.startTime).Seconds()

	// 输出最后未满1秒的剩余数据
	if s.intervalRecv > 0 {
		startSec := elapsed - (elapsed - s.lastPrintTime.Sub(s.startTime).Seconds())
		fmt.Printf("%d-%.3f sec   %.2f MB   %.2f Mbits/sec\n",
			int(startSec),
			elapsed,
			float64(s.intervalRecv)/1_000_000.0,
			float64(s.intervalRecv)/1_000_000.0*8.0/(elapsed-startSec))
	}

	fmt.Printf("Recv %.2f MB in %.3f s, goodput %.2f Mbps\n",
		float64(s.bytesRecv)/1_000_000.0,
		elapsed,
		float64(s.bytesRecv)/1_000_000.0*8.0/elapsed)
}

func main() {
	serverAddr := flag.String("p", "127.0.0.1:8080", "server IP and port")
	requestPacketNum := flag.String("n", "1", "request_packet_num")
	flag.Parse()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/0.9"},
	}

	// 连接
	session, err := quic.DialAddr(context.Background(), *serverAddr, tlsConf, nil)
	if err != nil {
		log.Fatal("Dial error:", err)
	}
	defer session.CloseWithError(0, "")

	// 拿上传输流
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
	buf := make([]byte, 65536) //gpt推荐开这么大

	for {
		n, err := stream.Read(buf)
		if n > 0 {
			stats.Add(n)
		}
		if err != nil {
			if err != io.EOF {
				// 忽略 ApplicationError 0x0(关闭时的正常信号)
				if qe, ok := err.(*quic.ApplicationError); ok && qe.ErrorCode == 0 {
					break
				}
				log.Println("Read error:", err)
			}
			break
		}
	}

	stats.PrintFinal()
}
