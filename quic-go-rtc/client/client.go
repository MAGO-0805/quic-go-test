package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	serverAddr := flag.String("p", "127.0.0.1:8080", "server IP:port")
	requestFrames := flag.Int("f", 300, "number of frames to request")
	frameSize := flag.Int("s", 5000, "frame size in bytes")
	t := flag.Float64("t", 0.0, "Start time of the test (unix seconds, 0 means now)")
	flag.Parse()

	// compute baseline time for logs: if t==0 use now, else use provided unix seconds (with fraction)
	var baseline time.Time
	if *t == 0.0 {
		baseline = time.Now()
	} else {
		sec := int64(*t)
		nsec := int64((*t - float64(sec)) * 1e9)
		baseline = time.Unix(sec, nsec)
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/0.9"},
	}

	session, err := quic.DialAddr(context.Background(), *serverAddr, tlsConf, nil)
	if err != nil {
		log.Fatal("Dial error:", err)
	}
	defer session.CloseWithError(0, "")

	log.Printf("GetN request: %d frames ( %d seconds)", *requestFrames, int(*requestFrames/30))
	// 发送 GETN 请求
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatal("Open stream error:", err)
	}
	cmd := fmt.Sprintf("GETN %d\r\n", *requestFrames)
	if _, err := stream.Write([]byte(cmd)); err != nil {
		log.Fatal("Write GETN error:", err)
	}

	totalBytes := 0
	var totalBytesMutex sync.Mutex
	var wg sync.WaitGroup
	var frameCounter int64

	// record the actual request start time (for elapsed/goodput)
	requestStart := time.Now()

	// 接收每个 server-initiated uni stream
	wg.Add(*requestFrames)
	for i := 0; i < *requestFrames; i++ {
		go func() {
			defer wg.Done()

			s, err := session.AcceptUniStream(context.Background())
			if err != nil {
				if qerr, ok := err.(*quic.ApplicationError); ok && qerr.ErrorCode == 0 {
					// 正常关闭的 stream，忽略
					return
				} else {
					log.Println("AcceptUniStream error:", err)
					return
				}
			}

			buf := make([]byte, *frameSize)
			for {
				n, err := s.Read(buf)
				if n > 0 {
					totalBytesMutex.Lock()
					totalBytes += n
					totalBytesMutex.Unlock()
				}
				if err != nil {
					if err != io.EOF {
						log.Println("Read stream error:", err)
					}
					break
				}
			}
			// When stream finished, increment frame counter and print fin time
			id := int(atomic.AddInt64(&frameCounter, 1))
			// print fin time relative to baseline (-t)
			fmt.Printf("frame %d, fin time: %.6f\n", id, time.Since(baseline).Seconds())
		}()
	}

	// 等待所有帧接收完成
	wg.Wait()

	elapsed := time.Since(requestStart).Seconds()
	mb := float64(totalBytes) / 1_000_000.0
	mbps := mb * 8.0 / elapsed

	log.Printf("Received %.2f MB in %.3f s, goodput: %.2f Mbps", mb, elapsed, mbps)
}
