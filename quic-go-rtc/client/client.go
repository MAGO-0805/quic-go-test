package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	serverAddr := flag.String("p", "127.0.0.1:8080", "server IP and port")
	requestFrames := flag.String("f", "300", "request_frames_num")
	flag.Parse()

	numFrames, err := strconv.Atoi(*requestFrames)
	if err != nil || numFrames <= 0 {
		log.Fatal("Invalid number of frames:", *requestFrames)
	}

	seconds := float64(numFrames) / 30.0
	log.Printf("GetN request: %d frames (%.2f seconds)", numFrames, seconds)

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/0.9"},
	}

	session, err := quic.DialAddr(context.Background(), *serverAddr, tlsConf, nil)
	if err != nil {
		log.Fatal("Dial error:", err)
	}
	defer session.CloseWithError(0, "")

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatal("Open stream error:", err)
	}

	cmd := "GETN " + *requestFrames + "\r\n"
	_, err = stream.Write([]byte(cmd))
	if err != nil {
		log.Fatal("Write GETN error:", err)
	}

	totalBytes := 0

	start := time.Now()

	for {
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			// 如果 session 已经关闭，就退出循环
			if session.Context().Err() != nil {
				break
			}
			log.Println("AcceptStream error:", err)
			continue
		}

		go func(s *quic.Stream) {
			defer s.Close()

			buf := make([]byte, 65536)
			for {
				n, err := s.Read(buf)
				if n > 0 {
					totalBytes += n // 注意：多 goroutine 累加时可能需要 sync/atomic
				}
				if err != nil {
					if err != io.EOF {
						// 忽略 ApplicationError(0) 关闭流的正常信号
						if qe, ok := err.(*quic.ApplicationError); ok && qe.ErrorCode == 0 {
							break
						}
						log.Println("Read error in stream:", err)
					}
					break
				}
			}
		}(stream)
	}

	elapsed := time.Since(start).Seconds()
	mb := float64(totalBytes) / 1_000_000.0
	mbps := mb * 8.0 / elapsed

	log.Printf("Received %.2f MB in %.3f s, goodput: %.2f Mbps", mb, elapsed, mbps)
}
