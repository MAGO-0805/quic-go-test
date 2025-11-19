package http09

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go"
)

const NextProto = "hq-interop"

type responseWriter struct {
	io.Writer
	headers http.Header
}

var _ http.ResponseWriter = &responseWriter{}

func (w *responseWriter) Header() http.Header {
	if w.headers == nil {
		w.headers = make(http.Header)
	}
	return w.headers
}

func (w *responseWriter) WriteHeader(int) {}

// Server is a HTTP/0.9 server listening for QUIC connections.
type Server struct {
	Handler *http.ServeMux
}

// ServeListener serves HTTP/0.9 on all connections accepted from a QUIC listener.
func (s *Server) ServeListener(ln *quic.EarlyListener) error {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn *quic.Conn) {
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("Error accepting stream: %s\n", err.Error())
			return
		}
		go func() {
			if err := s.handleStream(str); err != nil {
				log.Printf("Handling stream failed: %s\n", err.Error())
			}
		}()
	}
}

func (s *Server) handleStream(str *quic.Stream) error {
	reqBytes, err := io.ReadAll(str) // change byte[] into string
	if err != nil {
		return err
	}
	request := string(reqBytes)
	request = strings.TrimRight(request, "\r\n")
	request = strings.TrimRight(request, " ")

	log.Printf("Received request: %s\n", request)

	// the only code I add!
	if request[:5] == "GETN " {
		sizeStr := strings.TrimPrefix(request, "GETN")
		request_packet, err := strconv.Atoi(sizeStr) // abtain package number
		if err != nil || request_packet < 0 {
			str.CancelWrite(42)
			return nil
		}
		buf := make([]byte, request_packet*(MAX_DATAGRAM_SIZE-50)) // 返回数据
		_, err = str.Write(buf)                                    //send to client
		if err != nil {
			return err
		}

		return str.Close()
	}

	if request[:5] != "GET /" {
		str.CancelWrite(42)
		return nil
	}

	u, err := url.Parse(request[4:])
	if err != nil {
		return err
	}
	u.Scheme = "https"

	req := &http.Request{
		Method:     http.MethodGet,
		Proto:      "HTTP/0.9",
		ProtoMajor: 0,
		ProtoMinor: 9,
		Body:       str,
		URL:        u,
	}

	handler := s.Handler
	if handler == nil {
		handler = http.DefaultServeMux
	}

	var panicked bool
	func() {
		defer func() {
			if p := recover(); p != nil {
				// Copied from net/http/server.go
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				log.Printf("http: panic serving: %v\n%s", p, buf)
				panicked = true
			}
		}()
		handler.ServeHTTP(&responseWriter{Writer: str}, req)
	}()

	if panicked {
		if _, err := str.Write([]byte("500")); err != nil {
			return err
		}
	}
	return str.Close()
}
