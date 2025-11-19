package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go"
)

const NextProto = "http/0.9"

// RoundTripper performs HTTP/0.9 roundtrips over QUIC.
type RoundTripper struct {
	mutex sync.Mutex

	TLSClientConfig    *tls.Config
	QuicConfig         *quic.Config
	request_packet_num string

	clients map[string]*client
}

var _ http.RoundTripper = &RoundTripper{}

// RoundTrip performs a HTTP/0.9 request.
// It only supports GET requests.
func (r *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	log.Printf("Requesting %s.\n", req.URL)

	r.mutex.Lock()
	hostname := hostnameFromRequest(req)
	println(hostname)
	if r.clients == nil {
		r.clients = make(map[string]*client)
	}
	c, ok := r.clients[hostname]
	if !ok {
		tlsConf := &tls.Config{}
		if r.TLSClientConfig != nil {
			tlsConf = r.TLSClientConfig.Clone()
		}
		tlsConf.NextProtos = []string{NextProto}
		c = &client{
			hostname: hostname,
			tlsConf:  tlsConf,
			quicConf: r.QuicConfig,
		}
		r.clients[hostname] = c
	}
	r.mutex.Unlock()
	return c.RoundTrip(req, r.request_packet_num)
}

// Close closes the roundtripper.
func (r *RoundTripper) Close() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for id, c := range r.clients {
		if err := c.Close(); err != nil {
			return err
		}
		delete(r.clients, id)
	}
	return nil
}

type client struct {
	hostname string
	tlsConf  *tls.Config
	quicConf *quic.Config

	once    sync.Once
	conn    *quic.Conn
	dialErr error
}

// moderate
func (c *client) RoundTrip(req *http.Request, request_packet_num string) (*http.Response, error) {
	c.once.Do(func() {
		c.conn, c.dialErr = quic.DialAddrEarly(context.Background(), c.hostname, c.tlsConf, c.quicConf)
	})
	if c.dialErr != nil {
		return nil, c.dialErr
	}
	return c.doRequest(req, request_packet_num)
}

// moderate
func (c *client) doRequest(req *http.Request, request_packet_num string) (*http.Response, error) {
	str, err := c.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	cmd := "GETN " + request_packet_num + "\r\n"
	if _, err := str.Write([]byte(cmd)); err != nil {
		return nil, err
	}
	if err := str.Close(); err != nil {
		return nil, err
	}
	rsp := &http.Response{
		Proto:      "HTTP/0.9",
		ProtoMajor: 0,
		ProtoMinor: 9,
		Request:    req,
		Body:       io.NopCloser(str),
	}
	return rsp, nil
}

func (c *client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.CloseWithError(0, "")
}

func hostnameFromRequest(req *http.Request) string {
	if req.URL != nil {
		return req.URL.Host
	}
	return ""
}

func main() {
	var (
		Addr             = flag.String("p", "127.0.0.1:8080", "server_IP") // 字符串类型
		requestPacketNum = flag.String("n", "1", "request_packet_num")
		//start_time = flag.Float64("s", 0.0, "start time")        // 整数类型
	)
	flag.Parse()
	rt := &RoundTripper{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		request_packet_num: *requestPacketNum,
	}
	defer rt.Close()

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s", *Addr), nil)
	if err != nil {
		log.Fatalf("NewRequest error: %v", err)
	}

	rsp, err := rt.RoundTrip(req)
	if err != nil {
		log.Fatalf("request error: %v", err)
	}
	defer rsp.Body.Close()

	data, _ := io.ReadAll(rsp.Body)
	fmt.Printf("Response: %s\n", data)
}
