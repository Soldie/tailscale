// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdns

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"inet.af/netaddr"
	"tailscale.com/types/logger"
)

// headerBytes is the number of bytes in a DNS message header.
const headerBytes = 12

// forwardQueueSize is the maximal number of requests that can be pending delegation.
// Note that this is distinct from the number of requests that are pending a response,
// which is not limited (except by txid collisions).
const forwardQueueSize = 64

// connCount is the number of UDP connections to use for forwarding.
const connCount = 32

var errNoUpstreams = errors.New("upstream nameservers not set")

var aLongTimeAgo = time.Unix(0, 1)

type forwardedPacket struct {
	// payload is the content of the packet.
	payload []byte
	// addr is the address to forward to.
	addr net.Addr
}

type forwarder struct {
	logf logger.Logf

	// queue is the queue for delegated packets.
	queue chan forwardedPacket
	// responses is a channel by which responses are returned.
	responses chan Packet
	// closed signals all goroutines to stop.
	closed chan struct{}
	// wg signals when all goroutines have stopped.
	wg sync.WaitGroup

	// conns are the UDP connections used for delegation.
	// A random one is selected for each request, regardless of the target upstream.
	conns []*net.UDPConn

	mu sync.Mutex
	// upstreams is the list of nameserver addresses that should be used for forwarding.
	upstreams []net.Addr
	// txToAddr is the map of
	txToAddr map[uint16]netaddr.IPPort
}

func newForwarder(logf logger.Logf, responses chan Packet) *forwarder {
	return &forwarder{
		logf:      logger.WithPrefix(logf, "forward: "),
		responses: responses,
		queue:     make(chan forwardedPacket, forwardQueueSize),
		closed:    make(chan struct{}),
		conns:     make([]*net.UDPConn, connCount),
		txToAddr:  make(map[uint16]netaddr.IPPort),
	}
}

func (f *forwarder) Start() error {
	var err error

	for i := range f.conns {
		f.conns[i], err = net.ListenUDP("udp", nil)
		if err != nil {
			return err
		}
	}

	f.wg.Add(2 * connCount)
	for idx, conn := range f.conns {
		go f.send()
		go f.recv(uint16(idx), conn)
	}

	return nil
}

func (f *forwarder) Close() {
	select {
	case <-f.closed:
		return
	default:
		// continue
	}
	close(f.closed)

	for _, conn := range f.conns {
		conn.SetDeadline(aLongTimeAgo)
	}

	f.wg.Wait()

	for _, conn := range f.conns {
		conn.Close()
	}
}

func (f *forwarder) setUpstreams(upstreams []net.Addr) {
	f.mu.Lock()
	f.upstreams = upstreams
	f.mu.Unlock()
}

func (f *forwarder) send() {
	defer f.wg.Done()

	var packet forwardedPacket
	for {
		select {
		case <-f.closed:
			return
		case packet = <-f.queue:
			// continue
		}

		connIdx := rand.Intn(connCount)
		conn := f.conns[connIdx]
		_, err := conn.WriteTo(packet.payload, packet.addr)
		if err != nil {
			// Do not log errors due to expired deadline.
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				f.logf("send: %v", err)
			}
			return
		}
	}
}

func (f *forwarder) recv(connIdx uint16, conn *net.UDPConn) {
	defer f.wg.Done()

	for {
		out := make([]byte, maxResponseBytes)
		n, err := conn.Read(out)

		if err != nil {
			// Do not log errors due to expired deadline.
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				f.logf("send: %v", err)
			}
			return
		}

		if n < headerBytes {
			f.logf("recv: packet too small (%d bytes)", n)
		}

		txid := binary.BigEndian.Uint16(out[0:2])
		f.mu.Lock()
		addr, found := f.txToAddr[txid]
		delete(f.txToAddr, txid)
		f.mu.Unlock()

		// At most one nameserver will return a response:
		// the first one to do so will delete txid from the map.
		if !found {
			return
		}

		packet := Packet{
			Payload: out[:n],
			Addr:    addr,
		}
		select {
		case <-f.closed:
			return
		case f.responses <- packet:
			// continue
		}
	}
}

// forward forwards the query to all upstream nameservers and returns the first response.
func (f *forwarder) forward(query Packet) error {
	txid := binary.BigEndian.Uint16(query.Payload[0:2])

	f.mu.Lock()
	upstreams := f.upstreams
	f.txToAddr[txid] = query.Addr
	f.mu.Unlock()

	if len(upstreams) == 0 {
		f.mu.Lock()
		delete(f.txToAddr, txid)
		f.mu.Unlock()
		return errNoUpstreams
	}

	packet := forwardedPacket{
		payload: query.Payload,
	}
	for _, upstream := range upstreams {
		packet.addr = upstream
		select {
		case <-f.closed:
			return ErrClosed
		case f.queue <- packet:
			// continue
		}
	}

	return nil
}
