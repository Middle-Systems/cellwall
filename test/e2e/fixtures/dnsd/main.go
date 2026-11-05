// Command dnsd is a tiny authoritative DNS server for the end-to-end tests. It answers A and AAAA
// queries for the names given as name=ip[,ip...] arguments and returns NXDOMAIN for anything else.
// It exists so tests can make ordinary-looking hostnames resolve to loopback, private, link-local
// and metadata addresses without touching real DNS.
package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
)

var records = map[string][]netip.Addr{}

func main() {
	for _, arg := range os.Args[1:] {
		name, ips, ok := strings.Cut(arg, "=")
		if !ok {
			log.Fatalf("bad argument %q (want name=ip[,ip])", arg)
		}
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		for _, s := range strings.Split(ips, ",") {
			a, err := netip.ParseAddr(s)
			if err != nil {
				log.Fatalf("bad address %q: %v", s, err)
			}
			records[name] = append(records[name], a)
		}
	}
	pc, err := net.ListenPacket("udp", ":53")
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", ":53")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("dnsd serving %d names", len(records))
	go serveTCP(ln)
	buf := make([]byte, 512)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}
		if resp := answer(buf[:n]); resp != nil {
			_, _ = pc.WriteTo(resp, addr)
		}
	}
}

func serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			var l [2]byte
			if _, err := io.ReadFull(c, l[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(l[:]))
			if _, err := io.ReadFull(c, q); err != nil {
				return
			}
			if resp := answer(q); resp != nil {
				out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
				_, _ = c.Write(append(out, resp...))
			}
		}()
	}
}

// answer builds a response to a single-question query, or nil if the query is unusable.
func answer(q []byte) []byte {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil
	}
	i := 12
	var labels []string
	for {
		if i >= len(q) {
			return nil
		}
		l := int(q[i])
		if l == 0 {
			i++
			break
		}
		if l&0xc0 != 0 || i+1+l > len(q) {
			return nil
		}
		labels = append(labels, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	if i+4 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[i : i+2])
	end := i + 4
	name := strings.ToLower(strings.Join(labels, "."))

	addrs, known := records[name]
	resp := append([]byte(nil), q[:end]...)
	flags := uint16(0x8180) // QR, RD, RA
	if !known {
		flags |= 3 // NXDOMAIN
	}
	binary.BigEndian.PutUint16(resp[2:4], flags)
	var rrs [][]byte
	for _, a := range addrs {
		var data []byte
		switch {
		case qtype == 1 && a.Is4():
			b := a.As4()
			data = b[:]
		case qtype == 28 && (a.Is6() || a.Is4In6()):
			b := a.As16()
			data = b[:]
		default:
			continue
		}
		rr := []byte{0xc0, 0x0c}
		rr = binary.BigEndian.AppendUint16(rr, qtype)
		rr = binary.BigEndian.AppendUint16(rr, 1) // IN
		rr = binary.BigEndian.AppendUint32(rr, 1) // TTL 1s: never cached across test steps
		rr = binary.BigEndian.AppendUint16(rr, uint16(len(data)))
		rrs = append(rrs, append(rr, data...))
	}
	binary.BigEndian.PutUint16(resp[6:8], uint16(len(rrs))) // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:12], 0)               // NSCOUNT, ARCOUNT
	for _, rr := range rrs {
		resp = append(resp, rr...)
	}
	return resp
}
