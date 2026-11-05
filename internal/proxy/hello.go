package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// TLS constants used by the ClientHello inspector.
const (
	recordTypeHandshake   = 0x16
	handshakeClientHello  = 0x01
	maxRecordPayload      = 1 << 14 // TLS plaintext fragment limit
	maxHelloBytes         = 1 << 16 // total ClientHello we are willing to buffer
	maxHelloRecords       = 8       // a hello split into more records is not a real client
	extServerName         = uint16(0x0000)
	serverNameTypeHost    = 0x00
	minClientHelloBodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1
)

// echExtensions are the extension code points that carry Encrypted Client Hello (or its ESNI
// predecessor). A hello containing one hides its real destination name from the SNI check.
//
// Be conservative when editing this list: a false positive blocks legitimate clients. In particular
// 0xff01 is renegotiation_info (sent by most OpenSSL-based clients) and the rest of 0xff00-0xffff
// is private use, so none of those belong here. Code points assigned after this list was written
// cannot be detected, which is why docs/threat-model.md calls ECH only partially mitigated.
var echExtensions = map[uint16]bool{
	0xfe0d: true,                                                         // encrypted_client_hello (IANA-assigned)
	0xfe0c: true, 0xfe0b: true, 0xfe0a: true, 0xfe09: true, 0xfe08: true, // ECH draft code points
	0xffce: true, // encrypted_server_name (ESNI draft)
}

// HelloError describes why a ClientHello was rejected. Code is stable and goes in audit records.
type HelloError struct {
	Code string
	Msg  string
}

func (e *HelloError) Error() string { return e.Msg }

// Hello error codes.
const (
	HelloNotTLS       = "not-tls"
	HelloBadRecord    = "bad-record"
	HelloBadHello     = "bad-hello"
	HelloTruncated    = "truncated"
	HelloTooLarge     = "hello-too-large"
	HelloTrailing     = "trailing-data"
	HelloDupExtension = "duplicate-extension"
	HelloBadSNI       = "bad-sni"
	HelloMultiSNI     = "multiple-sni"
)

func helloErr(code, format string, args ...any) *HelloError {
	return &HelloError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// HelloInfo is what the gateway needs to know about a ClientHello.
type HelloInfo struct {
	// SNI is the raw host_name as sent (not yet normalized); empty when HasSNI is false.
	SNI    string
	HasSNI bool
	// ECH is true when any Encrypted Client Hello / ESNI extension is present.
	ECH bool
}

// ReadClientHello reads the first TLS flight from r and returns what it says plus the exact bytes
// consumed, which the caller must forward to the upstream verbatim. It reads whole records only,
// never past the end of the record containing the end of the ClientHello, so it cannot swallow
// application data the client pipelined behind the hello.
//
// A handshake message split across several records is reassembled. Anything that is not a single,
// well-formed ClientHello is an error: the point of the inspection is that the gateway and the
// upstream must agree on what was sent, so ambiguity is refused rather than guessed at.
func ReadClientHello(r io.Reader) (*HelloInfo, []byte, error) {
	var raw bytes.Buffer
	var hs []byte // handshake bytes accumulated across records
	need := -1    // total handshake length once the 4-byte header is known

	for records := 0; ; records++ {
		if records >= maxHelloRecords {
			return nil, raw.Bytes(), helloErr(HelloBadRecord, "ClientHello is split across more than %d records", maxHelloRecords)
		}
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, raw.Bytes(), readErr(err, records == 0)
		}
		raw.Write(hdr[:])
		if hdr[0] != recordTypeHandshake {
			return nil, raw.Bytes(), helloErr(HelloNotTLS, "first byte 0x%02x is not a TLS handshake record (not TLS?)", hdr[0])
		}
		// Record-layer version: 0x0301..0x0304 are what real clients put here (TLS 1.3 uses 0x0301).
		if hdr[1] != 0x03 || hdr[2] > 0x04 || hdr[2] == 0x00 {
			return nil, raw.Bytes(), helloErr(HelloNotTLS, "unsupported TLS record version 0x%02x%02x", hdr[1], hdr[2])
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n == 0 {
			return nil, raw.Bytes(), helloErr(HelloBadRecord, "empty handshake record")
		}
		if n > maxRecordPayload {
			return nil, raw.Bytes(), helloErr(HelloBadRecord, "record length %d exceeds the TLS limit of %d", n, maxRecordPayload)
		}
		if raw.Len()+n > maxHelloBytes {
			return nil, raw.Bytes(), helloErr(HelloTooLarge, "ClientHello is larger than %d bytes", maxHelloBytes)
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, raw.Bytes(), readErr(err, false)
		}
		raw.Write(payload)
		hs = append(hs, payload...)

		if need < 0 && len(hs) >= 4 {
			if hs[0] != handshakeClientHello {
				return nil, raw.Bytes(), helloErr(HelloBadHello, "first handshake message is type %d, not ClientHello", hs[0])
			}
			need = 4 + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
			if need > maxHelloBytes {
				return nil, raw.Bytes(), helloErr(HelloTooLarge, "ClientHello declares %d bytes; the limit is %d", need, maxHelloBytes)
			}
			if need < 4+minClientHelloBodyLen {
				return nil, raw.Bytes(), helloErr(HelloBadHello, "ClientHello is too short to be valid")
			}
		}
		if need >= 0 && len(hs) >= need {
			if len(hs) > need {
				return nil, raw.Bytes(), helloErr(HelloTrailing, "data follows the ClientHello in the same record")
			}
			info, err := ParseClientHello(hs)
			if err != nil {
				return nil, raw.Bytes(), err
			}
			return info, raw.Bytes(), nil
		}
	}
}

func readErr(err error, first bool) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		if first && errors.Is(err, io.EOF) {
			return helloErr(HelloTruncated, "connection closed before sending a TLS ClientHello")
		}
		return helloErr(HelloTruncated, "connection closed in the middle of the ClientHello")
	}
	return err // timeouts and network errors keep their identity
}

// cursor reads big-endian fields with bounds checks; every method fails closed.
type cursor struct {
	b   []byte
	err error
}

func (c *cursor) take(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || n > len(c.b) {
		c.err = helloErr(HelloBadHello, "malformed ClientHello (field overruns message)")
		return nil
	}
	out := c.b[:n]
	c.b = c.b[n:]
	return out
}

func (c *cursor) u8() int {
	b := c.take(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}

func (c *cursor) u16() int {
	return int(c.u16v())
}

func (c *cursor) u16v() uint16 {
	b := c.take(2)
	if b == nil {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}

// ParseClientHello parses a complete handshake message (4-byte header included).
func ParseClientHello(msg []byte) (*HelloInfo, error) {
	if len(msg) < 4 || msg[0] != handshakeClientHello {
		return nil, helloErr(HelloBadHello, "not a ClientHello")
	}
	bodyLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if bodyLen != len(msg)-4 {
		return nil, helloErr(HelloBadHello, "ClientHello length field disagrees with the data")
	}
	c := &cursor{b: msg[4:]}
	c.take(2)  // legacy_version
	c.take(32) // random
	if sid := c.u8(); sid > 32 {
		return nil, helloErr(HelloBadHello, "session id longer than 32 bytes")
	} else {
		c.take(sid)
	}
	cs := c.u16()
	if cs < 2 || cs%2 != 0 {
		return nil, helloErr(HelloBadHello, "invalid cipher suite list length %d", cs)
	}
	c.take(cs)
	if cm := c.u8(); cm < 1 {
		return nil, helloErr(HelloBadHello, "no compression methods")
	} else {
		c.take(cm)
	}
	if c.err != nil {
		return nil, c.err
	}
	info := &HelloInfo{}
	if len(c.b) == 0 {
		return info, nil // no extensions at all: no SNI
	}
	extLen := c.u16()
	if c.err != nil {
		return nil, c.err
	}
	if extLen != len(c.b) {
		return nil, helloErr(HelloBadHello, "extensions length disagrees with the data")
	}
	seen := map[uint16]bool{}
	for len(c.b) > 0 {
		typ := c.u16v()
		n := c.u16()
		data := c.take(n)
		if c.err != nil {
			return nil, c.err
		}
		// RFC 8446 section 4.2: there MUST NOT be more than one extension of the same type.
		// Two server_name or ECH extensions are how a smuggler makes the gateway and the
		// upstream disagree about the destination, so duplicates are refused outright.
		if seen[typ] {
			return nil, helloErr(HelloDupExtension, "extension 0x%04x appears more than once", typ)
		}
		seen[typ] = true
		if echExtensions[typ] {
			info.ECH = true
		}
		if typ == extServerName {
			name, err := parseServerName(data)
			if err != nil {
				return nil, err
			}
			info.SNI, info.HasSNI = name, true
		}
	}
	return info, nil
}

func parseServerName(data []byte) (string, error) {
	c := &cursor{b: data}
	listLen := c.u16()
	if c.err != nil || listLen != len(c.b) {
		return "", helloErr(HelloBadSNI, "malformed server_name extension")
	}
	var name string
	entries := 0
	for len(c.b) > 0 {
		typ := c.u8()
		n := c.u16()
		val := c.take(n)
		if c.err != nil {
			return "", helloErr(HelloBadSNI, "malformed server_name entry")
		}
		entries++
		if entries > 1 {
			return "", helloErr(HelloMultiSNI, "server_name lists more than one name")
		}
		if typ != serverNameTypeHost {
			return "", helloErr(HelloBadSNI, "server_name entry has unknown type %d", typ)
		}
		if len(val) == 0 {
			return "", helloErr(HelloBadSNI, "empty server_name")
		}
		name = string(val)
	}
	if entries == 0 {
		return "", helloErr(HelloBadSNI, "server_name extension is empty")
	}
	return name, nil
}
