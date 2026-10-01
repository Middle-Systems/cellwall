// Package proxytest builds TLS ClientHello byte streams for tests. It is only imported by tests,
// so none of it is linked into the shipped binary.
package proxytest

import "encoding/binary"

// HelloOpts describes a ClientHello to build. The zero value is a plausible hello with no SNI.
type HelloOpts struct {
	SNI        string   // host_name to send; empty means no server_name extension
	ExtraSNI   []string // additional host_name entries inside the same server_name extension
	DupSNIExt  bool     // include the server_name extension twice
	ECH        uint16   // if non-zero, add an extension with this code point (e.g. 0xfe0d)
	NoExt      bool     // omit the extensions block entirely
	SessionID  int      // session id length
	RecordSize []int    // split the handshake message across records of these payload sizes
	Version    [2]byte  // record-layer version; default 0x0301
	Trailing   []byte   // bytes appended after the ClientHello inside the final record
	Pad        int      // add a padding extension (0x0015) of this many bytes
}

func u16(v int) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, uint16(v)); return b } // #nosec G115

func ext(typ int, data []byte) []byte {
	out := append(u16(typ), u16(len(data))...)
	return append(out, data...)
}

func serverNameExt(names []string) []byte {
	var list []byte
	for _, n := range names {
		list = append(list, 0x00)
		list = append(list, u16(len(n))...)
		list = append(list, n...)
	}
	return ext(0x0000, append(u16(len(list)), list...))
}

// Handshake returns the ClientHello handshake message (4-byte header + body).
func Handshake(o HelloOpts) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, byte(o.SessionID))
	body = append(body, make([]byte, o.SessionID)...)
	body = append(body, u16(4)...)              // cipher suites: two suites
	body = append(body, 0x13, 0x01, 0xc0, 0x2f) //
	body = append(body, 0x01, 0x00)             // compression: null only
	if !o.NoExt {
		var exts []byte
		if o.SNI != "" {
			names := append([]string{o.SNI}, o.ExtraSNI...)
			exts = append(exts, serverNameExt(names)...)
			if o.DupSNIExt {
				exts = append(exts, serverNameExt([]string{o.SNI})...)
			}
		}
		exts = append(exts, ext(0x000a, append(u16(2), 0x00, 0x1d))...) // supported_groups
		exts = append(exts, ext(0x002b, []byte{0x02, 0x03, 0x04})...)   // supported_versions
		if o.ECH != 0 {
			exts = append(exts, ext(int(o.ECH), []byte{0x00, 0x01, 0x02, 0x03})...)
		}
		if o.Pad > 0 {
			exts = append(exts, ext(0x0015, make([]byte, o.Pad))...)
		}
		body = append(body, u16(len(exts))...)
		body = append(body, exts...)
	}
	msg := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...)
}

// Records returns the full byte stream: the handshake split into TLS records.
func Records(o HelloOpts) []byte {
	hs := append(Handshake(o), o.Trailing...)
	ver := o.Version
	if ver == [2]byte{} {
		ver = [2]byte{0x03, 0x01}
	}
	sizes := o.RecordSize
	if len(sizes) == 0 {
		sizes = []int{len(hs)}
	}
	var out []byte
	for i := 0; len(hs) > 0; i++ {
		n := len(hs)
		if i < len(sizes) && sizes[i] < n {
			n = sizes[i]
		}
		out = append(out, 0x16, ver[0], ver[1])
		out = append(out, u16(n)...)
		out = append(out, hs[:n]...)
		hs = hs[n:]
	}
	return out
}
