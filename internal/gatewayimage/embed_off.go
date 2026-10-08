//go:build !embedgw

package gatewayimage

// embeddedBinary is empty in a plain build: only release builds for macOS and Windows carry the
// Linux gateway binaries (see embed_on.go and .goreleaser.yaml).
func embeddedBinary(arch string) ([]byte, bool) { return nil, false }
