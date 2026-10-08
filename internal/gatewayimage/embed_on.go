//go:build embedgw

package gatewayimage

import _ "embed"

// Release builds for macOS and Windows carry the Linux gateway, because the host binary cannot run
// in a Linux container. The release pipeline builds these two files first (CGO_ENABLED=0), then
// builds the host binaries with `-tags embedgw`.

//go:embed embedded/cellwall-linux-amd64
var linuxAMD64 []byte

//go:embed embedded/cellwall-linux-arm64
var linuxARM64 []byte

func embeddedBinary(arch string) ([]byte, bool) {
	switch arch {
	case "amd64":
		return linuxAMD64, len(linuxAMD64) > 0
	case "arm64":
		return linuxARM64, len(linuxARM64) > 0
	}
	return nil, false
}
