// Package gatewayimage builds the gateway container image from the running cellwall binary.
//
// The gateway is this same static binary in a FROM scratch image (no shell, no libc). Building it
// from the binary that is running means the gateway can never be a different version from the CLI
// that configured it, and `init && run` works on a clean Linux machine with nothing to download.
// On other operating systems the host binary cannot run in a Linux container, so the image has to
// come from a release or from `make gateway-image`; Ensure says so rather than guessing.
package gatewayimage

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/middle-systems/cellwall/internal/engine"
)

//go:embed Dockerfile
var dockerfile []byte

// Dockerfile returns the embedded build recipe (used by tests and docs).
func Dockerfile() []byte { return append([]byte(nil), dockerfile...) }

// Tag is the image name the generated compose files use unless told otherwise.
const Tag = "cellwall-gateway:local"

// LabelBinarySHA records which binary an image was built from.
const LabelBinarySHA = "io.cellwall.binary-sha256"

// Outcome says what Ensure did.
type Outcome int

// Outcomes.
const (
	Present  Outcome = iota // the image exists and is usable as it is
	Built                   // it did not exist and was built from this binary
	Rebuilt                 // it was built from an older binary and was rebuilt
	External                // a custom image reference; left to compose to pull
)

func (o Outcome) String() string {
	return [...]string{"present", "built", "rebuilt", "external"}[o]
}

// Options configures Ensure.
type Options struct {
	Runner engine.Runner
	Image  string // image reference compose will use
	Exe    string // path of the running binary; defaults to os.Executable()
	GOOS   string // defaults to runtime.GOOS
	Log    io.Writer
}

// Ensure makes sure the gateway image exists and matches this binary. Only the default Tag is
// built or rebuilt here; any other reference is a deliberate choice (a digest from a release, a
// private registry) and is left alone for compose to pull.
func Ensure(ctx context.Context, o Options) (Outcome, error) {
	if o.Image != Tag {
		return External, nil
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	label, exists, err := inspect(ctx, o.Runner, o.Image)
	if err != nil {
		return 0, err
	}

	exe := o.Exe
	if exe == "" {
		if exe, err = os.Executable(); err != nil {
			return 0, err
		}
	}
	// An image without our label was built by hand (make gateway-image, a release build): trust it.
	if exists && label == "" {
		return Present, nil
	}
	if o.GOOS != "linux" {
		if exists {
			return Present, nil
		}
		return 0, fmt.Errorf("the gateway image %s does not exist, and this %s build of cellwall cannot make one (the gateway is a Linux binary)\n"+
			"  next: build it from a Linux binary with `make gateway-image`, or pass a published image with `cellwall up --gateway-image <ref>`", o.Image, o.GOOS)
	}
	sum, err := fileSHA256(exe)
	if err != nil {
		return 0, err
	}
	if exists && label == sum {
		return Present, nil
	}
	if err := requireStatic(exe); err != nil {
		return 0, err
	}
	if err := build(ctx, o.Runner, exe, sum, o.Image); err != nil {
		return 0, err
	}
	if exists {
		return Rebuilt, nil
	}
	return Built, nil
}

func inspect(ctx context.Context, r engine.Runner, image string) (label string, exists bool, err error) {
	out, err := r.Run(ctx, "docker", "image", "inspect", "--format", `{{index .Config.Labels "`+LabelBinarySHA+`"}}`, image)
	if err != nil {
		var ce *engine.CommandError
		if errors.As(err, &ce) && strings.Contains(strings.ToLower(ce.Stderr), "no such image") {
			return "", false, nil
		}
		return "", false, fmt.Errorf("could not inspect image %s: %w\n  next: check that the container engine is running (`cellwall doctor`)", image, err)
	}
	v := strings.TrimSpace(string(out))
	if v == "<no value>" {
		v = ""
	}
	return v, true, nil
}

func build(ctx context.Context, r engine.Runner, exe, sum, image string) error {
	dir, err := os.MkdirTemp("", "cellwall-gateway-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := copyFile(exe, filepath.Join(dir, "cellwall"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), dockerfile, 0o644); err != nil { //nolint:gosec // build context in a private temp dir
		return err
	}
	if _, err := r.Run(ctx, "docker", "build", "--label", LabelBinarySHA+"="+sum, "-t", image, dir); err != nil {
		return fmt.Errorf("building the gateway image failed: %w\n  next: check that the container engine is running (`cellwall doctor`)", err)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the running executable
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src) //nolint:gosec // the running executable
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, mode) //nolint:gosec // private temp dir
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// requireStatic refuses a dynamically linked binary: it would start in the scratch image only to
// fail with "no such file or directory" because the dynamic loader is missing.
func requireStatic(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return nil // not ELF (a test double): nothing to check
	}
	defer func() { _ = f.Close() }()
	if f.Section(".interp") != nil {
		return fmt.Errorf("%s is dynamically linked and cannot run in the gateway's scratch image\n"+
			"  next: install a release build of cellwall, or build with `CGO_ENABLED=0 go build ./cmd/cellwall`", path)
	}
	return nil
}
