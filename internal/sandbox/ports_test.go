package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1435 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11112 1
   2: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11113 1
   3: 00000000:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11114 1
   4: 0100007F:C350 0100007F:1435 01 00000000:00000000 00:00000000 00000000  1000        0 11115 1
   5: 0200A8C0:1388 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11116 1
`

const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1B58 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22221 1
   1: 00000000000000000000000000000000:1B59 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22222 1
`

func TestClassifyListeners(t *testing.T) {
	got := ClassifyListeners(procTCP + procTCP6)
	want := map[int]string{
		5173: ListenAll,      // 0.0.0.0
		8080: ListenLoopback, // 127.0.0.1 only: the gateway cannot reach it
		3000: ListenAll,      // both loopback and all interfaces: reachable
		5000: ListenAll,      // 192.168.0.2 (a specific, non-loopback address)
		7000: ListenLoopback, // ::1
		7001: ListenAll,      // ::
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
	if _, ok := got[0xC350]; ok {
		t.Error("an established connection is not a listener")
	}
	if len(ClassifyListeners("")) != 0 || len(ClassifyListeners("garbage\nmore garbage")) != 0 {
		t.Error("unparseable input must yield nothing")
	}
}

func TestChangePortsEditsConfigAndRegeneratesCompose(t *testing.T) {
	root, global := project(t)
	e := Env{Runner: &fakeEngine{root: root}, GlobalDir: global}

	res, err := ChangePorts(context.Background(), e, root, []int{3000, 5173}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Ports, []int{3000, 5173}) || res.GatewayReset {
		t.Errorf("result = %+v", res)
	}
	compose := readFile(t, root, ".devcontainer/compose.yaml")
	for _, want := range []string{`"--forward-port"`, `"3000"`, `"5173"`, "host_ip: 127.0.0.1", "published: \"3000\""} {
		if !strings.Contains(compose, want) {
			t.Errorf("compose lacks %q", want)
		}
	}
	if !strings.Contains(readFile(t, root, ".kennel/config.yaml"), "ports: [3000, 5173]") {
		t.Errorf("config:\n%s", readFile(t, root, ".kennel/config.yaml"))
	}

	// Adding the same port again is a no-op.
	res, err = ChangePorts(context.Background(), e, root, []int{3000}, nil)
	if err != nil || len(res.Added) != 0 || len(res.Written) != 0 {
		t.Errorf("re-adding: %+v %v", res, err)
	}

	res, err = ChangePorts(context.Background(), e, root, nil, []int{3000, 5173})
	if err != nil || len(res.Ports) != 0 {
		t.Fatalf("remove: %+v %v", res, err)
	}
	if strings.Contains(readFile(t, root, ".devcontainer/compose.yaml"), "--forward-port") {
		t.Error("a gateway with no preview ports must not be told to forward any")
	}
}

func TestChangePortsRefusesInvalidPortsAndLeavesFilesAlone(t *testing.T) {
	root, global := project(t)
	e := Env{Runner: &fakeEngine{root: root}, GlobalDir: global}
	beforeCfg := readFile(t, root, ".kennel/config.yaml")
	beforeCompose := readFile(t, root, ".devcontainer/compose.yaml")

	for _, port := range []int{80, 3128, 3129, 70000} {
		if _, err := ChangePorts(context.Background(), e, root, []int{port}, nil); err == nil {
			t.Errorf("port %d should be refused", port)
		}
	}
	if readFile(t, root, ".kennel/config.yaml") != beforeCfg || readFile(t, root, ".devcontainer/compose.yaml") != beforeCompose {
		t.Error("a refused change modified files")
	}
	if _, err := ChangePorts(context.Background(), e, root, nil, []int{4242}); err == nil || !strings.Contains(err.Error(), "ports ls") {
		t.Errorf("removing an unknown port: %v", err)
	}
}

func TestChangePortsDoesNotOverwriteAHandEditedComposeFile(t *testing.T) {
	root, global := project(t)
	e := Env{Runner: &fakeEngine{root: root}, GlobalDir: global}
	path := filepath.Join(root, ".devcontainer", "compose.yaml")
	b, _ := os.ReadFile(path)
	edited := string(b) + "\n# my own change\n"
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	beforeCfg := readFile(t, root, ".kennel/config.yaml")

	_, err := ChangePorts(context.Background(), e, root, []int{3000}, nil)
	if err == nil || !strings.Contains(err.Error(), "compose.yaml") || !strings.Contains(err.Error(), "next:") {
		t.Fatalf("got %v", err)
	}
	if readFile(t, root, ".devcontainer/compose.yaml") != edited {
		t.Error("the user's compose file was overwritten")
	}
	if readFile(t, root, ".kennel/config.yaml") != beforeCfg {
		t.Error("the config edit was not undone")
	}
}

func TestCheckHostPorts(t *testing.T) {
	if err := CheckHostPorts(nil); err != nil {
		t.Fatal(err)
	}
	ln, port := listenLoopback(t)
	defer func() { _ = ln.Close() }()
	err := CheckHostPorts([]int{port})
	if err == nil || !strings.Contains(err.Error(), "already in use") || !strings.Contains(err.Error(), "next:") {
		t.Fatalf("got %v", err)
	}
}
