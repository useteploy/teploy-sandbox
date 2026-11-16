// teploy-guestd is the agent inside a run's VM. The sandbox daemon's VM
// driver reaches it over the hypervisor's vsock device to run commands,
// move files and flush filesystems; see internal/guest for the protocol.
//
// It has no network listener and no authentication of its own: the only
// peer that can reach a guest's vsock port is the hypervisor process that
// owns the VM, which the daemon started.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/useteploy/teploy-sandbox/internal/guest"
)

// version is set at build time.
var version = "dev"

func main() {
	port := flag.Uint("port", guest.Port, "vsock port to listen on")
	workDir := flag.String("workdir", guest.DefaultWorkDir, "directory the files API is confined to and execs start in")
	unixSocket := flag.String("listen-unix", "", "listen on this unix socket instead of vsock (testing; any OS)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if err := os.MkdirAll(*workDir, 0o755); err != nil {
		log.Fatalf("teploy-guestd: workdir: %v", err)
	}
	server := &guest.Server{
		WorkDir: *workDir,
		Agent:   "teploy-guestd/" + version,
		Env:     baseEnv(os.Environ()),
		Logf:    log.Printf,
	}

	var accept func() (io.ReadWriteCloser, error)
	if *unixSocket != "" {
		_ = os.Remove(*unixSocket)
		listener, err := net.Listen("unix", *unixSocket)
		if err != nil {
			log.Fatalf("teploy-guestd: %v", err)
		}
		accept = func() (io.ReadWriteCloser, error) { return listener.Accept() }
		log.Printf("teploy-guestd %s listening on unix socket %s", version, *unixSocket)
	} else {
		listener, err := listenVsock(uint32(*port))
		if err != nil {
			log.Fatalf("teploy-guestd: %v", err)
		}
		accept = listener
		log.Printf("teploy-guestd %s listening on vsock port %d", version, *port)
	}
	for {
		conn, err := accept()
		if err != nil {
			log.Fatalf("teploy-guestd: accept: %v", err)
		}
		go server.ServeConn(conn)
	}
}

// baseEnv is the environment every exec starts from: the agent's own, with
// the things a service manager leaves out filled in so a command sees what
// a login shell would.
func baseEnv(env []string) []string {
	have := make(map[string]bool, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		have[name] = true
	}
	for _, fallback := range []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
		"USER=root",
		"LANG=C.UTF-8",
	} {
		if name, _, _ := strings.Cut(fallback, "="); !have[name] {
			env = append(env, fallback)
		}
	}
	return env
}
