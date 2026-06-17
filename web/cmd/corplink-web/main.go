// Command corplink-web is a self-hosted web control panel for the 飞连/CorpLink
// enterprise VPN. It runs the VPN data plane entirely in userspace (wireguard-go
// + gVisor netstack), exposes a mixed HTTP/SOCKS5 proxy, and serves a web UI +
// REST API to drive login and node selection from the browser.
//
// This is an unofficial third-party implementation with no affiliation to the
// official 飞连 product. The control plane and data plane are reimplemented in
// Go; the protocol follows the upstream Rust client PinkD/corplink-rs.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"corplink-web/internal/corplink"
	"corplink-web/internal/server"
	"corplink-web/internal/vpnmgr"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:6151", "control panel listen address")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [--listen host:port] [config.json]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	configPath := "config.json"
	if flag.NArg() > 0 {
		configPath = flag.Arg(0)
	}

	if err := run(*listen, configPath); err != nil {
		log.Fatalf("corplink-web: %v", err)
	}
}

func run(listen, configPath string) error {
	conf, err := corplink.LoadConfig(configPath)
	if err != nil {
		return err
	}

	mgr, err := vpnmgr.New(conf)
	if err != nil {
		return err
	}

	srv, err := server.New(mgr)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("control panel listening on http://%s", listen)
		if listenIsAllInterfaces(listen) {
			log.Printf("WARNING: control panel has no built-in authentication and is " +
				"bound to all interfaces; protect it with a firewall, reverse proxy " +
				"auth, or set admin_auth_enabled in the config")
		}
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = mgr.Disconnect(ctx)
	return httpServer.Shutdown(ctx)
}

// listenIsAllInterfaces reports whether the listen address binds all interfaces
// (0.0.0.0 / ::), which exposes the unauthenticated control panel to the network.
func listenIsAllInterfaces(listen string) bool {
	host := listen
	if h, _, err := net.SplitHostPort(listen); err == nil {
		host = h
	}
	switch host {
	case "0.0.0.0", "::", "":
		return true
	default:
		return false
	}
}
