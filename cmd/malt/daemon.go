package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	clientdaemon "github.com/dewebprotocol/malt-client/internal/daemon"
	"github.com/dewebprotocol/malt-client/internal/truststore"
	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{Use: "daemon", Short: "Manage the trusted local client daemon"}

var daemonServeCmd = &cobra.Command{
	Use:    "serve",
	Short:  "Run the trusted client daemon in the foreground",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE:   runDaemonServe,
}

var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the trusted client daemon",
	Args:  cobra.NoArgs,
	RunE:  runDaemonStart,
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check the trusted client daemon",
	Args:  cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error {
		cfg, err := loadRuntimeConfig()
		if err != nil {
			return err
		}
		if err := checkDaemon(cfg.Daemon.SocketPath); err != nil {
			return err
		}
		fmt.Println("MALT client daemon is running")
		return nil
	},
}

var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the trusted client daemon",
	Args:  cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error {
		cfg, err := loadRuntimeConfig()
		if err != nil {
			return err
		}
		pidBytes, err := os.ReadFile(pidPath(cfg.Daemon.SocketPath))
		if err != nil {
			return fmt.Errorf("read daemon pid: %w", err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
		if err != nil {
			return fmt.Errorf("decode daemon pid: %w", err)
		}
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			return fmt.Errorf("stop daemon: %w", err)
		}
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			if checkDaemon(cfg.Daemon.SocketPath) != nil {
				fmt.Println("MALT client daemon stopped")
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return fmt.Errorf("daemon did not stop before timeout")
	},
}

func init() {
	daemonCmd.AddCommand(daemonServeCmd, daemonStartCmd, daemonStatusCmd, daemonStopCmd)
	rootCmd.AddCommand(daemonCmd)
}

func runDaemonServe(*cobra.Command, []string) error {
	cfg, err := loadRuntimeConfig()
	if err != nil {
		return err
	}
	store, err := truststore.Open(cfg.Daemon.StatePath)
	if err != nil {
		return err
	}
	server, err := clientdaemon.New(store)
	if err != nil {
		return err
	}
	listener, err := server.Listen(cfg.Daemon.SocketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(cfg.Daemon.SocketPath)
		_ = os.Remove(pidPath(cfg.Daemon.SocketPath))
	}()
	if err := os.WriteFile(pidPath(cfg.Daemon.SocketPath), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		return err
	}
	httpServer := &http.Server{Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	if err := httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func runDaemonStart(*cobra.Command, []string) error {
	cfg, err := loadRuntimeConfig()
	if err != nil {
		return err
	}
	if checkDaemon(cfg.Daemon.SocketPath) == nil {
		return fmt.Errorf("MALT client daemon is already running")
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Daemon.SocketPath), 0o700); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{}
	if cfgFile != "" {
		args = append(args, "--config", cfgFile)
	}
	args = append(args, "daemon", "serve")
	logFile, err := os.OpenFile(filepath.Join(filepath.Dir(cfg.Daemon.SocketPath), "daemon.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	command := exec.Command(executable, args...)
	command.Stdout = logFile
	command.Stderr = logFile
	command.Stdin = nil
	if err := command.Start(); err != nil {
		return err
	}
	_ = command.Process.Release()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if checkDaemon(cfg.Daemon.SocketPath) == nil {
			fmt.Printf("MALT client daemon started (%s)\n", cfg.Daemon.SocketPath)
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("daemon did not become ready before timeout")
}

func checkDaemon(socketPath string) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socketPath)
	}}
	client := &http.Client{Transport: transport, Timeout: time.Second}
	resp, err := client.Get("http://malt.local/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon health returned %s", resp.Status)
	}
	return nil
}

func pidPath(socketPath string) string { return socketPath + ".pid" }
