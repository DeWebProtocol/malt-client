package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"time"

	clientconfig "github.com/dewebprotocol/malt-client/internal/config"
	clientdaemon "github.com/dewebprotocol/malt-client/internal/daemon"
	truststore "github.com/dewebprotocol/malt-client/trust"
	"github.com/spf13/cobra"
)

const (
	daemonInstanceEnv    = "MALT_CLIENT_DAEMON_INSTANCE"
	daemonInstanceHeader = "X-Malt-Client-Instance"
)

type daemonState struct {
	PID      int    `json:"pid"`
	Instance string `json:"instance"`
}

type daemonHealth struct {
	Status string `json:"status"`
	Role   string `json:"role"`
}

var daemonCmd = &cobra.Command{Use: "daemon", Short: "Manage the trusted local client daemon"}

var daemonServeCmd = &cobra.Command{
	Use:    "serve",
	Short:  "Run the trusted client daemon in the foreground",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE:   runDaemonServe,
}

var daemonStartCmd = &cobra.Command{
	Use:           "start",
	Short:         "Start the trusted client daemon",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runDaemonStart,
}

var daemonStatusCmd = &cobra.Command{
	Use:           "status",
	Short:         "Check the trusted client daemon",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
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
	Use:           "stop",
	Short:         "Stop the trusted client daemon",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(*cobra.Command, []string) error {
		cfg, err := loadRuntimeConfig()
		if err != nil {
			return err
		}
		return stopDaemon(cfg.Daemon.SocketPath)
	},
}

var daemonRestartCmd = &cobra.Command{
	Use:           "restart",
	Short:         "Restart the trusted client daemon",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runDaemonRestart,
}

func init() {
	daemonCmd.AddCommand(daemonServeCmd, daemonStartCmd, daemonStatusCmd, daemonStopCmd, daemonRestartCmd)
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
	instance := os.Getenv(daemonInstanceEnv)
	if instance == "" {
		instance, err = newDaemonInstance()
		if err != nil {
			return err
		}
	}
	server, err := clientdaemon.NewWithInstance(store, instance)
	if err != nil {
		return err
	}
	listener, err := server.Listen(cfg.Daemon.SocketPath)
	if err != nil {
		return err
	}
	socketInfo, err := captureDaemonEndpointIdentity(cfg.Daemon.SocketPath)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("record daemon endpoint identity: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = removeDaemonEndpointIfMatch(cfg.Daemon.SocketPath, socketInfo)
	}()
	httpServer := &http.Server{Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), daemonSignals()...)
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
	if err := os.MkdirAll(filepath.Dir(cfg.Daemon.SocketPath), 0o700); err != nil {
		return err
	}
	return withDaemonLifecycleLock(cfg.Daemon.SocketPath, func() error {
		return startDaemonLocked(cfg)
	})
}

func runDaemonRestart(*cobra.Command, []string) error {
	cfg, err := loadRuntimeConfig()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Daemon.SocketPath), 0o700); err != nil {
		return err
	}
	return withDaemonLifecycleLock(cfg.Daemon.SocketPath, func() error {
		if checkDaemon(cfg.Daemon.SocketPath) == nil {
			if err := stopDaemonWithSignalLocked(cfg.Daemon.SocketPath, signalDaemonProcess); err != nil {
				return err
			}
		}
		return startDaemonLocked(cfg)
	})
}

func startDaemonLocked(cfg *clientconfig.Config) error {
	if checkDaemon(cfg.Daemon.SocketPath) == nil {
		return fmt.Errorf("MALT client daemon is already running")
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
	instance, err := newDaemonInstance()
	if err != nil {
		return err
	}
	command.Env = withDaemonInstanceEnv(os.Environ(), instance)
	command.Stdout = logFile
	command.Stderr = logFile
	command.Stdin = nil
	configureDaemonCommand(command)
	if err := command.Start(); err != nil {
		return err
	}
	state := daemonState{PID: command.Process.Pid, Instance: instance}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if checkDaemonInstance(cfg.Daemon.SocketPath, instance) == nil {
			if err := writeDaemonState(pidPath(cfg.Daemon.SocketPath), state); err != nil {
				cleanupStartedDaemon(command)
				return err
			}
			if err := command.Process.Release(); err != nil {
				cleanupStartedDaemon(command)
				_ = removeDaemonStateIfMatch(pidPath(cfg.Daemon.SocketPath), state)
				return fmt.Errorf("release daemon process: %w", err)
			}
			fmt.Printf("MALT client daemon started (%s)\n", cfg.Daemon.SocketPath)
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	cleanupStartedDaemon(command)
	return fmt.Errorf("daemon did not become ready before timeout")
}

func checkDaemon(socketPath string) error {
	_, err := readDaemonHealth(socketPath)
	return err
}

func readDaemonHealth(socketPath string) (daemonHealth, error) {
	client, transport := daemonHTTPClient(socketPath)
	defer transport.CloseIdleConnections()
	resp, err := client.Get("http://malt.local/health")
	if err != nil {
		return daemonHealth{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return daemonHealth{}, fmt.Errorf("daemon health returned %s", resp.Status)
	}
	var health daemonHealth
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 64<<10))
	if err := decoder.Decode(&health); err != nil {
		return daemonHealth{}, fmt.Errorf("decode daemon health: %w", err)
	}
	if health.Status != "ok" || health.Role != "trusted-client" {
		return daemonHealth{}, fmt.Errorf("daemon health response is invalid")
	}
	return health, nil
}

func stopDaemon(socketPath string) error {
	return stopDaemonWithSignal(socketPath, signalDaemonProcess)
}

func stopDaemonWithSignal(socketPath string, signalProcess func(int) error) error {
	return withDaemonLifecycleLock(socketPath, func() error {
		return stopDaemonWithSignalLocked(socketPath, signalProcess)
	})
}

func stopDaemonWithSignalLocked(socketPath string, signalProcess func(int) error) error {
	state, err := readDaemonState(pidPath(socketPath))
	if err != nil {
		return err
	}
	if err := checkDaemonInstance(socketPath, state.Instance); err != nil {
		return fmt.Errorf("refusing to signal daemon because its live identity cannot be verified: %w", err)
	}
	if err := signalProcess(state.PID); err != nil {
		return fmt.Errorf("stop daemon: %w", err)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if checkDaemonInstance(socketPath, state.Instance) != nil {
			_ = removeDaemonStateIfMatch(pidPath(socketPath), state)
			fmt.Println("MALT client daemon stopped")
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("daemon did not stop before timeout")
}

func checkDaemonInstance(socketPath, instance string) error {
	if instance == "" {
		return fmt.Errorf("daemon instance token is empty")
	}
	client, transport := daemonHTTPClient(socketPath)
	defer transport.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, "http://malt.local/_lifecycle/identity", nil)
	if err != nil {
		return err
	}
	req.Header.Set(daemonInstanceHeader, instance)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon lifecycle identity returned %s", resp.Status)
	}
	return nil
}

func pidPath(socketPath string) string { return socketPath + ".pid" }

func lifecycleLockPath(socketPath string) string { return socketPath + ".lifecycle.lock" }

func withDaemonLifecycleLock(socketPath string, operation func() error) error {
	unlock, err := acquireDaemonLifecycleLock(lifecycleLockPath(socketPath))
	if err != nil {
		return fmt.Errorf("acquire daemon lifecycle lock: %w", err)
	}
	defer func() { _ = unlock() }()
	return operation()
}

func newDaemonInstance() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("generate daemon instance token: %w", err)
	}
	return hex.EncodeToString(token[:]), nil
}

func writeDaemonState(path string, state daemonState) error {
	if state.PID <= 0 || state.Instance == "" {
		return fmt.Errorf("daemon state identity is incomplete")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode daemon state: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write daemon state: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("protect daemon state: %w", err)
	}
	return nil
}

func readDaemonState(path string) (daemonState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return daemonState{}, fmt.Errorf("read daemon state: %w", err)
	}
	var state daemonState
	if err := json.Unmarshal(data, &state); err != nil {
		return daemonState{}, fmt.Errorf("decode daemon state: %w", err)
	}
	if state.PID <= 0 || state.Instance == "" {
		return daemonState{}, fmt.Errorf("daemon state identity is incomplete")
	}
	return state, nil
}

func withDaemonInstanceEnv(env []string, instance string) []string {
	prefix := daemonInstanceEnv + "="
	out := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if len(entry) >= len(prefix) && entry[:len(prefix)] == prefix {
			continue
		}
		out = append(out, entry)
	}
	return append(out, prefix+instance)
}

func cleanupStartedDaemon(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Kill()
	_ = command.Wait()
}

func removeDaemonStateIfMatch(path string, expected daemonState) error {
	current, err := readDaemonState(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if current != expected {
		return nil
	}
	return os.Remove(path)
}
