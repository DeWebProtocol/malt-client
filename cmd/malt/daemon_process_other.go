//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package main

import (
	"os"
	"os/exec"
)

func configureDaemonCommand(*exec.Cmd) {}

func signalDaemonProcess(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}

func daemonSignals() []os.Signal { return []os.Signal{os.Interrupt} }
