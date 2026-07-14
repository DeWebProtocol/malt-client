//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

const (
	createNewProcessGroup = 0x00000200
	detachProcess         = 0x00000008
)

func configureDaemonCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewProcessGroup | detachProcess}
}

func signalDaemonProcess(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}

func daemonSignals() []os.Signal { return []os.Signal{os.Interrupt} }
