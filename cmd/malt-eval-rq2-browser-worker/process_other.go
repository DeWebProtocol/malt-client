//go:build !linux

package main

import "os/exec"

func configureBrowserProcess(_ *exec.Cmd) {}

func forceKillBrowserProcess(command *exec.Cmd) error {
	if command == nil || command.Process == nil {
		return nil
	}
	return command.Process.Kill()
}
