//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package main

import "fmt"

type processUsage struct {
	userCPUNS    uint64
	systemCPUNS  uint64
	peakRSSBytes uint64
}

func readProcessUsage() (processUsage, error) {
	return processUsage{}, fmt.Errorf("client CPU and peak RSS accounting is unavailable on this platform")
}
