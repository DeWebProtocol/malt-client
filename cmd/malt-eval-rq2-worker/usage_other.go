//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package main

import "fmt"

type processUsage struct {
	cpuNS        uint64
	peakRSSBytes uint64
}

func readProcessUsage() (processUsage, error) {
	return processUsage{}, fmt.Errorf("process CPU and peak RSS accounting is unavailable on this platform")
}
