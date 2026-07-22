//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import "golang.org/x/sys/unix"

type processUsage struct {
	cpuNS        uint64
	peakRSSBytes uint64
}

func readProcessUsage() (processUsage, error) {
	var value unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &value); err != nil {
		return processUsage{}, err
	}
	cpu := timevalNS(value.Utime) + timevalNS(value.Stime)
	peak := uint64(value.Maxrss)
	// Linux and the BSDs report ru_maxrss in KiB. Darwin reports bytes.
	// Go's darwin Rusage shape is shared, so retain the documented exception.
	if unixRSSIsKiB {
		peak *= 1024
	}
	return processUsage{cpuNS: cpu, peakRSSBytes: peak}, nil
}

func timevalNS(value unix.Timeval) uint64 {
	if value.Sec < 0 || value.Usec < 0 {
		return 0
	}
	return uint64(value.Sec)*1_000_000_000 + uint64(value.Usec)*1_000
}
