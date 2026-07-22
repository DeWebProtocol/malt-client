//go:build !linux

package main

import "fmt"

type residentSampler struct{}

func startResidentSampler(_ int) (*residentSampler, error) {
	return nil, fmt.Errorf("real browser peak-RSS sampling requires Linux /proc")
}

func (s *residentSampler) stop() (uint64, uint64, error) {
	return 0, 0, fmt.Errorf("real browser peak-RSS sampling requires Linux /proc")
}
