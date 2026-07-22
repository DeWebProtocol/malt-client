//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type residentSampler struct {
	stopChannel chan struct{}
	done        chan struct{}
	peakBytes   uint64
	samples     uint64
	err         error
}

func startResidentSampler(processID int) (*residentSampler, error) {
	initial, err := processTreeResidentBytes(processID)
	if err != nil {
		return nil, fmt.Errorf("sample Chromium process tree RSS: %w", err)
	}
	if initial == 0 {
		return nil, fmt.Errorf("sample Chromium process tree RSS: zero bytes")
	}
	sampler := &residentSampler{stopChannel: make(chan struct{}), done: make(chan struct{}), peakBytes: initial, samples: 1}
	go func() {
		defer close(sampler.done)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-sampler.stopChannel:
				value, err := processTreeResidentBytes(processID)
				if err == nil {
					sampler.samples++
					sampler.peakBytes = max(sampler.peakBytes, value)
				} else if !errors.Is(err, os.ErrNotExist) {
					sampler.err = err
				}
				return
			case <-ticker.C:
				value, err := processTreeResidentBytes(processID)
				if err != nil {
					if !errors.Is(err, os.ErrNotExist) {
						sampler.err = err
					}
					continue
				}
				sampler.samples++
				sampler.peakBytes = max(sampler.peakBytes, value)
			}
		}
	}()
	return sampler, nil
}

func (s *residentSampler) stop() (uint64, uint64, error) {
	close(s.stopChannel)
	<-s.done
	return s.peakBytes, s.samples, s.err
}

func processTreeResidentBytes(root int) (uint64, error) {
	queue := []int{root}
	seen := map[int]struct{}{}
	var total uint64
	for len(queue) != 0 {
		processID := queue[0]
		queue = queue[1:]
		if _, exists := seen[processID]; exists {
			continue
		}
		seen[processID] = struct{}{}
		statm, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", processID))
		if err != nil {
			if processID == root {
				return 0, err
			}
			continue
		}
		fields := strings.Fields(string(statm))
		if len(fields) < 2 {
			return 0, fmt.Errorf("process %d statm is malformed", processID)
		}
		residentPages, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, err
		}
		total += residentPages * uint64(os.Getpagesize())
		children, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", processID, processID))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return 0, err
			}
			continue
		}
		for _, raw := range strings.Fields(string(children)) {
			child, err := strconv.Atoi(raw)
			if err != nil || child <= 0 {
				return 0, fmt.Errorf("process %d has invalid child PID %q", processID, raw)
			}
			queue = append(queue, child)
		}
	}
	return total, nil
}
