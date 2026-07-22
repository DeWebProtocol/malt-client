//go:build linux

package machine

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func Probe() (Identity, error) {
	cpuModel, cpuSource, err := probeCPUModel()
	if err != nil {
		return Identity{}, err
	}
	boardModel, boardSource, err := probeBoardModel()
	if err != nil {
		return Identity{}, err
	}
	memory, err := probeMemory()
	if err != nil {
		return Identity{}, err
	}
	cores := runtime.NumCPU()
	if cores <= 0 || cores > 4096 {
		return Identity{}, fmt.Errorf("runtime logical core count is outside evaluator bounds")
	}
	return Identity{
		OS: runtime.GOOS, Architecture: runtime.GOARCH,
		CPUModel: cpuModel, CPUModelSource: cpuSource,
		BoardModel: boardModel, BoardModelSource: boardSource,
		LogicalCores: uint32(cores), LogicalCoresSource: "go-runtime:NumCPU",
		MemoryBytes: memory, MemorySource: "linux:/proc/meminfo:MemTotal",
	}, nil
}

func probeCPUModel() (string, string, error) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", "", fmt.Errorf("read CPU identity: %w", err)
	}
	values := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), normalize(value)
		if value != "" && values[key] == "" {
			values[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	for _, key := range []string{"model name", "hardware", "model"} {
		if values[key] != "" {
			return values[key], "linux:/proc/cpuinfo:" + key, nil
		}
	}
	return "", "", fmt.Errorf("/proc/cpuinfo has no bounded CPU model field")
}

func probeBoardModel() (string, string, error) {
	for _, path := range []string{"/proc/device-tree/model", "/sys/firmware/devicetree/base/model", "/sys/class/dmi/id/product_name"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if value := normalize(string(data)); value != "" {
			return value, "linux:" + path, nil
		}
	}
	return "", "", fmt.Errorf("no device-tree or DMI board model is available")
}

func probeMemory() (uint64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil || value > ^uint64(0)/1024 {
				return 0, fmt.Errorf("parse /proc/meminfo MemTotal")
			}
			return value * 1024, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("/proc/meminfo omits MemTotal")
}
