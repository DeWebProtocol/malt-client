//go:build !linux

package machine

import "fmt"

func Probe() (Identity, error) {
	return Identity{}, fmt.Errorf("paper machine identity probing is unavailable on this operating system")
}
