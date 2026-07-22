//go:build !js || !wasm

package main

import "fmt"

func main() {
	fmt.Println("malt-eval-rq2-browser-wasm must be built with GOOS=js GOARCH=wasm")
}
