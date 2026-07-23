package main

import (
	"bufio"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestWebsocketReadCancellationIsImmediateAndDoesNotPoisonNextCall(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	websocket := &websocketConn{connection: client, reader: bufio.NewReader(client)}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := websocket.readText(ctx)
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled websocket read = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not interrupt websocket read")
	}

	go func() {
		_, _ = server.Write([]byte{0x81, 0x02, 'o', 'k'})
	}()
	next, err := websocket.readText(context.Background())
	if err != nil || string(next) != "ok" {
		t.Fatalf("read after cancellation = %q, %v", next, err)
	}
}
