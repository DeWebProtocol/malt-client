package main

import daemonclient "github.com/dewebprotocol/malt-client/internal/gateway"

// makeCASClient uses the gateway-owned CAS adapter. The client never imports a
// MALT-core storage implementation and verifies the returned CID locally.
func makeCASClient() (*daemonclient.Client, error) { return gatewayClient() }
