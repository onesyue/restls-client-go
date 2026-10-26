package tls

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestRestlsClientFullDuplexTLS(t *testing.T) {
	testRestlsClientFullDuplex(t, restlsClientConcurrentPair)
}

// After the handshake, unbuffered pipes expose opposite-direction lock coupling
// deterministically. The native client/server record layers still authenticate
// every byte and advance their real protocol counters.
func TestRestlsClientFullDuplexPipe(t *testing.T) {
	testRestlsClientFullDuplex(t, restlsClientRecordPipe)
}

func testRestlsClientFullDuplex(t *testing.T, pair func(*testing.T, uint16) (*UConn, net.Conn)) {
	for _, version := range []uint16{VersionTLS12, VersionTLS13} {
		for _, baseWrite := range []bool{false, true} {
			t.Run(fmt.Sprintf("tls%x/base_write_%t", version, baseWrite), func(t *testing.T) {
				client, server := pair(t, version)
				var writer io.Writer = client
				if baseWrite {
					writer = client.Conn
				}
				const records = 256
				up := bytes.Repeat([]byte{0x31}, 1024)
				down := bytes.Repeat([]byte{0x73}, 1024)
				start := make(chan struct{})
				done := make(chan error, 4)
				send := func(w io.Writer, payload []byte) {
					<-start
					for i := 0; i < records; i++ {
						if n, err := w.Write(payload); err != nil || n != len(payload) {
							done <- fmt.Errorf("write %d: n=%d, err=%v", i, n, err)
							return
						}
					}
					done <- nil
				}
				receive := func(r io.Reader, payload []byte) {
					<-start
					buf := make([]byte, len(payload))
					for i := 0; i < records; i++ {
						if _, err := io.ReadFull(r, buf); err != nil {
							done <- fmt.Errorf("read %d: %w", i, err)
							return
						}
						if !bytes.Equal(buf, payload) {
							done <- fmt.Errorf("record %d changed across the authenticated transport", i)
							return
						}
					}
					done <- nil
				}
				go send(writer, up)
				go receive(server, up)
				go send(server, down)
				go receive(client, down)
				close(start)
				for i := 0; i < 4; i++ {
					if err := <-done; err != nil {
						t.Error(err)
					}
				}
			})
		}
	}
}

func TestRestlsClientCloseUnblocksReadAndWrite(t *testing.T) {
	client, _ := restlsClientRecordPipe(t, VersionTLS13)
	observed := &restlsObservedConn{Conn: client.conn, readStarted: make(chan struct{}, 1), writeStarted: make(chan struct{}, 1)}
	client.conn = observed
	done := make(chan error, 2)
	go func() {
		_, err := client.Read(make([]byte, 1))
		done <- err
	}()
	go func() {
		_, err := client.Write(bytes.Repeat([]byte{0x42}, 4096))
		done <- err
	}()
	<-observed.readStarted
	<-observed.writeStarted
	// The peer does not read or write application data. Closing the client
	// must release both operations, regardless of which reached the pipe first.
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err == nil {
				t.Error("blocked I/O unexpectedly succeeded after close")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("close did not unblock concurrent I/O")
		}
	}
}

func restlsClientConcurrentPair(t *testing.T, version uint16) (*UConn, net.Conn) {
	t.Helper()
	target, stopTarget := startRestlsTestTLSTarget(t, version, nil)
	t.Cleanup(stopTarget)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rawClient, rawServer := localPipe(t)
	t.Cleanup(func() { _ = rawClient.Close(); _ = rawServer.Close() })
	deadline := time.Now().Add(10 * time.Second)
	_ = rawClient.SetDeadline(deadline)
	_ = rawServer.SetDeadline(deadline)
	const password = "restls-concurrency-test-password"
	accepted := make(chan net.Conn, 1)
	errors := make(chan error, 1)
	go func() {
		server, err := RestlsServer(ctx, rawServer, &RestlsServerConfig{
			ServerHostname: target, Password: password, RestlsScript: "1500",
		})
		if err != nil {
			errors <- err
			return
		}
		accepted <- server
	}()
	hint := "tls13"
	if version == VersionTLS12 {
		hint = "tls12"
	}
	config := newRestlsServerTestClientConfig(t, password, hint, "1500", "chrome", version)
	client := UClient(rawClient, config, *clientIDMap["chrome"])
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	// The first record authenticates the client at the Restls server.
	if _, err := client.Write([]byte("start")); err != nil {
		t.Fatalf("client authentication record: %v", err)
	}
	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-errors:
		t.Fatalf("Restls server handshake: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Restls server handshake did not finish")
	}
	initial := make([]byte, len("start"))
	if _, err := io.ReadFull(server, initial); err != nil || string(initial) != "start" {
		t.Fatalf("server authentication record: %q, %v", initial, err)
	}
	t.Cleanup(func() { _ = rawClient.Close(); _ = server.Close() })
	return client, server
}

// Seed only the already-negotiated TLS state; TestRestlsClientFullDuplexTLS
// separately performs actual TLS handshakes. TLS handshake flights assume a
// buffered stream, whereas this record-layer test deliberately uses net.Pipe.
func restlsClientRecordPipe(t *testing.T, version uint16) (*UConn, net.Conn) {
	t.Helper()
	rawClient, rawServer := net.Pipe()
	t.Cleanup(func() { _ = rawClient.Close(); _ = rawServer.Close() })
	_ = rawClient.SetDeadline(time.Now().Add(10 * time.Second))
	_ = rawServer.SetDeadline(time.Now().Add(10 * time.Second))
	const password = "restls-concurrency-test-password"
	hint := "tls13"
	if version == VersionTLS12 {
		hint = "tls12"
	}
	config := newRestlsServerTestClientConfig(t, password, hint, "1500", "chrome", version)
	client := UClient(rawClient, config, *clientIDMap["chrome"])
	client.vers, client.haveVers = version, true
	client.restlsAuthed = true
	client.serverRandom = make([]byte, 32)
	client.restls12WithGCM = version == VersionTLS12
	client.in.cipher = aeadAESGCMTLS13(make([]byte, 16), make([]byte, 12))
	client.isHandshakeComplete.Store(true)
	state, err := newRestlsServerState(&RestlsServerConfig{Password: password, RestlsScript: "1500", MinRecordLen: 15})
	if err != nil {
		t.Fatal(err)
	}
	state.serverRandom = make([]byte, 32)
	state.isTLS13 = version == VersionTLS13
	state.isTLS12GCM, state.parrotGCM = version == VersionTLS12, version == VersionTLS12
	server := &restlsServerConn{inbound: rawServer, target: rawServer, state: state, closed: make(chan struct{})}
	return client, server
}

type restlsObservedConn struct {
	net.Conn
	readStarted, writeStarted chan struct{}
}

func (c *restlsObservedConn) Read(p []byte) (int, error) {
	select {
	case c.readStarted <- struct{}{}:
	default:
	}
	return c.Conn.Read(p)
}

func (c *restlsObservedConn) Write(p []byte) (int, error) {
	select {
	case c.writeStarted <- struct{}{}:
	default:
	}
	return c.Conn.Write(p)
}
