package aiprovider

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestR9ProviderAddressFallbackPreservesNetworkValidation(t *testing.T) {
	ipv6, ipv4 := net.ParseIP("2001:4860:4860::8888"), net.ParseIP("8.8.8.8")
	attempts := 0
	left, right := net.Pipe()
	defer right.Close()
	conn, err := dialValidatedIPs(context.Background(), "tcp", "443", []net.IP{ipv6, ipv4}, ValidationPolicy{}, func(_ context.Context, _, address string) (net.Conn, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("unreachable route")
		}
		if address != "8.8.8.8:443" {
			t.Fatalf("unexpected fallback address %s", address)
		}
		return left, nil
	})
	if err != nil || conn != left || attempts != 2 {
		t.Fatalf("fallback failed: attempts=%d err=%v", attempts, err)
	}
	conn.Close()
	attempts = 0
	_, err = dialValidatedIPs(context.Background(), "tcp", "443", []net.IP{ipv4, net.ParseIP("127.0.0.1")}, ValidationPolicy{}, func(context.Context, string, string) (net.Conn, error) {
		attempts++
		return nil, errors.New("must not dial")
	})
	if err == nil || attempts != 0 {
		t.Fatal("complete DNS answer must be validated before any connection")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = dialValidatedIPs(ctx, "tcp", "443", []net.IP{ipv4}, ValidationPolicy{}, func(context.Context, string, string) (net.Conn, error) {
		attempts++
		return nil, errors.New("must not dial")
	})
	if !errors.Is(err, context.Canceled) || attempts != 0 {
		t.Fatal("cancelled request attempted a connection")
	}
}
