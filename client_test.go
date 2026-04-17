package envector

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewClient_DefaultsApplied(t *testing.T) {
	c, err := NewClient(context.Background(),
		WithAddress("127.0.0.1:1"),
		WithInsecure(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	cases := []struct {
		name string
		got  any
		want any
	}{
		{"DialTimeout", c.opts.DialTimeout, defaultDialTimeout},
		{"KeepaliveTime", c.opts.KeepaliveTime, defaultKeepaliveTime},
		{"KeepaliveTimeout", c.opts.KeepaliveTimeout, defaultKeepaliveTimeout},
		{"MaxMsgSize", c.opts.MaxMsgSize, defaultMaxMsgSize},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

func TestNewClient_OverridesTakeEffect(t *testing.T) {
	c, err := NewClient(context.Background(),
		WithAddress("127.0.0.1:1"),
		WithInsecure(),
		WithDialTimeout(5*time.Second),
		WithMaxMsgSize(1<<20),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	if c.opts.DialTimeout != 5*time.Second || c.opts.MaxMsgSize != 1<<20 {
		t.Errorf("overrides lost: %+v", c.opts)
	}
}

func TestNewClient_RequiresAddress(t *testing.T) {
	_, err := NewClient(context.Background())
	if !errors.Is(err, ErrAddressRequired) {
		t.Fatalf("expected ErrAddressRequired, got %v", err)
	}
}

func TestNewClient_Insecure_LazyConnect(t *testing.T) {
	c, err := NewClient(context.Background(),
		WithAddress("127.0.0.1:1"),
		WithInsecure(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.conn == nil {
		t.Fatal("client has no underlying conn")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestClient_CallsAfterCloseReturnErrClientClosed(t *testing.T) {
	c, err := NewClient(context.Background(),
		WithAddress("127.0.0.1:1"),
		WithInsecure(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_ = c.Close()

	if _, err := c.GetIndexList(context.Background()); !errors.Is(err, ErrClientClosed) {
		t.Errorf("GetIndexList after close: got %v, want ErrClientClosed", err)
	}
	if _, err := c.GetKeysList(context.Background()); !errors.Is(err, ErrClientClosed) {
		t.Errorf("GetKeysList after close: got %v, want ErrClientClosed", err)
	}
}
