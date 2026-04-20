package envector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	es2epb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2e"
)

const Version = "0.0.0"

// Client is a gRPC handle to an enVector server. Construct one with
// NewClient and release with Close. Methods are safe for concurrent use.
type Client struct {
	conn *grpc.ClientConn
	stub es2epb.ES2EServiceClient
	opts clientOptions
}

// NewClient dials the enVector server described by the supplied options.
// At minimum pass WithAddress; use WithInsecure for non-TLS endpoints
// (local dev, bufconn tests). The connection is opened lazily — the first
// RPC establishes the underlying channel.
func NewClient(opts ...ClientOption) (*Client, error) {
	o := defaultClientOptions()
	for _, opt := range opts {
		opt(&o)
	}
	if o.Address == "" {
		return nil, ErrAddressRequired
	}

	var creds credentials.TransportCredentials
	if o.Insecure {
		creds = insecure.NewCredentials()
	} else {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("envector: load system CA pool: %w", err)
		}
		creds = credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(o.MaxMsgSize),
			grpc.MaxCallSendMsgSize(o.MaxMsgSize),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                o.KeepaliveTime,
			Timeout:             o.KeepaliveTimeout,
			PermitWithoutStream: true,
		}),
	}

	conn, err := grpc.NewClient(o.Address, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("envector: new client %q: %w", o.Address, err)
	}

	return &Client{
		conn: conn,
		stub: es2epb.NewES2EServiceClient(conn),
		opts: o,
	}, nil
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func (c *Client) authCtx(ctx context.Context) context.Context {
	if c.opts.AccessToken == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.opts.AccessToken)
}
