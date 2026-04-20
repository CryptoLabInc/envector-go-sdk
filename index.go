package envector

import (
	"context"
	"fmt"

	es2pb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2"
	es2epb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2e"
)

// Index is a handle to a single server-side index, scoped to the Client
// that opened it. Closing the Client invalidates the Index — there is no
// separate Close on Index itself. Dimension lives on the bound Keys (if
// any); the Index never carries its own dim.
type Index struct {
	client *Client
	name   string
	keys   *Keys
}

// Name returns the index identifier this handle is bound to. Set at
// construction time and immutable thereafter — the SDK uses it verbatim
// in every RPC, so the getter shape exists to prevent accidental rebinding.
func (i *Index) Name() string { return i.name }

func (c *Client) GetIndexList(ctx context.Context) ([]string, error) {
	if c.conn == nil {
		return nil, ErrClientClosed
	}
	req := &es2epb.GetIndexListRequest{
		Header: &es2pb.RequestHeader{Type: es2pb.MessageType_GetIndexList},
	}
	resp, err := c.stub.GetIndexList(c.authCtx(ctx), req)
	if err != nil {
		return nil, fmt.Errorf("envector: get_index_list: %w", err)
	}
	if err := checkHeader("get_index_list", resp.GetHeader()); err != nil {
		return nil, err
	}
	return resp.GetIndexNames(), nil
}

// Index opens the named index, creating it from the remaining options if
// the server does not yet have one. Repeat calls with the same
// WithIndexName are idempotent and return equivalent handles.
func (c *Client) Index(ctx context.Context, opts ...IndexOption) (*Index, error) {
	if c.conn == nil {
		return nil, ErrClientClosed
	}
	var o indexOptions
	for _, opt := range opts {
		opt(&o)
	}
	if o.Name == "" {
		return nil, fmt.Errorf("envector: WithIndexName required")
	}
	list, err := c.GetIndexList(ctx)
	if err != nil {
		return nil, err
	}
	for _, n := range list {
		if n == o.Name {
			return &Index{client: c, name: o.Name, keys: o.Keys}, nil
		}
	}
	if err := c.createIndex(ctx, o); err != nil {
		return nil, err
	}
	return &Index{client: c, name: o.Name, keys: o.Keys}, nil
}

func (c *Client) createIndex(ctx context.Context, o indexOptions) error {
	if o.Keys == nil {
		return fmt.Errorf("envector: WithIndexKeys required to create a new index (dim is sourced from Keys.Dim())")
	}
	stream, err := c.stub.CreateIndex(c.authCtx(ctx))
	if err != nil {
		return fmt.Errorf("envector: create_index: %w", err)
	}
	// Mode is hardcoded because the SDK's Insert/Score code paths only
	// support (cipher index, plain query, FLAT, IPOnly). Other combinations
	// exist in the proto but have no client-side support; exposing them as
	// options would lie about what callers can actually run.
	info := &es2pb.IndexInfo{
		IndexName:       o.Name,
		Dim:             uint64(o.Keys.Dim()),
		SearchType:      es2pb.SearchType_IPOnly,
		IndexEncryption: "cipher",
		QueryEncryption: "plain",
		IndexType:       es2pb.IndexType_FLAT,
		Description:     o.Description,
		KeyId:           o.Keys.id,
	}
	msg := &es2epb.CreateIndexRequest{
		Header:    &es2pb.RequestHeader{Type: es2pb.MessageType_CreateIndex},
		IndexInfo: info,
	}
	if err := stream.Send(msg); err != nil {
		return fmt.Errorf("envector: create_index send: %w", err)
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("envector: create_index recv: %w", err)
	}
	return checkHeader("create_index", resp.GetHeader())
}

// Drop deletes the server-side index. No prior unload is required; any
// loaded state is released server-side as part of the call.
func (i *Index) Drop(ctx context.Context) error {
	if i.client.conn == nil {
		return ErrClientClosed
	}
	req := &es2epb.DeleteIndexRequest{
		Header:    &es2pb.RequestHeader{Type: es2pb.MessageType_DeleteIndex},
		IndexName: i.name,
	}
	resp, err := i.client.stub.DeleteIndex(i.client.authCtx(ctx), req)
	if err != nil {
		return fmt.Errorf("envector: delete_index: %w", err)
	}
	return checkHeader("delete_index", resp.GetHeader())
}

func checkHeader(rpc string, h *es2pb.ResponseHeader) error {
	if h == nil {
		return nil
	}
	if rc := h.GetReturnCode(); rc != es2pb.ReturnCode_Success {
		return fmt.Errorf("envector: %s: server returned %s: %s", rpc, rc, h.GetErrorMessage())
	}
	return nil
}

