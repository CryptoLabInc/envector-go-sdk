package envector

import (
	"context"
	"fmt"

	es2pb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2"
	es2epb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2e"
)

type indexOptions struct {
	Name            string
	Keys            *Keys
	Dim             int
	SearchType      string
	IndexEncryption string
	QueryEncryption string
	IndexType       string
	Description     string
}

type IndexOption func(*indexOptions)

func WithIndexName(n string) IndexOption         { return func(o *indexOptions) { o.Name = n } }
func WithIndexKeys(k *Keys) IndexOption          { return func(o *indexOptions) { o.Keys = k } }
func WithIndexDim(d int) IndexOption             { return func(o *indexOptions) { o.Dim = d } }
func WithIndexSearchType(s string) IndexOption   { return func(o *indexOptions) { o.SearchType = s } }
func WithIndexEncryption(s string) IndexOption   { return func(o *indexOptions) { o.IndexEncryption = s } }
func WithIndexQueryEncryption(s string) IndexOption {
	return func(o *indexOptions) { o.QueryEncryption = s }
}
func WithIndexType(s string) IndexOption        { return func(o *indexOptions) { o.IndexType = s } }
func WithIndexDescription(s string) IndexOption { return func(o *indexOptions) { o.Description = s } }

type Index struct {
	client *Client
	name   string
	keys   *Keys
	dim    int
}

type MetadataRef struct {
	ShardIdx uint64
	RowIdx   uint64
}

type Metadata struct {
	ID   uint64
	Data string
}

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
			return &Index{client: c, name: o.Name, keys: o.Keys, dim: o.Dim}, nil
		}
	}
	if err := c.createIndex(ctx, o); err != nil {
		return nil, err
	}
	return &Index{client: c, name: o.Name, keys: o.Keys, dim: o.Dim}, nil
}

func (c *Client) createIndex(ctx context.Context, o indexOptions) error {
	stream, err := c.stub.CreateIndex(c.authCtx(ctx))
	if err != nil {
		return fmt.Errorf("envector: create_index: %w", err)
	}
	info := &es2pb.IndexInfo{
		IndexName:       o.Name,
		Dim:             uint64(o.Dim),
		SearchType:      es2pb.SearchType_IPOnly,
		IndexEncryption: stringOrDefault(o.IndexEncryption, "cipher"),
		QueryEncryption: stringOrDefault(o.QueryEncryption, "plain"),
		IndexType:       indexTypeValue(o.IndexType),
		Description:     o.Description,
	}
	if o.Keys != nil {
		info.KeyId = o.Keys.id
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

func (i *Index) GetMetadata(ctx context.Context, refs []MetadataRef, fields []string) ([]Metadata, error) {
	if i.client.conn == nil {
		return nil, ErrClientClosed
	}
	idx := make([]*es2pb.MetadataIdx, len(refs))
	for j, r := range refs {
		idx[j] = &es2pb.MetadataIdx{ShardIdx: r.ShardIdx, RowIdx: r.RowIdx}
	}
	req := &es2epb.GetMetadataRequest{
		Header:       &es2pb.RequestHeader{Type: es2pb.MessageType_GetMetadata},
		IndexName:    i.name,
		Idx:          idx,
		OutputFields: fields,
	}
	resp, err := i.client.stub.GetMetadata(i.client.authCtx(ctx), req)
	if err != nil {
		return nil, fmt.Errorf("envector: get_metadata: %w", err)
	}
	if err := checkHeader("get_metadata", resp.GetHeader()); err != nil {
		return nil, err
	}
	out := make([]Metadata, len(resp.GetMetadata()))
	for j, m := range resp.GetMetadata() {
		out[j] = Metadata{ID: m.GetId(), Data: m.GetData()}
	}
	return out, nil
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

func stringOrDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func indexTypeValue(s string) es2pb.IndexType {
	if s == "HE_FLAT" {
		return es2pb.IndexType_HE_FLAT
	}
	return es2pb.IndexType_FLAT
}
