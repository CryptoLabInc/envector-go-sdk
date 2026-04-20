package envector

import (
	"context"
	"fmt"

	es2pb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2"
	es2epb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2e"
)

// MetadataRef addresses a metadata row by (shard, row). Use the shard /
// row pairs reported by Index.Score decryption to build a ref batch.
type MetadataRef struct {
	ShardIdx uint64
	RowIdx   uint64
}

// Metadata is a metadata row returned by Index.GetMetadata. Data is an
// opaque, server-provided string; its interpretation is the caller's
// (typical patterns: a JSON envelope, a content-addressable hash, or an
// opaque blob).
type Metadata struct {
	ID   uint64
	Data string
}

// GetMetadata fetches metadata rows for the given refs. fields names the
// metadata columns the server should include in the response; the common
// case is []string{"metadata"}.
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
