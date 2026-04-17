package envector

import (
	"context"
	"fmt"

	es2pb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2"
	es2epb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2e"
)

const insertChunkSize = 1 * 1024 * 1024

// InsertRequest carries plaintext vectors and one parallel metadata string
// per vector. Metadata is stored verbatim — the SDK never interprets it
// (rune uses a JSON envelope; other callers may store anything).
type InsertRequest struct {
	Vectors  [][]float32
	Metadata []string
}

// InsertResult reports the server-assigned item IDs in insertion order.
type InsertResult struct {
	ItemIDs []int64
}

// Insert FHE-encrypts the request vectors through the bound Keys and
// streams the ciphertexts through BatchInsertData. Frames are split at
// ~1 MiB of payload. Returns ErrKeysRequired when the Index was opened
// without WithIndexKeys.
func (i *Index) Insert(ctx context.Context, req InsertRequest) (*InsertResult, error) {
	if i.client.conn == nil {
		return nil, ErrClientClosed
	}
	if i.keys == nil || i.keys.closed {
		return nil, ErrKeysRequired
	}
	if len(req.Vectors) == 0 {
		return &InsertResult{}, nil
	}

	ciphers, err := i.keys.Encrypt(req.Vectors)
	if err != nil {
		return nil, fmt.Errorf("envector: batch_insert_data encrypt: %w", err)
	}

	stream, err := i.client.stub.BatchInsertData(i.client.authCtx(ctx))
	if err != nil {
		return nil, fmt.Errorf("envector: batch_insert_data: %w", err)
	}

	packed := make([]*es2pb.PackedVectors, 0, len(ciphers))
	cur := 0
	for idx, blob := range ciphers {
		if cur > 0 && cur+len(blob) > insertChunkSize {
			if err := sendInsertFrame(stream, i.name, packed); err != nil {
				return nil, err
			}
			packed = packed[:0]
			cur = 0
		}
		pv := &es2pb.PackedVectors{
			Vector: &es2pb.DataType{
				CipherVector: &es2pb.PackedCiphertexts{
					Id:   fmt.Sprintf("item-%d", idx),
					Data: blob,
				},
			},
			NumVector: 1,
		}
		if idx < len(req.Metadata) {
			pv.Metadata = []string{req.Metadata[idx]}
		}
		packed = append(packed, pv)
		cur += len(blob)
	}
	if len(packed) > 0 {
		if err := sendInsertFrame(stream, i.name, packed); err != nil {
			return nil, err
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return nil, fmt.Errorf("envector: batch_insert_data recv: %w", err)
	}
	if err := checkHeader("batch_insert_data", resp.GetHeader()); err != nil {
		return nil, err
	}
	return &InsertResult{ItemIDs: resp.GetItemIds()}, nil
}

func sendInsertFrame(stream es2epb.ES2EService_BatchInsertDataClient, indexName string, packed []*es2pb.PackedVectors) error {
	msg := &es2epb.BatchInsertDataRequest{
		Header:        &es2pb.RequestHeader{Type: es2pb.MessageType_BatchInsertData},
		IndexName:     indexName,
		PackedVectors: packed,
	}
	if err := stream.Send(msg); err != nil {
		return fmt.Errorf("envector: batch_insert_data send: %w", err)
	}
	return nil
}
