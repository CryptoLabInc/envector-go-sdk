package envector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	es2pb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2"
	es2epb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2e"
)

const keyUploadChunkSize = 1 * 1024 * 1024

// activationMu serialises ActivateKeys so the 4-RPC sequence does not
// interleave with concurrent callers targeting the same client.
var activationMu sync.Mutex

func (c *Client) GetKeysList(ctx context.Context) ([]string, error) {
	if c.conn == nil {
		return nil, ErrClientClosed
	}
	req := &es2epb.GetKeyListRequest{
		Header: &es2pb.RequestHeader{Type: es2pb.MessageType_GetKeyList},
	}
	resp, err := c.stub.GetKeyList(c.authCtx(ctx), req)
	if err != nil {
		return nil, fmt.Errorf("envector: get_key_list: %w", err)
	}
	if err := checkHeader("get_key_list", resp.GetHeader()); err != nil {
		return nil, err
	}
	return resp.GetKeyId(), nil
}

func (c *Client) RegisterKeys(ctx context.Context, keys *Keys) error {
	if c.conn == nil {
		return ErrClientClosed
	}
	if keys == nil || keys.closed {
		return ErrKeysClosed
	}

	stream, err := c.stub.RegisterKey(c.authCtx(ctx))
	if err != nil {
		return fmt.Errorf("envector: register_key: %w", err)
	}

	sum := sha256.Sum256(keys.evalKeyBytes)
	info := &es2pb.KeyInfo{
		KeyId:     keys.id,
		Type:      "EvalKey",
		Sha256Sum: hex.EncodeToString(sum[:]),
	}
	total := len(keys.evalKeyBytes)
	sendFrame := func(chunk []byte) error {
		msg := &es2epb.RegisterKeyRequest{
			Header:  &es2pb.RequestHeader{Type: es2pb.MessageType_RegisterKey},
			KeyInfo: info,
			Key:     &es2pb.Key{Size: uint64(total), Value: chunk},
		}
		if err := stream.Send(msg); err != nil {
			return fmt.Errorf("envector: register_key send: %w", err)
		}
		return nil
	}

	if total == 0 {
		if err := sendFrame(nil); err != nil {
			return err
		}
	} else {
		for off := 0; off < total; off += keyUploadChunkSize {
			end := off + keyUploadChunkSize
			if end > total {
				end = total
			}
			if err := sendFrame(keys.evalKeyBytes[off:end]); err != nil {
				return err
			}
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("envector: register_key recv: %w", err)
	}
	return checkHeader("register_key", resp.GetHeader())
}

func (c *Client) LoadKeys(ctx context.Context, keyID string) error {
	if c.conn == nil {
		return ErrClientClosed
	}
	req := &es2epb.LoadKeyRequest{
		Header: &es2pb.RequestHeader{Type: es2pb.MessageType_LoadKey},
		KeyId:  keyID,
	}
	resp, err := c.stub.LoadKey(c.authCtx(ctx), req)
	if err != nil {
		return fmt.Errorf("envector: load_key: %w", err)
	}
	return checkHeader("load_key", resp.GetHeader())
}

func (c *Client) UnloadKeys(ctx context.Context, keyID string) error {
	if c.conn == nil {
		return ErrClientClosed
	}
	req := &es2epb.UnloadKeyRequest{
		Header: &es2pb.RequestHeader{Type: es2pb.MessageType_UnloadKey},
		KeyId:  keyID,
	}
	resp, err := c.stub.UnloadKey(c.authCtx(ctx), req)
	if err != nil {
		return fmt.Errorf("envector: unload_key: %w", err)
	}
	return checkHeader("unload_key", resp.GetHeader())
}

func (c *Client) DeleteKeys(ctx context.Context, keyID string) error {
	if c.conn == nil {
		return ErrClientClosed
	}
	req := &es2epb.DeleteKeyRequest{
		Header: &es2pb.RequestHeader{Type: es2pb.MessageType_DeleteKey},
		KeyId:  keyID,
	}
	resp, err := c.stub.DeleteKey(c.authCtx(ctx), req)
	if err != nil {
		return fmt.Errorf("envector: delete_key: %w", err)
	}
	return checkHeader("delete_key", resp.GetHeader())
}

// ActivateKeys makes the given bundle the single resident key on the
// server. It runs the 4-RPC auto-setup sequence required when only one
// key may be loaded at a time: list existing keys, RegisterKeys if absent,
// UnloadKeys on every other key, then LoadKeys on the target.
//
// A Keys handle may only be activated against one Client at a time.
// Attempting to activate the same handle through a second Client returns
// ErrKeysAlreadyActivated; re-activating against the original Client is
// idempotent.
func (c *Client) ActivateKeys(ctx context.Context, keys *Keys) error {
	if c.conn == nil {
		return ErrClientClosed
	}
	if keys == nil || keys.closed {
		return ErrKeysClosed
	}

	activationMu.Lock()
	defer activationMu.Unlock()

	if keys.activated != nil && keys.activated != c {
		return ErrKeysAlreadyActivated
	}

	list, err := c.GetKeysList(ctx)
	if err != nil {
		return err
	}

	present := false
	for _, k := range list {
		if k == keys.id {
			present = true
			break
		}
	}
	if !present {
		if err := c.RegisterKeys(ctx, keys); err != nil {
			return err
		}
	}
	for _, k := range list {
		if k == keys.id {
			continue
		}
		if err := c.UnloadKeys(ctx, k); err != nil {
			return err
		}
	}
	if err := c.LoadKeys(ctx, keys.id); err != nil {
		return err
	}
	keys.activated = c
	return nil
}
