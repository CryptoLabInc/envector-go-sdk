// Package crypto's cgo provider binds the upstream C API in
// third_party/evi/include/evi_c/*.h to the Provider interface. The surface
// is intentionally narrow — only the functions pyenvector@1.2.2 exercises
// on its active (IP-preset, NONE-seal) path are wired up:
//
//	Context     evi_context_create / _destroy
//	KeyGen      evi_multikeygenerator_create / _generate_keys / _destroy
//	Encryptor   evi_keypack_create_from_path + evi_encryptor_create +
//	            evi_encryptor_encrypt_batch_with_pack +
//	            evi_query_serialize_to_string + evi_query_array_destroy
//	Decryptor   evi_secret_key_create_from_path + evi_decryptor_create +
//	            evi_search_result_deserialize_from_string +
//	            evi_decryptor_decrypt_search_result_with_seckey +
//	            evi_message_{data,size,destroy}
//
// Every other C API symbol is intentionally untouched. Keys are loaded
// from disk (not from in-memory bytes) because the C API lacks stream
// variants for KeyPack / SecretKey.
package crypto

/*
// OpenSSL note: libevi_crypto.a's AES.cpp.o + Utils.cpp.o reference BIO_*,
// EVP_* and RAND_* symbols. These .o members are pulled in transitively
// by evi_seal_info_create (which KeyGenerator and Decryptor both call,
// even at seal_mode=NONE), so -lssl -lcrypto are required at link time
// regardless of whether the SDK ever constructs a non-NONE seal. On
// macOS the Homebrew openssl@3 prefix differs between Apple Silicon and
// Intel; both search paths are supplied so the linker picks whichever
// exists. Linux assumes system libssl-dev. Windows assumes MSYS2
// mingw-w64-x86_64-openssl.
#cgo CPPFLAGS: -I${SRCDIR}/../../third_party/evi/include
#cgo darwin,arm64  LDFLAGS: -L${SRCDIR}/../../third_party/evi/darwin_arm64/lib  -levi_c_api -levi_crypto -ldeb -lalea -L/opt/homebrew/opt/openssl@3/lib -L/usr/local/opt/openssl@3/lib -lssl -lcrypto -lc++ -lm
#cgo darwin,amd64  LDFLAGS: -L${SRCDIR}/../../third_party/evi/darwin_amd64/lib  -levi_c_api -levi_crypto -ldeb -lalea -L/usr/local/opt/openssl@3/lib -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -lc++ -lm
#cgo linux,amd64   LDFLAGS: -L${SRCDIR}/../../third_party/evi/linux_amd64/lib   -levi_c_api -levi_crypto -ldeb -lalea -lssl -lcrypto -lstdc++ -lm
#cgo linux,arm64   LDFLAGS: -L${SRCDIR}/../../third_party/evi/linux_arm64/lib   -levi_c_api -levi_crypto -ldeb -lalea -lssl -lcrypto -lstdc++ -lm
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/../../third_party/evi/windows_amd64/lib -levi_c_api -levi_crypto -ldeb -lalea -lssl -lcrypto -lstdc++ -lm

#include <stdlib.h>
#include "c_api.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"google.golang.org/protobuf/proto"

	es2pb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2"
)

// Key file names that upstream's MultiKeyGenerator writes at seal=NONE.
const (
	cgoEncKeyFile  = "EncKey.bin"
	cgoEvalKeyFile = "EvalKey.bin"
	cgoSecKeyFile  = "SecKey.bin"
)

// --- error helpers ---------------------------------------------------------

func wrapEviError(op string, st C.evi_status_t) error {
	msg := C.GoString(C.evi_last_error_message())
	if msg == "" {
		return fmt.Errorf("envector/crypto: %s: status=%d", op, int(st))
	}
	return fmt.Errorf("envector/crypto: %s: %s (status=%d)", op, msg, int(st))
}

// --- context ---------------------------------------------------------------

type cgoContext struct {
	c *C.evi_context_t
}

func (c *cgoContext) Close() error {
	if c.c != nil {
		C.evi_context_destroy(c.c)
		c.c = nil
	}
	return nil
}

type cgoProvider struct{}

func (cgoProvider) NewCKKSContext(params CKKSParams) (CKKSContext, error) {
	if len(params.DimList) == 0 {
		return nil, errors.New("envector/crypto: CKKSParams.DimList must contain at least one dim")
	}
	preset, err := presetToEnum(params.Preset)
	if err != nil {
		return nil, err
	}
	evalMode, err := evalModeToEnum(params.EvalMode)
	if err != nil {
		return nil, err
	}

	var ctx *C.evi_context_t
	st := C.evi_context_create(
		C.evi_parameter_preset_t(preset),
		C.evi_device_type_t(C.EVI_DEVICE_TYPE_CPU),
		C.uint64_t(params.DimList[0]),
		C.evi_eval_mode_t(evalMode),
		nil,
		&ctx,
	)
	if st != C.EVI_STATUS_SUCCESS {
		return nil, wrapEviError("evi_context_create", st)
	}
	c := &cgoContext{c: ctx}
	runtime.SetFinalizer(c, func(c *cgoContext) { _ = c.Close() })
	return c, nil
}

// --- key generator (MultiKeyGenerator + seal_info NONE) -------------------

type cgoKeyGen struct {
	params KeyGenParams
}

func (cgoProvider) NewKeyGenerator(p KeyGenParams) (KeyGenerator, error) {
	return &cgoKeyGen{params: p}, nil
}

func (g *cgoKeyGen) Generate() error {
	if g.params.KeyPath == "" {
		return errors.New("envector/crypto: KeyPath required")
	}
	if len(g.params.DimList) == 0 {
		return errors.New("envector/crypto: DimList required")
	}
	preset, err := presetToEnum(g.params.Preset)
	if err != nil {
		return err
	}
	evalMode, err := evalModeToEnum(g.params.EvalMode)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(g.params.KeyPath, 0o755); err != nil {
		return fmt.Errorf("envector/crypto: mkdir key path: %w", err)
	}
	// pyenvector rejects non-empty key dirs; mirror that to make Generate
	// idempotent behaviour obvious to the caller. The higher-level
	// envector.GenerateKeys uses KeysExist as the primary guard, but this
	// second check catches stale partial state.
	if empty, err := isEmptyDir(g.params.KeyPath); err != nil {
		return err
	} else if !empty {
		return fmt.Errorf("envector/crypto: key path %q is not empty", g.params.KeyPath)
	}

	// Build one context per requested dim (pyenvector's MultiKeyGenerator
	// does the same — one CKKS parameter tuple per dimension, grouped
	// under the same secret key).
	contexts := make([]*C.evi_context_t, 0, len(g.params.DimList))
	defer func() {
		for _, c := range contexts {
			C.evi_context_destroy(c)
		}
	}()
	for _, dim := range g.params.DimList {
		var c *C.evi_context_t
		st := C.evi_context_create(
			C.evi_parameter_preset_t(preset),
			C.evi_device_type_t(C.EVI_DEVICE_TYPE_CPU),
			C.uint64_t(dim),
			C.evi_eval_mode_t(evalMode),
			nil,
			&c,
		)
		if st != C.EVI_STATUS_SUCCESS {
			return wrapEviError("evi_context_create", st)
		}
		contexts = append(contexts, c)
	}

	// SealInfo(NONE): the SDK does not ship an AES-KEK path, so pass a
	// NONE-mode seal_info to every key-generation / decryption call.
	var sealInfo *C.evi_seal_info_t
	st := C.evi_seal_info_create(C.EVI_SEAL_MODE_NONE, nil, 0, &sealInfo)
	if st != C.EVI_STATUS_SUCCESS {
		return wrapEviError("evi_seal_info_create", st)
	}
	defer C.evi_seal_info_destroy(sealInfo)

	// Pack Go []*C.evi_context_t into a C array of const evi_context_t *.
	ctxArr := (**C.evi_context_t)(C.malloc(C.size_t(len(contexts)) * C.size_t(unsafe.Sizeof(uintptr(0)))))
	defer C.free(unsafe.Pointer(ctxArr))
	ctxSlice := unsafe.Slice(ctxArr, len(contexts))
	for i, c := range contexts {
		ctxSlice[i] = c
	}

	cKeyDir := C.CString(g.params.KeyPath)
	defer C.free(unsafe.Pointer(cKeyDir))

	var gen *C.evi_multikeygenerator_t
	st = C.evi_multikeygenerator_create(
		(**C.evi_context_t)(unsafe.Pointer(ctxArr)),
		C.size_t(len(contexts)),
		cKeyDir,
		sealInfo,
		&gen,
	)
	if st != C.EVI_STATUS_SUCCESS {
		return wrapEviError("evi_multikeygenerator_create", st)
	}
	defer C.evi_multikeygenerator_destroy(gen)

	var sk *C.evi_secret_key_t
	st = C.evi_multikeygenerator_generate_keys(gen, &sk)
	if st != C.EVI_STATUS_SUCCESS {
		return wrapEviError("evi_multikeygenerator_generate_keys", st)
	}
	// generate_keys returns a secret key handle that we don't keep — the
	// keys are written to disk as a side-effect.
	C.evi_secret_key_destroy(sk)
	return nil
}

// --- encryptor -------------------------------------------------------------

type cgoEncryptor struct {
	enc  *C.evi_encryptor_t
	pack *C.evi_keypack_t
}

func (e *cgoEncryptor) Close() error {
	if e.enc != nil {
		C.evi_encryptor_destroy(e.enc)
		e.enc = nil
	}
	if e.pack != nil {
		C.evi_keypack_destroy(e.pack)
		e.pack = nil
	}
	return nil
}

func (cgoProvider) NewEncryptor(ctxIface CKKSContext, keyDir string) (Encryptor, error) {
	cctx, ok := ctxIface.(*cgoContext)
	if !ok || cctx.c == nil {
		return nil, errors.New("envector/crypto: NewEncryptor requires an open cgo context")
	}

	cKeyDir := C.CString(keyDir)
	defer C.free(unsafe.Pointer(cKeyDir))

	// Encrypt only consumes EncKey from the KeyPack. Skip the
	// _create_from_path overload — at EvalMode != MM it would also pull in
	// the (much larger) EvalKey via deserializeEvalKey + temp dump dir,
	// which the client-side encrypt path never touches.
	var pack *C.evi_keypack_t
	st := C.evi_keypack_create(cctx.c, &pack)
	if st != C.EVI_STATUS_SUCCESS {
		return nil, wrapEviError("evi_keypack_create", st)
	}
	st = C.evi_keypack_load_enc_key(pack, cKeyDir)
	if st != C.EVI_STATUS_SUCCESS {
		C.evi_keypack_destroy(pack)
		return nil, wrapEviError("evi_keypack_load_enc_key", st)
	}

	var enc *C.evi_encryptor_t
	st = C.evi_encryptor_create(cctx.c, &enc)
	if st != C.EVI_STATUS_SUCCESS {
		C.evi_keypack_destroy(pack)
		return nil, wrapEviError("evi_encryptor_create", st)
	}

	e := &cgoEncryptor{enc: enc, pack: pack}
	runtime.SetFinalizer(e, func(e *cgoEncryptor) { _ = e.Close() })
	return e, nil
}

func (e *cgoEncryptor) EncryptMultiple(vectors [][]float32, encodeType string) ([][]byte, error) {
	if e.enc == nil || e.pack == nil {
		return nil, errors.New("envector/crypto: encryptor closed")
	}
	if len(vectors) == 0 {
		return [][]byte{}, nil
	}
	encTypeInt, err := encodeTypeToEnum(encodeType)
	if err != nil {
		return nil, err
	}

	n := len(vectors)
	dim := len(vectors[0])
	if dim == 0 {
		return nil, errors.New("envector/crypto: vector dim must be > 0")
	}
	for i, v := range vectors {
		if len(v) != dim {
			return nil, fmt.Errorf("envector/crypto: vector %d has dim %d, want %d", i, len(v), dim)
		}
	}

	// Allocate n×dim contiguous C floats (one malloc per row so the
	// per-row pointer array is valid), then build a pointer-to-pointer
	// array for evi_encryptor_encrypt_batch_with_pack.
	rowPtrs := make([]*C.float, n)
	defer func() {
		for _, p := range rowPtrs {
			if p != nil {
				C.free(unsafe.Pointer(p))
			}
		}
	}()
	for i, v := range vectors {
		row := (*C.float)(C.malloc(C.size_t(dim) * C.size_t(unsafe.Sizeof(C.float(0)))))
		if row == nil {
			return nil, errors.New("envector/crypto: malloc failed")
		}
		rowPtrs[i] = row
		rowSlice := unsafe.Slice(row, dim)
		for j, f := range v {
			rowSlice[j] = C.float(f)
		}
	}

	ptrArr := (**C.float)(C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(uintptr(0)))))
	if ptrArr == nil {
		return nil, errors.New("envector/crypto: malloc failed")
	}
	defer C.free(unsafe.Pointer(ptrArr))
	ptrSlice := unsafe.Slice(ptrArr, n)
	for i, p := range rowPtrs {
		ptrSlice[i] = p
	}

	var outQueries **C.evi_query_t
	var outCount C.size_t
	st := C.evi_encryptor_encrypt_batch_with_pack(
		e.enc, e.pack,
		ptrArr,
		C.size_t(dim),
		C.size_t(n),
		C.evi_encode_type_t(encTypeInt),
		0,   // level = 0 (pyenvector "qf=False")
		nil, // scale = NULL → upstream default
		&outQueries,
		&outCount,
	)
	if st != C.EVI_STATUS_SUCCESS {
		return nil, wrapEviError("evi_encryptor_encrypt_batch_with_pack", st)
	}
	defer C.evi_query_array_destroy(outQueries, outCount)

	count := int(outCount)
	queries := unsafe.Slice(outQueries, count)
	result := make([][]byte, count)
	for i, q := range queries {
		var data *C.char
		var size C.size_t
		st := C.evi_query_serialize_to_string(q, &data, &size)
		if st != C.EVI_STATUS_SUCCESS {
			return nil, wrapEviError("evi_query_serialize_to_string", st)
		}
		result[i] = C.GoBytes(unsafe.Pointer(data), C.int(size))
		C.free(unsafe.Pointer(data))
	}
	return result, nil
}

// --- decryptor -------------------------------------------------------------

type cgoDecryptor struct {
	dec *C.evi_decryptor_t
	sk  *C.evi_secret_key_t
}

func (d *cgoDecryptor) Close() error {
	if d.dec != nil {
		C.evi_decryptor_destroy(d.dec)
		d.dec = nil
	}
	if d.sk != nil {
		C.evi_secret_key_destroy(d.sk)
		d.sk = nil
	}
	return nil
}

func (cgoProvider) NewDecryptor(ctxIface CKKSContext, keyDir string) (Decryptor, error) {
	cctx, ok := ctxIface.(*cgoContext)
	if !ok || cctx.c == nil {
		return nil, errors.New("envector/crypto: NewDecryptor requires an open cgo context")
	}

	secPath := filepath.Join(keyDir, cgoSecKeyFile)
	cPath := C.CString(secPath)
	defer C.free(unsafe.Pointer(cPath))

	var sk *C.evi_secret_key_t
	st := C.evi_secret_key_create_from_path(cPath, &sk)
	if st != C.EVI_STATUS_SUCCESS {
		return nil, wrapEviError("evi_secret_key_create_from_path", st)
	}

	var dec *C.evi_decryptor_t
	st = C.evi_decryptor_create(cctx.c, &dec)
	if st != C.EVI_STATUS_SUCCESS {
		C.evi_secret_key_destroy(sk)
		return nil, wrapEviError("evi_decryptor_create", st)
	}

	d := &cgoDecryptor{dec: dec, sk: sk}
	runtime.SetFinalizer(d, func(d *cgoDecryptor) { _ = d.Close() })
	return d, nil
}

func (d *cgoDecryptor) DecryptScore(scoreBytes []byte) ([][]float64, []int32, error) {
	if d.dec == nil || d.sk == nil {
		return nil, nil, errors.New("envector/crypto: decryptor closed")
	}
	var score es2pb.CiphertextScore
	if err := proto.Unmarshal(scoreBytes, &score); err != nil {
		return nil, nil, fmt.Errorf("envector/crypto: unmarshal CiphertextScore: %w", err)
	}
	shards := score.GetShardIdx()
	ctxts := score.GetCtxtScore()

	// pyenvector's decrypt_score (cipher.py L335) runs one decryption per
	// HEaaNCiphertext and asserts len(result) == len(shard_idx) when the
	// latter is populated. Each result row is `[:item_count]` floats from
	// the decrypted message. We mirror that shape: scores[i] is the full
	// score vector for HEaaNCiphertext i, and shardIdx[i] is its shard.
	scores := make([][]float64, len(ctxts))
	for i, ct := range ctxts {
		data := ct.GetData()
		if len(data) == 0 {
			return nil, nil, fmt.Errorf("envector/crypto: ctxt_score[%d] empty", i)
		}
		cData := (*C.char)(unsafe.Pointer(&data[0]))

		var sr *C.evi_search_result_t
		st := C.evi_search_result_deserialize_from_string(cData, C.size_t(len(data)), &sr)
		if st != C.EVI_STATUS_SUCCESS {
			return nil, nil, wrapEviError("evi_search_result_deserialize_from_string", st)
		}

		var msg *C.evi_message_t
		st = C.evi_decryptor_decrypt_search_result_with_seckey(d.dec, sr, d.sk, 1, nil, &msg)
		if st != C.EVI_STATUS_SUCCESS {
			C.evi_search_result_destroy(sr)
			return nil, nil, wrapEviError("evi_decryptor_decrypt_search_result_with_seckey", st)
		}

		var itemCount C.uint32_t
		st = C.evi_search_result_get_item_count(sr, &itemCount)
		if st != C.EVI_STATUS_SUCCESS {
			C.evi_message_destroy(msg)
			C.evi_search_result_destroy(sr)
			return nil, nil, wrapEviError("evi_search_result_get_item_count", st)
		}

		msgSize := int(C.evi_message_size(msg))
		n := int(itemCount)
		if n > msgSize {
			n = msgSize
		}
		row := make([]float64, n)
		if n > 0 {
			src := C.evi_message_data(msg)
			values := unsafe.Slice(src, n)
			for j, v := range values {
				row[j] = float64(v)
			}
		}
		scores[i] = row

		C.evi_message_destroy(msg)
		C.evi_search_result_destroy(sr)
	}

	if len(shards) > 0 && len(shards) != len(ctxts) {
		return nil, nil, fmt.Errorf("envector/crypto: ctxt_score has %d entries but shard_idx has %d", len(ctxts), len(shards))
	}
	idx := make([]int32, len(shards))
	for i, s := range shards {
		idx[i] = int32(s)
	}
	return scores, idx, nil
}

// --- misc ------------------------------------------------------------------

func isEmptyDir(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}
