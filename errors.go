package envector

import "errors"

var (
	ErrAddressRequired      = errors.New("envector: ClientOptions.Address is required")
	ErrClientClosed         = errors.New("envector: client is closed")
	ErrKeysClosed           = errors.New("envector: keys handle is closed")
	ErrKeysRequired         = errors.New("envector: IndexOptions.Keys is required for Insert")
	ErrKeysAlreadyExist     = errors.New("envector: key files already exist at path")
	ErrKeysNotFound         = errors.New("envector: key files not found at path")
	ErrKeysAlreadyActivated = errors.New("envector: keys already activated on another client")
	ErrCryptoUnavailable    = errors.New("envector/crypto: libevi_crypto binding not built (rebuild with -tags=libevi)")
	ErrNotImplemented       = errors.New("envector: not implemented")
)
