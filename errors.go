package envector

import "errors"

var (
	ErrAddressRequired    = errors.New("envector: ClientOptions.Address is required")
	ErrClientClosed       = errors.New("envector: client is closed")
	ErrKeysRequired       = errors.New("envector: IndexOptions.Keys is required for Insert")
	ErrKeysAlreadyExist   = errors.New("envector: key files already exist at path")
	ErrKeysNotFound       = errors.New("envector: key files not found at path")
	ErrKeysNotForEncrypt  = errors.New("envector: keys opened without KeyPartEnc cannot encrypt")
	ErrKeysNotForDecrypt  = errors.New("envector: keys opened without KeyPartSec cannot decrypt")
	ErrKeysNotForRegister = errors.New("envector: keys opened without KeyPartEval have no eval key for register/activate")
	ErrNotImplemented     = errors.New("envector: not implemented")
)
