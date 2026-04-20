//go:build libevi

package crypto

import "errors"

var errCGOStub = errors.New("envector/crypto: libevi CGO provider not yet implemented")

func defaultProvider() Provider { return stubCGO{} }

type stubCGO struct{}

func (stubCGO) NewCKKSContext(CKKSParams) (CKKSContext, error)        { return nil, errCGOStub }
func (stubCGO) NewEncryptor(CKKSContext, []byte) (Encryptor, error)   { return nil, errCGOStub }
func (stubCGO) NewDecryptor(CKKSContext, []byte) (Decryptor, error)   { return nil, errCGOStub }
func (stubCGO) NewKeyGenerator(KeyGenParams) (KeyGenerator, error)    { return nil, errCGOStub }
