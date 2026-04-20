package envector

import "fmt"

// KeyPart names one of the three key materials a Keys bundle can carry.
// Combine via WithKeyParts to opt into only what a process actually needs:
// capture-only clients typically pass {KeyPartEnc, KeyPartEval}, vault
// decrypt-only processes pass {KeyPartSec}. When WithKeyParts is omitted,
// OpenKeysFromFile loads all three.
type KeyPart int

const (
	KeyPartEnc  KeyPart = iota // EncKey.bin → cgo Encryptor handle (local Encrypt)
	KeyPartEval                // EvalKey.bin bytes → Client.RegisterKeys upload
	KeyPartSec                 // SecKey.bin  → cgo Decryptor handle (local Decrypt)
)

// Preset names one of the FHE parameter presets the active libevi build
// supports. Zero value (PresetIP0) is the default for inner-product search.
type Preset int

const (
	PresetIP0 Preset = iota
	PresetIP1
)

func (p Preset) String() string {
	switch p {
	case PresetIP1:
		return "ip1"
	case PresetIP0:
		return "ip0"
	default:
		return fmt.Sprintf("Preset(%d)", int(p))
	}
}

// EvalMode selects the homomorphic evaluation strategy. Zero value
// (EvalModeRMP) matches the default the upstream libevi builds use.
type EvalMode int

const (
	EvalModeRMP EvalMode = iota
	EvalModeMM
)

func (m EvalMode) String() string {
	switch m {
	case EvalModeMM:
		return "mm"
	case EvalModeRMP:
		return "rmp"
	default:
		return fmt.Sprintf("EvalMode(%d)", int(m))
	}
}

type keysOptions struct {
	Path     string
	KeyID    string
	Preset   Preset
	EvalMode EvalMode
	Dim      int
	Parts    []KeyPart
}

// KeysOption configures KeysExist, GenerateKeys and OpenKeysFromFile.
// Apply via the With* helpers below.
type KeysOption func(*keysOptions)

func WithKeyPath(p string) KeysOption       { return func(o *keysOptions) { o.Path = p } }
func WithKeyID(id string) KeysOption        { return func(o *keysOptions) { o.KeyID = id } }
func WithKeyPreset(p Preset) KeysOption     { return func(o *keysOptions) { o.Preset = p } }
func WithKeyEvalMode(m EvalMode) KeysOption { return func(o *keysOptions) { o.EvalMode = m } }
func WithKeyDim(d int) KeysOption           { return func(o *keysOptions) { o.Dim = d } }

// WithKeyParts restricts OpenKeysFromFile to load only the listed key
// materials. Passing no parts (or omitting the option) loads all three.
// Duplicate entries are tolerated.
func WithKeyParts(parts ...KeyPart) KeysOption {
	return func(o *keysOptions) { o.Parts = parts }
}

func buildKeysOptions(opts []KeysOption) keysOptions {
	var o keysOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// validate checks the required fields shared by GenerateKeys and
// OpenKeysFromFile. Preset/EvalMode/Parts have meaningful zero values, so
// only Path / KeyID / Dim need explicit guards.
func (o keysOptions) validate() error {
	if o.Path == "" {
		return fmt.Errorf("envector: WithKeyPath required")
	}
	if o.KeyID == "" {
		return fmt.Errorf("envector: WithKeyID required")
	}
	if o.Dim <= 0 {
		return fmt.Errorf("envector: WithKeyDim required (got %d)", o.Dim)
	}
	return nil
}

// resolveKeyParts maps the user-facing parts list to per-material flags.
// Empty list (the default) means "load everything" for backwards compat.
func resolveKeyParts(parts []KeyPart) (enc, eval, sec bool) {
	if len(parts) == 0 {
		return true, true, true
	}
	for _, p := range parts {
		switch p {
		case KeyPartEnc:
			enc = true
		case KeyPartEval:
			eval = true
		case KeyPartSec:
			sec = true
		}
	}
	return
}
