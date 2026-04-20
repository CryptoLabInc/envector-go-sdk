package crypto

import (
	"fmt"
	"strings"
)

// Integer values below must match the upstream enums in
// third_party/evi/include/evi_c/common.h. They are expressed as plain int
// so that the mapping functions are callable from both the cgo and the
// pure-Go build without importing "C".

const (
	eviPresetIP0 = 5
	eviPresetIP1 = 6

	eviEvalModeRMP = 0
	eviEvalModeMM  = 4

	eviEncodeItem  = 0
	eviEncodeQuery = 1
)

// presetToEnum maps the user-facing preset string to the upstream
// evi_parameter_preset_t value. The accepted set mirrors pyenvector@1.2.2's
// active parameters (IP / IP0 / IP1 only; QF is disabled without libHEaaN).
func presetToEnum(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "ip", "ip0":
		return eviPresetIP0, nil
	case "ip1":
		return eviPresetIP1, nil
	}
	return 0, fmt.Errorf("envector/crypto: invalid preset %q (supported: ip, ip0, ip1)", s)
}

// evalModeToEnum maps eval_mode strings to evi_eval_mode_t. Limited to RMP
// and MM — the only two modes pyenvector exposes in its active whitelist.
func evalModeToEnum(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "rmp":
		return eviEvalModeRMP, nil
	case "mm":
		return eviEvalModeMM, nil
	}
	return 0, fmt.Errorf("envector/crypto: invalid eval_mode %q (supported: rmp, mm)", s)
}

// encodeTypeToEnum maps encode type strings to evi_encode_type_t.
func encodeTypeToEnum(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "item":
		return eviEncodeItem, nil
	case "query":
		return eviEncodeQuery, nil
	}
	return 0, fmt.Errorf("envector/crypto: invalid encode type %q (supported: item, query)", s)
}
