// C++ implementation of the local KeyManager shim declared in
// keymanager_shim.h. Sits in the same cgo package as cryptocgo.go so the
// Go toolchain picks it up automatically; links against the
// already-bundled libevi_crypto.a for the evi::KeyManager symbols.
//
// Exception safety: every entry point catches C++ exceptions and stores
// the message in a thread-local buffer reachable via evi_km_last_error.
// Go callers check the int status and pull the message only on failure.
#include "keymanager_shim.h"

#include "km/KeyManager.hpp"

#include <exception>
#include <string>
#include <utility>

namespace {

thread_local std::string g_last_error;

template <typename Fn>
int runGuarded(Fn &&fn) {
    try {
        std::forward<Fn>(fn)();
        g_last_error.clear();
        return 0;
    } catch (const std::exception &e) {
        g_last_error = e.what();
        return -2;
    } catch (...) {
        g_last_error = "evi_km shim: unknown C++ exception";
        return -2;
    }
}

bool anyEmpty(const char *const *ptrs, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (ptrs[i] == nullptr || ptrs[i][0] == '\0') {
            return true;
        }
    }
    return false;
}

} // namespace

extern "C" {

int evi_km_wrap_sec_key(const char *key_id, const char *in_bin_path, const char *out_json_path) {
    const char *args[] = {key_id, in_bin_path, out_json_path};
    if (anyEmpty(args, 3)) {
        g_last_error = "evi_km_wrap_sec_key: null/empty argument";
        return -1;
    }
    return runGuarded([&] {
        auto km = evi::makeKeyManager();
        km.wrapSecKey(std::string(key_id), std::string(in_bin_path), std::string(out_json_path));
    });
}

int evi_km_wrap_enc_key(const char *key_id, const char *in_bin_path, const char *out_json_path) {
    const char *args[] = {key_id, in_bin_path, out_json_path};
    if (anyEmpty(args, 3)) {
        g_last_error = "evi_km_wrap_enc_key: null/empty argument";
        return -1;
    }
    return runGuarded([&] {
        auto km = evi::makeKeyManager();
        km.wrapEncKey(std::string(key_id), std::string(in_bin_path), std::string(out_json_path));
    });
}

int evi_km_wrap_eval_key(const char *key_id, const char *in_bin_path, const char *out_json_path) {
    const char *args[] = {key_id, in_bin_path, out_json_path};
    if (anyEmpty(args, 3)) {
        g_last_error = "evi_km_wrap_eval_key: null/empty argument";
        return -1;
    }
    return runGuarded([&] {
        auto km = evi::makeKeyManager();
        km.wrapEvalKey(std::string(key_id), std::string(in_bin_path), std::string(out_json_path));
    });
}

int evi_km_unwrap_sec_key(const char *in_json_path, const char *out_bin_path) {
    const char *args[] = {in_json_path, out_bin_path};
    if (anyEmpty(args, 2)) {
        g_last_error = "evi_km_unwrap_sec_key: null/empty argument";
        return -1;
    }
    return runGuarded([&] {
        auto km = evi::makeKeyManager();
        // NONE seal only: pass std::nullopt (default) so KeyManager does not
        // attempt AES-KEK unwrap. AES_KEK support would add a SealInfo arg.
        km.unwrapSecKey(std::string(in_json_path), std::string(out_bin_path));
    });
}

int evi_km_unwrap_enc_key(const char *in_json_path, const char *out_bin_path) {
    const char *args[] = {in_json_path, out_bin_path};
    if (anyEmpty(args, 2)) {
        g_last_error = "evi_km_unwrap_enc_key: null/empty argument";
        return -1;
    }
    return runGuarded([&] {
        auto km = evi::makeKeyManager();
        km.unwrapEncKey(std::string(in_json_path), std::string(out_bin_path));
    });
}

int evi_km_unwrap_eval_key(const char *in_json_path, const char *out_bin_path) {
    const char *args[] = {in_json_path, out_bin_path};
    if (anyEmpty(args, 2)) {
        g_last_error = "evi_km_unwrap_eval_key: null/empty argument";
        return -1;
    }
    return runGuarded([&] {
        auto km = evi::makeKeyManager();
        km.unwrapEvalKey(std::string(in_json_path), std::string(out_bin_path));
    });
}

const char *evi_km_last_error(void) {
    return g_last_error.c_str();
}

} // extern "C"
