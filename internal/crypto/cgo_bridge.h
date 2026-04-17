#ifndef ENVECTOR_GO_SDK_CGO_BRIDGE_H
#define ENVECTOR_GO_SDK_CGO_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct evi_context   evi_context_t;
typedef struct evi_encryptor evi_encryptor_t;

evi_context_t*   evi_context_new(const char* preset, int dim, const char* eval_mode);
void             evi_context_free(evi_context_t* ctx);

evi_encryptor_t* evi_encryptor_new(evi_context_t* ctx,
                                   const uint8_t* enc_key_stream,
                                   size_t enc_key_len);
void             evi_encryptor_free(evi_encryptor_t* enc);

// Caller owns the arrays returned via out_bytes/out_lens and MUST release
// them with evi_free_result. Returns 0 on success, non-zero on failure.
int evi_encrypt_multiple(evi_encryptor_t* enc,
                         const float*  const* vectors,
                         size_t                n_vec,
                         size_t                dim,
                         uint8_t***            out_bytes,
                         size_t**              out_lens,
                         size_t*               out_count);

void evi_free_result(uint8_t** bytes, size_t* lens, size_t count);

#ifdef __cplusplus
}
#endif

#endif
