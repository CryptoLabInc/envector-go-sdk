////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2025, CryptoLab, Inc.                                       //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "evi_c/common.h"

#ifdef __cplusplus
extern "C" {
#endif

evi_status_t evi_encryptor_create(const evi_context_t *context, evi_encryptor_t **out_encryptor);
evi_status_t evi_encryptor_create_with_seed(const evi_context_t *context, const uint8_t *seed, size_t seed_length,
                                            evi_encryptor_t **out_encryptor);
void evi_encryptor_destroy(evi_encryptor_t *encryptor);

// encode
// input : 1 data, output : 1 query
evi_status_t evi_encryptor_encode_vector(const evi_encryptor_t *encryptor, const float *data, size_t dim,
                                         evi_encode_type_t encode_type, int level, const float *scale,
                                         evi_query_t **out_query);

// input : batch data, output : batch queries
evi_status_t evi_encryptor_encode_batch(const evi_encryptor_t *encryptor, const float *const *data, const size_t dim,
                                        size_t data_count, evi_encode_type_t encode_type, int level, const float *scale,
                                        evi_query_t ***out_queries, size_t *out_count);

// input : batch data, output : 1 query
evi_status_t evi_encryptor_encode_vectors(const evi_encryptor_t *encryptor, const float *const *data, const size_t dim,
                                          size_t data_count, evi_encode_type_t encode_type, int level,
                                          const float *scale, evi_query_t **out_query);

// encrypt
// input : 1 data, output : 1 query
evi_status_t evi_encryptor_encrypt_vector_with_path(const evi_encryptor_t *encryptor, const char *enckey_path,
                                                    const float *data, size_t dim, evi_encode_type_t encode_type,
                                                    int level, const float *scale, evi_query_t **out_query);

// input : 1 data, output : 1 query
evi_status_t evi_encryptor_encrypt_vector_with_pack(const evi_encryptor_t *encryptor, const evi_keypack_t *pack,
                                                    const float *data, size_t dim, evi_encode_type_t encode_type,
                                                    int level, const float *scale, evi_query_t **out_query);

// input : batch data, output : batch query
evi_status_t evi_encryptor_encrypt_batch_with_path(const evi_encryptor_t *encryptor, const char *enckey_path,
                                                   const float *const *data, const size_t dim, size_t data_count,
                                                   evi_encode_type_t encode_type, int level, const float *scale,
                                                   evi_query_t ***out_queries, size_t *out_count);

// input : batch data, output : batch query
evi_status_t evi_encryptor_encrypt_batch_with_pack(const evi_encryptor_t *encryptor, const evi_keypack_t *pack,
                                                   const float *const *data, const size_t dim, size_t data_count,
                                                   evi_encode_type_t encode_type, int level, const float *scale,
                                                   evi_query_t ***out_queries, size_t *out_count);

#ifdef __cplusplus
}
#endif
