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

evi_status_t evi_decryptor_create(const evi_context_t *context, evi_decryptor_t **out_decryptor);
void evi_decryptor_destroy(evi_decryptor_t *decryptor);

evi_status_t evi_decryptor_decrypt_search_result_with_seckey(evi_decryptor_t *decryptor,
                                                             const evi_search_result_t *result,
                                                             const evi_secret_key_t *seckey, int is_score,
                                                             const double *scale, evi_message_t **out_message);

evi_status_t evi_decryptor_decrypt_search_result_with_path(evi_decryptor_t *decryptor,
                                                           const evi_search_result_t *result, const char *key_path,
                                                           int is_score, const double *scale,
                                                           evi_message_t **out_message);

evi_status_t evi_decryptor_decrypt_query_with_path(evi_decryptor_t *decryptor, const evi_query_t *query,
                                                   const char *key_path, const double *scale,
                                                   evi_message_t **out_message);

evi_status_t evi_decryptor_decrypt_query_with_seckey(evi_decryptor_t *decryptor, const evi_query_t *query,
                                                     const evi_secret_key_t *seckey, const double *scale,
                                                     evi_message_t **out_message);

#ifdef __cplusplus
}
#endif
