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

// keygenerator
evi_status_t evi_keygenerator_create(const evi_context_t *context, evi_keypack_t *pack,
                                     evi_keygenerator_t **out_keygen);
evi_status_t evi_keygenerator_create_with_seed(const evi_context_t *context, evi_keypack_t *pack, const uint8_t *seed,
                                               size_t seed_length, evi_keygenerator_t **out_keygen);
void evi_keygenerator_destroy(evi_keygenerator_t *keygen);
evi_status_t evi_keygenerator_generate_secret_key(evi_keygenerator_t *keygen, evi_secret_key_t **out_key);
evi_status_t evi_keygenerator_generate_public_keys(evi_keygenerator_t *keygen, evi_secret_key_t *seckey);

// seal info
evi_status_t evi_seal_info_create(evi_seal_mode_t mode, const uint8_t *key_data, size_t key_length,
                                  evi_seal_info_t **out_info);
void evi_seal_info_destroy(evi_seal_info_t *info);

// MultiKeyGenerator
evi_status_t evi_multikeygenerator_create(const evi_context_t *const *contexts, size_t count, const char *directory,
                                          const evi_seal_info_t *seal_info, evi_multikeygenerator_t **out_keygen);
void evi_multikeygenerator_destroy(evi_multikeygenerator_t *keygen);
evi_status_t evi_multikeygenerator_check_file_exist(evi_multikeygenerator_t *keygen, int *out_exists);
evi_status_t evi_multikeygenerator_generate_keys(evi_multikeygenerator_t *keygen, evi_secret_key_t **out_key);

#ifdef __cplusplus
}
#endif
