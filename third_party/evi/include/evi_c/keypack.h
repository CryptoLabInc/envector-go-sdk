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

evi_status_t evi_keypack_create(const evi_context_t *context, evi_keypack_t **out_pack);
evi_status_t evi_keypack_create_from_path(const evi_context_t *context, const char *directory,
                                          evi_keypack_t **out_pack);
void evi_keypack_destroy(evi_keypack_t *pack);

evi_status_t evi_keypack_save_enc_key(evi_keypack_t *pack, const char *path);
evi_status_t evi_keypack_load_enc_key(evi_keypack_t *pack, const char *path);
evi_status_t evi_keypack_save_eval_key(evi_keypack_t *pack, const char *path);
evi_status_t evi_keypack_load_eval_key(evi_keypack_t *pack, const char *path);

#ifdef __cplusplus
}
#endif
