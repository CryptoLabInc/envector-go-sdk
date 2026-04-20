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

void evi_secret_key_destroy(evi_secret_key_t *seckey);
evi_status_t evi_secret_key_create(const evi_context_t *context, evi_secret_key_t **out_key);
evi_status_t evi_secret_key_create_from_path(const char *path, evi_secret_key_t **out_key);
evi_status_t evi_secret_key_create_from_path_with_seal_info(const char *path, const evi_seal_info_t *seal_info,
                                                            evi_secret_key_t **out_key);

#ifdef __cplusplus
}
#endif
