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

evi_status_t evi_context_create(evi_parameter_preset_t preset, evi_device_type_t device, uint64_t dim,
                                evi_eval_mode_t eval_mode, const int32_t *device_id, evi_context_t **out_context);

void evi_context_destroy(evi_context_t *context);

// getters
evi_device_type_t evi_context_get_device_type(const evi_context_t *context);

evi_eval_mode_t evi_context_get_eval_mode(const evi_context_t *context);

uint32_t evi_context_get_pad_rank(const evi_context_t *context);

uint32_t evi_context_get_show_dim(const evi_context_t *context);

double evi_context_get_scale_factor(const evi_context_t *context);

#ifdef __cplusplus
}
#endif
