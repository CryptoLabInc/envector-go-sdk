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

void evi_search_result_destroy(evi_search_result_t *result);
evi_status_t evi_search_result_get_item_count(const evi_search_result_t *result, uint32_t *out_count);
evi_status_t evi_search_result_serialize_to_path(const evi_search_result_t *result, const char *path);
evi_status_t evi_search_result_deserialize_from_path(const char *path, evi_search_result_t **out_result);
evi_status_t evi_search_result_serialize_to_stream(const evi_search_result_t *result, evi_stream_write_fn write_fn,
                                                   void *handle);
evi_status_t evi_search_result_deserialize_from_stream(evi_stream_read_fn read_fn, void *handle,
                                                       evi_search_result_t **out_result);
evi_status_t evi_search_result_serialize_to_string(const evi_search_result_t *result, char **out_data,
                                                   size_t *out_size);
evi_status_t evi_search_result_deserialize_from_string(const char *data, size_t size, evi_search_result_t **out_result);

#ifdef __cplusplus
}
#endif
