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

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum evi_status {
    EVI_STATUS_SUCCESS = 0,
    EVI_STATUS_INVALID_ARGUMENT = 1,
    EVI_STATUS_RUNTIME_ERROR = 2,
    EVI_STATUS_OUT_OF_RANGE = 3,
    EVI_STATUS_NOT_IMPLEMENTED = 4,
    EVI_STATUS_NULL_POINTER = 5,
} evi_status_t;

typedef enum evi_parameter_preset {
    EVI_PARAMETER_PRESET_INVALID = -1,
    EVI_PARAMETER_PRESET_RUNTIME = 0,
    EVI_PARAMETER_PRESET_QF0 = 1,
    EVI_PARAMETER_PRESET_QF1 = 2,
    EVI_PARAMETER_PRESET_QF2 = 3,
    EVI_PARAMETER_PRESET_QF3 = 4,
    EVI_PARAMETER_PRESET_IP0 = 5,
    EVI_PARAMETER_PRESET_IP1 = 6
} evi_parameter_preset_t;

typedef enum evi_eval_mode {
    EVI_EVAL_MODE_INVALID = -1,
    EVI_EVAL_MODE_RMP = 0,
    EVI_EVAL_MODE_RMS = 1,
    EVI_EVAL_MODE_MS = 2,
    EVI_EVAL_MODE_FLAT = 3,
    EVI_EVAL_MODE_MM = 4
} evi_eval_mode_t;

typedef enum evi_device_type {
    EVI_DEVICE_TYPE_INVALID = -1,
    EVI_DEVICE_TYPE_CPU = 0,
    EVI_DEVICE_TYPE_GPU = 1,
    EVI_DEVICE_TYPE_AVX2 = 2,
    EVI_DEVICE_TYPE_
} evi_device_type_t;

typedef enum evi_data_type {
    EVI_DATA_TYPE_INVALID = -1,
    EVI_DATA_TYPE_CIPHER = 0,
    EVI_DATA_TYPE_PLAIN = 1
} evi_data_type_t;

typedef enum evi_encode_type {
    EVI_ENCODE_TYPE_INVALID = -1,
    EVI_ENCODE_TYPE_ITEM = 0,
    EVI_ENCODE_TYPE_QUERY = 1
} evi_encode_type_t;

typedef enum evi_seal_mode {
    EVI_SEAL_MODE_HSM_PORT = 0,
    EVI_SEAL_MODE_HSM_SERIAL = 1,
    EVI_SEAL_MODE_AES_KEK = 2,
    EVI_SEAL_MODE_NONE = 3
} evi_seal_mode_t;

typedef struct evi_context evi_context_t;
typedef struct evi_keypack evi_keypack_t;
typedef struct evi_keygenerator evi_keygenerator_t;
typedef struct evi_secret_key evi_secret_key_t;
typedef struct evi_encryptor evi_encryptor_t;
typedef struct evi_query evi_query_t;
typedef struct evi_search_result evi_search_result_t;
typedef struct evi_decryptor evi_decryptor_t;
typedef struct evi_message evi_message_t;
typedef struct evi_seal_info evi_seal_info_t;
typedef struct evi_multikeygenerator evi_multikeygenerator_t;

typedef size_t (*evi_stream_read_fn)(void *handle, uint8_t *buffer, size_t size);
typedef size_t (*evi_stream_write_fn)(void *handle, const uint8_t *buffer, size_t size);

const char *evi_last_error_message(void);

#ifdef __cplusplus
}
#endif
