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

#include "EVI/impl/Type.hpp"

namespace evi {
namespace detail {
constexpr u32 LOG_DEGREE = 12;
constexpr u32 HAMMING_WEIGHT = 2730;
constexpr u32 HW_REJ_BIT_SIZE = 12;
constexpr u32 CBD_COIN_SIZE = 21;
constexpr u32 SHAKE256_RATE = 136;
constexpr u32 PRNG_BUF_SIZE = SHAKE256_RATE * 80;
constexpr u32 BIT_MAX_LEN = 64;

constexpr double GAUSSIAN_ERROR_STDEV = 3.2;

constexpr u32 DEGREE = 1LU << LOG_DEGREE;
constexpr u32 TWO_DEGREE = DEGREE << 1;
constexpr u64 U64_DEGREE{sizeof(u64) << LOG_DEGREE};

constexpr u32 MAX_NUM_THREADS = 1U << 10;
constexpr u32 LOG_TENSOR_X_DIM = 5;
constexpr u32 LOG_TENSOR_Y_DIM = 3;

static constexpr u32 LOG_TILE_DIM = 5;
static constexpr u32 TILE_DIM = 1U << LOG_TILE_DIM;
static constexpr u32 BLOCK_ROWS = 8;

constexpr static u32 LOG_THREAD_NTT_SIZE = 3;
constexpr static u32 LOG_FIRST_RADIX = 6;
constexpr static u32 LOG_THREAD_N = 6;
constexpr static u32 PAD = 4;

constexpr static u32 FIRST_RADIX = 1U << LOG_FIRST_RADIX;
constexpr static u32 THREAD_NTT_SIZE = 1U << LOG_THREAD_NTT_SIZE;
constexpr static u32 THREAD_N = 1U << LOG_THREAD_N;
constexpr static u32 FIRST_PER_THREAD_RADIX = FIRST_RADIX >> LOG_THREAD_NTT_SIZE;
constexpr static u32 DEGREE_PER_SIZE = DEGREE >> LOG_THREAD_NTT_SIZE;
constexpr static u32 LOG_SECOND_RADIX = LOG_DEGREE - LOG_FIRST_RADIX;
constexpr static u32 SECOND_RADIX = 1U << LOG_SECOND_RADIX;
constexpr static u32 SECOND_PER_THREAD_RADIX = SECOND_RADIX >> LOG_THREAD_NTT_SIZE;

constexpr int AES256_KEY_SIZE = 32;
constexpr int AES256_IV_SIZE = 12;
constexpr int AES256_TAG_SIZE = 16;
constexpr int AES256_GCM_OUT_SIZE = 62;

} // namespace detail
} // namespace evi
