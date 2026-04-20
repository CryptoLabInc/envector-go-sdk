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

#include <array>
#include <cstdint>
#include <functional>

namespace evi {
namespace detail {
// NOLINTBEGIN(readability-identifier-naming)
using u64 = uint64_t;
using i64 = int64_t;
using u32 = uint32_t;
using i32 = int32_t;
using u8 = uint8_t;
#if defined(_MSC_VER) && !defined(__clang__)
struct alignas(16) u128 {
    u64 hi;
    u64 lo;

    constexpr u128() : hi(0), lo(0) {}
    constexpr u128(u64 value) : hi(0), lo(value) {}
    constexpr u128(u64 hi_value, u64 lo_value) : hi(hi_value), lo(lo_value) {}
};
#else
using u128 = unsigned __int128;
using i128 = __int128;
#endif
// NOLINTEND(readability-identifier-naming)

#define U64C(x) UINT64_C(x)
} // namespace detail
} // namespace evi
