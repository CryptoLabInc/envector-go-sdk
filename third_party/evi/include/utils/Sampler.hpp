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

#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/Const.hpp"
#include "EVI/impl/ContextImpl.hpp"
#include "EVI/impl/NTT.hpp"
#include "EVI/impl/Type.hpp"
#include "alea/alea.h"
#include "utils/span.hpp"

#include <cstdint>
#include <random>
#include <string>
#include <utility>

namespace evi {
namespace detail {
class RandomSampler {

public:
    RandomSampler() = delete; // Default constructor is deleted to enforce the use of context
    RandomSampler(const evi::detail::Context &context);
    RandomSampler(const evi::detail::Context &context, std::optional<std::vector<u8>> seed);
    ~RandomSampler() = default;

    void embedding(span<i64> coeff, span<u64> poly, u64 mod);

    i64 getCenteredBinomialError();

    void sampleZO(span<u64> res_q, std::optional<span<u64>> res_p = std::nullopt);
    void rejSamplingMod(span<i32> si);
    void sampleHWT(span<i64> res);
    void noSampleHWT(span<i64> res);
    void sampleGaussian(span<u64> res_q, std::optional<span<u64>> res_p = std::nullopt);
    void sampleUniformModQ(span<u64> res);
    void sampleUniformModP(span<u64> res);
    // Generates random bits of specified length
    // The parameter outLen must be less than or equal to 64
    u64 getRandomBits(u64 out_len);

private:
    const evi::detail::Context context_;
    std::shared_ptr<alea_state> as_;
    u64 buffer = 0;
    u64 buffer_size_ = 0;

    inline u64 bitWidth(u64 x) {
        if (x == 0)
            return 0;
#if defined(__GNUG__)
        return 64u - __builtin_clzll(x);
#else
        unsigned w = 0;
        while (x) {
            x >>= 1;
            ++w;
        }
        return w;
#endif
    }

    inline u64 sampleTernaryModU64(u64 b1, u64 b2, u64 mod) {
        // b1 ? ((b2 & 1) ? 1 : mod - 1 ): 0
        return b2 * (((b1 - 1) & mod) + ((b1 << 1) - 1));
    }
    inline u64 addIfLTZeroU64(i64 val, u64 mod) {
        // val < 0 ? mod + val : val
        return static_cast<u64>(val + (mod & (val >> 63)));
    }
};
} // namespace detail
} // namespace evi
