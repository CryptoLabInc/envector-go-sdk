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
#include "EVI/impl/Type.hpp"
#include <cstdint>
#include <set>
#include <vector>

namespace evi {
namespace detail {

namespace utils {
void findPrimeFactors(std::set<u64> &s, u64 n);
u64 findPrimitiveRoot(u64 prime);

bool isPrime(const u64 n);
std::vector<u64> seekPrimes(const u64 center, const u64 gap, u64 number, const bool only_smaller);
} // namespace utils
//

class NTT {
public:
    NTT() = default;
    NTT(u64 degree, u64 prime);
    NTT(u64 degree, u64 prime, u64 degree_mini);

    template <int OutputModFactor = 1> // possible value: 1, 2, 4
    void computeForward(u64 *op) const;
    template <int OutputModFactor = 1>
    void computeForward(u64 *op, const u64 pad_rank) const;

    template <int OutputModFactor = 1> // possible value: 1, 2
    void computeBackward(u64 *op) const;

    template <int OutputModFactor = 1> // possible value: 1, 2
    void computeBackward(u64 *op, u64 fullmod) const;

private:
    u64 prime_;
    u64 two_prime_;
    u64 degree_;

    // roots of unity (bit reversed)
    polyvec psi_rev_;
    polyvec psi_inv_rev_;
    polyvec psi_rev_shoup_;
    polyvec psi_inv_rev_shoup_;

    // variables for last step of backward NTT
    u64 degree_inv_;
    u64 degree_inv_barrett_;
    u64 degree_inv_w_;
    u64 degree_inv_w_barrett_;

    void computeForwardNativeSingleStep(u64 *op, const u64 t) const;
    void computeForwardNativeSingleStep1(u64 *op, const u64 t, const u64 pad_rank) const;
    void computeBackwardNativeSingleStep(u64 *op, const u64 t) const;
    void computeBackwardNativeSingleStep1(u64 *op, const u64 t, const u64 fullmod) const;
    void computeBackwardNativeSingleStep2(u64 *op, const u64 t, const u64 fullmod) const;
    void computeBackwardNativeLast(u64 *op) const;
    void computeBackwardNativeLast(u64 *op, u64 fullmod) const;
};
} // namespace detail
} // namespace evi
