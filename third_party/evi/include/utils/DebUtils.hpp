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
#include "EVI/impl/ContextImpl.hpp"

#include <deb/CKKSTypes.hpp>

namespace evi {
namespace detail {
namespace utils {

deb::Preset getDebPreset(const detail::Context &context);

deb::Preset getDebPreset(const std::string &preset);

std::optional<deb::RNGSeed> convertDebSeed(const std::optional<std::vector<u8>> &seed);

bool syncFixedKeyToDebSwkKey(const detail::Context &context, const detail::FixedKeyType &fixed, deb::SwitchKey &swk);

bool syncVarKeyToDebSwkKey(const detail::Context &context, const detail::VariadicKeyType &variad, deb::SwitchKey &swk);

deb::Ciphertext convertPointerToDebCipher(const detail::Context &context, detail::u64 *a_q, detail::u64 *b_q,
                                          detail::u64 *a_p = nullptr, detail::u64 *b_p = nullptr, bool is_ntt = true);

deb::Ciphertext convertSingleCipherToDebCipher(const detail::Context &context,
                                               detail::SingleBlock<DataType::CIPHER> &cipher, bool is_ntt = true);

} // namespace utils
} // namespace detail
} // namespace evi
