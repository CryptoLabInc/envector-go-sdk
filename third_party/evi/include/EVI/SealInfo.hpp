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
#include "EVI/Enums.hpp"
#include "EVI/Export.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace evi {

/// @brief AES-256 key size in bytes.
constexpr int AES256_KEY_SIZE = 32;
constexpr int AES_GCM_IV_SIZE = 12;
constexpr int AES_GCM_TAG_SIZE = 16;

namespace detail {
struct SealInfo;
}

/**
 * @class SealInfo
 * @brief Encapsulates sealing configuration used to protect secret keys in in homomorphic encryption schemes during
 * storage.
 *
 * The `SealInfo` class holds information related to how a secret key (e.g., `SecretKey`) should be sealed
 * before being saved externally. Supported sealing modes include no sealing and AES-256 key wrapping.
 */
class EVI_API SealInfo {
public:
    /**
     * @brief Constructs a `SealInfo` with the specified sealing mode.
     * @param m Sealing mode to be used (e.g., `SealMode::NONE`, `SealMode::AES_KEK`).
     */
    SealInfo(SealMode m);

    /**
     * @brief Constructs a `SealInfo` for AES-KEK sealing with a raw 256-bit key.
     * @param m Sealing mode (must be `SealMode::AES_KEK`).
     * @param aes_key A 32-byte AES key used for key wrapping.
     */
    SealInfo(SealMode m, std::vector<uint8_t> aes_key);

    /// @cond INTERNAL
    SealInfo(SealMode m, int cm, int id, const std::string &pw);
    /// @endcond

    /**
     * @brief Retrieves the current sealing mode.
     * @return The configured `SealMode` value.
     */
    SealMode getSealMode() const;

private:
    std::shared_ptr<detail::SealInfo> impl_;

    /// @cond INTERNAL
    friend std::shared_ptr<detail::SealInfo> &getImpl(SealInfo &) noexcept;
    friend const std::shared_ptr<detail::SealInfo> &getImpl(const SealInfo &) noexcept;
    /// @endcond
};

} // namespace evi
