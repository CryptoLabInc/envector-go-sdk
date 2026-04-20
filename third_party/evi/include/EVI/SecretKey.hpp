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
#include "EVI/Context.hpp"
#include "EVI/Export.hpp"
#include "EVI/SealInfo.hpp"
#include <istream>
#include <memory>
#include <optional>
#include <vector>

namespace evi {
namespace detail {
class SecretKey;
}

/**
 * @class SecretKey
 * @brief Represents a secret key used for homomorphic encryption.
 *
 * A `SecretKey` is required to derive public keys (e.g., encryption/evaluation keys)
 * and to perform encryption/decryption.
 */
class EVI_API SecretKey {
public:
    /// @brief Empty handle; initialize with makeSecKey() before use.
    SecretKey() : impl_(nullptr) {}

    /**
     * @brief Constructs a SecretKey from an internal implementation.
     * @param impl Shared pointer to the internal `detail::SecretKey` object.
     */
    SecretKey(std::shared_ptr<detail::SecretKey> impl) : impl_(std::move(impl)) {}

private:
    std::shared_ptr<detail::SecretKey> impl_;

    /// @cond INTERNAL
    friend std::shared_ptr<detail::SecretKey> &getImpl(SecretKey &) noexcept;
    friend const std::shared_ptr<detail::SecretKey> &getImpl(const SecretKey &) noexcept;
    /// @endcond
};

/**
 * @brief Creates a empty SecretKey associated with the given context.
 *
 * @param context Context used for key initialization and device selection.
 * @return A new `SecretKey` instance.
 */
EVI_API SecretKey makeSecKey(const evi::Context &context);

/**
 * @brief Load the secret key from a file.
 * @param file_path Path to the secret key file.
 * @param s_info  Optional sealing information for unsealing the secret key.
 * @return A new `SecretKey` instance.
 */
EVI_API SecretKey makeSecKey(const std::string &file_path, const std::optional<SealInfo> &s_info = std::nullopt);

/**
 * @brief Load the secret key from an input stream.
 * @param stream Stream containing a serialized secret key.
 * @param s_info Optional sealing information for unsealing the secret key.
 * @return A new `SecretKey` instance.
 */
EVI_API SecretKey makeSecKey(std::istream &stream, const std::optional<SealInfo> &s_info = std::nullopt);

/// @brief Alias representing multiple secret keys.
using MultiSecretKey = std::vector<SecretKey>;

} // namespace evi
