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
#include "EVI/Message.hpp"
#include "EVI/Query.hpp"
#include "EVI/SearchResult.hpp"
#include "EVI/SecretKey.hpp"
#include <istream>
#include <memory>

namespace evi {

namespace detail {
class Decryptor;
}

/**
 * @class Decryptor
 * @brief Decrypts queries and search results using a `SecretKey`.
 *
 * A `Decryptor` provides functions to convert encrypted data back into
 * plaintext `Message` objects. It supports decrypting individual queries,
 * ciphertexts, and search results.
 */
class EVI_API Decryptor {
public:
    /// @brief Empty handle; initialize with makeDecryptor() before use.
    Decryptor() : impl_(nullptr) {}

    /**
     * @brief Constructs a Decryptor with an internal implementation.
     * @param impl Shared pointer to the internal `detail::Decryptor` object.
     */
    explicit Decryptor(std::shared_ptr<detail::Decryptor> impl) noexcept;

    /**
     * @brief Decrypts a search result using the given secret key.
     * @param item Encrypted search result.
     * @param seckey Secret key used for decryption.
     * @return Decrypted `Message`.
     */
    Message decrypt(const SearchResult &item, const SecretKey &seckey);

    /**
     * @brief Decrypts a search result with optional score scaling.
     * @param item Encrypted search result.
     * @param seckey Secret key used for decryption.
     * @param is_score Indicates whether the decrypted result should be interpreted as a score.
     * @param scale Optional scaling factor for precise score computation.
     * @return Decrypted `Message`.
     */
    Message decrypt(const SearchResult &item, const SecretKey &seckey, bool is_score,
                    std::optional<double> scale = std::nullopt);

    /**
     * @brief Decrypts a search result using a key loaded from a file.
     * @param item Encrypted search result.
     * @param key_path Path to the secret key file.
     * @param is_score Indicates whether the decrypted result should be interpreted as a score.
     * @param scale Optional scaling factor for precise score computation.
     * @return Decrypted `Message`.
     */
    Message decrypt(const SearchResult &item, const std::string &key_path, bool is_score,
                    std::optional<double> scale = std::nullopt);

    /**
     * @brief Decrypts a search result using a key loaded from a stream.
     * @param item Encrypted search result.
     * @param key_stream Input stream providing the secret key material.
     * @param is_score Indicates whether the decrypted result should be interpreted as a score.
     * @param scale Optional scaling factor for precise score computation.
     * @return Decrypted `Message`.
     */
    Message decrypt(const SearchResult &item, std::istream &key_stream, bool is_score,
                    std::optional<double> scale = std::nullopt);

    /**
     * @brief Decrypts an entire encrypted query.
     * @param ctxt Encrypted query to decrypt.
     * @param key_path Path to the secret key file.
     * @param scale Optional scaling factor to adjust precision.
     * @return Decrypted `Message`.
     */
    Message decrypt(const Query &ctxt, const std::string &key_path, std::optional<double> scale = std::nullopt);

    /**
     * @brief Decrypts an entire encrypted query using a key stream.
     * @param ctxt Encrypted query to decrypt.
     * @param key_stream Input stream providing the secret key material.
     * @param scale Optional scaling factor to adjust precision.
     * @return Decrypted `Message`.
     */
    Message decrypt(const Query &ctxt, std::istream &key_stream, std::optional<double> scale = std::nullopt);

    /**
     * @brief Decrypts an entire encrypted query.
     * @param ctxt Encrypted query to decrypt.
     * @param seckey Secret key used for decryption.
     * @param scale Optional scaling factor to adjust precision.
     * @return Decrypted `Message`.
     */
    Message decrypt(const Query &ctxt, const SecretKey &seckey, std::optional<double> scale = std::nullopt);

    /**
     * @brief Decrypts a specific item from an encrypted query. This function is only supported in RMP mode.
     * @param idx Index of the item to decrypt.
     * @param ctxt Encrypted query.
     * @param key Secret key used for decryption.
     * @param scale Optional scaling factor to adjust precision.
     * @return Decrypted `Message`.
     */
    Message decrypt(int idx, const Query &ctxt, const SecretKey &seckey, std::optional<double> scale = std::nullopt);

private:
    std::shared_ptr<detail::Decryptor> impl_;
};

/**
 * @brief Creates a `Decryptor` instance using the given context.
 *
 * @param context Context used for key initialization and device selection.
 * @return Configured `Decryptor` instance.
 */
EVI_API Decryptor makeDecryptor(const Context &context);

} // namespace evi
