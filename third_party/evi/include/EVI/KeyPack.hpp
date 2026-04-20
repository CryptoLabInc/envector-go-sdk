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
#include <iosfwd>
#include <memory>
#include <string>

namespace evi {

namespace detail {
class IKeyPack;
}

/**
 * @class KeyPack
 * @brief A container for storing and managing public evaluation keys (e.g., encryption, evaluation, relin keys).
 *
 * The `KeyPack` class encapsulates all keys required for encrypted computation, excluding the secret key.
 * It is typically generated from a secret key and later used for encryption and evaluation.
 */
class EVI_API KeyPack {
public:
    /// @brief Default constructor is deleted. Use `makeKeyPack` factory functions instead.
    KeyPack() = delete;

    /**
     * @brief Constructs a KeyPack with an internal implementation.
     * @param impl Shared pointer to the internal `detail::KeyPack` object.
     */
    explicit KeyPack(std::shared_ptr<detail::IKeyPack> impl) noexcept;

    /**
     * @brief Save the encryption key to a file.
     * @param dir_path Path to the directory for storing the encryption key.
     */
    void saveEncKey(const std::string &dir_path);

    /**
     * @brief Write the encryption key to an output stream.
     * @param os Output stream to which the encryption key will be written.
     */
    void saveEncKey(std::ostream &os);

    /**
     * @brief Load the encryption key from a file.
     * @param file_path Path to the encryption key file.
     */
    void loadEncKey(const std::string &file_path);

    /**
     * @brief Load the encryption key from an input stream.
     * @param stream Input stream containing the serialized encryption key data.
     */
    void loadEncKey(std::istream &stream);

    /**
     * @brief Save the evaluation key to a file.
     * @param dir_path Path to the directory for storing the evaluation key.
     */
    void saveEvalKey(const std::string &dir_path);

    /**
     * @brief Write the evaluation key to an output stream.
     * @param os Output stream to which the evaluation key will be written.
     */
    void saveEvalKey(std::ostream &os);

    /**
     * @brief Load the evaluation key from a file.
     * @param file_path Path to the evaluation key file.
     */
    void loadEvalKey(const std::string &file_path);

    /**
     * @brief Load the evaluation key from an input stream.
     * @param stream Input stream containing the serialized evaluation key data.
     */
    void loadEvalKey(std::istream &stream);

private:
    std::shared_ptr<detail::IKeyPack> impl_;

    /// @cond INTERNAL
    friend std::shared_ptr<detail::IKeyPack> &getImpl(KeyPack &) noexcept;
    const friend std::shared_ptr<detail::IKeyPack> &getImpl(const KeyPack &) noexcept;
    /// @endcond
};

/**
 * @brief Creates an empty KeyPack associated with the given context.
 *
 * @param context Context used for key initialization and device selection.
 * @return A new `KeyPack` instance.
 */
EVI_API KeyPack makeKeyPack(const evi::Context &context);

/**
 * @brief Creates a KeyPack by loading key data from an input stream.
 *
 * @param context Context used for key initialization and device selection.
 * @param in Input stream containing the serialized key data.
 * @return A new `KeyPack` instance.
 */
EVI_API KeyPack makeKeyPack(const evi::Context &context, std::istream &in);

/**
 * @brief Creates a KeyPack by loading key data from a directory.
 *
 * @param context Context used for key initialization and device selection.
 * @param dir_path Path to the directory containing the key files.
 * @return A new `KeyPack` instance.
 */
EVI_API KeyPack makeKeyPack(const evi::Context &context, const std::string &dir_path);

} // namespace evi
